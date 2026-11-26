use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use libp2p::identity::Keypair;

const MAX_IDENTITY_FILE_BYTES: usize = 1024;
const MAX_IDENTITY_FILE_BYTES_U64: u64 = 1025;

/// Minimal persistence boundary for the process's long-lived transport identity.
pub trait PeerIdentityStore {
    /// Loads the encoded private identity, or returns `None` when it is absent.
    ///
    /// # Errors
    ///
    /// Returns storage errors or invalid-data errors for oversized files.
    fn load(&self) -> io::Result<Option<Vec<u8>>>;

    /// Creates a new identity file without replacing an existing one.
    ///
    /// # Errors
    ///
    /// Returns storage errors, including `AlreadyExists` when another process
    /// wins a concurrent first-start race.
    fn store_new(&self, encoded_identity: &[u8]) -> io::Result<()>;
}

/// File-backed persistent identity storage.
pub struct FilePeerIdentityStore {
    path: PathBuf,
}

impl FilePeerIdentityStore {
    /// Creates a store at `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Returns the configured identity-file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl PeerIdentityStore for FilePeerIdentityStore {
    fn load(&self) -> io::Result<Option<Vec<u8>>> {
        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        Read::take(file, MAX_IDENTITY_FILE_BYTES_U64).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_IDENTITY_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer identity file exceeds maximum size",
            ));
        }
        Ok(Some(bytes))
    }

    fn store_new(&self, encoded_identity: &[u8]) -> io::Result<()> {
        if encoded_identity.len() > MAX_IDENTITY_FILE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "peer identity exceeds maximum size",
            ));
        }
        if let Some(parent) = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&self.path)?;
        file.write_all(encoded_identity)?;
        file.sync_all()
    }
}

/// Failures while loading or initializing the persistent libp2p identity.
#[derive(Debug)]
pub enum PeerIdentityError {
    /// The persistence backend failed.
    Storage(io::Error),
    /// Stored bytes are not a valid libp2p private-key encoding.
    InvalidEncoding,
    /// libp2p failed to encode a newly generated private key.
    Encoding,
}

impl std::fmt::Display for PeerIdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(formatter, "peer identity storage failed: {error}"),
            Self::InvalidEncoding => formatter.write_str("stored PeerId key is malformed"),
            Self::Encoding => formatter.write_str("failed to encode generated PeerId key"),
        }
    }
}

impl std::error::Error for PeerIdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::InvalidEncoding | Self::Encoding => None,
        }
    }
}

/// Loads the saved transport identity or creates it exactly once.
///
/// If another process creates the key first, the winner's key is loaded. A
/// malformed existing file is reported rather than silently rotating `PeerId`.
///
/// # Errors
///
/// Returns [`PeerIdentityError`] when storage or key encoding fails.
pub fn load_or_create_peer_identity(
    store: &impl PeerIdentityStore,
) -> Result<Keypair, PeerIdentityError> {
    if let Some(bytes) = store.load().map_err(PeerIdentityError::Storage)? {
        return Keypair::from_protobuf_encoding(&bytes)
            .map_err(|_| PeerIdentityError::InvalidEncoding);
    }
    let keypair = Keypair::generate_ed25519();
    let encoded = keypair
        .to_protobuf_encoding()
        .map_err(|_| PeerIdentityError::Encoding)?;
    match store.store_new(&encoded) {
        Ok(()) => Ok(keypair),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let bytes = store
                .load()
                .map_err(PeerIdentityError::Storage)?
                .ok_or_else(|| {
                    PeerIdentityError::Storage(io::Error::new(
                        io::ErrorKind::NotFound,
                        "peer identity disappeared after concurrent initialization",
                    ))
                })?;
            Keypair::from_protobuf_encoding(&bytes).map_err(|_| PeerIdentityError::InvalidEncoding)
        }
        Err(error) => Err(PeerIdentityError::Storage(error)),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use libp2p::identity::Keypair;

    use super::{
        FilePeerIdentityStore, PeerIdentityError, PeerIdentityStore, load_or_create_peer_identity,
    };

    static NEXT_TEST_FILE: AtomicU64 = AtomicU64::new(0);

    fn test_path() -> PathBuf {
        let sequence = NEXT_TEST_FILE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "populus-peer-identity-{}-{sequence}",
            std::process::id()
        ))
    }

    #[test]
    fn peer_id_is_stable_across_store_reload() {
        let path = test_path();
        let store = FilePeerIdentityStore::new(&path);
        let first = load_or_create_peer_identity(&store).expect("create identity");
        let restarted = load_or_create_peer_identity(&store).expect("reload identity");
        assert_eq!(first.public().to_peer_id(), restarted.public().to_peer_id());
        fs::remove_file(path).expect("remove test identity");
    }

    #[test]
    fn malformed_identity_is_rejected_without_rotating_key() {
        let path = test_path();
        let store = FilePeerIdentityStore::new(&path);
        store
            .store_new(b"not a private key")
            .expect("write fixture");
        assert!(matches!(
            load_or_create_peer_identity(&store),
            Err(PeerIdentityError::InvalidEncoding)
        ));
        fs::remove_file(path).expect("remove test identity");
    }

    #[test]
    fn concurrent_create_race_loads_the_winning_identity() {
        struct RacingStore {
            key: Vec<u8>,
        }
        impl PeerIdentityStore for RacingStore {
            fn load(&self) -> std::io::Result<Option<Vec<u8>>> {
                Ok(Some(self.key.clone()))
            }

            fn store_new(&self, _: &[u8]) -> std::io::Result<()> {
                Err(std::io::ErrorKind::AlreadyExists.into())
            }
        }
        let winner = Keypair::generate_ed25519();
        let store = RacingStore {
            key: winner.to_protobuf_encoding().expect("encode winning key"),
        };
        let loaded = load_or_create_peer_identity(&store).expect("load concurrent winner");
        assert_eq!(loaded.public().to_peer_id(), winner.public().to_peer_id());
    }
}
