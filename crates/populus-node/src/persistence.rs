use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use libp2p::identity::Keypair;
use populus_cluster::{OwnershipError, OwnershipVoteJournal, OwnershipVoteKey, OwnershipVoteKind};
use populus_types::NodeId;

const MAX_IDENTITY_FILE_BYTES: usize = 1024;
const MAX_IDENTITY_FILE_BYTES_U64: u64 = 1025;
const OWNERSHIP_JOURNAL_HEADER: &[u8; 5] = b"POVJ\x01";
const OWNERSHIP_JOURNAL_RECORD_BYTES: usize = 137;
const MAX_OWNERSHIP_JOURNAL_RECORDS: usize = 4096;
const MAX_OWNERSHIP_JOURNAL_BYTES: u64 = (OWNERSHIP_JOURNAL_HEADER.len()
    + OWNERSHIP_JOURNAL_RECORD_BYTES * MAX_OWNERSHIP_JOURNAL_RECORDS)
    as u64;

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

    /// Opens the durable non-equivocation journal associated with this identity
    /// store, when the backend supports one.
    ///
    /// # Errors
    ///
    /// Returns storage errors when the journal cannot be opened or validated.
    fn open_ownership_vote_journal(&self) -> io::Result<Option<Box<dyn OwnershipVoteJournal>>> {
        Ok(None)
    }
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

    fn open_ownership_vote_journal(&self) -> io::Result<Option<Box<dyn OwnershipVoteJournal>>> {
        let path = self.path.with_extension("ownership-votes");
        Ok(Some(Box::new(FileOwnershipVoteJournal::open(path)?)))
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

/// Append-only, fsync-before-signature ownership vote journal.
///
/// The journal is locked across reload, conflict checking, append, and sync so
/// concurrent processes cannot persist conflicting votes through the same file.
pub struct FileOwnershipVoteJournal {
    path: PathBuf,
}

impl FileOwnershipVoteJournal {
    /// Opens or initializes a bounded ownership-vote journal.
    ///
    /// # Errors
    ///
    /// Returns storage errors for inaccessible, malformed, truncated, or
    /// over-limit journal files. Invalid state fails closed.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(OWNERSHIP_JOURNAL_HEADER)?;
                file.sync_all()?;
                if let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    File::open(parent)?.sync_all()?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let journal = Self { path };
        journal.with_locked_file(|file| read_vote_records(file).map(|_| ()))?;
        Ok(journal)
    }

    /// Returns the configured journal path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn with_locked_file<T>(
        &self,
        operation: impl FnOnce(&mut File) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        file.lock()?;
        operation(&mut file)
    }
}

impl OwnershipVoteJournal for FileOwnershipVoteJournal {
    fn record_vote(
        &mut self,
        key: OwnershipVoteKey,
        decision_digest: [u8; 32],
    ) -> Result<(), OwnershipError> {
        self.with_locked_file(|file| {
            let mut records = read_vote_records(file)?;
            match records.get(&key) {
                Some(existing) if existing != &decision_digest => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "ownership vote context already has a conflicting digest",
                    ));
                }
                Some(_) => return Ok(()),
                None => {}
            }
            if records.len() >= MAX_OWNERSHIP_JOURNAL_RECORDS {
                return Err(io::Error::other("ownership vote journal is full"));
            }
            file.seek(SeekFrom::End(0))?;
            file.write_all(&encode_vote_record(key, decision_digest))?;
            file.sync_all()?;
            records.insert(key, decision_digest);
            Ok(())
        })
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                OwnershipError::JournalConflict
            } else {
                OwnershipError::JournalFailure
            }
        })
    }
}

fn read_vote_records(file: &mut File) -> io::Result<HashMap<OwnershipVoteKey, [u8; 32]>> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    Read::take(file, MAX_OWNERSHIP_JOURNAL_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_OWNERSHIP_JOURNAL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership vote journal exceeds its bound",
        ));
    }
    let Some(records_bytes) = bytes.strip_prefix(OWNERSHIP_JOURNAL_HEADER) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership vote journal encoding is malformed",
        ));
    };
    if !records_bytes
        .len()
        .is_multiple_of(OWNERSHIP_JOURNAL_RECORD_BYTES)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ownership vote journal encoding is malformed",
        ));
    }
    let mut records = HashMap::new();
    let (record_chunks, _) = records_bytes.as_chunks::<OWNERSHIP_JOURNAL_RECORD_BYTES>();
    for record in record_chunks {
        let mut cursor = 0;
        let network_id = take_array::<32>(record, &mut cursor)?;
        let subject = NodeId::from_bytes(take_array::<32>(record, &mut cursor)?);
        let epoch = u64::from_be_bytes(take_array::<8>(record, &mut cursor)?);
        let previous_decision_hash = take_array::<32>(record, &mut cursor)?;
        let kind = match take_array::<1>(record, &mut cursor)?[0] {
            0 => OwnershipVoteKind::Binding,
            1 => OwnershipVoteKind::CommitteeTransition,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "ownership vote journal contains an unknown vote kind",
                ));
            }
        };
        let decision_digest = take_array::<32>(record, &mut cursor)?;
        let key = OwnershipVoteKey {
            network_id,
            subject,
            epoch,
            previous_decision_hash,
            kind,
        };
        if let Some(previous) = records.insert(key, decision_digest)
            && previous != decision_digest
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "ownership vote journal contains conflicting records",
            ));
        }
    }
    Ok(records)
}

fn encode_vote_record(
    key: OwnershipVoteKey,
    decision_digest: [u8; 32],
) -> [u8; OWNERSHIP_JOURNAL_RECORD_BYTES] {
    let mut bytes = [0; OWNERSHIP_JOURNAL_RECORD_BYTES];
    let mut cursor = 0;
    for part in [
        key.network_id.as_slice(),
        key.subject.as_bytes(),
        &key.epoch.to_be_bytes(),
        &key.previous_decision_hash,
    ] {
        let end = cursor + part.len();
        bytes[cursor..end].copy_from_slice(part);
        cursor = end;
    }
    bytes[cursor] = match key.kind {
        OwnershipVoteKind::Binding => 0,
        OwnershipVoteKind::CommitteeTransition => 1,
    };
    cursor += 1;
    bytes[cursor..].copy_from_slice(&decision_digest);
    bytes
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> io::Result<[u8; N]> {
    let end = cursor
        .checked_add(N)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "journal offset overflow"))?;
    let value = bytes
        .get(*cursor..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated journal record"))?;
    *cursor = end;
    value
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid journal record"))
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
    use populus_cluster::{
        OwnershipError, OwnershipVoteJournal, OwnershipVoteKey, OwnershipVoteKind,
    };
    use populus_types::NodeId;

    use super::{
        FileOwnershipVoteJournal, FilePeerIdentityStore, PeerIdentityError, PeerIdentityStore,
        load_or_create_peer_identity,
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

    #[test]
    fn ownership_journal_persists_votes_and_rejects_equivocation_after_reopen() {
        let path = test_path();
        let key = OwnershipVoteKey {
            network_id: [1; 32],
            subject: NodeId::from_bytes([2; 32]),
            epoch: 3,
            previous_decision_hash: [4; 32],
            kind: OwnershipVoteKind::Binding,
        };
        {
            let mut journal = FileOwnershipVoteJournal::open(&path).expect("open journal");
            journal
                .record_vote(key, [5; 32])
                .expect("persist first vote");
            journal
                .record_vote(key, [5; 32])
                .expect("repeat is idempotent");
        }
        let mut reopened = FileOwnershipVoteJournal::open(&path).expect("reopen journal");
        assert_eq!(
            reopened.record_vote(key, [6; 32]),
            Err(OwnershipError::JournalConflict)
        );
        fs::remove_file(path).expect("remove test journal");
    }

    #[test]
    fn ownership_journal_fails_closed_on_truncated_record() {
        let path = test_path();
        fs::write(&path, b"POVJ\x01\x01").expect("write truncated journal");
        assert!(FileOwnershipVoteJournal::open(&path).is_err());
        fs::remove_file(path).expect("remove test journal");
    }
}
