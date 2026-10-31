//! Versioned, domain-separated identifier derivations for Populus.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use populus_types::{
    AuthorityId, ClientId, ContentId, MutableContentId, NetworkIdentity, NodeId, ProducerId,
    RoutingKey,
};
use sha2::{Digest, Sha256};
use std::fmt;

const NODE_DOMAIN: &[u8] = b"populus/node/v1";
const CLIENT_DOMAIN: &[u8] = b"populus/client/v1";
const ROUTING_DOMAIN: &[u8] = b"populus/routing/v1";
const PRODUCER_DOMAIN: &[u8] = b"populus/producer/v1";
const AUTHORITY_DOMAIN: &[u8] = b"populus/authority/v1";
const MUTABLE_DOMAIN: &[u8] = b"populus/mutable/v1";

fn encoded_length<const N: usize>(length: usize) -> [u8; N] {
    let mut encoded = [0; N];
    for (destination, source) in encoded
        .iter_mut()
        .rev()
        .zip(length.to_be_bytes().iter().rev())
    {
        *destination = *source;
    }
    encoded
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(encoded_length::<1>(domain.len()));
    hasher.update(domain);
    hasher.update(encoded_length::<4>(payload.len()));
    hasher.update(payload);
    hasher.finalize().into()
}

/// Derives a node's Populus DHT position from the canonical v1 scarcity identity.
#[must_use]
pub fn node_id(identity: &NetworkIdentity) -> NodeId {
    NodeId::from_bytes(domain_hash(NODE_DOMAIN, identity.as_bytes()))
}

/// Derives a voting identity from the same scarcity source under the separate ID-001 domain.
#[must_use]
pub fn client_id(identity: &NetworkIdentity) -> ClientId {
    ClientId::from_bytes(domain_hash(CLIENT_DOMAIN, identity.as_bytes()))
}

/// Logical routing identifier category, serialized as a one-byte v1 tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RoutingKind {
    /// Immutable v1 `ContentId`, tagged `0x01`.
    Content = 0x01,
    /// Stable v1 `MutableContentId`, tagged `0x02`.
    MutableContent = 0x02,
}

/// A typed logical identifier accepted as input to [`routing_key`].
///
/// The variants prevent callers from hashing untyped bytes or pairing a kind
/// tag with an identifier from a different domain.
#[derive(Clone, Copy)]
pub enum RoutingIdentifier<'a> {
    /// Route to an immutable content CID.
    Content(&'a ContentId),
    /// Route to a stable mutable-content identity.
    MutableContent(&'a MutableContentId),
}

/// Derives a fixed-width routing key from a typed logical identifier.
#[must_use]
pub fn routing_key(identifier: RoutingIdentifier<'_>) -> RoutingKey {
    let mut payload = [0; 37];
    let payload_length = match identifier {
        RoutingIdentifier::Content(content_id) => {
            payload[0] = RoutingKind::Content as u8;
            payload[1..].copy_from_slice(content_id.as_bytes());
            37
        }
        RoutingIdentifier::MutableContent(mutable_id) => {
            payload[0] = RoutingKind::MutableContent as u8;
            payload[1..33].copy_from_slice(mutable_id.as_bytes());
            33
        }
    };
    RoutingKey::from_bytes(domain_hash(ROUTING_DOMAIN, &payload[..payload_length]))
}

/// Public-key algorithm identifiers supported by v1 producer and authority IDs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    /// Ed25519 public keys, exactly 32 bytes, tagged `0x01`.
    Ed25519 = 0x01,
}

/// Invalid input to a public-key identifier derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Ed25519 keys must contain exactly 32 bytes.
    InvalidPublicKeyLength {
        /// Required public-key byte length.
        expected: usize,
        /// Supplied public-key byte length.
        actual: usize,
    },
    /// The Ed25519 public key is not a valid curve point.
    InvalidPublicKey,
    /// The Ed25519 signature does not verify for the supplied message.
    InvalidSignature,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    formatter,
                    "expected {expected}-byte public key, got {actual} bytes"
                )
            }
            Self::InvalidPublicKey => formatter.write_str("invalid Ed25519 public key"),
            Self::InvalidSignature => formatter.write_str("invalid Ed25519 signature"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Ed25519 signing key for content authorship.
///
/// The underlying key value is kept private and is zeroized on drop with the
/// enabled zeroization feature. The caller must protect the input seed.
pub struct ProducerKeypair {
    signing_key: SigningKey,
}

/// Ed25519 signing key for authority-to-authority protocol messages.
///
/// Authority keys are distinct at the type and identifier level from producer
/// keys, even though both use the same v1 Ed25519 algorithm.
pub struct AuthorityKeypair {
    signing_key: SigningKey,
}

impl AuthorityKeypair {
    /// Constructs an authority signing key from its 32-byte Ed25519 secret seed.
    #[must_use]
    pub fn from_secret_key(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Returns this key's 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the domain-separated authority identity for this key.
    #[must_use]
    pub fn authority_id(&self) -> AuthorityId {
        let public_key = self.public_key();
        let mut payload = [0; 33];
        payload[0] = PublicKeyAlgorithm::Ed25519 as u8;
        payload[1..].copy_from_slice(&public_key);
        AuthorityId::from_bytes(domain_hash(AUTHORITY_DOMAIN, &payload))
    }

    /// Signs an exact authority protocol message with Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

impl ProducerKeypair {
    /// Constructs a signing key from its 32-byte Ed25519 secret seed.
    #[must_use]
    pub fn from_secret_key(secret: [u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&secret),
        }
    }

    /// Returns this key's 32-byte Ed25519 public key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Returns the domain-separated producer identity for this key.
    #[must_use]
    pub fn producer_id(&self) -> ProducerId {
        let public_key = self.public_key();
        let mut payload = [0; 33];
        payload[0] = PublicKeyAlgorithm::Ed25519 as u8;
        payload[1..].copy_from_slice(&public_key);
        ProducerId::from_bytes(domain_hash(PRODUCER_DOMAIN, &payload))
    }

    /// Signs an exact message with Ed25519.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }
}

/// Verifies an Ed25519 signature for an exact message.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] for malformed public-key bytes or
/// [`CryptoError::InvalidSignature`] when verification fails.
pub fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    verifying_key
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| CryptoError::InvalidSignature)
}

/// Validates that byte-array input is a valid Ed25519 public key.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKey`] for bytes that are not a valid
/// Ed25519 curve point.
pub fn validate_ed25519_public_key(public_key: &[u8; 32]) -> Result<(), CryptoError> {
    VerifyingKey::from_bytes(public_key)
        .map(|_| ())
        .map_err(|_| CryptoError::InvalidPublicKey)
}

fn key_payload(algorithm: PublicKeyAlgorithm, public_key: &[u8]) -> Result<[u8; 33], CryptoError> {
    if public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKeyLength {
            expected: 32,
            actual: public_key.len(),
        });
    }
    let mut payload = [0; 33];
    payload[0] = algorithm as u8;
    payload[1..].copy_from_slice(public_key);
    Ok(payload)
}

/// Derives an authorship identity from an algorithm tag and its public key.
///
/// This function identifies the key; it does not sign messages or validate key
/// material beyond enforcing the v1 Ed25519 public-key width.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKeyLength`] unless the public key is 32 bytes.
pub fn producer_id(
    algorithm: PublicKeyAlgorithm,
    public_key: &[u8],
) -> Result<ProducerId, CryptoError> {
    let payload = key_payload(algorithm, public_key)?;
    Ok(ProducerId::from_bytes(domain_hash(
        PRODUCER_DOMAIN,
        &payload,
    )))
}

/// Derives an authority signing-key identity under a domain distinct from `ProducerId`.
///
/// This function identifies the key; it does not sign messages or validate key
/// material beyond enforcing the v1 Ed25519 public-key width.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKeyLength`] unless the public key is 32 bytes.
pub fn authority_id(
    algorithm: PublicKeyAlgorithm,
    public_key: &[u8],
) -> Result<AuthorityId, CryptoError> {
    let payload = key_payload(algorithm, public_key)?;
    Ok(AuthorityId::from_bytes(domain_hash(
        AUTHORITY_DOMAIN,
        &payload,
    )))
}

/// Derives a stable mutable-object identity from its genesis anchor content CID.
#[must_use]
pub fn mutable_content_id(genesis_anchor: &ContentId) -> MutableContentId {
    MutableContentId::from_bytes(domain_hash(MUTABLE_DOMAIN, genesis_anchor.as_bytes()))
}

#[cfg(test)]
mod tests;
