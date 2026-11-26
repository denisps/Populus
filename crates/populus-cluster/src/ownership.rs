//! Signed candidate discovery records and a bounded local registry.

use std::collections::BTreeMap;

use populus_crypto::{AuthorityKeypair, PublicKeyAlgorithm, authority_id, verify_ed25519};
use populus_types::{AuthorityId, NetworkIdentity, NodeId, RoutingKey};
use sha2::{Digest, Sha256};

const MAX_PEER_ID_BYTES: usize = 128;
const MAX_ADDRESSES: usize = 8;
const MAX_ADDRESS_BYTES: usize = 256;
const MAX_CANDIDATE_TTL_MS: u64 = 86_400_000;
const MAX_CANDIDATES: usize = 4096;
const CANDIDATES_PER_SHARD: usize = 64;
const REGISTRATION_DOMAIN: &[u8] = b"populus/node-candidate-registration/v1";

type CandidateShardKey = ([u8; 32], NodeId, u8);
type CandidateShard = BTreeMap<Vec<u8>, CandidateRegistration>;

#[derive(Debug, Clone, Copy)]
struct SequenceWatermark {
    sequence: u64,
    retain_until_ms: u64,
}

/// A signed, expiring candidate discovery record. It is not an ownership
/// certificate and cannot by itself activate a `NodeId`.
#[derive(Clone, PartialEq, Eq)]
pub struct CandidateRegistration {
    network_id: [u8; 32],
    node_id: NodeId,
    identity: NetworkIdentity,
    peer_id: Vec<u8>,
    authority_id: AuthorityId,
    public_key: [u8; 32],
    sequence: u64,
    expires_at_ms: u64,
    addresses: Vec<String>,
    signature: [u8; 64],
}

impl std::fmt::Debug for CandidateRegistration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CandidateRegistration")
            .field("network_id", &self.network_id)
            .field("node_id", &self.node_id)
            .field("identity", &self.identity.as_bytes())
            .field("peer_id", &self.peer_id)
            .field("authority_id", &self.authority_id)
            .field("sequence", &self.sequence)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("addresses", &self.addresses)
            .field("public_key", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl CandidateRegistration {
    /// Creates a canonical signed candidate registration.
    ///
    /// The signature binds the advertised `PeerId` bytes and addresses. The
    /// transport adapter must separately verify that the authenticated
    /// transport `PeerId` is the one named here.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for invalid identity, transport identifier,
    /// key, or address fields.
    pub fn sign(
        network_id: [u8; 32],
        identity: NetworkIdentity,
        peer_id: Vec<u8>,
        sequence: u64,
        expires_at_ms: u64,
        mut addresses: Vec<String>,
        signer: &AuthorityKeypair,
    ) -> Result<Self, OwnershipError> {
        if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID_BYTES {
            return Err(OwnershipError::InvalidCandidate);
        }
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty()
            || addresses.len() > MAX_ADDRESSES
            || addresses
                .iter()
                .any(|address| !valid_address(address.as_str()))
        {
            return Err(OwnershipError::InvalidCandidate);
        }
        let public_key = signer.public_key();
        if peer_id != Self::peer_id_for_public_key(&public_key) {
            return Err(OwnershipError::InvalidCandidate);
        }
        let authority_id = signer.authority_id();
        let mut registration = Self {
            network_id,
            node_id: populus_crypto::node_id(&identity),
            identity,
            peer_id,
            authority_id,
            public_key,
            sequence,
            expires_at_ms,
            addresses,
            signature: [0; 64],
        };
        registration.signature = signer.sign(&registration.signing_message()?);
        Ok(registration)
    }

    /// Verifies the signature and checks that the registration remains valid.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::InvalidCandidate`] for malformed or forged
    /// registrations and [`OwnershipError::Expired`] when stale.
    pub fn verify(&self, now_ms: u64) -> Result<(), OwnershipError> {
        if self.node_id != populus_crypto::node_id(&self.identity)
            || self.peer_id.is_empty()
            || self.peer_id.len() > MAX_PEER_ID_BYTES
            || self.addresses.is_empty()
            || self.addresses.len() > MAX_ADDRESSES
            || self
                .addresses
                .iter()
                .any(|address| !valid_address(address.as_str()))
            || self.expires_at_ms <= now_ms
            || self.expires_at_ms.saturating_sub(now_ms) > MAX_CANDIDATE_TTL_MS
            || self.peer_id != Self::peer_id_for_public_key(&self.public_key)
            || authority_id(PublicKeyAlgorithm::Ed25519, &self.public_key)
                .map_err(|_| OwnershipError::InvalidCandidate)?
                != self.authority_id
        {
            return Err(if self.expires_at_ms <= now_ms {
                OwnershipError::Expired
            } else {
                OwnershipError::InvalidCandidate
            });
        }
        verify_ed25519(&self.public_key, &self.signing_message()?, &self.signature)
            .map_err(|_| OwnershipError::InvalidSignature)
    }

    /// Returns the candidate `NodeId`.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the configured Populus network identifier.
    #[must_use]
    pub const fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    /// Returns the canonical network identity committed by this registration.
    #[must_use]
    pub const fn identity(&self) -> NetworkIdentity {
        self.identity
    }

    /// Returns the signed transport `PeerId` bytes.
    #[must_use]
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Returns the bounded direct dial addresses advertised by this candidate.
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// Returns the monotonically increasing candidate sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the registration expiry.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Encodes the complete signed record in bounded canonical form.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::InvalidCandidate`] if an invariant needed for
    /// canonical encoding is violated.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, OwnershipError> {
        let mut bytes = self.signing_message()?;
        bytes.extend_from_slice(&self.signature);
        if bytes.len() > 4096 {
            return Err(OwnershipError::InvalidCandidate);
        }
        Ok(bytes)
    }

    /// Decodes one bounded canonical registration. Signature verification is
    /// deliberately separate and must be performed with [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::InvalidCandidate`] for malformed,
    /// noncanonical, trailing, or oversized input.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, OwnershipError> {
        if bytes.len() > 4096 {
            return Err(OwnershipError::InvalidCandidate);
        }
        let mut decoder = OwnershipDecoder::new(bytes);
        if decoder.take(REGISTRATION_DOMAIN.len())? != REGISTRATION_DOMAIN {
            return Err(OwnershipError::InvalidCandidate);
        }
        let network_id = decoder.array()?;
        let node_id = NodeId::from_bytes(decoder.array()?);
        let identity_length = usize::from(decoder.byte()?);
        if !matches!(identity_length, 5 | 7) {
            return Err(OwnershipError::InvalidCandidate);
        }
        let identity = NetworkIdentity::from_bytes(decoder.take(identity_length)?)
            .map_err(|_| OwnershipError::InvalidCandidate)?;
        let peer_id_length = usize::from(decoder.byte()?);
        if peer_id_length == 0 || peer_id_length > MAX_PEER_ID_BYTES {
            return Err(OwnershipError::InvalidCandidate);
        }
        let peer_id = decoder.take(peer_id_length)?.to_vec();
        let authority_id = AuthorityId::from_bytes(decoder.array()?);
        let public_key = decoder.array()?;
        let sequence = decoder.u64()?;
        let expires_at_ms = decoder.u64()?;
        let address_count = usize::from(decoder.byte()?);
        if address_count == 0 || address_count > MAX_ADDRESSES {
            return Err(OwnershipError::InvalidCandidate);
        }
        let mut addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            let address_length = usize::from(decoder.u16()?);
            if address_length == 0 || address_length > MAX_ADDRESS_BYTES {
                return Err(OwnershipError::InvalidCandidate);
            }
            let address = std::str::from_utf8(decoder.take(address_length)?)
                .map_err(|_| OwnershipError::InvalidCandidate)?;
            addresses.push(address.to_owned());
        }
        let signature = decoder.array()?;
        decoder.finish()?;
        if addresses.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(OwnershipError::InvalidCandidate);
        }
        let registration = Self {
            network_id,
            node_id,
            identity,
            peer_id,
            authority_id,
            public_key,
            sequence,
            expires_at_ms,
            addresses,
            signature,
        };
        if registration.canonical_bytes()?.as_slice() != bytes {
            return Err(OwnershipError::InvalidCandidate);
        }
        Ok(registration)
    }

    /// Derives the canonical libp2p identity-multihash `PeerId` bytes for an
    /// Ed25519 transport public key.
    #[must_use]
    pub fn peer_id_for_public_key(public_key: &[u8; 32]) -> Vec<u8> {
        let mut peer_id = Vec::with_capacity(38);
        peer_id.extend_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
        peer_id.extend_from_slice(public_key);
        peer_id
    }

    /// Returns a stable hash of the complete signed record.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::InvalidCandidate`] if canonical encoding
    /// violates a validated field bound.
    pub fn hash(&self) -> Result<[u8; 32], OwnershipError> {
        Ok(digest(&self.canonical_bytes()?))
    }

    fn signing_message(&self) -> Result<Vec<u8>, OwnershipError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(REGISTRATION_DOMAIN);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(self.node_id.as_bytes());
        let identity = self.identity.as_bytes();
        bytes.push(u8::try_from(identity.len()).map_err(|_| OwnershipError::InvalidCandidate)?);
        bytes.extend_from_slice(identity);
        bytes.push(u8::try_from(self.peer_id.len()).map_err(|_| OwnershipError::InvalidCandidate)?);
        bytes.extend_from_slice(&self.peer_id);
        bytes.extend_from_slice(self.authority_id.as_bytes());
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        bytes.push(
            u8::try_from(self.addresses.len()).map_err(|_| OwnershipError::InvalidCandidate)?,
        );
        for address in &self.addresses {
            let address = address.as_bytes();
            bytes.extend_from_slice(
                &u16::try_from(address.len())
                    .map_err(|_| OwnershipError::InvalidCandidate)?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(address);
        }
        Ok(bytes)
    }
}

/// Bounded, deterministic candidate registration index.
#[derive(Debug, Default)]
pub struct CandidateRegistry {
    shards: BTreeMap<CandidateShardKey, CandidateShard>,
    sequence_high_water: BTreeMap<CandidateShardKey, BTreeMap<Vec<u8>, SequenceWatermark>>,
    sequence_count: usize,
    count: usize,
}

impl CandidateRegistry {
    /// Inserts or renews a candidate and expires stale records.
    ///
    /// Each `NodeId` has 64 deterministic shards, each capped at 64 candidates.
    /// This keeps both insertion and page reads bounded.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for invalid, stale, equivocal, or over-limit
    /// registrations.
    pub fn insert(
        &mut self,
        registration: CandidateRegistration,
        now_ms: u64,
    ) -> Result<(), OwnershipError> {
        registration.verify(now_ms)?;
        self.expire(now_ms);
        let shard = candidate_shard(registration.peer_id());
        let key = (registration.network_id, registration.node_id, shard);
        let high_water = self
            .sequence_high_water
            .get(&key)
            .and_then(|sequences| sequences.get(registration.peer_id()))
            .copied();
        let high_water_sequence = high_water.map(|watermark| watermark.sequence);
        let shard_entries = self.shards.entry(key).or_default();
        if let Some(existing) = shard_entries.get(registration.peer_id()) {
            if registration.sequence == existing.sequence && registration == *existing {
                return Ok(());
            }
            if registration.sequence <= existing.sequence {
                return Err(OwnershipError::StaleRegistration);
            }
        } else if high_water_sequence.is_some_and(|sequence| registration.sequence <= sequence) {
            return Err(OwnershipError::StaleRegistration);
        }
        if high_water.is_none() && self.sequence_count >= MAX_CANDIDATES {
            return Err(OwnershipError::CandidateLimit);
        }
        let is_new_candidate = !shard_entries.contains_key(registration.peer_id());
        if is_new_candidate
            && (self.count >= MAX_CANDIDATES || shard_entries.len() >= CANDIDATES_PER_SHARD)
        {
            return Err(OwnershipError::CandidateLimit);
        }
        let retain_until_ms = high_water.map_or(registration.expires_at_ms, |watermark| {
            watermark.retain_until_ms.max(registration.expires_at_ms)
        });
        self.sequence_high_water.entry(key).or_default().insert(
            registration.peer_id.clone(),
            SequenceWatermark {
                sequence: registration.sequence,
                retain_until_ms,
            },
        );
        if high_water.is_none() {
            self.sequence_count += 1;
        }
        if !is_new_candidate {
            shard_entries.insert(registration.peer_id.clone(), registration);
            return Ok(());
        }
        shard_entries.insert(registration.peer_id.clone(), registration);
        self.count += 1;
        Ok(())
    }

    /// Returns candidates from one deterministic shard, after a `PeerId` cursor.
    #[must_use]
    pub fn page(
        &self,
        network_id: [u8; 32],
        node_id: NodeId,
        shard: u8,
        after_peer_id: Option<&[u8]>,
        limit: usize,
        now_ms: u64,
    ) -> Vec<&CandidateRegistration> {
        let Some(entries) = self.shards.get(&(network_id, node_id, shard)) else {
            return Vec::new();
        };
        if limit == 0 || limit > CANDIDATES_PER_SHARD {
            return Vec::new();
        }
        entries
            .iter()
            .filter(|(peer_id, registration)| {
                registration.expires_at_ms > now_ms
                    && after_peer_id.is_none_or(|cursor| peer_id.as_slice() > cursor)
            })
            .take(limit)
            .map(|(_, registration)| registration)
            .collect()
    }

    /// Finds one current registration by subject and exact transport `PeerId`.
    #[must_use]
    pub fn get(
        &self,
        network_id: [u8; 32],
        node_id: NodeId,
        peer_id: &[u8],
    ) -> Option<&CandidateRegistration> {
        let entries = self
            .shards
            .get(&(network_id, node_id, candidate_shard(peer_id)))?;
        entries.get(peer_id)
    }

    /// Expires stale registrations and releases their bounded slots.
    pub fn expire(&mut self, now_ms: u64) {
        self.shards.retain(|_, entries| {
            entries.retain(|_, registration| registration.expires_at_ms > now_ms);
            !entries.is_empty()
        });
        self.count = self.shards.values().map(BTreeMap::len).sum();
        self.sequence_high_water.retain(|_, sequences| {
            sequences.retain(|_, watermark| watermark.retain_until_ms > now_ms);
            !sequences.is_empty()
        });
        self.sequence_count = self.sequence_high_water.values().map(BTreeMap::len).sum();
    }

    /// Returns the current number of retained candidates.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Returns whether the registry is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

fn candidate_shard(peer_id: &[u8]) -> u8 {
    let hash = digest(peer_id);
    hash[0] & 0x3f
}

/// Returns the deterministic 6-bit shard for a signed candidate `PeerId`.
#[must_use]
pub fn candidate_registry_shard(peer_id: &[u8]) -> u8 {
    candidate_shard(peer_id)
}

/// Derives the Populus DHT key for one `NodeId` candidate-registry shard.
#[must_use]
pub fn candidate_registry_key(
    network_id: [u8; 32],
    node_id: NodeId,
    shard: u8,
) -> Option<RoutingKey> {
    if shard >= 64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(98);
    bytes.extend_from_slice(b"populus/node-candidates/shard/v1");
    bytes.extend_from_slice(&network_id);
    bytes.extend_from_slice(node_id.as_bytes());
    bytes.push(shard);
    Some(RoutingKey::from_bytes(digest(&bytes)))
}

fn valid_address(address: &str) -> bool {
    !address.is_empty()
        && address.len() <= MAX_ADDRESS_BYTES
        && address.is_ascii()
        && address.starts_with('/')
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

struct OwnershipDecoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> OwnershipDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], OwnershipError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(OwnershipError::InvalidCandidate)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(OwnershipError::InvalidCandidate)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], OwnershipError> {
        self.take(N)?
            .try_into()
            .map_err(|_| OwnershipError::InvalidCandidate)
    }

    fn byte(&mut self) -> Result<u8, OwnershipError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, OwnershipError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, OwnershipError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), OwnershipError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(OwnershipError::InvalidCandidate)
        }
    }
}

/// Errors while validating or applying ownership protocol transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipError {
    /// Candidate fields or its signature are invalid.
    InvalidCandidate,
    /// A registration or lease has expired.
    Expired,
    /// The candidate's Ed25519 signature is invalid.
    InvalidSignature,
    /// A registration sequence did not advance.
    StaleRegistration,
    /// The candidate registry reached its bounded capacity.
    CandidateLimit,
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidCandidate => "candidate registration is malformed",
            Self::Expired => "candidate registration or lease has expired",
            Self::InvalidSignature => "candidate registration signature is invalid",
            Self::StaleRegistration => "candidate registration sequence is stale",
            Self::CandidateLimit => "candidate registry reached its bounded capacity",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OwnershipError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{CandidateRegistration, CandidateRegistry, MAX_CANDIDATES, OwnershipError};
    use populus_crypto::AuthorityKeypair;
    use populus_types::NetworkIdentity;

    fn registration(sequence: u64, expiry: u64) -> CandidateRegistration {
        let signer = AuthorityKeypair::from_secret_key([52; 32]);
        CandidateRegistration::sign(
            [7; 32],
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("public IP"))
                .expect("network identity"),
            CandidateRegistration::peer_id_for_public_key(&signer.public_key()),
            sequence,
            expiry,
            vec!["/ip4/8.8.8.8/tcp/4001".to_owned()],
            &signer,
        )
        .expect("candidate registration")
    }

    fn distinct_registration(index: u64, expiry: u64) -> CandidateRegistration {
        let mut secret = [52; 32];
        secret[..8].copy_from_slice(&index.to_be_bytes());
        let signer = AuthorityKeypair::from_secret_key(secret);
        let mut network_id = [0; 32];
        network_id[..8].copy_from_slice(&index.to_be_bytes());
        CandidateRegistration::sign(
            network_id,
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("public IP"))
                .expect("network identity"),
            CandidateRegistration::peer_id_for_public_key(&signer.public_key()),
            1,
            expiry,
            vec!["/ip4/8.8.8.8/tcp/4001".to_owned()],
            &signer,
        )
        .expect("candidate registration")
    }

    #[test]
    fn candidate_registry_is_sharded_bounded_and_network_scoped() {
        let candidate = registration(1, 100);
        let mut registry = CandidateRegistry::default();
        registry.insert(candidate.clone(), 1).expect("insert");
        let shard = super::candidate_registry_shard(candidate.peer_id());
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry
                .page([7; 32], candidate.node_id(), shard, None, 1, 1)
                .len(),
            1
        );
        assert_eq!(
            registry.page([8; 32], candidate.node_id(), shard, None, 1, 1),
            Vec::<&CandidateRegistration>::new()
        );
        registry.expire(100);
        assert!(registry.is_empty());
    }

    #[test]
    fn expired_newer_registration_does_not_allow_sequence_rollback() {
        let mut registry = CandidateRegistry::default();
        let older = registration(1, 1_000);
        let newer = registration(2, 100);
        registry
            .insert(older.clone(), 1)
            .expect("older registration");
        registry.insert(newer, 2).expect("newer registration");
        registry.expire(100);
        assert_eq!(
            registry.insert(older, 100),
            Err(OwnershipError::StaleRegistration)
        );
    }

    #[test]
    fn expired_sequence_metadata_releases_admission_capacity() {
        let mut registry = CandidateRegistry::default();
        for index in 0..u64::try_from(MAX_CANDIDATES).expect("capacity fits u64") {
            registry
                .insert(distinct_registration(index, 100), 1)
                .expect("candidate admitted within capacity");
        }
        assert_eq!(registry.sequence_count, MAX_CANDIDATES);
        registry.expire(100);
        assert_eq!(registry.sequence_count, 0);

        registry
            .insert(
                distinct_registration(
                    u64::try_from(MAX_CANDIDATES).expect("capacity fits u64"),
                    200,
                ),
                100,
            )
            .expect("expired replay metadata releases capacity");
        assert_eq!(registry.sequence_count, 1);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn candidate_registration_encoding_round_trips() {
        let candidate = registration(3, 100);
        let encoded = candidate.canonical_bytes().expect("encode");
        let decoded = CandidateRegistration::from_canonical_bytes(&encoded).expect("decode");
        assert_eq!(decoded, candidate);
        decoded.verify(1).expect("signature verifies");
    }
}
