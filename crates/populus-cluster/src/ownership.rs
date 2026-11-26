//! Committee-chained `NodeId` ownership certificates and bounded candidate records.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use populus_crypto::{
    AuthorityKeypair, PublicKeyAlgorithm, authority_id, validate_ed25519_public_key, verify_ed25519,
};
use populus_types::{AuthorityId, NetworkIdentity, NodeId, RoutingKey, XorDistance};
use sha2::{Digest, Sha256};

use crate::{AUTHORITY_COUNT, AuthorityMember};

const MAX_ELIGIBLE_MEMBERS: usize = 256;
const MAX_PEER_ID_BYTES: usize = 128;
const MAX_ADDRESSES: usize = 8;
const MAX_ADDRESS_BYTES: usize = 256;
const MAX_CANDIDATE_TTL_MS: u64 = 86_400_000;
const MAX_CANDIDATES: usize = 4096;
const CANDIDATES_PER_SHARD: usize = 64;
const MAX_LEASE_MS: u64 = 86_400_000;
const MAX_ATTESTATION_AGE_MS: u64 = 300_000;
const COMMITTEE_DOMAIN: &[u8] = b"populus/ownership-committee/v1";
const TRANSITION_DOMAIN: &[u8] = b"populus/ownership-committee-transition/v1";
const REGISTRATION_DOMAIN: &[u8] = b"populus/node-candidate-registration/v1";
const ATTESTATION_DOMAIN: &[u8] = b"populus/ownership-reachability-attestation/v1";
const BINDING_DOMAIN: &[u8] = b"populus/ownership-binding-decision/v1";
const BINDING_VOTE_DOMAIN: &[u8] = b"populus/ownership-binding-vote/v1";

type CandidateShardKey = ([u8; 32], NodeId, u8);
type CandidateShard = BTreeMap<Vec<u8>, CandidateRegistration>;

/// One deterministically selected verifier committee for an unbound target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipCommittee {
    network_id: [u8; 32],
    subject: NodeId,
    epoch: u64,
    previous_committee_hash: [u8; 32],
    eligibility_snapshot: Vec<AuthorityMember>,
    members: Vec<AuthorityMember>,
    hash: [u8; 32],
}

impl OwnershipCommittee {
    /// Creates the epoch-zero committee from an explicitly trusted genesis root.
    ///
    /// The subject is excluded from the snapshot; all four verifiers must be
    /// distinct active `NodeId`s. `genesis_root` must be supplied by the
    /// out-of-band genesis mechanism.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for an invalid or insufficient snapshot.
    pub fn from_genesis(
        network_id: [u8; 32],
        subject: NodeId,
        genesis_root: [u8; 32],
        eligibility_snapshot: Vec<AuthorityMember>,
    ) -> Result<Self, OwnershipError> {
        Self::new(network_id, subject, 0, genesis_root, eligibility_snapshot)
    }

    /// Deterministically proposes the next committee from a committed active
    /// eligibility snapshot.
    ///
    /// The returned committee is only a proposal; it becomes current only
    /// after a transition certificate from this committee is applied.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::InvalidEligibilitySnapshot`] for an invalid
    /// snapshot or an exhausted committee epoch.
    pub fn next_committee(
        &self,
        eligibility_snapshot: Vec<AuthorityMember>,
    ) -> Result<Self, OwnershipError> {
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or(OwnershipError::InvalidEligibilitySnapshot)?;
        Self::new(
            self.network_id,
            self.subject,
            epoch,
            self.hash,
            eligibility_snapshot,
        )
    }

    fn new(
        network_id: [u8; 32],
        subject: NodeId,
        epoch: u64,
        previous_committee_hash: [u8; 32],
        mut eligibility_snapshot: Vec<AuthorityMember>,
    ) -> Result<Self, OwnershipError> {
        validate_snapshot(subject, &mut eligibility_snapshot)?;
        let mut ranked = eligibility_snapshot.clone();
        ranked.sort_unstable_by_key(|member| {
            (
                XorDistance::between_nodes(&subject, &member.node_id()),
                member.node_id(),
            )
        });
        ranked.truncate(AUTHORITY_COUNT);
        let mut committee = Self {
            network_id,
            subject,
            epoch,
            previous_committee_hash,
            eligibility_snapshot,
            members: ranked,
            hash: [0; 32],
        };
        committee.hash = digest(&committee.canonical_bytes()?);
        Ok(committee)
    }

    /// Returns the network identifier.
    #[must_use]
    pub const fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    /// Returns the subject `NodeId` whose ownership is being decided.
    #[must_use]
    pub const fn subject(&self) -> NodeId {
        self.subject
    }

    /// Returns the chain epoch.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the exact previous committee certificate hash.
    #[must_use]
    pub const fn previous_committee_hash(&self) -> &[u8; 32] {
        &self.previous_committee_hash
    }

    /// Returns the canonical eligibility snapshot committed by this committee.
    #[must_use]
    pub fn eligibility_snapshot(&self) -> &[AuthorityMember] {
        &self.eligibility_snapshot
    }

    /// Returns the exact four voting members in deterministic XOR order.
    #[must_use]
    pub fn members(&self) -> &[AuthorityMember] {
        &self.members
    }

    /// Returns this committee's hash.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, OwnershipError> {
        let mut bytes =
            Vec::with_capacity(COMMITTEE_DOMAIN.len() + 32 * (5 + self.eligibility_snapshot.len()));
        bytes.extend_from_slice(COMMITTEE_DOMAIN);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(self.subject.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.previous_committee_hash);
        bytes.extend_from_slice(
            &u16::try_from(self.eligibility_snapshot.len())
                .map_err(|_| OwnershipError::InvalidEligibilitySnapshot)?
                .to_be_bytes(),
        );
        for member in &self.eligibility_snapshot {
            encode_member(&mut bytes, member);
        }
        Ok(bytes)
    }
}

/// A signed proposal to advance exactly one committee-chain link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeTransitionCertificate {
    previous_hash: [u8; 32],
    next_committee: OwnershipCommittee,
    signatures: Vec<CommitteeSignature>,
}

impl CommitteeTransitionCertificate {
    /// Verifies and assembles a transition from at least three members of the
    /// exact preceding committee.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for a stale/foreign transition, invalid
    /// signatures, duplicate signers, or insufficient quorum.
    pub fn new(
        previous: &OwnershipCommittee,
        next_committee: OwnershipCommittee,
        mut signatures: Vec<CommitteeSignature>,
    ) -> Result<Self, OwnershipError> {
        if next_committee.network_id != previous.network_id
            || next_committee.subject != previous.subject
            || previous.epoch.checked_add(1) != Some(next_committee.epoch)
            || next_committee.previous_committee_hash != previous.hash
        {
            return Err(OwnershipError::CommitteeMismatch);
        }
        let expected = Self::message(&previous.hash, &next_committee.hash);
        verify_quorum_signatures(previous, &expected, &mut signatures)?;
        Ok(Self {
            previous_hash: previous.hash,
            next_committee,
            signatures,
        })
    }

    /// Returns the certified next committee.
    #[must_use]
    pub const fn next_committee(&self) -> &OwnershipCommittee {
        &self.next_committee
    }

    /// Returns the previous committee-chain hash.
    #[must_use]
    pub const fn previous_hash(&self) -> &[u8; 32] {
        &self.previous_hash
    }

    fn message(previous_hash: &[u8; 32], next_hash: &[u8; 32]) -> Vec<u8> {
        let mut message = Vec::with_capacity(TRANSITION_DOMAIN.len() + 64);
        message.extend_from_slice(TRANSITION_DOMAIN);
        message.extend_from_slice(previous_hash);
        message.extend_from_slice(next_hash);
        message
    }
}

/// One committee member's signature over a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeSignature {
    signer: AuthorityId,
    signature: [u8; 64],
}

impl CommitteeSignature {
    /// Returns the signing authority identity.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }
}

/// One proposal signature chained to a prior committee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeTransitionVote {
    previous_hash: [u8; 32],
    next_hash: [u8; 32],
    signature: CommitteeSignature,
}

impl CommitteeTransitionVote {
    /// Signs a next-committee proposal with a member of the exact current
    /// committee after durably recording the non-equivocation vote.
    ///
    /// The caller must pass the durable journal used by the process. The
    /// in-memory implementation is intended only for deterministic tests.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] if the signer is not a current member, the
    /// proposal does not follow the current chain, or the journal rejects it.
    pub fn sign(
        current: &OwnershipCommittee,
        next: &OwnershipCommittee,
        signer: &AuthorityKeypair,
        journal: &mut dyn OwnershipVoteJournal,
    ) -> Result<Self, OwnershipError> {
        if next.network_id != current.network_id
            || next.subject != current.subject
            || current.epoch.checked_add(1) != Some(next.epoch)
            || next.previous_committee_hash != current.hash
        {
            return Err(OwnershipError::CommitteeMismatch);
        }
        let signer_id = signer.authority_id();
        let member = current
            .members
            .iter()
            .find(|member| member.authority_id() == signer_id)
            .ok_or(OwnershipError::NotCommitteeMember)?;
        if member.public_key() != &signer.public_key() {
            return Err(OwnershipError::InvalidSignature);
        }
        let message = CommitteeTransitionCertificate::message(&current.hash, &next.hash);
        let vote_digest = digest(&message);
        journal.record_vote(
            OwnershipVoteKey {
                network_id: current.network_id,
                subject: current.subject,
                epoch: current.epoch,
                previous_decision_hash: current.hash,
                kind: OwnershipVoteKind::CommitteeTransition,
            },
            vote_digest,
        )?;
        Ok(Self {
            previous_hash: current.hash,
            next_hash: next.hash,
            signature: CommitteeSignature {
                signer: signer_id,
                signature: signer.sign(&message),
            },
        })
    }

    /// Returns the signature as a certificate member.
    #[must_use]
    pub fn signature(&self) -> &CommitteeSignature {
        &self.signature
    }

    /// Returns the proposal's next-committee hash.
    #[must_use]
    pub const fn next_hash(&self) -> &[u8; 32] {
        &self.next_hash
    }

    /// Returns the previous committee-chain hash.
    #[must_use]
    pub const fn previous_hash(&self) -> &[u8; 32] {
        &self.previous_hash
    }
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
        let shard_entries = self.shards.entry(key).or_default();
        if let Some(existing) = shard_entries.get(registration.peer_id()) {
            if registration.sequence == existing.sequence && registration == *existing {
                return Ok(());
            }
            if registration.sequence <= existing.sequence {
                return Err(OwnershipError::StaleRegistration);
            }
            shard_entries.insert(registration.peer_id.clone(), registration);
            return Ok(());
        }
        if self.count >= MAX_CANDIDATES || shard_entries.len() >= CANDIDATES_PER_SHARD {
            return Err(OwnershipError::CandidateLimit);
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

/// A direct reachability attestation from one exact committee member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachabilityAttestation {
    network_id: [u8; 32],
    subject: NodeId,
    peer_id: Vec<u8>,
    committee_hash: [u8; 32],
    committee_epoch: u64,
    binding_generation: u64,
    previous_binding_hash: [u8; 32],
    challenge: [u8; 16],
    checked_at_ms: u64,
    expires_at_ms: u64,
    signer: AuthorityId,
    signature: [u8; 64],
}

impl ReachabilityAttestation {
    /// Signs a fresh direct-reachability result for an exact proposed binding.
    ///
    /// The caller must create this only after a fresh direct challenge succeeds
    /// against the advertised `PeerId` and normalized `NetworkIdentity`.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] when the signer is not in the exact committee,
    /// the challenge is zero, or the attestation expiry is invalid.
    pub fn sign(
        committee: &OwnershipCommittee,
        decision: &OwnershipBindingDecision,
        registration: &CandidateRegistration,
        challenge: [u8; 16],
        checked_at_ms: u64,
        expires_at_ms: u64,
        signer: &AuthorityKeypair,
    ) -> Result<Self, OwnershipError> {
        decision.validate_registration(registration, checked_at_ms)?;
        if challenge == [0; 16]
            || expires_at_ms <= checked_at_ms
            || expires_at_ms > decision.valid_until_ms
            || decision.committee_hash != committee.hash
            || decision.committee_epoch != committee.epoch
            || decision.subject != committee.subject
        {
            return Err(OwnershipError::InvalidAttestation);
        }
        let signer_id = signer.authority_id();
        let member = committee
            .members
            .iter()
            .find(|member| member.authority_id() == signer_id)
            .ok_or(OwnershipError::NotCommitteeMember)?;
        if member.public_key() != &signer.public_key() {
            return Err(OwnershipError::InvalidSignature);
        }
        let mut attestation = Self {
            network_id: committee.network_id,
            subject: decision.subject,
            peer_id: decision.peer_id.clone(),
            committee_hash: committee.hash,
            committee_epoch: committee.epoch,
            binding_generation: decision.generation,
            previous_binding_hash: decision.previous_binding_hash,
            challenge,
            checked_at_ms,
            expires_at_ms,
            signer: signer_id,
            signature: [0; 64],
        };
        attestation.signature = signer.sign(&attestation.signing_message()?);
        Ok(attestation)
    }

    fn verify(
        &self,
        committee: &OwnershipCommittee,
        decision: &OwnershipBindingDecision,
        now_ms: u64,
    ) -> Result<(), OwnershipError> {
        if self.network_id != committee.network_id
            || self.subject != decision.subject
            || self.peer_id != decision.peer_id
            || self.committee_hash != committee.hash
            || self.committee_epoch != committee.epoch
            || self.binding_generation != decision.generation
            || self.previous_binding_hash != decision.previous_binding_hash
            || self.challenge == [0; 16]
            || self.checked_at_ms > now_ms
            || now_ms.saturating_sub(self.checked_at_ms) > MAX_ATTESTATION_AGE_MS
            || self.expires_at_ms <= now_ms
            || self.expires_at_ms > decision.valid_until_ms
        {
            return Err(OwnershipError::InvalidAttestation);
        }
        let member = committee
            .members
            .iter()
            .find(|member| member.authority_id() == self.signer)
            .ok_or(OwnershipError::NotCommitteeMember)?;
        verify_ed25519(
            member.public_key(),
            &self.signing_message()?,
            &self.signature,
        )
        .map_err(|_| OwnershipError::InvalidSignature)
    }

    fn signing_message(&self) -> Result<Vec<u8>, OwnershipError> {
        let mut message = Vec::with_capacity(ATTESTATION_DOMAIN.len() + 240);
        message.extend_from_slice(ATTESTATION_DOMAIN);
        message.extend_from_slice(&self.network_id);
        message.extend_from_slice(self.subject.as_bytes());
        message.push(
            u8::try_from(self.peer_id.len()).map_err(|_| OwnershipError::InvalidAttestation)?,
        );
        message.extend_from_slice(&self.peer_id);
        message.extend_from_slice(&self.committee_hash);
        message.extend_from_slice(&self.committee_epoch.to_be_bytes());
        message.extend_from_slice(&self.binding_generation.to_be_bytes());
        message.extend_from_slice(&self.previous_binding_hash);
        message.extend_from_slice(&self.challenge);
        message.extend_from_slice(&self.checked_at_ms.to_be_bytes());
        message.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        message.extend_from_slice(self.signer.as_bytes());
        Ok(message)
    }
}

/// A single ownership binding decision, fully bound to a committee-chain link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipBindingDecision {
    network_id: [u8; 32],
    subject: NodeId,
    committee_hash: [u8; 32],
    committee_epoch: u64,
    generation: u64,
    previous_binding_hash: [u8; 32],
    peer_id: Vec<u8>,
    registration_hash: [u8; 32],
    valid_until_ms: u64,
}

impl OwnershipBindingDecision {
    /// Creates a decision over a signed candidate registration.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for a candidate or lease that does not match
    /// the committee and binding context.
    pub fn new(
        committee: &OwnershipCommittee,
        generation: u64,
        previous_binding_hash: [u8; 32],
        registration: &CandidateRegistration,
        valid_until_ms: u64,
        now_ms: u64,
    ) -> Result<Self, OwnershipError> {
        registration.verify(now_ms)?;
        if registration.network_id != committee.network_id
            || registration.node_id != committee.subject
            || valid_until_ms <= now_ms
            || valid_until_ms > registration.expires_at_ms
            || valid_until_ms.saturating_sub(now_ms) > MAX_LEASE_MS
        {
            return Err(OwnershipError::InvalidBinding);
        }
        Ok(Self {
            network_id: committee.network_id,
            subject: committee.subject,
            committee_hash: committee.hash,
            committee_epoch: committee.epoch,
            generation,
            previous_binding_hash,
            peer_id: registration.peer_id.clone(),
            registration_hash: registration.hash()?,
            valid_until_ms,
        })
    }

    /// Returns the selected candidate `PeerId` bytes.
    #[must_use]
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Returns the binding generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the binding lease expiry.
    #[must_use]
    pub const fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }

    /// Checks that a registration is the exact candidate committed by this
    /// decision and remains valid at the supplied time.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::InvalidBinding`] when the registration does
    /// not match the decision.
    pub fn validate_registration(
        &self,
        registration: &CandidateRegistration,
        now_ms: u64,
    ) -> Result<(), OwnershipError> {
        registration.verify(now_ms)?;
        if self.network_id != registration.network_id
            || self.subject != registration.node_id
            || self.peer_id != registration.peer_id
            || self.registration_hash != registration.hash()?
            || self.valid_until_ms > registration.expires_at_ms
        {
            return Err(OwnershipError::InvalidBinding);
        }
        Ok(())
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, OwnershipError> {
        let mut bytes = Vec::with_capacity(BINDING_DOMAIN.len() + 220);
        bytes.extend_from_slice(BINDING_DOMAIN);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(self.subject.as_bytes());
        bytes.extend_from_slice(&self.committee_hash);
        bytes.extend_from_slice(&self.committee_epoch.to_be_bytes());
        bytes.extend_from_slice(&self.generation.to_be_bytes());
        bytes.extend_from_slice(&self.previous_binding_hash);
        bytes.push(u8::try_from(self.peer_id.len()).map_err(|_| OwnershipError::InvalidBinding)?);
        bytes.extend_from_slice(&self.peer_id);
        bytes.extend_from_slice(&self.registration_hash);
        bytes.extend_from_slice(&self.valid_until_ms.to_be_bytes());
        Ok(bytes)
    }
}

/// One verifier vote. The included signed reachability attestation binds the
/// exact challenge and ownership decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipBindingVote {
    decision_hash: [u8; 32],
    attestation: ReachabilityAttestation,
    signature: CommitteeSignature,
}

impl OwnershipBindingVote {
    /// Signs one binding decision only after committing its non-equivocation
    /// record to the supplied vote journal.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] when the signer, attestation, or journal is
    /// invalid.
    pub fn sign(
        committee: &OwnershipCommittee,
        decision: &OwnershipBindingDecision,
        registration: &CandidateRegistration,
        attestation: ReachabilityAttestation,
        signer: &AuthorityKeypair,
        journal: &mut dyn OwnershipVoteJournal,
        now_ms: u64,
    ) -> Result<Self, OwnershipError> {
        registration.verify(now_ms)?;
        attestation.verify(committee, decision, now_ms)?;
        if registration.hash()? != decision.registration_hash
            || attestation.signer != signer.authority_id()
            || decision.committee_hash != committee.hash
            || decision.committee_epoch != committee.epoch
        {
            return Err(OwnershipError::InvalidBinding);
        }
        let signer_id = signer.authority_id();
        let member = committee
            .members
            .iter()
            .find(|member| member.authority_id() == signer_id)
            .ok_or(OwnershipError::NotCommitteeMember)?;
        if member.public_key() != &signer.public_key() {
            return Err(OwnershipError::InvalidSignature);
        }
        let decision_hash = digest(&decision.canonical_bytes()?);
        let message = Self::message(decision_hash, &attestation)?;
        journal.record_vote(
            OwnershipVoteKey {
                network_id: committee.network_id,
                subject: committee.subject,
                epoch: committee.epoch,
                previous_decision_hash: decision.previous_binding_hash,
                kind: OwnershipVoteKind::Binding,
            },
            decision_hash,
        )?;
        Ok(Self {
            decision_hash,
            attestation,
            signature: CommitteeSignature {
                signer: signer_id,
                signature: signer.sign(&message),
            },
        })
    }

    fn message(
        decision_hash: [u8; 32],
        attestation: &ReachabilityAttestation,
    ) -> Result<Vec<u8>, OwnershipError> {
        let mut message = Vec::with_capacity(BINDING_VOTE_DOMAIN.len() + 128);
        message.extend_from_slice(BINDING_VOTE_DOMAIN);
        message.extend_from_slice(&decision_hash);
        message.extend_from_slice(&attestation.signing_message()?);
        Ok(message)
    }
}

/// A 3-of-4 certificate for one active NodeId-to-PeerId binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipBindingCertificate {
    decision: OwnershipBindingDecision,
    registration: CandidateRegistration,
    votes: Vec<OwnershipBindingVote>,
    hash: [u8; 32],
}

impl OwnershipBindingCertificate {
    /// Verifies and assembles an exact-committee quorum certificate.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for invalid signatures, insufficient quorum,
    /// duplicate verifiers, stale registrations, or context mismatch.
    pub fn new(
        committee: &OwnershipCommittee,
        decision: OwnershipBindingDecision,
        registration: CandidateRegistration,
        mut votes: Vec<OwnershipBindingVote>,
        now_ms: u64,
    ) -> Result<Self, OwnershipError> {
        registration.verify(now_ms)?;
        if decision.network_id != committee.network_id
            || decision.subject != committee.subject
            || decision.committee_hash != committee.hash
            || decision.committee_epoch != committee.epoch
            || decision.registration_hash != registration.hash()?
            || decision.peer_id != registration.peer_id
            || decision.valid_until_ms <= now_ms
            || decision.valid_until_ms > registration.expires_at_ms
            || decision.valid_until_ms.saturating_sub(now_ms) > MAX_LEASE_MS
        {
            return Err(OwnershipError::InvalidBinding);
        }
        let decision_hash = digest(&decision.canonical_bytes()?);
        votes.sort_unstable_by_key(|vote| vote.signature.signer);
        if votes.len() < 3 || votes.len() > AUTHORITY_COUNT {
            return Err(OwnershipError::InsufficientQuorum);
        }
        let mut signers = BTreeSet::new();
        for vote in &votes {
            if vote.decision_hash != decision_hash || !signers.insert(vote.signature.signer) {
                return Err(OwnershipError::ConflictingDecision);
            }
            vote.attestation.verify(committee, &decision, now_ms)?;
            if vote.attestation.signer != vote.signature.signer {
                return Err(OwnershipError::InvalidAttestation);
            }
            let member = committee
                .members
                .iter()
                .find(|member| member.authority_id() == vote.signature.signer)
                .ok_or(OwnershipError::NotCommitteeMember)?;
            verify_ed25519(
                member.public_key(),
                &OwnershipBindingVote::message(decision_hash, &vote.attestation)?,
                &vote.signature.signature,
            )
            .map_err(|_| OwnershipError::InvalidSignature)?;
        }
        let hash = certificate_hash(&decision, &registration, &votes)?;
        Ok(Self {
            decision,
            registration,
            votes,
            hash,
        })
    }

    /// Returns the binding decision.
    #[must_use]
    pub const fn decision(&self) -> &OwnershipBindingDecision {
        &self.decision
    }

    /// Returns the signed candidate registration.
    #[must_use]
    pub const fn registration(&self) -> &CandidateRegistration {
        &self.registration
    }

    /// Returns the certificate hash used as the next generation's parent.
    #[must_use]
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// Current committee and active binding for one subject `NodeId`.
#[derive(Debug, Clone)]
pub struct OwnershipState {
    committee: OwnershipCommittee,
    binding: Option<OwnershipBindingCertificate>,
}

impl OwnershipState {
    /// Creates an ownership state from a trusted epoch-zero committee.
    #[must_use]
    pub const fn new(committee: OwnershipCommittee) -> Self {
        Self {
            committee,
            binding: None,
        }
    }

    /// Returns the currently committed verifier committee.
    #[must_use]
    pub const fn committee(&self) -> &OwnershipCommittee {
        &self.committee
    }

    /// Returns the current certified active binding, if any.
    #[must_use]
    pub const fn binding(&self) -> Option<&OwnershipBindingCertificate> {
        self.binding.as_ref()
    }

    /// Advances one exact, 3-of-4-certified committee-chain link.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::CommitteeMismatch`] for stale, skipped, or
    /// competing committee transitions.
    pub fn apply_transition(
        &mut self,
        certificate: CommitteeTransitionCertificate,
    ) -> Result<(), OwnershipError> {
        if certificate.previous_hash != self.committee.hash
            || certificate.next_committee.previous_committee_hash != self.committee.hash
            || self.committee.epoch.checked_add(1) != Some(certificate.next_committee.epoch)
        {
            return Err(OwnershipError::CommitteeMismatch);
        }
        self.committee = certificate.next_committee;
        Ok(())
    }

    /// Applies a quorum-authorized binding while preserving a still-valid
    /// incumbent until its lease expires.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError`] for a stale generation, wrong prior
    /// certificate, conflicting committee, expired lease, or active incumbent.
    pub fn apply_binding(
        &mut self,
        certificate: OwnershipBindingCertificate,
        now_ms: u64,
    ) -> Result<(), OwnershipError> {
        let decision = &certificate.decision;
        if decision.network_id != self.committee.network_id
            || decision.subject != self.committee.subject
            || decision.committee_hash != self.committee.hash
            || decision.committee_epoch != self.committee.epoch
            || decision.valid_until_ms <= now_ms
        {
            return Err(OwnershipError::CommitteeMismatch);
        }
        let (expected_generation, expected_previous_hash) = match &self.binding {
            Some(binding) => (
                binding
                    .decision
                    .generation
                    .checked_add(1)
                    .ok_or(OwnershipError::StaleBinding)?,
                binding.hash,
            ),
            None => (0, [0; 32]),
        };
        if decision.generation != expected_generation
            || decision.previous_binding_hash != expected_previous_hash
        {
            return Err(OwnershipError::StaleBinding);
        }
        if let Some(incumbent) = &self.binding
            && incumbent.decision.valid_until_ms > now_ms
            && incumbent.decision.peer_id != decision.peer_id
        {
            return Err(OwnershipError::IncumbentLeaseActive);
        }
        self.binding = Some(certificate);
        Ok(())
    }
}

/// Identifies one anti-equivocation journal slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OwnershipVoteKey {
    /// The network in which this vote is valid.
    pub network_id: [u8; 32],
    /// The `NodeId` whose ownership or committee is changing.
    pub subject: NodeId,
    /// Current committee epoch.
    pub epoch: u64,
    /// Previous certificate hash for this transition.
    pub previous_decision_hash: [u8; 32],
    /// Separates a binding vote from a committee transition.
    pub kind: OwnershipVoteKind,
}

/// Ownership decision category stored in the anti-equivocation journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnershipVoteKind {
    /// A binding-generation vote.
    Binding,
    /// A verifier-committee transition vote.
    CommitteeTransition,
}

/// Durable-before-signing non-equivocation interface.
pub trait OwnershipVoteJournal: Send {
    /// Records a digest for this unique context, rejecting a different digest.
    ///
    /// Implementations must make a successful return durable before the caller
    /// emits its signature.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipError::JournalConflict`] for conflicting reuse or
    /// [`OwnershipError::JournalFailure`] for an unavailable/full journal.
    fn record_vote(
        &mut self,
        key: OwnershipVoteKey,
        decision_digest: [u8; 32],
    ) -> Result<(), OwnershipError>;
}

/// Test/reference journal. This is not durable and must not be used by a
/// production signing path.
#[derive(Debug, Default)]
pub struct MemoryOwnershipVoteJournal {
    votes: HashMap<OwnershipVoteKey, [u8; 32]>,
}

impl OwnershipVoteJournal for MemoryOwnershipVoteJournal {
    fn record_vote(
        &mut self,
        key: OwnershipVoteKey,
        decision_digest: [u8; 32],
    ) -> Result<(), OwnershipError> {
        match self.votes.get(&key) {
            Some(existing) if existing != &decision_digest => Err(OwnershipError::JournalConflict),
            Some(_) => Ok(()),
            None => {
                self.votes.insert(key, decision_digest);
                Ok(())
            }
        }
    }
}

fn validate_snapshot(
    subject: NodeId,
    members: &mut [AuthorityMember],
) -> Result<(), OwnershipError> {
    if members.len() < AUTHORITY_COUNT || members.len() > MAX_ELIGIBLE_MEMBERS {
        return Err(OwnershipError::InvalidEligibilitySnapshot);
    }
    members.sort_unstable_by_key(AuthorityMember::node_id);
    let mut node_ids = BTreeSet::new();
    let mut authority_ids = BTreeSet::new();
    for member in members.iter() {
        validate_ed25519_public_key(member.public_key())
            .map_err(|_| OwnershipError::InvalidSignature)?;
        if member.node_id() == subject
            || !node_ids.insert(member.node_id())
            || !authority_ids.insert(member.authority_id())
        {
            return Err(OwnershipError::InvalidEligibilitySnapshot);
        }
    }
    Ok(())
}

fn verify_quorum_signatures(
    committee: &OwnershipCommittee,
    message: &[u8],
    signatures: &mut [CommitteeSignature],
) -> Result<(), OwnershipError> {
    signatures.sort_unstable_by_key(|signature| signature.signer);
    if signatures.len() < 3 || signatures.len() > AUTHORITY_COUNT {
        return Err(OwnershipError::InsufficientQuorum);
    }
    let mut seen = BTreeSet::new();
    for signature in signatures.iter() {
        if !seen.insert(signature.signer) {
            return Err(OwnershipError::ConflictingDecision);
        }
        let member = committee
            .members
            .iter()
            .find(|member| member.authority_id() == signature.signer)
            .ok_or(OwnershipError::NotCommitteeMember)?;
        verify_ed25519(member.public_key(), message, &signature.signature)
            .map_err(|_| OwnershipError::InvalidSignature)?;
    }
    Ok(())
}

fn encode_member(bytes: &mut Vec<u8>, member: &AuthorityMember) {
    bytes.extend_from_slice(member.node_id().as_bytes());
    bytes.extend_from_slice(member.authority_id().as_bytes());
    bytes.extend_from_slice(member.public_key());
}

fn certificate_hash(
    decision: &OwnershipBindingDecision,
    registration: &CandidateRegistration,
    votes: &[OwnershipBindingVote],
) -> Result<[u8; 32], OwnershipError> {
    let mut bytes = decision.canonical_bytes()?;
    bytes.extend_from_slice(&registration.hash()?);
    for vote in votes {
        bytes.extend_from_slice(vote.signature.signer.as_bytes());
        bytes.extend_from_slice(&vote.signature.signature);
        bytes.extend_from_slice(&vote.attestation.signature);
    }
    Ok(digest(&bytes))
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
    /// The candidate eligibility set is malformed, too small, too large, or
    /// contains the subject.
    InvalidEligibilitySnapshot,
    /// The decision does not bind to the candidate registration or lease.
    InvalidBinding,
    /// Candidate fields or its signature are invalid.
    InvalidCandidate,
    /// A registration or lease has expired.
    Expired,
    /// A signed message does not verify against the exact committee member.
    InvalidSignature,
    /// The signer is not in the current exact committee.
    NotCommitteeMember,
    /// A committee or binding quorum has fewer than three unique members.
    InsufficientQuorum,
    /// Duplicate or conflicting statements appeared in one certificate.
    ConflictingDecision,
    /// The committee transition does not chain from the current committee.
    CommitteeMismatch,
    /// The binding generation or preceding certificate hash is stale.
    StaleBinding,
    /// A healthy, unexpired incumbent cannot be displaced.
    IncumbentLeaseActive,
    /// A direct-reachability attestation does not match its challenge, lease,
    /// candidate, or decision context.
    InvalidAttestation,
    /// A registration sequence did not advance.
    StaleRegistration,
    /// The candidate registry reached its bounded capacity.
    CandidateLimit,
    /// The durable vote journal rejected or could not store the vote.
    JournalFailure,
    /// A previous vote exists for a different decision in this context.
    JournalConflict,
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidEligibilitySnapshot => "invalid ownership eligibility snapshot",
            Self::InvalidBinding => "ownership binding does not match its candidate",
            Self::InvalidCandidate => "candidate registration is malformed",
            Self::Expired => "candidate registration or lease has expired",
            Self::InvalidSignature => "ownership signature is invalid",
            Self::NotCommitteeMember => "signer is not in the exact verifier committee",
            Self::InsufficientQuorum => "ownership decision lacks a three-member quorum",
            Self::ConflictingDecision => "ownership certificate contains conflicting signers",
            Self::CommitteeMismatch => "ownership decision does not match the committee chain",
            Self::StaleBinding => "ownership binding generation or parent is stale",
            Self::IncumbentLeaseActive => "a valid incumbent binding cannot be displaced",
            Self::InvalidAttestation => "direct reachability attestation is invalid",
            Self::StaleRegistration => "candidate registration sequence is stale",
            Self::CandidateLimit => "candidate registry reached its bounded capacity",
            Self::JournalFailure => "durable ownership vote journal is unavailable",
            Self::JournalConflict => "ownership voter already signed a conflicting decision",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OwnershipError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{
        CandidateRegistration, CandidateRegistry, CommitteeTransitionCertificate,
        CommitteeTransitionVote, MemoryOwnershipVoteJournal, OwnershipBindingCertificate,
        OwnershipBindingDecision, OwnershipBindingVote, OwnershipCommittee, OwnershipError,
        OwnershipState, ReachabilityAttestation,
    };
    use crate::AuthorityMember;
    use populus_crypto::AuthorityKeypair;
    use populus_types::{NetworkIdentity, NodeId};

    struct Fixture {
        subject: NodeId,
        keys: Vec<AuthorityKeypair>,
        members: Vec<AuthorityMember>,
        network_id: [u8; 32],
    }

    fn fixture() -> Fixture {
        let keys: Vec<_> = (1..=4)
            .map(|seed| AuthorityKeypair::from_secret_key([seed; 32]))
            .collect();
        let members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityMember::new(
                    NodeId::from_bytes([u8::try_from(index + 11).expect("node seed"); 32]),
                    key.public_key(),
                )
                .expect("member")
            })
            .collect();
        Fixture {
            subject: populus_crypto::node_id(
                &NetworkIdentity::from_ip("8.8.8.8".parse().expect("public IP")).expect("identity"),
            ),
            keys,
            members,
            network_id: [7; 32],
        }
    }

    fn registration(
        fixture: &Fixture,
        peer_seed: u8,
        sequence: u64,
        expiry: u64,
    ) -> CandidateRegistration {
        let signer = AuthorityKeypair::from_secret_key([peer_seed.wrapping_add(51); 32]);
        let peer_id = CandidateRegistration::peer_id_for_public_key(&signer.public_key());
        CandidateRegistration::sign(
            fixture.network_id,
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("public IP")).expect("identity"),
            peer_id,
            sequence,
            expiry,
            vec!["/ip4/8.8.8.8/tcp/4001".to_owned()],
            &signer,
        )
        .expect("candidate registration")
    }

    fn committee(fixture: &Fixture) -> OwnershipCommittee {
        OwnershipCommittee::from_genesis(
            fixture.network_id,
            fixture.subject,
            [3; 32],
            fixture.members.clone(),
        )
        .expect("genesis committee")
    }

    fn binding_certificate(
        fixture: &Fixture,
        committee: &OwnershipCommittee,
        registration: CandidateRegistration,
        generation: u64,
        previous_hash: [u8; 32],
        now_ms: u64,
    ) -> OwnershipBindingCertificate {
        let valid_until_ms = registration.expires_at_ms().min(now_ms + 10_000);
        let decision = OwnershipBindingDecision::new(
            committee,
            generation,
            previous_hash,
            &registration,
            valid_until_ms,
            now_ms,
        )
        .expect("binding decision");
        let mut journal = MemoryOwnershipVoteJournal::default();
        let votes = committee
            .members()
            .iter()
            .take(3)
            .map(|member| {
                let key = fixture
                    .keys
                    .iter()
                    .find(|key| key.authority_id() == member.authority_id())
                    .expect("committee key");
                let attestation = ReachabilityAttestation::sign(
                    committee,
                    &decision,
                    &registration,
                    [member.node_id().as_bytes()[0].max(1); 16],
                    now_ms,
                    now_ms + 500,
                    key,
                )
                .expect("attestation");
                OwnershipBindingVote::sign(
                    committee,
                    &decision,
                    &registration,
                    attestation,
                    key,
                    &mut journal,
                    now_ms,
                )
                .expect("vote")
            })
            .collect();
        OwnershipBindingCertificate::new(committee, decision, registration, votes, now_ms)
            .expect("binding quorum")
    }

    #[test]
    fn ownership_committee_is_deterministic_and_excludes_subject() {
        let fixture = fixture();
        let committee = committee(&fixture);
        assert_eq!(committee.members().len(), 4);
        assert!(
            committee
                .members()
                .iter()
                .all(|member| member.node_id() != fixture.subject)
        );
        let mut reversed = fixture.members.clone();
        reversed.reverse();
        let other = OwnershipCommittee::from_genesis(
            fixture.network_id,
            fixture.subject,
            [3; 32],
            reversed,
        )
        .expect("same snapshot in different order");
        assert_eq!(committee.hash(), other.hash());
        assert_eq!(committee.members(), other.members());
    }

    #[test]
    fn candidate_registry_is_sharded_bounded_and_expires_records() {
        let fixture = fixture();
        let registration = registration(&fixture, 1, 1, 100);
        let mut registry = CandidateRegistry::default();
        registry.insert(registration.clone(), 1).expect("insert");
        assert_eq!(registry.len(), 1);
        let shard = super::candidate_shard(registration.peer_id());
        assert_eq!(
            registry
                .page(
                    fixture.network_id,
                    registration.node_id(),
                    shard,
                    None,
                    10,
                    1
                )
                .len(),
            1
        );
        assert_eq!(
            registry
                .page(
                    fixture.network_id,
                    registration.node_id(),
                    shard,
                    None,
                    65,
                    1
                )
                .len(),
            0
        );
        assert_eq!(
            registry
                .page([8; 32], registration.node_id(), shard, None, 10, 1)
                .len(),
            0
        );
        registry.expire(100);
        assert!(registry.is_empty());
    }

    #[test]
    fn candidate_registration_matches_ownership_v1_vector() {
        let fixture = fixture();
        let candidate = registration(&fixture, 1, 1, 100);
        let encoded = candidate.canonical_bytes().expect("canonical record");
        let expected = decode_hex(concat!(
            "706f70756c75732f6e6f64652d63616e6469646174652d726567697374726174696f6e2f7631",
            "0707070707070707070707070707070707070707070707070707070707070707",
            "c3a9efa00a0266221ec1ffd1030a91b167cabf3d2d7b89c089aa1bc385b878d",
            "b05040808080826002408011220eb2cf13bf7ae3a5f614168a1fb09272d39771ec4b8523727815e466caf8ee163",
            "7b88fa8ba9a99e308d312dc7a59158dd9966a60dd10e053c4d895a891e7675a9",
            "eb2cf13bf7ae3a5f614168a1fb09272d39771ec4b8523727815e466caf8ee163",
            "000000000000000100000000000000640100152f6970342f382e382e382e382f7463702f34303031",
            "768503e48346f1bd1f8bc5351a325d39cb2e2877e37672d381689ec412f78d4defcdb40e1b1acabf7df9317cadeae1f30d58f7ef3ef309f2e937ff746e362004"
        ));
        assert_eq!(encoded, expected);
    }

    fn decode_hex(encoded: &str) -> Vec<u8> {
        let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
        assert_eq!(remainder, b"");
        pairs
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("ASCII hex");
                u8::from_str_radix(pair, 16).expect("valid hex pair")
            })
            .collect()
    }

    #[test]
    fn candidate_registry_keeps_distinct_peers_for_the_same_node_id() {
        let fixture = fixture();
        let first = registration(&fixture, 1, 1, 100);
        let second = registration(&fixture, 2, 1, 100);
        let first_signer = AuthorityKeypair::from_secret_key([52; 32]);
        let other_network = CandidateRegistration::sign(
            [8; 32],
            first.identity(),
            first.peer_id().to_vec(),
            2,
            100,
            first.addresses().to_vec(),
            &first_signer,
        )
        .expect("same candidate on another network");
        assert_eq!(first.node_id(), second.node_id());
        assert_ne!(first.peer_id(), second.peer_id());

        let mut registry = CandidateRegistry::default();
        registry.insert(first.clone(), 1).expect("first candidate");
        registry
            .insert(second.clone(), 1)
            .expect("second candidate");
        registry
            .insert(other_network.clone(), 1)
            .expect("other network registration");

        assert_eq!(registry.len(), 3);
        assert!(
            registry
                .get(fixture.network_id, first.node_id(), first.peer_id())
                .is_some()
        );
        assert!(
            registry
                .get(fixture.network_id, second.node_id(), second.peer_id())
                .is_some()
        );
        assert!(
            registry
                .get([8; 32], other_network.node_id(), other_network.peer_id())
                .is_some()
        );
    }

    #[test]
    fn committee_transition_is_deterministic_and_requires_current_quorum() {
        let fixture = fixture();
        let current = committee(&fixture);
        let next = current
            .next_committee(fixture.members.clone())
            .expect("next committee");
        assert_eq!(next.epoch(), current.epoch() + 1);
        assert_eq!(next.previous_committee_hash(), current.hash());
        assert_eq!(
            next,
            current
                .next_committee(fixture.members.clone())
                .expect("deterministic next committee")
        );

        let mut journal = MemoryOwnershipVoteJournal::default();
        let votes = current
            .members()
            .iter()
            .take(3)
            .map(|member| {
                let signer = fixture
                    .keys
                    .iter()
                    .find(|key| key.authority_id() == member.authority_id())
                    .expect("committee signer");
                CommitteeTransitionVote::sign(&current, &next, signer, &mut journal)
                    .expect("persist before signing")
            })
            .collect::<Vec<_>>();
        let certificate = CommitteeTransitionCertificate::new(
            &current,
            next.clone(),
            votes.iter().map(|vote| vote.signature().clone()).collect(),
        )
        .expect("current committee quorum");
        let mut state = OwnershipState::new(current.clone());
        state
            .apply_transition(certificate)
            .expect("advance exactly one link");
        assert_eq!(state.committee(), &next);
        let stale_certificate = CommitteeTransitionCertificate::new(
            &current,
            next,
            votes.iter().map(|vote| vote.signature().clone()).collect(),
        )
        .expect("certificate remains cryptographically valid");
        assert_eq!(
            state.apply_transition(stale_certificate),
            Err(OwnershipError::CommitteeMismatch),
            "a stale transition cannot be applied twice"
        );
    }

    #[test]
    fn ownership_votes_are_non_equivocating_and_certificates_are_committee_bound() {
        let fixture = fixture();
        let committee = committee(&fixture);
        let candidate = registration(&fixture, 7, 1, 20_000);
        let decision = OwnershipBindingDecision::new(&committee, 0, [0; 32], &candidate, 10_000, 1)
            .expect("decision");
        let voter = committee.members()[0].authority_id();
        let signer = fixture
            .keys
            .iter()
            .find(|key| key.authority_id() == voter)
            .expect("committee signer");
        let attestation = ReachabilityAttestation::sign(
            &committee, &decision, &candidate, [1; 16], 1, 9_000, signer,
        )
        .expect("attestation");
        let mut journal = MemoryOwnershipVoteJournal::default();
        OwnershipBindingVote::sign(
            &committee,
            &decision,
            &candidate,
            attestation.clone(),
            signer,
            &mut journal,
            1,
        )
        .expect("first vote");
        let conflicting = registration(&fixture, 10, 1, 20_000);
        let conflicting_decision =
            OwnershipBindingDecision::new(&committee, 0, [0; 32], &conflicting, 10_000, 1)
                .expect("conflicting decision");
        let conflicting_attestation = ReachabilityAttestation::sign(
            &committee,
            &conflicting_decision,
            &conflicting,
            [2; 16],
            1,
            9_000,
            signer,
        )
        .expect("conflicting attestation");
        assert_eq!(
            OwnershipBindingVote::sign(
                &committee,
                &conflicting_decision,
                &conflicting,
                conflicting_attestation,
                signer,
                &mut journal,
                1,
            ),
            Err(OwnershipError::JournalConflict)
        );
    }

    #[test]
    fn valid_incumbent_is_retained_and_expired_binding_can_be_replaced() {
        let fixture = fixture();
        let committee = committee(&fixture);
        let mut state = OwnershipState::new(committee.clone());
        let incumbent = binding_certificate(
            &fixture,
            &committee,
            registration(&fixture, 1, 1, 10_000),
            0,
            [0; 32],
            1,
        );
        let incumbent_hash = *incumbent.hash();
        state.apply_binding(incumbent, 1).expect("initial binding");
        let replacement = binding_certificate(
            &fixture,
            &committee,
            registration(&fixture, 2, 1, 20_000),
            1,
            incumbent_hash,
            2,
        );
        assert_eq!(
            state.apply_binding(replacement.clone(), 2),
            Err(OwnershipError::IncumbentLeaseActive)
        );
        state
            .apply_binding(replacement, 10_000)
            .expect("replacement after lease expiry");
        assert_eq!(
            state
                .binding()
                .expect("new binding")
                .decision()
                .generation(),
            1
        );
    }

    #[test]
    fn committee_transitions_require_exact_prior_committee_quorum() {
        let fixture = fixture();
        let current = committee(&fixture);
        let new_keys: Vec<_> = (5..=8)
            .map(|seed| AuthorityKeypair::from_secret_key([seed; 32]))
            .collect();
        let mut eligibility: Vec<_> = new_keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                AuthorityMember::new(
                    NodeId::from_bytes([u8::try_from(index + 21).expect("node"); 32]),
                    key.public_key(),
                )
                .expect("member")
            })
            .collect();
        eligibility.extend(fixture.members.clone());
        let next = OwnershipCommittee::new(
            fixture.network_id,
            fixture.subject,
            1,
            *current.hash(),
            eligibility,
        )
        .expect("next committee");
        let mut journal = MemoryOwnershipVoteJournal::default();
        let votes = current
            .members()
            .iter()
            .take(3)
            .map(|member| {
                let key = fixture
                    .keys
                    .iter()
                    .find(|key| key.authority_id() == member.authority_id())
                    .expect("old member key");
                CommitteeTransitionVote::sign(&current, &next, key, &mut journal)
                    .expect("transition vote")
                    .signature
            })
            .collect();
        let certificate =
            CommitteeTransitionCertificate::new(&current, next.clone(), votes).expect("quorum");
        let mut state = OwnershipState::new(current);
        state
            .apply_transition(certificate)
            .expect("apply transition");
        assert_eq!(state.committee().hash(), next.hash());
    }
}
