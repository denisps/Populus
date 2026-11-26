//! Bounded delegated-ingest reports and their four-authority acknowledgement lifecycle.

use crate::{
    AUTHORITY_COUNT, AuthorityKeypair, DelegationDescriptor, MAX_STATE_COMPONENT_BYTES,
    MembershipView,
};
use populus_crypto::{RoutingIdentifier, routing_key, verify_ed25519};
use populus_sketch::{ClientSketch, SketchDecodeError};
use populus_types::{AuthorityId, ClientId, ContentId, NodeId, UtcDay};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const REPORT_HEADER: [u8; 4] = *b"PIRP";
const ACK_HEADER: [u8; 4] = *b"PIAK";
const INGEST_STATE_HEADER: [u8; 4] = *b"PINS";
const AUTHORITY_STATE_HEADER: [u8; 4] = *b"PIAS";
const FORMAT_VERSION: u8 = 1;
const REPORT_RECEIVER_FIXED_BYTES: usize = 4 + 1 + 36 + 8 + 1 + 4 + 4 + 4;
const MAX_SERIALIZED_SKETCH_BYTES: usize = 6 + populus_sketch::REGISTER_COUNT * 6 / 8;
const REPORT_RECEIVER_CANDIDATE_BYTES: usize = 32 + 32 + 8 + 32;
const MAX_REPORT_RECEIVER_CANDIDATES: usize =
    (MAX_STATE_COMPONENT_BYTES - REPORT_RECEIVER_FIXED_BYTES - MAX_SERIALIZED_SKETCH_BYTES)
        / REPORT_RECEIVER_CANDIDATE_BYTES;

/// One immutable aggregate from an ingest node for one content, day, and view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngestReport {
    content_id: ContentId,
    day: UtcDay,
    view: u8,
    node_id: NodeId,
    sequence: u64,
    sketch: ClientSketch,
}

impl IngestReport {
    /// Creates a report with a nonzero sequence and one of the three defined views.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::InvalidView`],
    /// [`DelegatedIngestError::InvalidSequence`], or
    /// [`DelegatedIngestError::StateTooLarge`] for invalid report metadata or
    /// an oversized sketch.
    pub fn new(
        content_id: ContentId,
        day: UtcDay,
        view: u8,
        node_id: NodeId,
        sequence: u64,
        sketch: ClientSketch,
    ) -> Result<Self, DelegatedIngestError> {
        validate_view(view)?;
        if sequence == 0 {
            return Err(DelegatedIngestError::InvalidSequence);
        }
        if sketch.serialize().len().saturating_add(94) > MAX_STATE_COMPONENT_BYTES {
            return Err(DelegatedIngestError::StateTooLarge);
        }
        Ok(Self {
            content_id,
            day,
            view,
            node_id,
            sequence,
            sketch,
        })
    }

    /// Returns the content, daily epoch, and assignment view bound to the report.
    #[must_use]
    pub const fn scope(&self) -> (ContentId, UtcDay, u8) {
        (self.content_id, self.day, self.view)
    }

    /// Returns the reporting Populus node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns this node's monotonically increasing report sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the immutable client sketch carried by the report.
    #[must_use]
    pub const fn sketch(&self) -> &ClientSketch {
        &self.sketch
    }

    /// Encodes this report in canonical v1 form.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::StateTooLarge`] if the report exceeds
    /// the bounded state-component size.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DelegatedIngestError> {
        let sketch = self.sketch.serialize();
        let sketch_len =
            u32::try_from(sketch.len()).map_err(|_| DelegatedIngestError::StateTooLarge)?;
        let mut bytes = Vec::with_capacity(91 + sketch.len());
        bytes.extend_from_slice(&REPORT_HEADER);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.push(self.view);
        bytes.extend_from_slice(self.node_id.as_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&sketch_len.to_be_bytes());
        bytes.extend_from_slice(&sketch);
        enforce_state_limit(bytes.len())?;
        Ok(bytes)
    }

    /// Decodes a bounded canonical v1 report.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed metadata, unsupported versions,
    /// oversized input, or an invalid nested sketch.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DelegatedIngestError> {
        if bytes.len() > MAX_STATE_COMPONENT_BYTES {
            return Err(DelegatedIngestError::StateTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != REPORT_HEADER || cursor.byte()? != FORMAT_VERSION {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DelegatedIngestError::InvalidEncoding)?;
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let view = cursor.byte()?;
        validate_view(view)?;
        let node_id = NodeId::from_bytes(cursor.take::<32>()?);
        let sequence = u64::from_be_bytes(cursor.take::<8>()?);
        if sequence == 0 {
            return Err(DelegatedIngestError::InvalidSequence);
        }
        let sketch_len = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
            .map_err(|_| DelegatedIngestError::InvalidEncoding)?;
        let sketch_bytes = cursor.remaining_exact(sketch_len)?;
        let sketch = ClientSketch::deserialize(sketch_bytes)?;
        Self::new(content_id, day, view, node_id, sequence, sketch)
    }
}

/// An authority-signed acknowledgement for one immutable ingest report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIngestReportAck {
    content_id: ContentId,
    day: UtcDay,
    view: u8,
    node_id: NodeId,
    report_sequence: u64,
    membership_generation: u64,
    signer: AuthorityId,
    signature: [u8; 64],
}

impl SignedIngestReportAck {
    /// Signs an acknowledgement using an authority represented by the content membership.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the membership, report, or signer does not match.
    pub fn sign(
        report: &IngestReport,
        membership: &MembershipView,
        signer: &AuthorityKeypair,
    ) -> Result<Self, DelegatedIngestError> {
        validate_membership(report.content_id, membership)?;
        let signer_id = signer.authority_id();
        let member = membership
            .member(signer_id)
            .ok_or(DelegatedIngestError::UnexpectedAcknowledgement)?;
        if member.public_key() != &signer.public_key() {
            return Err(DelegatedIngestError::UnexpectedAcknowledgement);
        }
        let mut ack = Self {
            content_id: report.content_id,
            day: report.day,
            view: report.view,
            node_id: report.node_id,
            report_sequence: report.sequence,
            membership_generation: membership.generation(),
            signer: signer_id,
            signature: [0; 64],
        };
        ack.signature = signer.sign(&ack.message());
        Ok(ack)
    }

    /// Returns the authority identity that signed this acknowledgement.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }

    /// Returns the content, daily epoch, and assignment view acknowledged.
    #[must_use]
    pub const fn scope(&self) -> (ContentId, UtcDay, u8) {
        (self.content_id, self.day, self.view)
    }

    /// Returns the ingest node identity bound to the acknowledged report.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the acknowledged report sequence.
    #[must_use]
    pub const fn report_sequence(&self) -> u64 {
        self.report_sequence
    }

    /// Encodes this acknowledgement in canonical v1 form.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(198);
        bytes.extend_from_slice(&ACK_HEADER);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.push(self.view);
        bytes.extend_from_slice(self.node_id.as_bytes());
        bytes.extend_from_slice(&self.report_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        bytes.extend_from_slice(self.signer.as_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes an acknowledgement; its signature must still be verified with [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed or unsupported encodings.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DelegatedIngestError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != ACK_HEADER || cursor.byte()? != FORMAT_VERSION {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DelegatedIngestError::InvalidEncoding)?;
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let view = cursor.byte()?;
        validate_view(view)?;
        let node_id = NodeId::from_bytes(cursor.take::<32>()?);
        let report_sequence = u64::from_be_bytes(cursor.take::<8>()?);
        if report_sequence == 0 {
            return Err(DelegatedIngestError::InvalidSequence);
        }
        let membership_generation = u64::from_be_bytes(cursor.take::<8>()?);
        let signer = AuthorityId::from_bytes(cursor.take::<32>()?);
        let signature = cursor.take::<64>()?;
        cursor.remaining_exact(0)?;
        Ok(Self {
            content_id,
            day,
            view,
            node_id,
            report_sequence,
            membership_generation,
            signer,
            signature,
        })
    }

    /// Verifies the scope, membership generation, signer, and Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::UnexpectedAcknowledgement`] when a
    /// membership or signature check fails.
    pub fn verify(&self, membership: &MembershipView) -> Result<(), DelegatedIngestError> {
        validate_membership(self.content_id, membership)?;
        if membership.generation() != self.membership_generation {
            return Err(DelegatedIngestError::UnexpectedAcknowledgement);
        }
        let member = membership
            .member(self.signer)
            .ok_or(DelegatedIngestError::UnexpectedAcknowledgement)?;
        verify_ed25519(member.public_key(), &self.message(), &self.signature)
            .map_err(|_| DelegatedIngestError::UnexpectedAcknowledgement)
    }

    fn message(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(115);
        bytes.extend_from_slice(b"populus/delegated-ingest-ack/v1");
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.push(self.view);
        bytes.extend_from_slice(self.node_id.as_bytes());
        bytes.extend_from_slice(&self.report_sequence.to_be_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        bytes
    }
}

/// One ingest node's double-buffered state for a single content/day/view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedIngestState {
    content_id: ContentId,
    day: UtcDay,
    view: u8,
    node_id: NodeId,
    membership_generation: u64,
    expected_authorities: BTreeSet<AuthorityId>,
    report_sequence: u64,
    active: ClientSketch,
    pending: Option<PendingReport>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingReport {
    report: IngestReport,
    acknowledged_authorities: BTreeSet<AuthorityId>,
}

impl DelegatedIngestState {
    /// Creates a report buffer bound to a content's authority membership.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::InvalidView`] or
    /// [`DelegatedIngestError::WrongMembership`] for an invalid scope.
    pub fn new(
        content_id: ContentId,
        day: UtcDay,
        view: u8,
        node_id: NodeId,
        membership: &MembershipView,
    ) -> Result<Self, DelegatedIngestError> {
        validate_view(view)?;
        validate_membership(content_id, membership)?;
        Ok(Self {
            content_id,
            day,
            view,
            node_id,
            membership_generation: membership.generation(),
            expected_authorities: authority_ids(membership),
            report_sequence: 0,
            active: ClientSketch::new(),
            pending: None,
        })
    }

    /// Returns the content, daily epoch, and assignment view for this sender.
    #[must_use]
    pub const fn scope(&self) -> (ContentId, UtcDay, u8) {
        (self.content_id, self.day, self.view)
    }

    /// Returns the identity of the ingest node producing reports.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Adds a client to the active sketch; collection continues while a report is pending.
    pub fn record_client(&mut self, client_id: ClientId) {
        self.active.insert(client_id);
    }

    /// Moves a nonempty active sketch into the immutable pending report buffer.
    ///
    /// If the prior report is still awaiting any authority, the active sketch
    /// is retained and `Ok(None)` is returned; collection is never paused or lost.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::SequenceOverflow`] if the local sequence
    /// is exhausted.
    pub fn rollover(&mut self) -> Result<Option<&IngestReport>, DelegatedIngestError> {
        if self.pending.is_some() || self.active.estimate() == 0.0 {
            return Ok(None);
        }
        let sequence = self
            .report_sequence
            .checked_add(1)
            .ok_or(DelegatedIngestError::SequenceOverflow)?;
        let report = IngestReport::new(
            self.content_id,
            self.day,
            self.view,
            self.node_id,
            sequence,
            self.active.clone(),
        )?;
        self.active = ClientSketch::new();
        self.report_sequence = sequence;
        self.pending = Some(PendingReport {
            report,
            acknowledged_authorities: BTreeSet::new(),
        });
        Ok(self.pending_report())
    }

    /// Returns the immutable report to transmit or retry, if any.
    #[must_use]
    pub fn pending_report(&self) -> Option<&IngestReport> {
        self.pending.as_ref().map(|pending| &pending.report)
    }

    /// Returns authorities that have not acknowledged the current report.
    #[must_use]
    pub fn pending_authorities(&self) -> Vec<AuthorityId> {
        self.pending.as_ref().map_or_else(Vec::new, |pending| {
            self.expected_authorities
                .difference(&pending.acknowledged_authorities)
                .copied()
                .collect()
        })
    }

    /// Retargets the pending report after a valid authority-membership replacement.
    ///
    /// A newer generation invalidates acknowledgements from the previous view.
    ///
    /// # Errors
    ///
    /// Returns a typed error for wrong, stale, or conflicting membership.
    pub fn retarget_membership(
        &mut self,
        membership: &MembershipView,
    ) -> Result<(), DelegatedIngestError> {
        validate_membership(self.content_id, membership)?;
        let authorities = authority_ids(membership);
        if membership.generation() < self.membership_generation {
            return Err(DelegatedIngestError::StaleMembership);
        }
        if membership.generation() == self.membership_generation {
            if authorities != self.expected_authorities {
                return Err(DelegatedIngestError::MembershipGenerationConflict);
            }
            return Ok(());
        }
        self.membership_generation = membership.generation();
        self.expected_authorities = authorities;
        if let Some(pending) = &mut self.pending {
            pending.acknowledged_authorities.clear();
        }
        Ok(())
    }

    /// Applies a signed acknowledgement; duplicate and already-completed ACKs are harmless.
    ///
    /// Returns `true` when all four current authorities have acknowledged the
    /// report and its pending buffer can be reclaimed.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid signature, scope, or unexpected
    /// future acknowledgement.
    pub fn acknowledge(
        &mut self,
        acknowledgement: &SignedIngestReportAck,
        membership: &MembershipView,
    ) -> Result<bool, DelegatedIngestError> {
        acknowledgement.verify(membership)?;
        self.retarget_membership(membership)?;
        if acknowledgement.node_id != self.node_id
            || acknowledgement.content_id != self.content_id
            || acknowledgement.day != self.day
            || acknowledgement.view != self.view
        {
            return Err(DelegatedIngestError::UnexpectedAcknowledgement);
        }
        let Some(pending) = &mut self.pending else {
            return if acknowledgement.report_sequence <= self.report_sequence {
                Ok(false)
            } else {
                Err(DelegatedIngestError::UnexpectedAcknowledgement)
            };
        };
        if acknowledgement.report_sequence < pending.report.sequence {
            return Ok(false);
        }
        if acknowledgement.report_sequence != pending.report.sequence
            || !self.expected_authorities.contains(&acknowledgement.signer)
        {
            return Err(DelegatedIngestError::UnexpectedAcknowledgement);
        }
        pending
            .acknowledged_authorities
            .insert(acknowledgement.signer);
        if pending.acknowledged_authorities.len() != AUTHORITY_COUNT {
            return Ok(false);
        }
        self.pending = None;
        Ok(true)
    }

    /// Encodes active and pending state for crash-safe local persistence.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::StateTooLarge`] if the snapshot exceeds
    /// the authority component limit.
    pub fn serialize(&self) -> Result<Vec<u8>, DelegatedIngestError> {
        let active = self.active.serialize();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&INGEST_STATE_HEADER);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.push(self.view);
        bytes.extend_from_slice(self.node_id.as_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        bytes.extend_from_slice(&self.report_sequence.to_be_bytes());
        write_authorities(&mut bytes, &self.expected_authorities)?;
        write_len_prefixed(&mut bytes, &active)?;
        if let Some(pending) = &self.pending {
            bytes.push(1);
            write_len_prefixed(&mut bytes, &pending.report.canonical_bytes()?)?;
            write_authorities(&mut bytes, &pending.acknowledged_authorities)?;
        } else {
            bytes.push(0);
        }
        enforce_state_limit(bytes.len())?;
        Ok(bytes)
    }

    /// Restores a bounded canonical ingest-node snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, oversized, or inconsistent state.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DelegatedIngestError> {
        if bytes.len() > MAX_STATE_COMPONENT_BYTES {
            return Err(DelegatedIngestError::StateTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != INGEST_STATE_HEADER || cursor.byte()? != FORMAT_VERSION {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DelegatedIngestError::InvalidEncoding)?;
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let view = cursor.byte()?;
        validate_view(view)?;
        let node_id = NodeId::from_bytes(cursor.take::<32>()?);
        let membership_generation = u64::from_be_bytes(cursor.take::<8>()?);
        let report_sequence = u64::from_be_bytes(cursor.take::<8>()?);
        let expected_authorities = read_authorities(&mut cursor)?;
        if expected_authorities.len() != AUTHORITY_COUNT {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        let active = ClientSketch::deserialize(cursor.length_prefixed()?)?;
        let pending = match cursor.byte()? {
            0 => None,
            1 => {
                let report = IngestReport::deserialize(cursor.length_prefixed()?)?;
                let acknowledged_authorities = read_authorities(&mut cursor)?;
                if !acknowledged_authorities.is_subset(&expected_authorities)
                    || acknowledged_authorities == expected_authorities
                    || report.scope() != (content_id, day, view)
                    || report.node_id != node_id
                    || report.sequence != report_sequence
                {
                    return Err(DelegatedIngestError::InvalidEncoding);
                }
                Some(PendingReport {
                    report,
                    acknowledged_authorities,
                })
            }
            _ => return Err(DelegatedIngestError::InvalidEncoding),
        };
        cursor.remaining_exact(0)?;
        Ok(Self {
            content_id,
            day,
            view,
            node_id,
            membership_generation,
            expected_authorities,
            report_sequence,
            active,
            pending,
        })
    }
}

/// Authority-side aggregation and deduplication for one content/day/view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegatedReportReceiver {
    content_id: ContentId,
    day: UtcDay,
    view: u8,
    candidates: BTreeSet<NodeId>,
    last_sequences: BTreeMap<NodeId, u64>,
    last_report_digests: BTreeMap<NodeId, [u8; 32]>,
    sketch: ClientSketch,
}

impl DelegatedReportReceiver {
    /// Creates an authority-side accumulator bound to the published descriptor.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid view, content membership, or a
    /// descriptor too large to fit one replay entry per candidate in a bounded
    /// receiver snapshot.
    pub fn new(
        content_id: ContentId,
        day: UtcDay,
        view: u8,
        descriptor: &DelegationDescriptor,
        membership: &MembershipView,
    ) -> Result<Self, DelegatedIngestError> {
        validate_view(view)?;
        validate_membership(content_id, membership)?;
        enforce_report_receiver_capacity(descriptor.candidates().len())?;
        Ok(Self {
            content_id,
            day,
            view,
            candidates: descriptor
                .candidates()
                .iter()
                .map(|candidate| candidate.node_id())
                .collect(),
            last_sequences: BTreeMap::new(),
            last_report_digests: BTreeMap::new(),
            sketch: ClientSketch::new(),
        })
    }

    /// Accepts the next report from an authenticated candidate and signs its ACK.
    ///
    /// A retry of the latest report is acknowledged without merging it twice.
    /// Reports from a candidate outside the descriptor, a different view, or
    /// a sequence gap are rejected. The caller must pass the `NodeId` authenticated
    /// by its transport, not merely the identity claimed inside the report.
    ///
    /// # Errors
    ///
    /// Returns a typed error for wrong scope/sender, stale or skipped sequence,
    /// invalid membership, or an invalid authority signer.
    pub fn accept_report(
        &mut self,
        report: &IngestReport,
        authenticated_sender: NodeId,
        membership: &MembershipView,
        signer: &AuthorityKeypair,
    ) -> Result<SignedIngestReportAck, DelegatedIngestError> {
        validate_membership(self.content_id, membership)?;
        if report.content_id != self.content_id
            || report.day != self.day
            || report.view != self.view
        {
            return Err(DelegatedIngestError::WrongScope);
        }
        if report.node_id != authenticated_sender
            || !self.candidates.contains(&authenticated_sender)
        {
            return Err(DelegatedIngestError::UnauthorizedIngestNode);
        }
        let ack = SignedIngestReportAck::sign(report, membership, signer)?;
        let report_bytes = report.canonical_bytes()?;
        let report_digest: [u8; 32] = Sha256::digest(report_bytes).into();
        let last = self
            .last_sequences
            .get(&authenticated_sender)
            .copied()
            .unwrap_or(0);
        if report.sequence < last {
            return Err(DelegatedIngestError::StaleReport);
        }
        if report.sequence == last {
            if self.last_report_digests.get(&authenticated_sender) != Some(&report_digest) {
                return Err(DelegatedIngestError::ConflictingReport);
            }
            return Ok(ack);
        }
        let expected = last
            .checked_add(1)
            .ok_or(DelegatedIngestError::SequenceOverflow)?;
        if report.sequence != expected {
            return Err(DelegatedIngestError::ReportSequenceGap);
        }
        self.sketch.merge(&report.sketch);
        self.last_sequences
            .insert(authenticated_sender, report.sequence);
        self.last_report_digests
            .insert(authenticated_sender, report_digest);
        Ok(ack)
    }

    /// Returns the aggregate estimate across all accepted candidate reports.
    #[must_use]
    pub fn estimate(&self) -> f64 {
        self.sketch.estimate()
    }

    /// Returns the content, daily epoch, and assignment view bound to this receiver.
    #[must_use]
    pub const fn scope(&self) -> (ContentId, UtcDay, u8) {
        (self.content_id, self.day, self.view)
    }

    /// Returns the highest accepted report sequence from a candidate.
    #[must_use]
    pub fn last_sequence(&self, node_id: NodeId) -> u64 {
        self.last_sequences.get(&node_id).copied().unwrap_or(0)
    }

    /// Encodes the aggregate and per-candidate replay protection state.
    ///
    /// # Errors
    ///
    /// Returns [`DelegatedIngestError::StateTooLarge`] when the authority
    /// component exceeds the established one-megabyte bound.
    pub fn serialize(&self) -> Result<Vec<u8>, DelegatedIngestError> {
        let sketch = self.sketch.serialize();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&AUTHORITY_STATE_HEADER);
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.push(self.view);
        write_node_ids(&mut bytes, &self.candidates)?;
        let sequence_count = u32::try_from(self.last_sequences.len())
            .map_err(|_| DelegatedIngestError::StateTooLarge)?;
        bytes.extend_from_slice(&sequence_count.to_be_bytes());
        for (node_id, sequence) in &self.last_sequences {
            bytes.extend_from_slice(node_id.as_bytes());
            bytes.extend_from_slice(&sequence.to_be_bytes());
            bytes.extend_from_slice(
                self.last_report_digests
                    .get(node_id)
                    .ok_or(DelegatedIngestError::InvalidEncoding)?,
            );
        }
        write_len_prefixed(&mut bytes, &sketch)?;
        enforce_state_limit(bytes.len())?;
        Ok(bytes)
    }

    /// Restores authority aggregation state against the currently published descriptor.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed state, a mismatched content scope,
    /// or a descriptor candidate set that differs from the one used before
    /// the crash. The candidate-count capacity bound is enforced as well.
    ///
    /// Restoration compares candidate `NodeId`s only. It does not validate the
    /// descriptor's assignment algorithm or compare the snapshot's day and
    /// view with caller-provided expected values. Callers must compare the
    /// restored [`Self::scope`] with the expected content/day/view and validate
    /// the assignment algorithm separately before using the receiver.
    pub fn deserialize(
        bytes: &[u8],
        descriptor: &DelegationDescriptor,
        membership: &MembershipView,
    ) -> Result<Self, DelegatedIngestError> {
        if bytes.len() > MAX_STATE_COMPONENT_BYTES {
            return Err(DelegatedIngestError::StateTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != AUTHORITY_STATE_HEADER || cursor.byte()? != FORMAT_VERSION {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DelegatedIngestError::InvalidEncoding)?;
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let view = cursor.byte()?;
        validate_view(view)?;
        validate_membership(content_id, membership)?;
        let candidates = read_node_ids(&mut cursor)?;
        enforce_report_receiver_capacity(candidates.len())?;
        let descriptor_candidates: BTreeSet<_> = descriptor
            .candidates()
            .iter()
            .map(|candidate| candidate.node_id())
            .collect();
        if candidates != descriptor_candidates {
            return Err(DelegatedIngestError::DescriptorMismatch);
        }
        let sequence_count = cursor.u32_len()?;
        if sequence_count > candidates.len() {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        let mut last_sequences = BTreeMap::new();
        let mut last_report_digests = BTreeMap::new();
        let mut previous_node = None;
        for _ in 0..sequence_count {
            let node_id = NodeId::from_bytes(cursor.take::<32>()?);
            let sequence = u64::from_be_bytes(cursor.take::<8>()?);
            let digest = cursor.take::<32>()?;
            if sequence == 0
                || !candidates.contains(&node_id)
                || previous_node.is_some_and(|previous| previous >= node_id)
                || last_sequences.insert(node_id, sequence).is_some()
            {
                return Err(DelegatedIngestError::InvalidEncoding);
            }
            previous_node = Some(node_id);
            last_report_digests.insert(node_id, digest);
        }
        let sketch = ClientSketch::deserialize(cursor.length_prefixed()?)?;
        cursor.remaining_exact(0)?;
        Ok(Self {
            content_id,
            day,
            view,
            candidates,
            last_sequences,
            last_report_digests,
            sketch,
        })
    }
}

/// Errors while validating, buffering, or acknowledging delegated reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatedIngestError {
    /// The report view is outside `0..3`.
    InvalidView,
    /// The report sequence must start at one.
    InvalidSequence,
    /// The report or snapshot does not match the state scope.
    WrongScope,
    /// The authority membership does not route to the report's content.
    WrongMembership,
    /// The report sender is not an authenticated descriptor candidate.
    UnauthorizedIngestNode,
    /// The report sequence is older than the latest accepted report.
    StaleReport,
    /// A duplicate sequence carried different report bytes.
    ConflictingReport,
    /// A report skipped a sequence and may have lost buffered data.
    ReportSequenceGap,
    /// Membership generation is older than the state generation.
    StaleMembership,
    /// A membership changed without incrementing its generation.
    MembershipGenerationConflict,
    /// An acknowledgement does not match a pending or completed report.
    UnexpectedAcknowledgement,
    /// The serialized descriptor candidate set differs from current authority state.
    DescriptorMismatch,
    /// A sequence counter overflowed.
    SequenceOverflow,
    /// A serialized report, snapshot, or sketch exceeds the one-megabyte bound.
    StateTooLarge,
    /// A report or snapshot encoding is malformed, noncanonical, or unsupported.
    InvalidEncoding,
    /// The nested client sketch could not be decoded.
    Sketch(SketchDecodeError),
}

impl std::fmt::Display for DelegatedIngestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidView => "delegated-ingest view is outside 0..3",
            Self::InvalidSequence => "delegated-ingest report sequence must be nonzero",
            Self::WrongScope => "delegated-ingest report has a different content, day, or view",
            Self::WrongMembership => "delegated-ingest authority membership routes elsewhere",
            Self::UnauthorizedIngestNode => {
                "delegated-ingest sender is not an authenticated descriptor candidate"
            }
            Self::StaleReport => "delegated-ingest report sequence is stale",
            Self::ConflictingReport => {
                "delegated-ingest report reused a sequence with different data"
            }
            Self::ReportSequenceGap => "delegated-ingest report sequence has a gap",
            Self::StaleMembership => "delegated-ingest authority membership is stale",
            Self::MembershipGenerationConflict => {
                "delegated-ingest membership changed without a new generation"
            }
            Self::UnexpectedAcknowledgement => {
                "delegated-ingest acknowledgement is unexpected or invalid"
            }
            Self::DescriptorMismatch => "delegated-ingest descriptor changed during restoration",
            Self::SequenceOverflow => "delegated-ingest sequence overflowed",
            Self::StateTooLarge => "delegated-ingest data exceeds its size limit",
            Self::InvalidEncoding => "invalid delegated-ingest encoding",
            Self::Sketch(error) => return write!(formatter, "invalid client sketch: {error}"),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for DelegatedIngestError {}

impl From<SketchDecodeError> for DelegatedIngestError {
    fn from(error: SketchDecodeError) -> Self {
        Self::Sketch(error)
    }
}

fn validate_view(view: u8) -> Result<(), DelegatedIngestError> {
    if usize::from(view) >= usize::from(crate::INGEST_VIEW_COUNT) {
        return Err(DelegatedIngestError::InvalidView);
    }
    Ok(())
}

fn validate_membership(
    content_id: ContentId,
    membership: &MembershipView,
) -> Result<(), DelegatedIngestError> {
    if membership.routing_key() != routing_key(RoutingIdentifier::Content(&content_id)) {
        return Err(DelegatedIngestError::WrongMembership);
    }
    Ok(())
}

fn authority_ids(membership: &MembershipView) -> BTreeSet<AuthorityId> {
    membership
        .members()
        .iter()
        .map(crate::AuthorityMember::authority_id)
        .collect()
}

fn enforce_state_limit(length: usize) -> Result<(), DelegatedIngestError> {
    if length > MAX_STATE_COMPONENT_BYTES {
        return Err(DelegatedIngestError::StateTooLarge);
    }
    Ok(())
}

fn enforce_report_receiver_capacity(candidate_count: usize) -> Result<(), DelegatedIngestError> {
    if candidate_count > MAX_REPORT_RECEIVER_CANDIDATES {
        return Err(DelegatedIngestError::StateTooLarge);
    }
    Ok(())
}

fn write_len_prefixed(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), DelegatedIngestError> {
    let length = u32::try_from(value.len()).map_err(|_| DelegatedIngestError::StateTooLarge)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

fn write_authorities(
    bytes: &mut Vec<u8>,
    authorities: &BTreeSet<AuthorityId>,
) -> Result<(), DelegatedIngestError> {
    let count = u8::try_from(authorities.len()).map_err(|_| DelegatedIngestError::StateTooLarge)?;
    bytes.push(count);
    for authority in authorities {
        bytes.extend_from_slice(authority.as_bytes());
    }
    Ok(())
}

fn read_authorities(
    cursor: &mut Cursor<'_>,
) -> Result<BTreeSet<AuthorityId>, DelegatedIngestError> {
    let count = usize::from(cursor.byte()?);
    if count > AUTHORITY_COUNT {
        return Err(DelegatedIngestError::InvalidEncoding);
    }
    let mut authorities = BTreeSet::new();
    let mut previous = None;
    for _ in 0..count {
        let id = AuthorityId::from_bytes(cursor.take::<32>()?);
        if previous.is_some_and(|previous| previous >= id) || !authorities.insert(id) {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        previous = Some(id);
    }
    Ok(authorities)
}

fn write_node_ids(
    bytes: &mut Vec<u8>,
    node_ids: &BTreeSet<NodeId>,
) -> Result<(), DelegatedIngestError> {
    let count = u32::try_from(node_ids.len()).map_err(|_| DelegatedIngestError::StateTooLarge)?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for node_id in node_ids {
        bytes.extend_from_slice(node_id.as_bytes());
    }
    Ok(())
}

fn read_node_ids(cursor: &mut Cursor<'_>) -> Result<BTreeSet<NodeId>, DelegatedIngestError> {
    let count = cursor.u32_len()?;
    let mut node_ids = BTreeSet::new();
    let mut previous = None;
    for _ in 0..count {
        let node_id = NodeId::from_bytes(cursor.take::<32>()?);
        if previous.is_some_and(|previous| previous >= node_id) || !node_ids.insert(node_id) {
            return Err(DelegatedIngestError::InvalidEncoding);
        }
        previous = Some(node_id);
    }
    Ok(node_ids)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, DelegatedIngestError> {
        Ok(self.take::<1>()?[0])
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], DelegatedIngestError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(DelegatedIngestError::InvalidEncoding)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(DelegatedIngestError::InvalidEncoding)?;
        let mut result = [0; N];
        result.copy_from_slice(source);
        self.offset = end;
        Ok(result)
    }

    fn u32_len(&mut self) -> Result<usize, DelegatedIngestError> {
        usize::try_from(u32::from_be_bytes(self.take::<4>()?))
            .map_err(|_| DelegatedIngestError::InvalidEncoding)
    }

    fn length_prefixed(&mut self) -> Result<&'a [u8], DelegatedIngestError> {
        let length = self.u32_len()?;
        self.take_slice(length)
    }

    fn remaining_exact(&mut self, expected: usize) -> Result<&'a [u8], DelegatedIngestError> {
        self.take_slice(expected).and_then(|remaining| {
            if self.offset == self.bytes.len() {
                Ok(remaining)
            } else {
                Err(DelegatedIngestError::InvalidEncoding)
            }
        })
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], DelegatedIngestError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DelegatedIngestError::InvalidEncoding)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(DelegatedIngestError::InvalidEncoding)?;
        self.offset = end;
        Ok(source)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::{AssignmentAlgorithm, AuthorityMember, IngestNode, select_authorities};
    use std::collections::BTreeSet;

    fn content(value: u8) -> ContentId {
        ContentId::from_digest([value; 32])
    }

    fn client(value: u8) -> ClientId {
        ClientId::from_bytes([value; 32])
    }

    fn node(value: u8) -> NodeId {
        NodeId::from_bytes([value; 32])
    }

    fn make_membership(
        content_id: ContentId,
        generation: u64,
    ) -> (MembershipView, Vec<AuthorityKeypair>) {
        let keys: Vec<_> = (1..=4)
            .map(|value| AuthorityKeypair::from_secret_key([value; 32]))
            .collect();
        let members: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let value = u8::try_from(index + 1).expect("four fixture members");
                AuthorityMember::new(node(value), key.public_key())
                    .expect("generated public key is valid")
            })
            .collect();
        let routing_key = routing_key(RoutingIdentifier::Content(&content_id));
        let selected = select_authorities(&routing_key, &members)
            .expect("fixture authority identities are unique");
        (
            MembershipView::new(routing_key, generation, selected)
                .expect("fixture membership is canonical"),
            keys,
        )
    }

    fn signing_key<'a>(
        membership: &MembershipView,
        keys: &'a [AuthorityKeypair],
        index: usize,
    ) -> &'a AuthorityKeypair {
        let authority = membership.members()[index].authority_id();
        keys.iter()
            .find(|key| key.authority_id() == authority)
            .expect("fixture authority has a signing key")
    }

    fn descriptor(nodes: &[NodeId]) -> DelegationDescriptor {
        DelegationDescriptor::new(
            AssignmentAlgorithm::XorNearest,
            nodes.iter().copied().map(IngestNode::new).collect(),
            0,
        )
        .expect("fixture descriptor is unique and nonempty")
    }

    #[test]
    fn receiver_candidate_count_is_bounded_by_snapshot_capacity() {
        let content_id = content(8);
        let (membership, keys) = make_membership(content_id, 0);
        let nodes: Vec<_> = (0..=MAX_REPORT_RECEIVER_CANDIDATES)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[28..].copy_from_slice(
                    &u32::try_from(index)
                        .expect("candidate fixture index fits in u32")
                        .to_be_bytes(),
                );
                NodeId::from_bytes(bytes)
            })
            .collect();
        let largest_descriptor = descriptor(&nodes[..MAX_REPORT_RECEIVER_CANDIDATES]);
        let mut receiver = DelegatedReportReceiver::new(
            content_id,
            UtcDay::new(0),
            0,
            &largest_descriptor,
            &membership,
        )
        .expect("largest capacity-safe descriptor is accepted");
        let mut dense_sketch = ClientSketch::new();
        for value in 0..=u8::MAX {
            dense_sketch.insert(client(value));
        }
        let mut extra_client = [0; 32];
        extra_client[0] = 1;
        dense_sketch.insert(ClientId::from_bytes(extra_client));
        let candidate = largest_descriptor.candidates()[0].node_id();
        let report = IngestReport::new(
            content_id,
            UtcDay::new(0),
            0,
            candidate,
            1,
            dense_sketch.clone(),
        )
        .expect("dense report is valid");
        receiver
            .accept_report(
                &report,
                candidate,
                &membership,
                signing_key(&membership, &keys, 0),
            )
            .expect("candidate report is accepted");
        for replay_candidate in receiver.candidates.iter().copied() {
            let replay_report = if replay_candidate == candidate {
                report.clone()
            } else {
                IngestReport::new(
                    content_id,
                    UtcDay::new(0),
                    0,
                    replay_candidate,
                    1,
                    ClientSketch::new(),
                )
                .expect("candidate replay report is valid")
            };
            let digest: [u8; 32] = Sha256::digest(
                replay_report
                    .canonical_bytes()
                    .expect("candidate replay report is bounded"),
            )
            .into();
            receiver.last_sequences.insert(replay_candidate, 1);
            receiver
                .last_report_digests
                .insert(replay_candidate, digest);
        }
        let snapshot = receiver
            .serialize()
            .expect("maximum receiver snapshot with every replay entry fits");
        assert!(snapshot.len() <= MAX_STATE_COMPONENT_BYTES);
        let restored =
            DelegatedReportReceiver::deserialize(&snapshot, &largest_descriptor, &membership)
                .expect("fully populated maximum receiver snapshot restores");
        assert_eq!(restored, receiver);

        let oversized_descriptor = descriptor(&nodes);
        assert_eq!(
            DelegatedReportReceiver::new(
                content_id,
                UtcDay::new(0),
                0,
                &oversized_descriptor,
                &membership,
            ),
            Err(DelegatedIngestError::StateTooLarge)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn buffered_reports_survive_lost_delivery_ack_and_both_crash_boundaries() {
        let content_id = content(9);
        let day = UtcDay::new(17);
        let (membership, keys) = make_membership(content_id, 3);
        let ingest_node = node(42);
        let descriptor = descriptor(&[ingest_node]);
        let mut ingest = DelegatedIngestState::new(content_id, day, 1, ingest_node, &membership)
            .expect("valid ingest scope");
        ingest.record_client(client(1));
        let first = ingest
            .rollover()
            .expect("rollover succeeds")
            .expect("nonempty sketch creates a report")
            .clone();
        let first_bytes = first
            .canonical_bytes()
            .expect("bounded report has a canonical encoding");
        assert_eq!(
            IngestReport::deserialize(&first_bytes).expect("report decodes"),
            first
        );
        assert!(
            ingest
                .rollover()
                .expect("pending report is retained")
                .is_none()
        );
        ingest.record_client(client(2));
        assert_eq!(
            ingest
                .pending_report()
                .expect("pending report remains")
                .canonical_bytes()
                .expect("report remains encodable"),
            first_bytes,
            "pending report is immutable while collection continues"
        );

        let mut receivers: Vec<_> = (0..AUTHORITY_COUNT)
            .map(|_| {
                DelegatedReportReceiver::new(content_id, day, 1, &descriptor, &membership)
                    .expect("authority report state is valid")
            })
            .collect();
        let mut acknowledgements = Vec::new();
        for (index, receiver) in receivers.iter_mut().take(2).enumerate() {
            acknowledgements.push(
                receiver
                    .accept_report(
                        &first,
                        ingest_node,
                        &membership,
                        signing_key(&membership, &keys, index),
                    )
                    .expect("authority accepts report"),
            );
        }
        ingest
            .acknowledge(&acknowledgements[0], &membership)
            .expect("first authority ACK is valid");
        ingest
            .acknowledge(&acknowledgements[1], &membership)
            .expect("second authority ACK is valid");
        assert_eq!(ingest.pending_authorities().len(), 2);

        // The sender crashes with two ACKs recorded and the report still pending.
        let snapshot = ingest.serialize().expect("sender snapshot is bounded");
        ingest = DelegatedIngestState::deserialize(&snapshot)
            .expect("sender restart restores both buffers and ACK state");
        assert_eq!(ingest.pending_report(), Some(&first));

        // A report may be accepted while its ACK is lost; retransmission is idempotent.
        let lost_ack = receivers[2]
            .accept_report(
                &first,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 2),
            )
            .expect("third authority accepts report");
        let retried_ack = receivers[2]
            .accept_report(
                &first,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 2),
            )
            .expect("duplicate report receives another ACK");
        assert_eq!(retried_ack, lost_ack);
        ingest
            .acknowledge(&retried_ack, &membership)
            .expect("lost ACK retry is applied");

        // The fourth authority persists its merge before the response is delivered.
        let _lost_report = receivers[3]
            .accept_report(
                &first,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 3),
            )
            .expect("fourth authority accepts delayed report");
        let authority_snapshot = receivers[3]
            .serialize()
            .expect("authority snapshot is bounded");
        receivers[3] =
            DelegatedReportReceiver::deserialize(&authority_snapshot, &descriptor, &membership)
                .expect("authority restart restores its merge and sequence");
        let recovered_ack = receivers[3]
            .accept_report(
                &first,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 3),
            )
            .expect("duplicate report after authority restart is harmless");
        assert_eq!(receivers[3].estimate(), 1.0);
        assert!(
            ingest
                .acknowledge(&recovered_ack, &membership)
                .expect("fourth ACK reclaims the report")
        );
        assert!(
            !ingest
                .acknowledge(&recovered_ack, &membership)
                .expect("duplicate completed ACK is harmless")
        );
        assert!(ingest.pending_report().is_none());

        // The active buffer was never stopped and becomes the next report.
        let second = ingest
            .rollover()
            .expect("second report rollover succeeds")
            .expect("active sketch accumulated while the first report was pending")
            .clone();
        assert_eq!(second.sequence(), 2);
        assert_eq!(second.sketch().estimate(), 1.0);
        ingest.record_client(client(3));
        assert!(
            ingest
                .rollover()
                .expect("third rollover is deferred")
                .is_none()
        );
        assert_eq!(ingest.active.estimate(), 1.0);
    }

    #[test]
    fn receiver_rejects_spoofed_senders_gaps_and_conflicting_replays() {
        let content_id = content(10);
        let day = UtcDay::new(0);
        let (membership, keys) = make_membership(content_id, 1);
        let ingest_node = node(55);
        let other_node = node(56);
        let descriptor = descriptor(&[ingest_node]);
        let mut receiver =
            DelegatedReportReceiver::new(content_id, day, 0, &descriptor, &membership)
                .expect("receiver uses a valid descriptor");
        let mut sketch = ClientSketch::new();
        sketch.insert(client(1));
        let first = IngestReport::new(content_id, day, 0, ingest_node, 1, sketch.clone())
            .expect("valid first report");
        assert_eq!(
            receiver.accept_report(
                &first,
                other_node,
                &membership,
                signing_key(&membership, &keys, 0),
            ),
            Err(DelegatedIngestError::UnauthorizedIngestNode)
        );
        let gap = IngestReport::new(content_id, day, 0, ingest_node, 2, sketch.clone())
            .expect("valid but skipped report");
        assert_eq!(
            receiver.accept_report(
                &gap,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 0),
            ),
            Err(DelegatedIngestError::ReportSequenceGap)
        );
        receiver
            .accept_report(
                &first,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 0),
            )
            .expect("first report is accepted");
        let mut changed_sketch = ClientSketch::new();
        changed_sketch.insert(client(2));
        let conflicting = IngestReport::new(content_id, day, 0, ingest_node, 1, changed_sketch)
            .expect("same sequence with another sketch");
        assert_eq!(
            receiver.accept_report(
                &conflicting,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 0),
            ),
            Err(DelegatedIngestError::ConflictingReport)
        );
        let repeated = receiver
            .accept_report(
                &first,
                ingest_node,
                &membership,
                signing_key(&membership, &keys, 0),
            )
            .expect("exact replay gets an idempotent acknowledgement");
        repeated
            .verify(&membership)
            .expect("replay acknowledgement has a valid signature");
        assert_eq!(receiver.estimate(), 1.0);
    }

    #[test]
    fn acknowledgements_bind_report_identity_and_membership_generation() {
        let content_id = content(11);
        let day = UtcDay::new(2);
        let (membership, keys) = make_membership(content_id, 4);
        let node_id = node(60);
        let mut sketch = ClientSketch::new();
        sketch.insert(client(4));
        let report =
            IngestReport::new(content_id, day, 2, node_id, 1, sketch).expect("valid report");
        let ack =
            SignedIngestReportAck::sign(&report, &membership, signing_key(&membership, &keys, 0))
                .expect("member signs ACK");
        let decoded =
            SignedIngestReportAck::deserialize(&ack.canonical_bytes()).expect("ACK decodes");
        decoded
            .verify(&membership)
            .expect("decoded ACK retains its signature");

        let (new_membership, _) = make_membership(content_id, 5);
        assert_eq!(
            decoded.verify(&new_membership),
            Err(DelegatedIngestError::UnexpectedAcknowledgement)
        );
        let mut tampered = decoded;
        tampered.signature[0] ^= 1;
        assert_eq!(
            tampered.verify(&membership),
            Err(DelegatedIngestError::UnexpectedAcknowledgement)
        );

        let mut ingest = DelegatedIngestState::new(content_id, day, 2, node_id, &membership)
            .expect("valid state");
        ingest.record_client(client(4));
        ingest.rollover().expect("rollover");
        ingest
            .acknowledge(&ack, &membership)
            .expect("old-generation ACK applies before replacement");
        ingest
            .retarget_membership(&new_membership)
            .expect("new authority generation retargets report");
        assert_eq!(ingest.pending_authorities().len(), AUTHORITY_COUNT);
        assert_eq!(
            ingest.acknowledge(&ack, &membership),
            Err(DelegatedIngestError::StaleMembership)
        );
    }

    #[test]
    fn state_decoders_reject_trailing_and_oversized_bytes() {
        let content_id = content(12);
        let day = UtcDay::new(0);
        let (membership, _) = make_membership(content_id, 0);
        let ingest_node = node(70);
        let mut ingest = DelegatedIngestState::new(content_id, day, 0, ingest_node, &membership)
            .expect("valid state");
        ingest.record_client(client(1));
        let mut encoded = ingest.serialize().expect("snapshot encodes");
        encoded.push(0);
        assert_eq!(
            DelegatedIngestState::deserialize(&encoded),
            Err(DelegatedIngestError::InvalidEncoding)
        );
        assert_eq!(
            IngestReport::deserialize(&vec![0; MAX_STATE_COMPONENT_BYTES + 1]),
            Err(DelegatedIngestError::StateTooLarge)
        );

        let mut sketch = ClientSketch::new();
        sketch.insert(client(1));
        let report =
            IngestReport::new(content_id, day, 0, ingest_node, 1, sketch).expect("valid report");
        let descriptor = descriptor(&[ingest_node]);
        let receiver = DelegatedReportReceiver::new(content_id, day, 0, &descriptor, &membership)
            .expect("valid receiver");
        let snapshot = receiver.serialize().expect("authority snapshot encodes");
        let restored = DelegatedReportReceiver::deserialize(&snapshot, &descriptor, &membership)
            .expect("authority snapshot restores");
        assert_eq!(restored, receiver);

        let expected: BTreeSet<_> = [client(1)].into_iter().collect();
        assert!(expected.contains(&client(1)));
        assert_eq!(
            report.sketch().estimate(),
            f64::from(u8::try_from(expected.len()).expect("one client fits in u8"))
        );
    }

    #[test]
    fn active_ingest_buffer_restores_before_the_first_rollover() {
        let content_id = content(13);
        let (membership, _) = make_membership(content_id, 0);
        let mut ingest =
            DelegatedIngestState::new(content_id, UtcDay::new(0), 0, node(80), &membership)
                .expect("valid ingest state");
        ingest.record_client(client(1));
        ingest.record_client(client(2));

        let snapshot = ingest.serialize().expect("active state serializes");
        let restored = DelegatedIngestState::deserialize(&snapshot).expect("active state restores");

        assert_eq!(restored, ingest);
        assert_eq!(restored.active.estimate(), 2.0);
        assert!(restored.pending_report().is_none());
    }

    #[test]
    fn pending_snapshot_rejects_all_acknowledgements_but_restores_partial_sets() {
        let content_id = content(15);
        let (membership, keys) = make_membership(content_id, 1);
        let mut ingest =
            DelegatedIngestState::new(content_id, UtcDay::new(0), 0, node(82), &membership)
                .expect("valid ingest state");
        ingest.record_client(client(1));
        let report = ingest
            .rollover()
            .expect("rollover succeeds")
            .expect("nonempty sketch creates a pending report")
            .clone();

        for authority_index in 0..AUTHORITY_COUNT - 1 {
            let ack = SignedIngestReportAck::sign(
                &report,
                &membership,
                signing_key(&membership, &keys, authority_index),
            )
            .expect("member signs ACK");
            ingest
                .acknowledge(&ack, &membership)
                .expect("partial ACK is recorded");
            let snapshot = ingest.serialize().expect("partial snapshot fits");
            let restored =
                DelegatedIngestState::deserialize(&snapshot).expect("partial ACK state restores");
            assert_eq!(
                restored.pending_authorities().len(),
                AUTHORITY_COUNT - authority_index - 1
            );
        }

        let mut impossible_snapshot = ingest.serialize().expect("three-ACK snapshot fits");
        let acknowledgements_start = impossible_snapshot.len() - 1 - (AUTHORITY_COUNT - 1) * 32;
        impossible_snapshot.truncate(acknowledgements_start);
        impossible_snapshot.push(u8::try_from(AUTHORITY_COUNT).expect("authority count fits u8"));
        for authority in &ingest.expected_authorities {
            impossible_snapshot.extend_from_slice(authority.as_bytes());
        }
        assert_eq!(
            DelegatedIngestState::deserialize(&impossible_snapshot),
            Err(DelegatedIngestError::InvalidEncoding)
        );
    }

    #[test]
    fn state_decoders_reject_noncanonical_set_ordering() {
        let content_id = content(14);
        let day = UtcDay::new(0);
        let (membership, keys) = make_membership(content_id, 0);
        let ingest = DelegatedIngestState::new(content_id, day, 0, node(81), &membership)
            .expect("valid ingest state");
        let mut ingest_bytes = ingest.serialize().expect("ingest state serializes");
        let authority_start = 99;
        let authority_bytes = authority_start..authority_start + AUTHORITY_COUNT * 32;
        let (authority_ids, remainder) = ingest_bytes[authority_bytes.clone()].as_chunks::<32>();
        assert_eq!(remainder, &[]);
        assert!(authority_ids.windows(2).all(|pair| pair[0] < pair[1]));
        for index in 0..AUTHORITY_COUNT / 2 {
            let left = authority_start + index * 32;
            let right = authority_start + (AUTHORITY_COUNT - index - 1) * 32;
            let (before_right, right_and_after) = ingest_bytes.split_at_mut(right);
            before_right[left..left + 32].swap_with_slice(&mut right_and_after[..32]);
        }
        assert_eq!(
            DelegatedIngestState::deserialize(&ingest_bytes),
            Err(DelegatedIngestError::InvalidEncoding)
        );

        let nodes = [node(1), node(2)];
        let descriptor = descriptor(&nodes);
        let receiver = DelegatedReportReceiver::new(content_id, day, 0, &descriptor, &membership)
            .expect("valid report receiver");
        let mut receiver_bytes = receiver.serialize().expect("receiver serializes");
        let candidates_start = 54;
        assert!(nodes[0] < nodes[1]);
        let (before_right, right_and_after) = receiver_bytes.split_at_mut(candidates_start + 32);
        before_right[candidates_start..candidates_start + 32]
            .swap_with_slice(&mut right_and_after[..32]);
        assert_eq!(
            DelegatedReportReceiver::deserialize(&receiver_bytes, &descriptor, &membership),
            Err(DelegatedIngestError::InvalidEncoding)
        );

        let signer = signing_key(&membership, &keys, 0);
        let mut populated_receiver =
            DelegatedReportReceiver::new(content_id, day, 0, &descriptor, &membership)
                .expect("valid report receiver");
        for (index, node_id) in nodes.into_iter().enumerate() {
            let mut sketch = ClientSketch::new();
            sketch.insert(client(
                u8::try_from(index + 1).expect("two nodes fit in u8"),
            ));
            let report =
                IngestReport::new(content_id, day, 0, node_id, 1, sketch).expect("valid report");
            populated_receiver
                .accept_report(&report, node_id, &membership, signer)
                .expect("candidate report is accepted");
        }
        let mut sequence_bytes = populated_receiver
            .serialize()
            .expect("receiver sequence state serializes");
        let sequence_entries_start = 50 + 4 + nodes.len() * 32 + 4;
        let second_entry = sequence_entries_start + 32 + 8 + 32;
        let (before_second_entry, second_entry_bytes) = sequence_bytes.split_at_mut(second_entry);
        before_second_entry[sequence_entries_start..sequence_entries_start + 32]
            .swap_with_slice(&mut second_entry_bytes[..32]);
        assert_eq!(
            DelegatedReportReceiver::deserialize(&sequence_bytes, &descriptor, &membership),
            Err(DelegatedIngestError::InvalidEncoding)
        );
    }

    #[test]
    fn delegated_report_and_ack_match_the_v1_wire_vector() {
        let field = |name: &str| {
            include_str!("../../../testvectors/delegated-ingest-v1.txt")
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing delegated-ingest vector field {name}"))
        };
        let hex = |bytes: &[u8]| {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            let mut encoded = String::with_capacity(bytes.len() * 2);
            for byte in bytes {
                encoded.push(char::from(DIGITS[usize::from(*byte >> 4)]));
                encoded.push(char::from(DIGITS[usize::from(*byte & 0x0f)]));
            }
            encoded
        };
        let content_id = content(5);
        let day = UtcDay::new(10);
        let (membership, keys) = make_membership(content_id, 1);
        let signer = signing_key(&membership, &keys, 0);
        let mut sketch = ClientSketch::new();
        sketch.insert(client(9));
        let report =
            IngestReport::new(content_id, day, 1, node(42), 1, sketch).expect("valid report");
        let ack =
            SignedIngestReportAck::sign(&report, &membership, signer).expect("member signs ACK");
        assert_eq!(hex(content_id.as_bytes()), field("content_id"));
        assert_eq!(hex(client(9).as_bytes()), field("client_id"));
        assert_eq!(hex(&day.to_bytes()), field("utc_day"));
        assert_eq!(hex(node(42).as_bytes()), field("node_id"));
        assert_eq!(hex(&report.sketch().serialize()), field("report_sketch"));
        let report_wire = format!(
            "5049525001{}{}{}{}{}00000026{}",
            field("content_id"),
            field("utc_day"),
            field("view"),
            field("node_id"),
            field("report_sequence"),
            field("report_sketch")
        );
        assert_eq!(
            hex(&report.canonical_bytes().expect("report encodes")),
            report_wire
        );
        assert_eq!(
            hex(&membership.generation().to_be_bytes()),
            field("membership_generation")
        );
        let ack_message = format!(
            "{}{}{}{}{}{}{}",
            hex(b"populus/delegated-ingest-ack/v1"),
            field("content_id"),
            field("utc_day"),
            field("view"),
            field("node_id"),
            field("report_sequence"),
            field("membership_generation")
        );
        assert_eq!(hex(&ack.message()), ack_message);
        assert_eq!(hex(&ack.signature), field("ack_signature"));
        assert_eq!(hex(ack.signer.as_bytes()), field("signer_id"));
        let ack_wire = format!(
            "5049414b01{}{}{}{}{}{}{}{}",
            field("content_id"),
            field("utc_day"),
            field("view"),
            field("node_id"),
            field("report_sequence"),
            field("membership_generation"),
            field("signer_id"),
            field("ack_signature")
        );
        assert_eq!(hex(&ack.canonical_bytes()), ack_wire);
        assert_eq!(
            IngestReport::deserialize(&report.canonical_bytes().expect("report encodes")),
            Ok(report)
        );
        SignedIngestReportAck::deserialize(&ack.canonical_bytes())
            .expect("ACK vector decodes")
            .verify(&membership)
            .expect("ACK vector signature verifies");
    }
}
