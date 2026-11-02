//! Daily direct-vote ingestion for a content authority cluster.

use crate::MAX_STATE_COMPONENT_BYTES;
use populus_crypto::{
    AuthorityKeypair, RoutingIdentifier, daily_vote_id, routing_key, verify_ed25519,
};
use populus_sketch::{ClientSketch, SketchDecodeError};
use populus_types::{AuthorityId, ClientId, ContentId, DailyVoteId, RoutingKey, UtcDay};
use std::{collections::BTreeSet, fmt};

const STATE_HEADER: [u8; 4] = *b"PDIR";
const STATE_VERSION: u8 = 1;
const RATE_WINDOW_MS: i64 = 60_000;
const MAX_BOUNDARY_ALLOWANCE_MS: u64 = 86_400_000;

/// Default desired maximum direct rate for each authority, in votes per minute.
pub const DEFAULT_MAX_DIRECT_VOTES_PER_MINUTE: u64 = 1_000;
/// Default provisional period after a UTC day ends.
pub const DEFAULT_CLOSE_GRACE_PERIOD_MS: u64 = 5 * 60 * 1_000;
/// Default allowance for authority clock skew around UTC-day boundaries.
pub const DEFAULT_MAX_CLOCK_SKEW_MS: u64 = 60 * 1_000;

/// Tunable direct-ingest policy. These values are engineering defaults, not
/// protocol constants; the rate target can be changed without changing vote IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectIngestPolicy {
    max_direct_votes_per_minute: u64,
    close_grace_period_ms: u64,
    max_clock_skew_ms: u64,
}

impl Default for DirectIngestPolicy {
    fn default() -> Self {
        Self {
            max_direct_votes_per_minute: DEFAULT_MAX_DIRECT_VOTES_PER_MINUTE,
            close_grace_period_ms: DEFAULT_CLOSE_GRACE_PERIOD_MS,
            max_clock_skew_ms: DEFAULT_MAX_CLOCK_SKEW_MS,
        }
    }
}

impl DirectIngestPolicy {
    /// Creates a policy with an explicit rate target, close grace, and clock allowance.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::InvalidPolicy`] when the rate target is
    /// zero or the combined close-grace and clock-skew allowance exceeds one
    /// UTC day.
    pub fn new(
        max_direct_votes_per_minute: u64,
        close_grace_period_ms: u64,
        max_clock_skew_ms: u64,
    ) -> Result<Self, DirectIngestError> {
        let boundary_allowance_is_bounded = close_grace_period_ms
            .checked_add(max_clock_skew_ms)
            .is_some_and(|allowance| allowance <= MAX_BOUNDARY_ALLOWANCE_MS);
        if max_direct_votes_per_minute == 0 || !boundary_allowance_is_bounded {
            return Err(DirectIngestError::InvalidPolicy);
        }
        Ok(Self {
            max_direct_votes_per_minute,
            close_grace_period_ms,
            max_clock_skew_ms,
        })
    }

    /// Returns the configured desired maximum direct rate.
    #[must_use]
    pub const fn max_direct_votes_per_minute(self) -> u64 {
        self.max_direct_votes_per_minute
    }

    /// Returns the configured post-midnight late-vote grace period.
    #[must_use]
    pub const fn close_grace_period_ms(self) -> u64 {
        self.close_grace_period_ms
    }

    /// Returns the clock-skew allowance around UTC-day boundaries.
    #[must_use]
    pub const fn max_clock_skew_ms(self) -> u64 {
        self.max_clock_skew_ms
    }
}

/// One client contribution to a specific content item's UTC-day sketch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectVote {
    content_id: ContentId,
    client_id: ClientId,
    day: UtcDay,
    daily_vote_id: DailyVoteId,
}

impl DirectVote {
    /// Creates a vote for one content item and UTC day.
    #[must_use]
    pub fn new(content_id: ContentId, client_id: ClientId, day: UtcDay) -> Self {
        Self {
            content_id,
            client_id,
            day,
            daily_vote_id: daily_vote_id(&content_id, day),
        }
    }

    /// Returns the immutable content identifier.
    #[must_use]
    pub const fn content_id(self) -> ContentId {
        self.content_id
    }

    /// Returns the scarcity-derived client identity.
    #[must_use]
    pub const fn client_id(self) -> ClientId {
        self.client_id
    }

    /// Returns the UTC day claimed by this vote.
    #[must_use]
    pub const fn day(self) -> UtcDay {
        self.day
    }

    /// Returns the daily content-bucket identity.
    #[must_use]
    pub const fn daily_vote_id(self) -> DailyVoteId {
        self.daily_vote_id
    }

    /// Encodes this vote in canonical v1 direct-ingest wire form.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(113);
        bytes.extend_from_slice(b"PDVT");
        bytes.push(1);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(self.client_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.extend_from_slice(self.daily_vote_id.as_bytes());
        bytes
    }

    /// Decodes a canonical v1 direct vote, verifying its bucket identity.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::InvalidStateEncoding`] for malformed
    /// bytes or an invalid `DailyVoteId`.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DirectIngestError> {
        let mut cursor = StateCursor::new(bytes);
        if cursor.take::<4>()? != *b"PDVT" || cursor.byte()? != 1 {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DirectIngestError::InvalidStateEncoding)?;
        let client_id = ClientId::from_bytes(cursor.take::<32>()?);
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let daily_vote_id = DailyVoteId::from_bytes(cursor.take::<32>()?);
        cursor.remaining_exact(0)?;
        let vote = Self::new(content_id, client_id, day);
        if vote.daily_vote_id != daily_vote_id {
            return Err(DirectIngestError::InvalidVoteId);
        }
        Ok(vote)
    }
}

/// Persistent local like state that issues at most one vote per UTC day.
///
/// The pending vote is returned unchanged for retries until every authority in
/// the pinned membership acknowledges it, even if the client returns on the
/// following UTC day. A pending vote is discarded once the client returns at
/// least two days later, when the bounded acceptance allowance is guaranteed
/// closed. Replacements advance the pending vote to the new membership
/// generation and restart its acknowledgement set. Once no vote is pending, a
/// client returning after offline days creates a vote only for the current day.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentLike {
    content_id: ContentId,
    liked: bool,
    last_acknowledged_day: Option<UtcDay>,
    pending: Option<PendingDirectVote>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingDirectVote {
    vote: DirectVote,
    membership_generation: u64,
    expected_authorities: BTreeSet<AuthorityId>,
    acknowledged_authorities: BTreeSet<AuthorityId>,
}

/// Cryptographically verifiable confirmation that one authority accepted a vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDirectVoteAck {
    vote: DirectVote,
    membership_generation: u64,
    signer: AuthorityId,
    signature: [u8; 64],
}

impl SignedDirectVoteAck {
    /// Signs an acknowledgement using an authority represented by the membership.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::UnexpectedAcknowledgement`] if the signing
    /// key is not the matching member of the content's authority view.
    pub fn sign(
        vote: DirectVote,
        membership: &crate::MembershipView,
        signer: &AuthorityKeypair,
    ) -> Result<Self, DirectIngestError> {
        if membership.routing_key() != routing_key(RoutingIdentifier::Content(&vote.content_id)) {
            return Err(DirectIngestError::WrongMembership);
        }
        let signer_id = signer.authority_id();
        let Some(member) = membership.member(signer_id) else {
            return Err(DirectIngestError::UnexpectedAcknowledgement);
        };
        if member.public_key() != &signer.public_key() {
            return Err(DirectIngestError::UnexpectedAcknowledgement);
        }
        let mut acknowledgement = Self {
            vote,
            membership_generation: membership.generation(),
            signer: signer_id,
            signature: [0; 64],
        };
        acknowledgement.signature = signer.sign(&acknowledgement.message());
        Ok(acknowledgement)
    }

    /// Returns the authority identity that signed this acknowledgement.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }

    /// Encodes this signed acknowledgement in canonical v1 wire form.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(217);
        bytes.extend_from_slice(b"PDAK");
        bytes.push(1);
        bytes.extend_from_slice(self.vote.content_id.as_bytes());
        bytes.extend_from_slice(self.vote.client_id.as_bytes());
        bytes.extend_from_slice(&self.vote.day.to_bytes());
        bytes.extend_from_slice(self.vote.daily_vote_id.as_bytes());
        bytes.extend_from_slice(&self.membership_generation.to_be_bytes());
        bytes.extend_from_slice(self.signer.as_bytes());
        bytes.extend_from_slice(&self.signature);
        bytes
    }

    /// Decodes a canonical v1 signed acknowledgement.
    ///
    /// The decoded signature must still be verified against a trusted
    /// [`crate::MembershipView`] using [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::InvalidStateEncoding`] for malformed
    /// bytes and [`DirectIngestError::InvalidVoteId`] for inconsistent vote scope.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DirectIngestError> {
        let mut cursor = StateCursor::new(bytes);
        if cursor.take::<4>()? != *b"PDAK" || cursor.byte()? != 1 {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DirectIngestError::InvalidStateEncoding)?;
        let client_id = ClientId::from_bytes(cursor.take::<32>()?);
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let daily_vote_id = DailyVoteId::from_bytes(cursor.take::<32>()?);
        let membership_generation = u64::from_be_bytes(cursor.take::<8>()?);
        let signer = AuthorityId::from_bytes(cursor.take::<32>()?);
        let signature = cursor.take::<64>()?;
        cursor.remaining_exact(0)?;
        let vote = DirectVote::new(content_id, client_id, day);
        if vote.daily_vote_id != daily_vote_id {
            return Err(DirectIngestError::InvalidVoteId);
        }
        Ok(Self {
            vote,
            membership_generation,
            signer,
            signature,
        })
    }

    /// Verifies the vote, membership generation, signer, and signature.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::UnexpectedAcknowledgement`] if any binding
    /// or signature is invalid.
    pub fn verify(&self, membership: &crate::MembershipView) -> Result<(), DirectIngestError> {
        if membership.routing_key()
            != routing_key(RoutingIdentifier::Content(&self.vote.content_id))
            || membership.generation() != self.membership_generation
        {
            return Err(DirectIngestError::UnexpectedAcknowledgement);
        }
        let Some(member) = membership.member(self.signer) else {
            return Err(DirectIngestError::UnexpectedAcknowledgement);
        };
        verify_ed25519(member.public_key(), &self.message(), &self.signature)
            .map_err(|_| DirectIngestError::UnexpectedAcknowledgement)
    }

    fn message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(150);
        message.extend_from_slice(b"populus/direct-vote-ack/v1");
        message.extend_from_slice(self.vote.content_id.as_bytes());
        message.extend_from_slice(self.vote.client_id.as_bytes());
        message.extend_from_slice(&self.vote.day.to_bytes());
        message.extend_from_slice(self.vote.daily_vote_id.as_bytes());
        message.extend_from_slice(&self.membership_generation.to_be_bytes());
        message
    }
}

impl PersistentLike {
    /// Creates local persistent-like state for one content item.
    #[must_use]
    pub const fn new(content_id: ContentId, liked: bool) -> Self {
        Self {
            content_id,
            liked,
            last_acknowledged_day: None,
            pending: None,
        }
    }

    /// Sets whether this client continues to like the content.
    ///
    /// Unliking stops new votes and drops an unacknowledged local retry. Any
    /// already delivered vote remains part of that day's immutable set.
    pub fn set_liked(&mut self, liked: bool) {
        self.liked = liked;
        if !liked {
            self.pending = None;
        }
    }

    /// Produces or retries today's vote when the client is online.
    ///
    /// The membership view pins the four direct recipients for this vote.
    /// A newer membership generation re-targets the pending vote and clears
    /// acknowledgements from the previous authority set. Pending votes expire
    /// when the current day is at least two days after the vote day; the
    /// policy's one-day boundary-allowance bound guarantees they can no longer
    /// be accepted.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::WrongMembership`],
    /// [`DirectIngestError::StaleMembership`], or
    /// [`DirectIngestError::MembershipGenerationConflict`] when the supplied
    /// membership does not represent a valid view for this pending vote.
    pub fn vote_when_online(
        &mut self,
        client_id: ClientId,
        day: UtcDay,
        membership: &crate::MembershipView,
    ) -> Result<Option<DirectVote>, DirectIngestError> {
        if !self.liked {
            return Ok(None);
        }
        if membership.routing_key() != routing_key(RoutingIdentifier::Content(&self.content_id)) {
            return Err(DirectIngestError::WrongMembership);
        }
        let pending_vote_expired = self
            .pending
            .as_ref()
            .is_some_and(|pending| day.value() > pending.vote.day.value().saturating_add(1));
        if pending_vote_expired {
            self.pending = None;
        }
        if let Some(pending) = &mut self.pending {
            let expected_authorities: BTreeSet<_> = membership
                .members()
                .iter()
                .map(crate::AuthorityMember::authority_id)
                .collect();
            if membership.generation() < pending.membership_generation {
                return Err(DirectIngestError::StaleMembership);
            }
            if membership.generation() == pending.membership_generation {
                if pending.expected_authorities != expected_authorities {
                    return Err(DirectIngestError::MembershipGenerationConflict);
                }
            } else {
                pending.membership_generation = membership.generation();
                pending.expected_authorities = expected_authorities;
                pending.acknowledged_authorities.clear();
            }
            return Ok(Some(pending.vote));
        }
        if self
            .last_acknowledged_day
            .is_some_and(|last_day| day <= last_day)
        {
            return Ok(None);
        }
        let vote = DirectVote::new(self.content_id, client_id, day);
        self.pending = Some(PendingDirectVote {
            vote,
            membership_generation: membership.generation(),
            expected_authorities: membership
                .members()
                .iter()
                .map(crate::AuthorityMember::authority_id)
                .collect(),
            acknowledged_authorities: BTreeSet::new(),
        });
        Ok(Some(vote))
    }

    /// Returns the authorities that have not yet acknowledged the pending vote.
    #[must_use]
    pub fn pending_authorities(&self) -> Vec<AuthorityId> {
        self.pending.as_ref().map_or_else(Vec::new, |pending| {
            pending
                .expected_authorities
                .difference(&pending.acknowledged_authorities)
                .copied()
                .collect()
        })
    }

    /// Records one signed authority acknowledgement of the current daily vote.
    ///
    /// Returns `true` only after all four pinned authorities acknowledge the
    /// vote; duplicate acknowledgements from a pending authority are harmless.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::UnexpectedAcknowledgement`] if the vote ID
    /// or authority does not match the outstanding vote.
    pub fn acknowledge(
        &mut self,
        acknowledgement: &SignedDirectVoteAck,
        membership: &crate::MembershipView,
    ) -> Result<bool, DirectIngestError> {
        let Some(pending) = &mut self.pending else {
            return Err(DirectIngestError::UnexpectedAcknowledgement);
        };
        acknowledgement.verify(membership)?;
        let authority_id = acknowledgement.signer();
        if pending.vote != acknowledgement.vote
            || pending.membership_generation != membership.generation()
            || !pending.expected_authorities.contains(&authority_id)
        {
            return Err(DirectIngestError::UnexpectedAcknowledgement);
        }
        pending.acknowledged_authorities.insert(authority_id);
        if pending.acknowledged_authorities.len() != pending.expected_authorities.len() {
            return Ok(false);
        }
        self.last_acknowledged_day = Some(
            self.last_acknowledged_day
                .map_or(pending.vote.day, |previous| previous.max(pending.vote.day)),
        );
        self.pending = None;
        Ok(true)
    }

    /// Encodes the local like, retry, and acknowledgement state canonically.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(b"PLIK");
        bytes.push(1);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.push(u8::from(self.liked));
        match self.last_acknowledged_day {
            Some(day) => {
                bytes.push(1);
                bytes.extend_from_slice(&day.to_bytes());
            }
            None => bytes.push(0),
        }
        match &self.pending {
            Some(pending) => {
                bytes.push(1);
                bytes.extend_from_slice(pending.vote.client_id.as_bytes());
                bytes.extend_from_slice(&pending.vote.day.to_bytes());
                bytes.extend_from_slice(pending.vote.daily_vote_id.as_bytes());
                bytes.extend_from_slice(&pending.membership_generation.to_be_bytes());
                bytes.push(u8::try_from(pending.expected_authorities.len()).unwrap_or(u8::MAX));
                for authority_id in &pending.expected_authorities {
                    bytes.extend_from_slice(authority_id.as_bytes());
                }
                bytes.push(u8::try_from(pending.acknowledged_authorities.len()).unwrap_or(u8::MAX));
                for authority_id in &pending.acknowledged_authorities {
                    bytes.extend_from_slice(authority_id.as_bytes());
                }
            }
            None => bytes.push(0),
        }
        bytes
    }

    /// Restores canonical local like, retry, and acknowledgement state.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::InvalidStateEncoding`] for malformed or
    /// inconsistent state.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DirectIngestError> {
        let mut cursor = StateCursor::new(bytes);
        if cursor.take::<4>()? != *b"PLIK" || cursor.byte()? != 1 {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        let content_id = ContentId::from_bytes(cursor.take::<36>()?)
            .map_err(|_| DirectIngestError::InvalidStateEncoding)?;
        let liked = match cursor.byte()? {
            0 => false,
            1 => true,
            _ => return Err(DirectIngestError::InvalidStateEncoding),
        };
        let last_acknowledged_day = match cursor.byte()? {
            0 => None,
            1 => Some(UtcDay::from_bytes(cursor.take::<8>()?)),
            _ => return Err(DirectIngestError::InvalidStateEncoding),
        };
        let pending = match cursor.byte()? {
            0 => None,
            1 => {
                let client_id = ClientId::from_bytes(cursor.take::<32>()?);
                let day = UtcDay::from_bytes(cursor.take::<8>()?);
                let daily_vote_id = DailyVoteId::from_bytes(cursor.take::<32>()?);
                let membership_generation = u64::from_be_bytes(cursor.take::<8>()?);
                let vote = DirectVote::new(content_id, client_id, day);
                if vote.daily_vote_id != daily_vote_id || !liked {
                    return Err(DirectIngestError::InvalidStateEncoding);
                }
                let expected_count = cursor.byte()?;
                if usize::from(expected_count) != crate::AUTHORITY_COUNT {
                    return Err(DirectIngestError::InvalidStateEncoding);
                }
                let expected_authorities = read_authority_ids(&mut cursor, expected_count)?;
                let acknowledged_count = cursor.byte()?;
                if acknowledged_count > expected_count {
                    return Err(DirectIngestError::InvalidStateEncoding);
                }
                let acknowledged_authorities = read_authority_ids(&mut cursor, acknowledged_count)?;
                if !acknowledged_authorities.is_subset(&expected_authorities)
                    || last_acknowledged_day.is_some_and(|last_day| day <= last_day)
                {
                    return Err(DirectIngestError::InvalidStateEncoding);
                }
                Some(PendingDirectVote {
                    vote,
                    membership_generation,
                    expected_authorities,
                    acknowledged_authorities,
                })
            }
            _ => return Err(DirectIngestError::InvalidStateEncoding),
        };
        cursor.remaining_exact(0)?;
        Ok(Self {
            content_id,
            liked,
            last_acknowledged_day,
            pending,
        })
    }
}

fn read_authority_ids(
    cursor: &mut StateCursor<'_>,
    count: u8,
) -> Result<BTreeSet<AuthorityId>, DirectIngestError> {
    let mut authorities = BTreeSet::new();
    let mut previous = None;
    for _ in 0..count {
        let authority = AuthorityId::from_bytes(cursor.take::<32>()?);
        if previous.is_some_and(|previous| previous >= authority) || !authorities.insert(authority)
        {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        previous = Some(authority);
    }
    Ok(authorities)
}

/// Result of applying one direct-vote delivery.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DirectVoteOutcome {
    /// Provisional estimate after idempotently inserting the client identity.
    pub provisional_estimate: f64,
    /// Count of deliveries in the authority's current fixed UTC-minute bucket.
    pub current_minute_deliveries: u64,
    /// Whether the desired direct-rate target has been exceeded.
    pub delegation_recommended: bool,
}

/// Finalization state of one daily popularity sketch.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DailyPopularityStatus {
    /// The estimate may still change while late votes are accepted.
    Provisional {
        /// Current approximate distinct-client estimate.
        estimate: f64,
    },
    /// The grace period elapsed; this total is immutable.
    Finalized {
        /// Final approximate distinct-client estimate.
        estimate: f64,
    },
}

/// One authority's direct-mode popularity state for a content item and UTC day.
///
/// The caller supplies an already validated `ClientId`; binding a remote
/// transport connection to the scarcity identity is outside this state machine.
#[derive(Debug, Clone, PartialEq)]
pub struct DirectIngestState {
    content_id: ContentId,
    day: UtcDay,
    policy: DirectIngestPolicy,
    sketch: ClientSketch,
    finalized: bool,
    rate_minute: Option<i64>,
    minute_deliveries: u64,
}

impl DirectIngestState {
    /// Creates an empty direct-ingest state for one content item and day.
    #[must_use]
    pub fn new(content_id: ContentId, day: UtcDay, policy: DirectIngestPolicy) -> Self {
        Self {
            content_id,
            day,
            policy,
            sketch: ClientSketch::new(),
            finalized: false,
            rate_minute: None,
            minute_deliveries: 0,
        }
    }

    /// Returns the content and daily bucket bound to this state.
    #[must_use]
    pub const fn scope(&self) -> (ContentId, UtcDay) {
        (self.content_id, self.day)
    }

    /// Returns the authority routing key for the bound immutable content.
    #[must_use]
    pub fn routing_key(&self) -> RoutingKey {
        routing_key(RoutingIdentifier::Content(&self.content_id))
    }

    /// Returns the current provisional or finalized cardinality estimate.
    #[must_use]
    pub fn estimate(&self) -> f64 {
        self.sketch.estimate()
    }

    /// Applies a vote delivery; duplicate `ClientId`s are idempotent.
    ///
    /// Deliveries inside the configured grace period are accepted even when
    /// received after UTC midnight. The vote's explicit day, rather than each
    /// authority's local date, selects the sketch.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a mismatched scope, malformed vote identity,
    /// closed epoch, unacceptable timestamp, or arithmetic overflow.
    pub fn record_vote(
        &mut self,
        vote: DirectVote,
        received_at_ms: i64,
    ) -> Result<DirectVoteOutcome, DirectIngestError> {
        if vote.content_id != self.content_id {
            return Err(DirectIngestError::WrongContent);
        }
        if vote.day != self.day {
            return Err(DirectIngestError::WrongDay);
        }
        if vote.daily_vote_id != daily_vote_id(&self.content_id, self.day) {
            return Err(DirectIngestError::InvalidVoteId);
        }
        if self.finalized {
            return Err(DirectIngestError::EpochFinalized);
        }

        let (accept_from, finalize_at) = self.time_bounds()?;
        if received_at_ms >= finalize_at {
            self.finalized = true;
            return Err(DirectIngestError::EpochFinalized);
        }
        if received_at_ms < accept_from {
            return Err(DirectIngestError::VoteOutsideAcceptanceWindow);
        }

        let minute = received_at_ms.div_euclid(RATE_WINDOW_MS);
        if self.rate_minute.is_none_or(|current| minute > current) {
            self.rate_minute = Some(minute);
            self.minute_deliveries = 0;
        }
        if self.rate_minute == Some(minute) {
            self.minute_deliveries = self
                .minute_deliveries
                .checked_add(1)
                .ok_or(DirectIngestError::RateCounterOverflow)?;
        }
        self.sketch.insert(vote.client_id);
        Ok(DirectVoteOutcome {
            provisional_estimate: self.sketch.estimate(),
            current_minute_deliveries: self.minute_deliveries,
            delegation_recommended: self.minute_deliveries
                > self.policy.max_direct_votes_per_minute,
        })
    }

    /// Records a vote and returns a signed acknowledgement from this authority.
    ///
    /// The membership and signer are checked before the sketch is changed.
    ///
    /// # Errors
    ///
    /// Returns any validation error from [`Self::record_vote`] or
    /// [`SignedDirectVoteAck::sign`].
    pub fn record_vote_and_acknowledge(
        &mut self,
        vote: DirectVote,
        received_at_ms: i64,
        membership: &crate::MembershipView,
        signer: &AuthorityKeypair,
    ) -> Result<(DirectVoteOutcome, SignedDirectVoteAck), DirectIngestError> {
        let acknowledgement = SignedDirectVoteAck::sign(vote, membership, signer)?;
        let outcome = self.record_vote(vote, received_at_ms)?;
        Ok((outcome, acknowledgement))
    }

    /// Closes the day once its grace and clock-skew allowance have elapsed.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::TimeOutOfRange`] if a timestamp boundary
    /// cannot be represented as Unix milliseconds.
    pub fn finalize(&mut self, now_ms: i64) -> Result<DailyPopularityStatus, DirectIngestError> {
        let (_, finalize_at) = self.time_bounds()?;
        if now_ms >= finalize_at {
            self.finalized = true;
        }
        Ok(if self.finalized {
            DailyPopularityStatus::Finalized {
                estimate: self.sketch.estimate(),
            }
        } else {
            DailyPopularityStatus::Provisional {
                estimate: self.sketch.estimate(),
            }
        })
    }

    /// Encodes this daily sketch and its finalization/rate state canonically.
    ///
    /// # Errors
    ///
    /// Returns [`DirectIngestError::StateTooLarge`] if the authority component
    /// would exceed the Phase 7 replicated-state bound.
    pub fn serialize(&self) -> Result<Vec<u8>, DirectIngestError> {
        self.time_bounds()?;
        let sketch = self.sketch.serialize();
        let sketch_len =
            u32::try_from(sketch.len()).map_err(|_| DirectIngestError::StateTooLarge)?;
        let mut bytes = Vec::with_capacity(95 + sketch.len());
        bytes.extend_from_slice(&STATE_HEADER);
        bytes.push(STATE_VERSION);
        bytes.extend_from_slice(self.content_id.as_bytes());
        bytes.extend_from_slice(&self.day.to_bytes());
        bytes.extend_from_slice(&self.policy.max_direct_votes_per_minute.to_be_bytes());
        bytes.extend_from_slice(&self.policy.close_grace_period_ms.to_be_bytes());
        bytes.extend_from_slice(&self.policy.max_clock_skew_ms.to_be_bytes());
        bytes.push(u8::from(self.finalized));
        match self.rate_minute {
            Some(minute) => {
                bytes.push(1);
                bytes.extend_from_slice(&minute.to_be_bytes());
            }
            None => bytes.push(0),
        }
        bytes.extend_from_slice(&self.minute_deliveries.to_be_bytes());
        bytes.extend_from_slice(&sketch_len.to_be_bytes());
        bytes.extend_from_slice(&sketch);
        if bytes.len() > MAX_STATE_COMPONENT_BYTES {
            return Err(DirectIngestError::StateTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes a canonical daily-ingest snapshot.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed, oversized, or unsupported state.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, DirectIngestError> {
        if bytes.len() > MAX_STATE_COMPONENT_BYTES {
            return Err(DirectIngestError::StateTooLarge);
        }
        let mut cursor = StateCursor::new(bytes);
        if cursor.take::<4>()? != STATE_HEADER || cursor.byte()? != STATE_VERSION {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        let content_bytes = cursor.take::<36>()?;
        let content_id = ContentId::from_bytes(content_bytes)
            .map_err(|_| DirectIngestError::InvalidStateEncoding)?;
        let day = UtcDay::from_bytes(cursor.take::<8>()?);
        let policy = DirectIngestPolicy::new(
            u64::from_be_bytes(cursor.take::<8>()?),
            u64::from_be_bytes(cursor.take::<8>()?),
            u64::from_be_bytes(cursor.take::<8>()?),
        )?;
        let finalized = match cursor.byte()? {
            0 => false,
            1 => true,
            _ => return Err(DirectIngestError::InvalidStateEncoding),
        };
        let rate_minute = match cursor.byte()? {
            0 => None,
            1 => Some(i64::from_be_bytes(cursor.take::<8>()?)),
            _ => return Err(DirectIngestError::InvalidStateEncoding),
        };
        let minute_deliveries = u64::from_be_bytes(cursor.take::<8>()?);
        if rate_minute.is_some() != (minute_deliveries != 0) {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        let sketch_length = usize::try_from(u32::from_be_bytes(cursor.take::<4>()?))
            .map_err(|_| DirectIngestError::InvalidStateEncoding)?;
        let sketch_bytes = cursor.remaining_exact(sketch_length)?;
        let sketch = ClientSketch::deserialize(sketch_bytes).map_err(DirectIngestError::Sketch)?;
        let state = Self {
            content_id,
            day,
            policy,
            sketch,
            finalized,
            rate_minute,
            minute_deliveries,
        };
        let (accept_from, finalize_at) = state.time_bounds()?;
        if state.rate_minute.is_some_and(|minute| {
            minute < accept_from.div_euclid(RATE_WINDOW_MS)
                || minute > (finalize_at - 1).div_euclid(RATE_WINDOW_MS)
        }) {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        Ok(state)
    }

    fn time_bounds(&self) -> Result<(i64, i64), DirectIngestError> {
        let start = self
            .day
            .start_unix_millis()
            .ok_or(DirectIngestError::TimeOutOfRange)?;
        let end = self
            .day
            .end_unix_millis()
            .ok_or(DirectIngestError::TimeOutOfRange)?;
        let skew = i64::try_from(self.policy.max_clock_skew_ms)
            .map_err(|_| DirectIngestError::TimeOutOfRange)?;
        let grace = i64::try_from(self.policy.close_grace_period_ms)
            .map_err(|_| DirectIngestError::TimeOutOfRange)?;
        let accept_from = start
            .checked_sub(skew)
            .ok_or(DirectIngestError::TimeOutOfRange)?;
        let finalize_at = end
            .checked_add(grace)
            .and_then(|deadline| deadline.checked_add(skew))
            .ok_or(DirectIngestError::TimeOutOfRange)?;
        Ok((accept_from, finalize_at))
    }
}

struct StateCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> StateCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, DirectIngestError> {
        Ok(self.take::<1>()?[0])
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], DirectIngestError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or(DirectIngestError::InvalidStateEncoding)?;
        let source = self
            .bytes
            .get(self.offset..end)
            .ok_or(DirectIngestError::InvalidStateEncoding)?;
        let mut result = [0; N];
        result.copy_from_slice(source);
        self.offset = end;
        Ok(result)
    }

    fn remaining_exact(&mut self, expected: usize) -> Result<&'a [u8], DirectIngestError> {
        let remaining = self
            .bytes
            .get(self.offset..)
            .ok_or(DirectIngestError::InvalidStateEncoding)?;
        if remaining.len() != expected {
            return Err(DirectIngestError::InvalidStateEncoding);
        }
        self.offset = self.bytes.len();
        Ok(remaining)
    }
}

/// Errors encountered while validating or applying a direct vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectIngestError {
    /// A policy has a zero direct-rate target or an excessive boundary allowance.
    InvalidPolicy,
    /// The vote belongs to another immutable content item.
    WrongContent,
    /// The vote belongs to another UTC day.
    WrongDay,
    /// The membership view routes to another content item.
    WrongMembership,
    /// An older authority membership was supplied while a vote is pending.
    StaleMembership,
    /// The authority set changed without incrementing its membership generation.
    MembershipGenerationConflict,
    /// The daily bucket identity does not match the content and UTC day.
    InvalidVoteId,
    /// The vote is outside the configured boundary/skew acceptance interval.
    VoteOutsideAcceptanceWindow,
    /// The daily epoch is finalized and cannot accept additional votes.
    EpochFinalized,
    /// A timestamp or rate counter exceeded its representable range.
    TimeOutOfRange,
    /// The per-minute delivery counter overflowed.
    RateCounterOverflow,
    /// A client acknowledgement does not match its outstanding vote.
    UnexpectedAcknowledgement,
    /// The encoded authority state exceeds the Phase 7 component limit.
    StateTooLarge,
    /// The encoded authority state is malformed, noncanonical, or unsupported.
    InvalidStateEncoding,
    /// The nested client sketch could not be decoded.
    Sketch(SketchDecodeError),
}

impl fmt::Display for DirectIngestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy => formatter.write_str(
                "direct-ingest rate target must be nonzero and combined boundary allowances must not exceed one UTC day",
            ),
            Self::WrongContent => formatter.write_str("vote belongs to another content item"),
            Self::WrongDay => formatter.write_str("vote belongs to another UTC day"),
            Self::WrongMembership => {
                formatter.write_str("authority membership does not route to this content")
            }
            Self::StaleMembership => {
                formatter.write_str("authority membership generation is stale")
            }
            Self::MembershipGenerationConflict => {
                formatter.write_str("authority membership changed without a new generation")
            }
            Self::InvalidVoteId => formatter.write_str("vote has an invalid daily bucket identity"),
            Self::VoteOutsideAcceptanceWindow => {
                formatter.write_str("vote is outside its UTC-day acceptance window")
            }
            Self::EpochFinalized => formatter.write_str("daily popularity epoch is finalized"),
            Self::TimeOutOfRange => formatter.write_str("direct-ingest time is out of range"),
            Self::RateCounterOverflow => {
                formatter.write_str("direct-ingest rate counter overflowed")
            }
            Self::UnexpectedAcknowledgement => {
                formatter.write_str("acknowledgement does not match the pending vote")
            }
            Self::StateTooLarge => {
                formatter.write_str("direct-ingest state exceeds its size limit")
            }
            Self::InvalidStateEncoding => {
                formatter.write_str("invalid direct-ingest state encoding")
            }
            Self::Sketch(error) => write!(formatter, "invalid client sketch: {error}"),
        }
    }
}

impl std::error::Error for DirectIngestError {}

#[cfg(test)]
mod tests;
