//! Deterministic authority selection and pure replicated-state handling.

use populus_crypto::{
    AuthorityKeypair, PublicKeyAlgorithm, authority_id, validate_ed25519_public_key, verify_ed25519,
};
use populus_types::{AuthorityId, Epoch, NodeId, RoutingKey, XorDistance};
use std::collections::BTreeSet;

/// Number of authorities selected for a routing key.
pub const AUTHORITY_COUNT: usize = 4;

/// Maximum size of each opaque state component retained for a later protocol phase.
pub const MAX_STATE_COMPONENT_BYTES: usize = 1_048_576;

const STATE_DOMAIN: &[u8] = b"populus/authority-state/v1";
const SIGNATURE_DOMAIN: &[u8] = b"populus/authority-state-signature/v1";
const REQUEST_DOMAIN: &[u8] = b"populus/authority-state-request/v1";

/// The authority's current popularity-ingest mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityMode {
    /// Votes are accepted directly by the authority cluster.
    Direct = 0,
    /// Votes are accepted through a delegated ingest descriptor.
    Delegated = 1,
}

/// Public identity information required to select and authenticate an authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuthorityMember {
    node_id: NodeId,
    authority_id: AuthorityId,
    public_key: [u8; 32],
}

impl AuthorityMember {
    /// Creates a member from its Populus routing position and Ed25519 public key.
    ///
    /// The authority identifier is derived from the key under its separate
    /// `populus/authority/v1` domain.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidPublicKey`] if the key is not a valid
    /// Ed25519 public key.
    pub fn new(node_id: NodeId, public_key: [u8; 32]) -> Result<Self, AuthorityError> {
        validate_ed25519_public_key(&public_key).map_err(|_| AuthorityError::InvalidPublicKey)?;
        let authority_id = authority_id(PublicKeyAlgorithm::Ed25519, &public_key)
            .map_err(|_| AuthorityError::InvalidPublicKey)?;
        Ok(Self {
            node_id,
            authority_id,
            public_key,
        })
    }

    /// Returns this member's Populus DHT position.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns this member's authority signing-key identity.
    #[must_use]
    pub const fn authority_id(&self) -> AuthorityId {
        self.authority_id
    }

    /// Returns this member's Ed25519 public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

/// Versioned, ordered membership for one authority cluster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipView {
    routing_key: RoutingKey,
    generation: u64,
    members: Vec<AuthorityMember>,
}

impl MembershipView {
    /// Creates a membership view with exactly four unique members.
    ///
    /// The order is significant and should be the XOR-distance order returned
    /// by [`select_authorities`].
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidMembership`] unless four members are
    /// supplied and [`AuthorityError::DuplicateMember`] for repeated identities.
    pub fn new(
        routing_key: RoutingKey,
        generation: u64,
        members: Vec<AuthorityMember>,
    ) -> Result<Self, AuthorityError> {
        if members.len() != AUTHORITY_COUNT {
            return Err(AuthorityError::InvalidMembership);
        }
        let mut node_ids = BTreeSet::new();
        let mut authority_ids = BTreeSet::new();
        for member in &members {
            if !node_ids.insert(member.node_id) || !authority_ids.insert(member.authority_id) {
                return Err(AuthorityError::DuplicateMember);
            }
        }
        if select_authorities(&routing_key, &members)? != members {
            return Err(AuthorityError::NonCanonicalMembership);
        }
        Ok(Self {
            routing_key,
            generation,
            members,
        })
    }

    /// Returns the routing key whose neighborhood this view represents.
    #[must_use]
    pub const fn routing_key(&self) -> RoutingKey {
        self.routing_key
    }

    /// Returns the membership generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns members in their canonical, XOR-distance order.
    #[must_use]
    pub fn members(&self) -> &[AuthorityMember] {
        &self.members
    }

    /// Finds a member by its authority signing-key identity.
    #[must_use]
    pub fn member(&self, authority_id: AuthorityId) -> Option<&AuthorityMember> {
        self.members
            .iter()
            .find(|member| member.authority_id == authority_id)
    }
}

/// Selects up to the four closest unique known members to a routing key.
///
/// The function only ranks supplied contacts; it does not claim that the
/// neighborhood is complete. Equal XOR distances are ordered by `NodeId`.
///
/// # Errors
///
/// Returns [`AuthorityError::DuplicateMember`] if known contacts repeat a
/// `NodeId` or authority identity.
pub fn select_authorities(
    routing_key: &RoutingKey,
    known_members: &[AuthorityMember],
) -> Result<Vec<AuthorityMember>, AuthorityError> {
    let mut node_ids = BTreeSet::new();
    let mut authority_ids = BTreeSet::new();
    for member in known_members {
        if !node_ids.insert(member.node_id) || !authority_ids.insert(member.authority_id) {
            return Err(AuthorityError::DuplicateMember);
        }
    }
    let mut candidates: Vec<_> = known_members
        .iter()
        .copied()
        .map(|member| RankedMember {
            distance: XorDistance::between_node_and_key(&member.node_id, routing_key),
            member,
        })
        .collect();
    candidates.sort_unstable();
    Ok(candidates
        .into_iter()
        .take(AUTHORITY_COUNT)
        .map(|candidate| candidate.member)
        .collect())
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct RankedMember {
    distance: XorDistance,
    member: AuthorityMember,
}

/// Opaque subsystem snapshots included in the signed authority state.
///
/// Their internal formats are owned by later protocol phases. Phase 7 carries
/// and authenticates them without interpreting those formats.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuthorityComponents {
    /// Delegation descriptor; empty in direct mode and nonempty in delegated mode.
    pub delegation_descriptor: Vec<u8>,
    /// Rate-controller state.
    pub rate_state: Vec<u8>,
    /// Daily popularity sketch state.
    pub daily_popularity_state: Vec<u8>,
    /// Association aggregation summary.
    pub association_summary: Vec<u8>,
    /// Tag reporting state.
    pub tag_reporting_state: Vec<u8>,
}

/// Minimal replicated state for one routing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityState {
    routing_key: RoutingKey,
    epoch: Epoch,
    membership_view: MembershipView,
    mode: AuthorityMode,
    components: AuthorityComponents,
    sequence: u64,
}

impl AuthorityState {
    /// Creates an empty direct-mode state at the supplied epoch and sequence.
    #[must_use]
    pub fn new(
        routing_key: RoutingKey,
        epoch: Epoch,
        membership_view: MembershipView,
        sequence: u64,
    ) -> Self {
        Self {
            routing_key,
            epoch,
            membership_view,
            mode: AuthorityMode::Direct,
            components: AuthorityComponents::default(),
            sequence,
        }
    }

    /// Replaces the state components after validating mode and size constraints.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidModeDescriptor`] if direct mode has a
    /// descriptor or delegated mode lacks one, and
    /// [`AuthorityError::StateComponentTooLarge`] for oversized component data.
    pub fn with_components(
        mut self,
        mode: AuthorityMode,
        components: AuthorityComponents,
    ) -> Result<Self, AuthorityError> {
        validate_components(mode, &components)?;
        self.mode = mode;
        self.components = components;
        Ok(self)
    }

    /// Returns this state's routing key.
    #[must_use]
    pub const fn routing_key(&self) -> RoutingKey {
        self.routing_key
    }

    /// Returns this state's daily popularity epoch.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns this state's versioned membership.
    #[must_use]
    pub const fn membership_view(&self) -> &MembershipView {
        &self.membership_view
    }

    /// Returns the current mode.
    #[must_use]
    pub const fn mode(&self) -> AuthorityMode {
        self.mode
    }

    /// Returns the subsystem snapshots.
    #[must_use]
    pub const fn components(&self) -> &AuthorityComponents {
        &self.components
    }

    /// Returns the monotonically increasing state sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Produces the deterministic v1 encoding used for signatures.
    ///
    /// # Errors
    ///
    /// Returns an error if state component bounds or mode constraints fail.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AuthorityError> {
        validate_components(self.mode, &self.components)?;
        if self.membership_view.routing_key != self.routing_key {
            return Err(AuthorityError::RoutingKeyMismatch);
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(STATE_DOMAIN);
        bytes.extend_from_slice(self.routing_key.as_bytes());
        bytes.extend_from_slice(&self.epoch.to_bytes());
        bytes.extend_from_slice(&self.sequence.to_be_bytes());
        bytes.extend_from_slice(&self.membership_view.generation.to_be_bytes());
        bytes.push(self.mode as u8);
        bytes.push(
            u8::try_from(self.membership_view.members.len())
                .map_err(|_| AuthorityError::InvalidMembership)?,
        );
        for member in &self.membership_view.members {
            bytes.extend_from_slice(member.node_id.as_bytes());
            bytes.extend_from_slice(member.authority_id.as_bytes());
            bytes.extend_from_slice(&member.public_key);
        }
        append_component(&mut bytes, &self.components.delegation_descriptor)?;
        append_component(&mut bytes, &self.components.rate_state)?;
        append_component(&mut bytes, &self.components.daily_popularity_state)?;
        append_component(&mut bytes, &self.components.association_summary)?;
        append_component(&mut bytes, &self.components.tag_reporting_state)?;
        Ok(bytes)
    }
}

fn validate_components(
    mode: AuthorityMode,
    components: &AuthorityComponents,
) -> Result<(), AuthorityError> {
    match (mode, components.delegation_descriptor.is_empty()) {
        (AuthorityMode::Direct, false) | (AuthorityMode::Delegated, true) => {
            return Err(AuthorityError::InvalidModeDescriptor);
        }
        (AuthorityMode::Direct, true) | (AuthorityMode::Delegated, false) => {}
    }
    for component in [
        &components.delegation_descriptor,
        &components.rate_state,
        &components.daily_popularity_state,
        &components.association_summary,
        &components.tag_reporting_state,
    ] {
        if component.len() > MAX_STATE_COMPONENT_BYTES {
            return Err(AuthorityError::StateComponentTooLarge);
        }
    }
    Ok(())
}

fn append_component(bytes: &mut Vec<u8>, component: &[u8]) -> Result<(), AuthorityError> {
    let length =
        u32::try_from(component.len()).map_err(|_| AuthorityError::StateComponentTooLarge)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(component);
    Ok(())
}

/// A signed request for a peer's latest state for one routing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedStateRequest {
    routing_key: RoutingKey,
    membership_generation: u64,
    request_sequence: u64,
    signer: AuthorityId,
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl SignedStateRequest {
    /// Signs a state request as a member of the supplied membership view.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::NotAMember`] if the signing key is not in the
    /// view.
    pub fn sign(
        routing_key: RoutingKey,
        membership: &MembershipView,
        request_sequence: u64,
        signer: &AuthorityKeypair,
    ) -> Result<Self, AuthorityError> {
        if membership.routing_key != routing_key {
            return Err(AuthorityError::RoutingKeyMismatch);
        }
        let signer_id = signer.authority_id();
        let member = membership
            .member(signer_id)
            .ok_or(AuthorityError::NotAMember)?;
        let public_key = signer.public_key();
        if member.public_key != public_key {
            return Err(AuthorityError::NotAMember);
        }
        let mut request = Self {
            routing_key,
            membership_generation: membership.generation,
            request_sequence,
            signer: signer_id,
            public_key,
            signature: [0; 64],
        };
        request.signature = signer.sign(&request.message());
        Ok(request)
    }

    /// Returns the request routing key.
    #[must_use]
    pub const fn routing_key(&self) -> RoutingKey {
        self.routing_key
    }

    /// Returns the request's monotonic sequence.
    #[must_use]
    pub const fn request_sequence(&self) -> u64 {
        self.request_sequence
    }

    /// Returns the request signer.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }

    /// Verifies the request against the expected membership view.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidSignature`] if its signer, view, or
    /// signature does not match.
    pub fn verify(&self, membership: &MembershipView) -> Result<(), AuthorityError> {
        let member = membership
            .member(self.signer)
            .ok_or(AuthorityError::InvalidSignature)?;
        if membership.routing_key != self.routing_key
            || membership.generation != self.membership_generation
            || member.public_key != self.public_key
            || authority_id(PublicKeyAlgorithm::Ed25519, &self.public_key)
                .map_err(|_| AuthorityError::InvalidSignature)?
                != self.signer
        {
            return Err(AuthorityError::InvalidSignature);
        }
        verify_ed25519(&self.public_key, &self.message(), &self.signature)
            .map_err(|_| AuthorityError::InvalidSignature)
    }

    fn message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(REQUEST_DOMAIN.len() + 32 + 32 + 8 + 8);
        message.extend_from_slice(REQUEST_DOMAIN);
        message.extend_from_slice(self.signer.as_bytes());
        message.extend_from_slice(self.routing_key.as_bytes());
        message.extend_from_slice(&self.membership_generation.to_be_bytes());
        message.extend_from_slice(&self.request_sequence.to_be_bytes());
        message
    }
}

/// Per-cluster replay guard for signed state requests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestSequenceTracker {
    latest: std::collections::BTreeMap<(AuthorityId, RoutingKey, u64), u64>,
}

impl RequestSequenceTracker {
    /// Accepts a request only if its signature is valid and its sequence advances.
    ///
    /// Sequences are tracked independently per requester, routing key, and
    /// membership generation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidSignature`] for unauthenticated or
    /// wrong-view requests and [`AuthorityError::StaleRequest`] for a replay
    /// or sequence rollback.
    pub fn accept(
        &mut self,
        request: &SignedStateRequest,
        membership: &MembershipView,
    ) -> Result<(), AuthorityError> {
        request.verify(membership)?;
        let key = (
            request.signer,
            request.routing_key,
            request.membership_generation,
        );
        if self
            .latest
            .get(&key)
            .is_some_and(|latest| request.request_sequence <= *latest)
        {
            return Err(AuthorityError::StaleRequest);
        }
        self.latest.insert(key, request.request_sequence);
        Ok(())
    }
}

/// A state snapshot signed by one member of its embedded membership view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAuthorityState {
    signer: AuthorityId,
    public_key: [u8; 32],
    state: AuthorityState,
    signature: [u8; 64],
}

impl SignedAuthorityState {
    /// Signs an authority state with a member key.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::NotAMember`] if the signing key is not in the
    /// state's membership view, or a state validation error.
    pub fn sign(state: AuthorityState, signer: &AuthorityKeypair) -> Result<Self, AuthorityError> {
        let signer_id = signer.authority_id();
        let member = state
            .membership_view
            .member(signer_id)
            .ok_or(AuthorityError::NotAMember)?;
        let public_key = signer.public_key();
        if member.public_key != public_key {
            return Err(AuthorityError::NotAMember);
        }
        let message = signed_state_message(signer_id, &state)?;
        Ok(Self {
            signer: signer_id,
            public_key,
            state,
            signature: signer.sign(&message),
        })
    }

    /// Returns the signer identity.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }

    /// Returns the signed state.
    #[must_use]
    pub const fn state(&self) -> &AuthorityState {
        &self.state
    }

    /// Verifies the signer identity, membership, and Ed25519 signature.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::InvalidSignature`] if any authentication check
    /// fails or the signer is not an exact member of the embedded view.
    pub fn verify(&self) -> Result<(), AuthorityError> {
        let member = self
            .state
            .membership_view
            .member(self.signer)
            .ok_or(AuthorityError::InvalidSignature)?;
        if member.public_key != self.public_key
            || authority_id(PublicKeyAlgorithm::Ed25519, &self.public_key)
                .map_err(|_| AuthorityError::InvalidSignature)?
                != self.signer
        {
            return Err(AuthorityError::InvalidSignature);
        }
        let message = signed_state_message(self.signer, &self.state)?;
        verify_ed25519(&self.public_key, &message, &self.signature)
            .map_err(|_| AuthorityError::InvalidSignature)
    }
}

fn signed_state_message(
    signer: AuthorityId,
    state: &AuthorityState,
) -> Result<Vec<u8>, AuthorityError> {
    let state_bytes = state.canonical_bytes()?;
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 32 + state_bytes.len());
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.extend_from_slice(signer.as_bytes());
    message.extend_from_slice(&state_bytes);
    Ok(message)
}

/// A state supported by a strict majority of the expected responders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuorumState {
    state: AuthorityState,
    matching_signers: Vec<AuthorityId>,
    expected_membership: MembershipView,
    rejected_responses: Vec<RejectedStateResponse>,
}

impl QuorumState {
    /// Returns the state supported by the quorum.
    #[must_use]
    pub const fn state(&self) -> &AuthorityState {
        &self.state
    }

    /// Returns the authorities that signed the matching state.
    #[must_use]
    pub fn matching_signers(&self) -> &[AuthorityId] {
        &self.matching_signers
    }

    /// Returns malformed, duplicate, or unexpected responses excluded from the quorum.
    #[must_use]
    pub fn rejected_responses(&self) -> &[RejectedStateResponse] {
        &self.rejected_responses
    }
}

/// An invalid response excluded while resolving a state quorum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RejectedStateResponse {
    signer: AuthorityId,
    reason: AuthorityError,
}

impl RejectedStateResponse {
    /// Returns the claimed signer identity.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }

    /// Returns why the response did not count toward a quorum.
    #[must_use]
    pub const fn reason(&self) -> AuthorityError {
        self.reason
    }
}

/// Result of comparing signed state views during initialization or recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateResolution {
    /// A strict majority agreed on this exact state.
    Quorum(Box<QuorumState>),
    /// No state reached the required strict majority; rebuild instead of guessing.
    RecoveryNeeded {
        /// Number of responders supporting the most common state.
        best_matching: usize,
        /// Strict-majority threshold among expected responders.
        required: usize,
        /// Invalid or unexpected responses excluded from the comparison.
        rejected_responses: Vec<RejectedStateResponse>,
    },
}

/// Verifies state responses and selects a strict-majority matching snapshot.
///
/// Missing responses do not reduce the quorum threshold. For three expected
/// responders, two matching states initialize a replacement; for four,
/// three are required, so a 2-vs-2 partition enters recovery.
///
/// # Errors
///
/// Returns an error for an invalid expected responder set. Invalid, duplicate,
/// or unexpected individual responses are excluded and reported in the result,
/// so one bad response cannot suppress a valid quorum.
pub fn resolve_authority_state(
    expected_membership: &MembershipView,
    expected_signers: &[AuthorityId],
    responses: &[SignedAuthorityState],
) -> Result<StateResolution, AuthorityError> {
    if expected_signers.len() < AUTHORITY_COUNT - 1
        || expected_signers.len() > AUTHORITY_COUNT
        || expected_membership.members.len() != AUTHORITY_COUNT
    {
        return Err(AuthorityError::InvalidMembership);
    }
    let expected: BTreeSet<_> = expected_signers.iter().copied().collect();
    if expected.len() != expected_signers.len() {
        return Err(AuthorityError::DuplicateMember);
    }
    if expected
        .iter()
        .any(|signer| expected_membership.member(*signer).is_none())
    {
        return Err(AuthorityError::UnknownResponder);
    }

    let required = expected_signers.len() / 2 + 1;
    let mut seen = BTreeSet::new();
    let mut groups: Vec<(AuthorityState, Vec<AuthorityId>)> = Vec::new();
    let mut rejected_responses = Vec::new();
    for response in responses {
        if !expected.contains(&response.signer) {
            rejected_responses.push(RejectedStateResponse {
                signer: response.signer,
                reason: AuthorityError::UnknownResponder,
            });
            continue;
        }
        if seen.contains(&response.signer) {
            rejected_responses.push(RejectedStateResponse {
                signer: response.signer,
                reason: AuthorityError::UnexpectedOrDuplicateResponse,
            });
            continue;
        }
        if let Err(reason) = response.verify() {
            rejected_responses.push(RejectedStateResponse {
                signer: response.signer,
                reason,
            });
            continue;
        }
        if response.state.routing_key != expected_membership.routing_key {
            rejected_responses.push(RejectedStateResponse {
                signer: response.signer,
                reason: AuthorityError::RoutingKeyMismatch,
            });
            continue;
        }
        let expected_member = expected_membership
            .member(response.signer)
            .ok_or(AuthorityError::UnknownResponder)?;
        if expected_member.public_key != response.public_key {
            rejected_responses.push(RejectedStateResponse {
                signer: response.signer,
                reason: AuthorityError::InvalidSignature,
            });
            continue;
        }
        seen.insert(response.signer);
        if let Some((_, signers)) = groups
            .iter_mut()
            .find(|(state, _)| state == &response.state)
        {
            signers.push(response.signer);
        } else {
            groups.push((response.state.clone(), vec![response.signer]));
        }
    }

    let best = groups.iter().max_by_key(|(_, signers)| signers.len());
    if let Some((state, signers)) = best
        && signers.len() >= required
    {
        return Ok(StateResolution::Quorum(Box::new(QuorumState {
            state: state.clone(),
            matching_signers: signers.clone(),
            expected_membership: expected_membership.clone(),
            rejected_responses,
        })));
    }
    Ok(StateResolution::RecoveryNeeded {
        best_matching: best.map_or(0, |(_, signers)| signers.len()),
        required,
        rejected_responses,
    })
}

/// A local committed view that only advances from a verified quorum result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityReplica {
    state: AuthorityState,
}

impl AuthorityReplica {
    /// Creates a replica from trusted genesis or locally restored state.
    ///
    /// # Errors
    ///
    /// Returns an error if the initial state's mode, components, or membership
    /// binding is invalid.
    pub fn new(state: AuthorityState) -> Result<Self, AuthorityError> {
        state.canonical_bytes()?;
        Ok(Self { state })
    }

    /// Initializes a replacement replica from a verified state quorum.
    #[must_use]
    pub fn from_quorum(quorum: QuorumState) -> Self {
        Self {
            state: quorum.state,
        }
    }

    /// Returns the replica's committed state.
    #[must_use]
    pub const fn state(&self) -> &AuthorityState {
        &self.state
    }

    /// Applies a quorum state unless it is a replay or a version rollback.
    ///
    /// Sequence numbers are monotonic across epochs. A state with the same
    /// version but different content is rejected rather than overwritten.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::StaleState`] for epoch/sequence rollback and
    /// [`AuthorityError::ConflictingVersion`] for contradictory state at the
    /// current version.
    pub fn apply_quorum(&mut self, quorum: QuorumState) -> Result<ApplyOutcome, AuthorityError> {
        let candidate = quorum.state;
        if quorum.expected_membership != self.state.membership_view {
            return Err(AuthorityError::MembershipMismatch);
        }
        if candidate.routing_key != self.state.routing_key {
            return Err(AuthorityError::RoutingKeyMismatch);
        }
        if candidate.epoch < self.state.epoch
            || candidate.sequence < self.state.sequence
            || candidate.membership_view.generation < self.state.membership_view.generation
        {
            return Err(AuthorityError::StaleState);
        }
        if candidate.sequence == self.state.sequence {
            if candidate == self.state {
                return Ok(ApplyOutcome::Duplicate);
            }
            return Err(AuthorityError::ConflictingVersion);
        }
        if candidate.membership_view != self.state.membership_view
            && candidate.membership_view.generation <= self.state.membership_view.generation
        {
            return Err(AuthorityError::MembershipMismatch);
        }
        self.state = candidate;
        Ok(ApplyOutcome::Applied)
    }
}

/// Outcome from applying a quorum-backed state snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The replica advanced to a newer state.
    Applied,
    /// The exact committed state was received again.
    Duplicate,
}

/// Cryptographic evidence that one authority signed incompatible states at
/// the same routing key, epoch, and sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationProof {
    first: SignedAuthorityState,
    second: SignedAuthorityState,
}

impl EquivocationProof {
    /// Constructs proof from two contradictory signed statements.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::NotEquivocation`] unless both valid
    /// signatures are from the same authority and version but contain
    /// different states.
    pub fn new(
        first: SignedAuthorityState,
        second: SignedAuthorityState,
    ) -> Result<Self, AuthorityError> {
        let proof = Self { first, second };
        proof.verify()?;
        Ok(proof)
    }

    /// Returns the equivocating authority identity.
    #[must_use]
    pub const fn authority(&self) -> AuthorityId {
        self.first.signer
    }

    /// Verifies both signatures and the contradiction conditions.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityError::NotEquivocation`] if the statements do not
    /// prove same-version equivocation, or [`AuthorityError::InvalidSignature`]
    /// if either signature fails.
    pub fn verify(&self) -> Result<(), AuthorityError> {
        self.first.verify()?;
        self.second.verify()?;
        let first = &self.first.state;
        let second = &self.second.state;
        if self.first.signer != self.second.signer
            || first.routing_key != second.routing_key
            || first.epoch != second.epoch
            || first.sequence != second.sequence
            || first == second
        {
            return Err(AuthorityError::NotEquivocation);
        }
        Ok(())
    }
}

/// Errors raised while validating authority membership or replicated state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityError {
    /// The supplied membership or expected responder set does not match the
    /// four-authority protocol.
    InvalidMembership,
    /// A `NodeId` or authority identity appears more than once.
    DuplicateMember,
    /// Membership entries are not ordered by the routing key's XOR distance.
    NonCanonicalMembership,
    /// A signer key is not a valid Ed25519 public key.
    InvalidPublicKey,
    /// A signing key is not represented by the expected membership.
    NotAMember,
    /// A response signer is not an expected cluster member.
    UnknownResponder,
    /// A signed state or membership belongs to a different routing key.
    RoutingKeyMismatch,
    /// A request replayed or rolled back its sequence.
    StaleRequest,
    /// A response is duplicated or was not requested.
    UnexpectedOrDuplicateResponse,
    /// A signature or its identity binding is invalid.
    InvalidSignature,
    /// Direct/delegated mode does not match the descriptor presence.
    InvalidModeDescriptor,
    /// A replicated state component exceeds its size bound.
    StateComponentTooLarge,
    /// A state transition was not based on the replica's current membership.
    MembershipMismatch,
    /// A committed epoch or sequence was rolled back.
    StaleState,
    /// A different state reused the currently committed sequence.
    ConflictingVersion,
    /// Two statements do not establish equivocation.
    NotEquivocation,
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidMembership => "invalid authority membership",
            Self::DuplicateMember => "duplicate authority member",
            Self::NonCanonicalMembership => {
                "authority membership is not in canonical distance order"
            }
            Self::InvalidPublicKey => "invalid authority public key",
            Self::NotAMember => "signer is not in the authority membership",
            Self::UnknownResponder => "unknown authority state responder",
            Self::StaleRequest => "authority state request is stale or replayed",
            Self::UnexpectedOrDuplicateResponse => {
                "unexpected or duplicate authority state response"
            }
            Self::InvalidSignature => "invalid authority state signature",
            Self::InvalidModeDescriptor => "authority mode and delegation descriptor disagree",
            Self::StateComponentTooLarge => "authority state component exceeds its size limit",
            Self::RoutingKeyMismatch => "authority state belongs to another routing key",
            Self::MembershipMismatch => "authority state transition uses a different membership",
            Self::StaleState => "authority state would roll back a committed version",
            Self::ConflictingVersion => "conflicting authority state at the current version",
            Self::NotEquivocation => "statements do not prove authority equivocation",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for AuthorityError {}

#[cfg(test)]
mod tests;
