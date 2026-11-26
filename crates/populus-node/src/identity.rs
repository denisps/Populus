use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

use libp2p::PeerId;
use populus_crypto::node_id;
use populus_types::{NetworkIdentity, NodeId};

const MAX_TRACKED_IDENTITIES: usize = 64;
const MAX_OBSERVERS_PER_IDENTITY: usize = 64;
const DEFAULT_OBSERVATION_TTL_MS: u64 = 10 * 60 * 1000;
const DEFAULT_VERIFICATION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

/// Per-process limits and lifetimes for public identity discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityManagerConfig {
    /// Maximum simultaneously active logical `NodeId`s.
    pub max_active_nodes: usize,
    /// Lifetime of one externally observed endpoint.
    pub observation_ttl_ms: u64,
    /// Lifetime of one successful direct verification.
    pub verification_ttl_ms: u64,
    /// Independent observations required before verification may start.
    pub observation_quorum: usize,
    /// Independent direct verifiers required before activation.
    pub verification_quorum: usize,
}

impl Default for IdentityManagerConfig {
    fn default() -> Self {
        Self {
            max_active_nodes: 4,
            observation_ttl_ms: DEFAULT_OBSERVATION_TTL_MS,
            verification_ttl_ms: DEFAULT_VERIFICATION_TTL_MS,
            observation_quorum: 3,
            verification_quorum: 3,
        }
    }
}

/// Lifecycle state of one locally discovered network identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityLifecycle {
    /// No current observation has reached the configured agreement threshold.
    Unknown,
    /// Independent authenticated peers have agreed on this identity.
    Discovered,
    /// Fresh direct-reachability challenges are in progress.
    Verifying,
    /// The identity passed current local verification and arbitration policy.
    Active,
    /// Reachability or evidence is temporarily uncertain.
    Suspect,
    /// The identity is no longer advertised and is awaiting local removal.
    Retiring,
}

/// Errors returned by the bounded identity lifecycle manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityManagerError {
    /// The required observer nonce did not match the outstanding request.
    NonceMismatch,
    /// The observation came through a relay or other non-direct path.
    IndirectObservation,
    /// The observed IP address is not eligible under `NetworkIdentity` v1.
    IneligibleAddress,
    /// A configured bound or quorum is invalid.
    InvalidConfiguration,
    /// The bounded identity or observation table is full.
    ResourceLimit,
    /// The identity has not received enough independent observations.
    InsufficientObservations,
    /// A verification response did not match its current challenge.
    StaleChallenge,
    /// Verification did not demonstrate direct reachability and identity consistency.
    InvalidVerification,
    /// The identity has not received enough independent verifications.
    InsufficientVerifications,
    /// The process has reached its active logical-node limit.
    ActiveNodeLimit,
    /// The requested lifecycle transition is not valid.
    InvalidTransition,
}

impl std::fmt::Display for IdentityManagerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::NonceMismatch => "observation nonce mismatch",
            Self::IndirectObservation => "identity observation is not direct",
            Self::IneligibleAddress => "observed address is not an eligible network identity",
            Self::InvalidConfiguration => "invalid identity manager configuration",
            Self::ResourceLimit => "identity manager resource limit reached",
            Self::InsufficientObservations => "insufficient independent address observations",
            Self::StaleChallenge => "verification challenge is stale or unknown",
            Self::InvalidVerification => "identity verification did not meet requirements",
            Self::InsufficientVerifications => "insufficient independent verifications",
            Self::ActiveNodeLimit => "maximum active logical-node count reached",
            Self::InvalidTransition => "invalid identity lifecycle transition",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for IdentityManagerError {}

#[derive(Debug, Clone, Copy)]
struct Observation {
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Verification {
    expires_at_ms: u64,
}

#[derive(Debug, Clone, Copy)]
struct Challenge {
    nonce: [u8; 16],
    expires_at_ms: u64,
}

#[derive(Debug)]
struct ManagedIdentity {
    lifecycle: IdentityLifecycle,
    observers: HashMap<NodeId, Observation>,
    challenges: HashMap<NodeId, Challenge>,
    verifications: HashMap<NodeId, Verification>,
}

/// Continuous, bounded public-identity discovery and verification state.
pub struct IdentityManager {
    local_peer_id: PeerId,
    config: IdentityManagerConfig,
    identities: HashMap<NetworkIdentity, ManagedIdentity>,
}

impl IdentityManager {
    /// Creates an identity manager for one process.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidConfiguration`] for zero or
    /// internally inconsistent resource limits.
    pub fn new(
        local_peer_id: PeerId,
        config: IdentityManagerConfig,
    ) -> Result<Self, IdentityManagerError> {
        if config.max_active_nodes == 0
            || config.max_active_nodes > MAX_TRACKED_IDENTITIES
            || config.observation_ttl_ms == 0
            || config.verification_ttl_ms == 0
            || config.observation_quorum < 3
            || config.observation_quorum > MAX_OBSERVERS_PER_IDENTITY
            || config.verification_quorum < 3
            || config.verification_quorum > MAX_OBSERVERS_PER_IDENTITY
        {
            return Err(IdentityManagerError::InvalidConfiguration);
        }
        Ok(Self {
            local_peer_id,
            config,
            identities: HashMap::new(),
        })
    }

    /// Adds a direct observation from an already verified active `NodeId`,
    /// correlated to the outstanding nonce.
    ///
    /// Repeated observations from one `NodeId` count once. The caller must
    /// establish that this observer's current active binding is valid; this
    /// method deliberately does not infer that a `PeerId` is a `NodeId`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for stale/non-direct evidence, ineligible addresses,
    /// or exhausted bounds.
    pub fn observe(
        &mut self,
        observer: NodeId,
        expected_nonce: [u8; 16],
        response_nonce: [u8; 16],
        endpoint: SocketAddr,
        is_direct: bool,
        now_ms: u64,
    ) -> Result<IdentityLifecycle, IdentityManagerError> {
        self.expire(now_ms);
        if expected_nonce != response_nonce {
            return Err(IdentityManagerError::NonceMismatch);
        }
        if !is_direct {
            return Err(IdentityManagerError::IndirectObservation);
        }
        let identity = NetworkIdentity::from_ip(endpoint.ip())
            .map_err(|_| IdentityManagerError::IneligibleAddress)?;
        if !self.identities.contains_key(&identity)
            && self.identities.len() >= MAX_TRACKED_IDENTITIES
        {
            return Err(IdentityManagerError::ResourceLimit);
        }
        let state = self
            .identities
            .entry(identity)
            .or_insert_with(|| ManagedIdentity {
                lifecycle: IdentityLifecycle::Unknown,
                observers: HashMap::new(),
                challenges: HashMap::new(),
                verifications: HashMap::new(),
            });
        if state.lifecycle == IdentityLifecycle::Retiring {
            return Err(IdentityManagerError::InvalidTransition);
        }
        if !state.observers.contains_key(&observer)
            && state.observers.len() >= MAX_OBSERVERS_PER_IDENTITY
        {
            return Err(IdentityManagerError::ResourceLimit);
        }
        state.observers.insert(
            observer,
            Observation {
                expires_at_ms: now_ms.saturating_add(self.config.observation_ttl_ms),
            },
        );
        if state.observers.len() >= self.config.observation_quorum
            && matches!(state.lifecycle, IdentityLifecycle::Unknown)
        {
            state.lifecycle = IdentityLifecycle::Discovered;
        }
        Ok(state.lifecycle)
    }

    /// Advances identity expiration using caller-supplied time.
    ///
    /// This pure transition hook lets deterministic simulations exercise lease
    /// expiry without sleeping.
    pub fn advance(&mut self, now_ms: u64) {
        self.expire(now_ms);
    }

    /// Starts or refreshes one verifier's fresh direct-reachability challenge.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InsufficientObservations`] if this is a
    /// new identity without enough independent observations.
    pub fn begin_verification(
        &mut self,
        identity: NetworkIdentity,
        verifier: NodeId,
        challenge: [u8; 16],
        now_ms: u64,
    ) -> Result<(), IdentityManagerError> {
        self.expire(now_ms);
        let state = self
            .identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::InsufficientObservations)?;
        if state.lifecycle == IdentityLifecycle::Unknown
            || state.lifecycle == IdentityLifecycle::Retiring
        {
            return Err(IdentityManagerError::InsufficientObservations);
        }
        if !state.challenges.contains_key(&verifier)
            && state.challenges.len() >= MAX_OBSERVERS_PER_IDENTITY
        {
            return Err(IdentityManagerError::ResourceLimit);
        }
        state.lifecycle = IdentityLifecycle::Verifying;
        state.challenges.insert(
            verifier,
            Challenge {
                nonce: challenge,
                expires_at_ms: now_ms.saturating_add(self.config.verification_ttl_ms),
            },
        );
        Ok(())
    }

    /// Records a successful, authenticated direct dial-back response.
    ///
    /// The caller must derive `verifier` from an already eligible active DHT
    /// contact and must only call this after the libp2p-authenticated response
    /// matches `local_peer_id`, the normalized identity, and the fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::StaleChallenge`] for unknown or mismatched
    /// challenges and [`IdentityManagerError::InvalidVerification`] when any
    /// required direct-reachability check failed.
    #[allow(clippy::too_many_arguments)]
    pub fn record_verification(
        &mut self,
        identity: NetworkIdentity,
        verifier: NodeId,
        challenge: [u8; 16],
        authenticated_peer: PeerId,
        direct_reachable: bool,
        identity_matches: bool,
        valid_until_ms: u64,
        now_ms: u64,
    ) -> Result<(), IdentityManagerError> {
        self.expire(now_ms);
        let state = self
            .identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::StaleChallenge)?;
        let Some(expected) = state.challenges.remove(&verifier) else {
            return Err(IdentityManagerError::StaleChallenge);
        };
        if expected.nonce != challenge || expected.expires_at_ms <= now_ms {
            return Err(IdentityManagerError::StaleChallenge);
        }
        if authenticated_peer != self.local_peer_id
            || !direct_reachable
            || !identity_matches
            || valid_until_ms <= now_ms
        {
            return Err(IdentityManagerError::InvalidVerification);
        }
        state.verifications.insert(
            verifier,
            Verification {
                expires_at_ms: valid_until_ms
                    .min(now_ms.saturating_add(self.config.verification_ttl_ms)),
            },
        );
        Ok(())
    }

    /// Promotes a locally verified identity to Active.
    ///
    /// This local step does not replace distributed `NodeId` ownership arbitration;
    /// callers must obtain an accepted active binding before activating the
    /// corresponding logical DHT node.
    ///
    /// # Errors
    ///
    /// Returns a typed error if verification is insufficient or the active-node
    /// capacity is exhausted.
    pub fn activate(
        &mut self,
        identity: NetworkIdentity,
        now_ms: u64,
    ) -> Result<NodeId, IdentityManagerError> {
        self.expire(now_ms);
        let already_active = self.identities.get(&identity).is_some_and(|state| {
            matches!(
                state.lifecycle,
                IdentityLifecycle::Active | IdentityLifecycle::Suspect
            )
        });
        let active_count = self.active_count();
        let state = self
            .identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::InsufficientVerifications)?;
        if state.verifications.len() < self.config.verification_quorum {
            return Err(IdentityManagerError::InsufficientVerifications);
        }

        if !already_active && active_count >= self.config.max_active_nodes {
            return Err(IdentityManagerError::ActiveNodeLimit);
        }
        state.lifecycle = IdentityLifecycle::Active;
        Ok(node_id(&identity))
    }

    /// Activates a manifest identity after the genesis observation quorum is met.
    ///
    /// This is crate-private so only the signed-manifest runtime adapter can
    /// authorize the genesis transition.
    pub(crate) fn activate_manifest_member(
        &mut self,
        identity: NetworkIdentity,
        now_ms: u64,
    ) -> Result<NodeId, IdentityManagerError> {
        self.expire(now_ms);
        let already_active = self.identities.get(&identity).is_some_and(|state| {
            matches!(
                state.lifecycle,
                IdentityLifecycle::Active | IdentityLifecycle::Suspect
            )
        });
        if self
            .identities
            .get(&identity)
            .is_none_or(|state| state.lifecycle != IdentityLifecycle::Discovered)
        {
            return Err(IdentityManagerError::InsufficientObservations);
        }
        if !already_active && self.active_count() >= self.config.max_active_nodes {
            return Err(IdentityManagerError::ActiveNodeLimit);
        }
        self.identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::InsufficientObservations)?
            .lifecycle = IdentityLifecycle::Active;
        Ok(node_id(&identity))
    }

    /// Test-only bypass for isolated unit and localhost fixtures.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::ActiveNodeLimit`] when local capacity is
    /// exhausted, or [`IdentityManagerError::ResourceLimit`] when tracking is
    /// full.
    #[cfg(test)]
    pub fn activate_genesis(
        &mut self,
        identity: NetworkIdentity,
    ) -> Result<NodeId, IdentityManagerError> {
        if !self.identities.contains_key(&identity)
            && self.identities.len() >= MAX_TRACKED_IDENTITIES
        {
            return Err(IdentityManagerError::ResourceLimit);
        }
        let already_active = self.identities.get(&identity).is_some_and(|state| {
            matches!(
                state.lifecycle,
                IdentityLifecycle::Active | IdentityLifecycle::Suspect
            )
        });
        let active_count = self.active_count();
        if !already_active && active_count >= self.config.max_active_nodes {
            return Err(IdentityManagerError::ActiveNodeLimit);
        }
        let state = self
            .identities
            .entry(identity)
            .or_insert_with(|| ManagedIdentity {
                lifecycle: IdentityLifecycle::Active,
                observers: HashMap::new(),
                challenges: HashMap::new(),
                verifications: HashMap::new(),
            });
        state.lifecycle = IdentityLifecycle::Active;
        Ok(node_id(&identity))
    }

    /// Marks an active identity Suspect without immediately removing it.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidTransition`] unless it is Active.
    pub fn mark_suspect(&mut self, identity: NetworkIdentity) -> Result<(), IdentityManagerError> {
        let state = self
            .identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::InvalidTransition)?;
        if state.lifecycle != IdentityLifecycle::Active {
            return Err(IdentityManagerError::InvalidTransition);
        }
        state.lifecycle = IdentityLifecycle::Suspect;
        Ok(())
    }

    /// Restores a Suspect identity after its reachability and evidence recover.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidTransition`] unless it is Suspect.
    pub fn restore(
        &mut self,
        identity: NetworkIdentity,
        now_ms: u64,
    ) -> Result<(), IdentityManagerError> {
        self.expire(now_ms);
        let state = self
            .identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::InvalidTransition)?;
        if state.lifecycle != IdentityLifecycle::Suspect {
            return Err(IdentityManagerError::InvalidTransition);
        }
        if state.verifications.len() < self.config.verification_quorum {
            return Err(IdentityManagerError::InsufficientVerifications);
        }
        state.lifecycle = IdentityLifecycle::Active;
        Ok(())
    }

    /// Stops advertising an identity while preserving it for graceful handoff.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidTransition`] unless it is Active
    /// or Suspect.
    pub fn retire(&mut self, identity: NetworkIdentity) -> Result<(), IdentityManagerError> {
        let state = self
            .identities
            .get_mut(&identity)
            .ok_or(IdentityManagerError::InvalidTransition)?;
        if !matches!(
            state.lifecycle,
            IdentityLifecycle::Active | IdentityLifecycle::Suspect
        ) {
            return Err(IdentityManagerError::InvalidTransition);
        }
        state.lifecycle = IdentityLifecycle::Retiring;
        Ok(())
    }

    /// Removes an identity after it is no longer active.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidTransition`] while it is active.
    pub fn remove(&mut self, identity: NetworkIdentity) -> Result<(), IdentityManagerError> {
        let state = self
            .identities
            .get(&identity)
            .ok_or(IdentityManagerError::InvalidTransition)?;
        if matches!(
            state.lifecycle,
            IdentityLifecycle::Active | IdentityLifecycle::Suspect
        ) {
            return Err(IdentityManagerError::InvalidTransition);
        }
        self.identities.remove(&identity);
        Ok(())
    }

    /// Returns the current state of a normalized identity.
    #[must_use]
    pub fn lifecycle(&self, identity: &NetworkIdentity) -> IdentityLifecycle {
        self.identities
            .get(identity)
            .map_or(IdentityLifecycle::Unknown, |state| state.lifecycle)
    }

    /// Returns the number of active logical identities.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.identities
            .values()
            .filter(|state| {
                matches!(
                    state.lifecycle,
                    IdentityLifecycle::Active | IdentityLifecycle::Suspect
                )
            })
            .count()
    }

    /// Returns currently active `NodeId`s in deterministic order.
    #[must_use]
    pub fn active_node_ids(&self) -> Vec<NodeId> {
        let mut active: Vec<_> = self
            .identities
            .iter()
            .filter(|(_, state)| state.lifecycle == IdentityLifecycle::Active)
            .map(|(identity, _)| node_id(identity))
            .collect();
        active.sort_unstable();
        active
    }

    fn expire(&mut self, now_ms: u64) {
        for state in self.identities.values_mut() {
            state
                .observers
                .retain(|_, observation| observation.expires_at_ms > now_ms);
            state
                .verifications
                .retain(|_, verification| verification.expires_at_ms > now_ms);
            state
                .challenges
                .retain(|_, challenge| challenge.expires_at_ms > now_ms);
            let discovery_expired = state.lifecycle == IdentityLifecycle::Discovered
                && state.observers.len() < self.config.observation_quorum;
            let verification_incomplete = state.lifecycle == IdentityLifecycle::Verifying
                && state.verifications.len() < self.config.verification_quorum
                && state.observers.len() < self.config.observation_quorum;
            if discovery_expired || verification_incomplete {
                state.lifecycle = IdentityLifecycle::Unknown;
            }
        }
        for state in self.identities.values_mut() {
            if matches!(
                state.lifecycle,
                IdentityLifecycle::Active | IdentityLifecycle::Suspect
            ) && state.verifications.len() < self.config.verification_quorum
            {
                state.lifecycle = IdentityLifecycle::Suspect;
            }
        }
        self.identities.retain(|_, state| {
            !matches!(
                state.lifecycle,
                IdentityLifecycle::Unknown | IdentityLifecycle::Retiring
            ) || !state.observers.is_empty()
                || !state.verifications.is_empty()
        });
    }
}

/// A bounded record of authenticated, time-limited observations.
#[derive(Clone, PartialEq, Eq)]
pub struct ObservationEvidence {
    /// Already-verified active Populus `NodeId` of the observer.
    pub observer_node_id: NodeId,
    /// Address seen on the direct connection.
    pub endpoint: SocketAddr,
    /// Expiration of this evidence.
    pub expires_at_ms: u64,
}

impl std::fmt::Debug for ObservationEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservationEvidence")
            .field("observer_node_id", &self.observer_node_id)
            .field("endpoint", &self.endpoint)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

/// Verifies that an observation set has the required distinct active `NodeId`s.
///
/// This only deduplicates protocol identities; it does not establish distinct
/// physical operators or any other real-world independence property.
#[must_use]
pub fn has_independent_observers(
    evidence: &[ObservationEvidence],
    identity: NetworkIdentity,
    now_ms: u64,
    required: usize,
) -> bool {
    let distinct = evidence
        .iter()
        .filter(|item| {
            item.expires_at_ms > now_ms
                && NetworkIdentity::from_ip(item.endpoint.ip()).ok() == Some(identity)
        })
        .map(|item| item.observer_node_id)
        .collect::<HashSet<_>>();
    distinct.len() >= required
}

#[cfg(test)]
mod tests {
    #![allow(clippy::cast_possible_truncation, clippy::expect_used)]

    use std::net::SocketAddr;

    use libp2p::identity::Keypair;
    use populus_types::{NetworkIdentity, NodeId};

    use super::{
        IdentityLifecycle, IdentityManager, IdentityManagerConfig, IdentityManagerError,
        ObservationEvidence, has_independent_observers,
    };

    fn peer() -> libp2p::PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    fn observer(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn observation_quorum_counts_node_ids_not_connections_or_physical_operators() {
        let network_identity = identity("8.8.8.8");
        let evidence = [
            ObservationEvidence {
                observer_node_id: observer(1),
                endpoint: endpoint("8.8.8.8"),
                expires_at_ms: 100,
            },
            ObservationEvidence {
                observer_node_id: observer(1),
                endpoint: endpoint("8.8.8.8"),
                expires_at_ms: 100,
            },
            ObservationEvidence {
                observer_node_id: observer(2),
                endpoint: endpoint("8.8.8.8"),
                expires_at_ms: 100,
            },
            ObservationEvidence {
                observer_node_id: observer(3),
                endpoint: endpoint("8.8.8.8"),
                expires_at_ms: 100,
            },
        ];
        assert!(has_independent_observers(
            &evidence,
            network_identity,
            50,
            3
        ));
        assert!(!has_independent_observers(
            &evidence[..3],
            network_identity,
            50,
            3
        ));
        assert!(!has_independent_observers(
            &evidence,
            network_identity,
            100,
            3
        ));
    }

    fn identity(ip: &str) -> NetworkIdentity {
        NetworkIdentity::from_ip(ip.parse().expect("address")).expect("eligible identity")
    }

    fn endpoint(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().expect("IP address"), 4000)
    }

    #[test]
    fn three_distinct_active_node_ids_promote_discovery() {
        let mut manager =
            IdentityManager::new(peer(), IdentityManagerConfig::default()).expect("manager");
        let identity = identity("8.8.8.8");
        for index in 0..3 {
            let result = manager
                .observe(
                    observer(index + 1),
                    [index; 16],
                    [index; 16],
                    endpoint("8.8.8.8"),
                    true,
                    u64::from(index),
                )
                .expect("observation");
            assert_eq!(
                result,
                if index == 2 {
                    IdentityLifecycle::Discovered
                } else {
                    IdentityLifecycle::Unknown
                }
            );
        }
        assert_eq!(manager.lifecycle(&identity), IdentityLifecycle::Discovered);
    }

    #[test]
    fn duplicate_observer_and_stale_or_relayed_observations_do_not_count() {
        let mut manager =
            IdentityManager::new(peer(), IdentityManagerConfig::default()).expect("manager");
        let same_observer = observer(1);
        for index in 0..3 {
            let result = manager.observe(
                same_observer,
                [index; 16],
                [index; 16],
                endpoint("8.8.8.8"),
                true,
                u64::from(index),
            );
            assert!(result.is_ok());
        }
        assert_eq!(
            manager.lifecycle(&identity("8.8.8.8")),
            IdentityLifecycle::Unknown
        );
        assert_eq!(
            manager.observe(observer(2), [1; 16], [2; 16], endpoint("8.8.8.8"), true, 4,),
            Err(IdentityManagerError::NonceMismatch)
        );
        assert_eq!(
            manager.observe(observer(2), [1; 16], [1; 16], endpoint("8.8.8.8"), false, 4,),
            Err(IdentityManagerError::IndirectObservation)
        );
    }

    #[test]
    fn normalized_ipv6_addresses_share_observation_identity() {
        let mut manager =
            IdentityManager::new(peer(), IdentityManagerConfig::default()).expect("manager");
        for (index, ip) in ["2001:4860:1:2::1", "2001:4860:1:2::2", "2001:4860:1:2::3"]
            .into_iter()
            .enumerate()
        {
            manager
                .observe(
                    observer(u8::try_from(index + 1).expect("three observers")),
                    [index as u8; 16],
                    [index as u8; 16],
                    endpoint(ip),
                    true,
                    index as u64,
                )
                .expect("observation");
        }
        assert_eq!(
            manager.lifecycle(&identity("2001:4860:1:2::99")),
            IdentityLifecycle::Discovered
        );
    }

    #[test]
    fn activation_requires_three_fresh_direct_verifiers_and_respects_limit() {
        let local_peer = peer();
        let config = IdentityManagerConfig {
            max_active_nodes: 1,
            ..IdentityManagerConfig::default()
        };
        let mut manager = IdentityManager::new(local_peer, config).expect("manager");
        let network_identity = identity("8.8.8.8");
        for index in 1..=3 {
            manager
                .observe(
                    observer(index),
                    [index; 16],
                    [index; 16],
                    endpoint("8.8.8.8"),
                    true,
                    1,
                )
                .expect("observation");
        }
        for verifier_number in 1..=3 {
            let verifier = NodeId::from_bytes([verifier_number; 32]);
            let challenge = [verifier_number; 16];
            manager
                .begin_verification(network_identity, verifier, challenge, 2)
                .expect("begin verification");
            manager
                .record_verification(
                    network_identity,
                    verifier,
                    challenge,
                    local_peer,
                    true,
                    true,
                    100,
                    2,
                )
                .expect("valid direct result");
        }
        assert_eq!(
            manager.activate(network_identity, 3),
            Ok(populus_crypto::node_id(&network_identity))
        );
        assert_eq!(manager.active_count(), 1);
        assert_eq!(
            manager.activate(identity("1.1.1.1"), 3),
            Err(IdentityManagerError::InsufficientVerifications)
        );
    }

    #[test]
    fn verification_expiration_and_retirement_do_not_affect_other_identities() {
        let local_peer = peer();
        let mut manager =
            IdentityManager::new(local_peer, IdentityManagerConfig::default()).expect("manager");
        let network_identity = identity("8.8.8.8");
        for index in 1..=3 {
            manager
                .observe(
                    observer(index),
                    [index; 16],
                    [index; 16],
                    endpoint("8.8.8.8"),
                    true,
                    1,
                )
                .expect("observation");
        }
        for byte in 1..=3 {
            let verifier = NodeId::from_bytes([byte; 32]);
            let challenge = [byte; 16];
            manager
                .begin_verification(network_identity, verifier, challenge, 2)
                .expect("begin verification");
            manager
                .record_verification(
                    network_identity,
                    verifier,
                    challenge,
                    local_peer,
                    true,
                    true,
                    100,
                    2,
                )
                .expect("verification");
        }
        manager.activate(network_identity, 3).expect("activate");
        manager.mark_suspect(network_identity).expect("suspect");
        manager.restore(network_identity, 3).expect("restore");
        manager.retire(network_identity).expect("retire");
        manager.remove(network_identity).expect("remove");
        assert_eq!(manager.active_count(), 0);
    }

    #[test]
    fn stale_verification_challenge_is_rejected() {
        let local_peer = peer();
        let mut manager =
            IdentityManager::new(local_peer, IdentityManagerConfig::default()).expect("manager");
        let network_identity = identity("8.8.8.8");
        for index in 1..=3 {
            manager
                .observe(
                    observer(index),
                    [index; 16],
                    [index; 16],
                    endpoint("8.8.8.8"),
                    true,
                    1,
                )
                .expect("observation");
        }
        let verifier = NodeId::from_bytes([4; 32]);
        manager
            .begin_verification(network_identity, verifier, [4; 16], 2)
            .expect("challenge");
        assert_eq!(
            manager.record_verification(
                network_identity,
                verifier,
                [5; 16],
                local_peer,
                true,
                true,
                100,
                2,
            ),
            Err(IdentityManagerError::StaleChallenge)
        );
    }

    #[test]
    fn expired_verifier_quorum_moves_active_identity_to_suspect() {
        let local_peer = peer();
        let config = IdentityManagerConfig {
            verification_ttl_ms: 10,
            ..IdentityManagerConfig::default()
        };
        let mut manager = IdentityManager::new(local_peer, config).expect("manager");
        let network_identity = identity("8.8.8.8");
        for index in 0..3 {
            manager
                .observe(
                    observer(index + 1),
                    [index; 16],
                    [index; 16],
                    endpoint("8.8.8.8"),
                    true,
                    1,
                )
                .expect("observation");
        }
        for index in 1..=3 {
            let verifier = NodeId::from_bytes([index; 32]);
            let challenge = [index; 16];
            manager
                .begin_verification(network_identity, verifier, challenge, 2)
                .expect("challenge");
            manager
                .record_verification(
                    network_identity,
                    verifier,
                    challenge,
                    local_peer,
                    true,
                    true,
                    100,
                    2,
                )
                .expect("verification");
        }
        manager.activate(network_identity, 3).expect("activate");
        manager.advance(13);
        assert_eq!(
            manager.lifecycle(&network_identity),
            IdentityLifecycle::Suspect
        );
        assert_eq!(
            manager.restore(network_identity, 13),
            Err(IdentityManagerError::InsufficientVerifications)
        );
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_only_genesis_activation_bypasses_verification() {
        let identity = identity("8.8.8.8");
        let mut test_network =
            IdentityManager::new(peer(), IdentityManagerConfig::default()).expect("manager");
        assert_eq!(
            test_network.activate_genesis(identity),
            Ok(populus_crypto::node_id(&identity))
        );
    }
}
