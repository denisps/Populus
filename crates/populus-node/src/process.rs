use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use libp2p::{Multiaddr, PeerId, core::multiaddr::Protocol, identity::Keypair};
use populus_cluster::{
    DailyPopularityStatus, DelegatedIngestError, DelegatedIngestState, DelegatedReportReceiver,
    DelegationDescriptor, DirectIngestError, DirectIngestPolicy, DirectIngestState, DirectVote,
    DirectVoteOutcome, GenesisManifest, GenesisManifestError, GenesisMember, IngestReport,
    MembershipView, SignedIngestReportAck, SignedPopularityResponse,
};
use populus_crypto::{AuthorityKeypair, client_id, node_id};
use populus_network::{
    RequestId, ResponseChannel, SendRequestError, SendResponseError, Transport, TransportEvent,
};
use populus_protocol::{ApplicationMessage, ProtocolError, RoutingContact};
use populus_routing::{InsertError, RoutingTable};
use populus_types::{
    ClientId, ContentId, NetworkIdentity, NodeId, RoutingKey, UtcDay, XorDistance,
};

use crate::{
    ApplicationErrorCode, ApplicationSendError, DirectVoteRejection, IdentityLifecycle,
    IdentityManager, IdentityManagerConfig, IdentityManagerError, PeerIdentityStore,
    load_or_create_peer_identity,
};

const MAX_BOOTSTRAP_PEERS: usize = 32;
const MAX_DISCOVERED_CONTACTS: usize = 256;
const MAX_AUTODIALED_CONTACTS: usize = 32;
const MAX_LOCAL_ADDRESSES: usize = 16;
const MAX_PERIODIC_OBSERVATION_PEERS: usize = 32;
const MAX_PENDING_REQUESTS: usize = 128;
const MAX_DELEGATED_INGEST_SCOPES: usize = 64;
const OBSERVATION_REFRESH_INTERVAL: Duration = Duration::from_mins(5);

struct DirectAuthority {
    membership: MembershipView,
    state: DirectIngestState,
    signer: AuthorityKeypair,
}

struct DelegatedIngestSender {
    membership: MembershipView,
    state: DelegatedIngestState,
}

struct DelegatedIngestAuthority {
    membership: MembershipView,
    receiver: DelegatedReportReceiver,
    signer: AuthorityKeypair,
}

struct GenesisBootstrap {
    manifest: GenesisManifest,
    trusted_public_key: [u8; 32],
}

/// One active Populus `NodeId` with routing state independent of sibling identities.
pub struct LogicalNode {
    network_identity: NetworkIdentity,
    node_id: NodeId,
    routing: RoutingTable,
    contacts: HashMap<NodeId, RoutingContact>,
}

impl LogicalNode {
    /// Returns the logical node's canonical network identity.
    #[must_use]
    pub const fn network_identity(&self) -> NetworkIdentity {
        self.network_identity
    }

    /// Returns the logical node's Populus routing position.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns this logical node's independent routing table.
    #[must_use]
    pub const fn routing_table(&self) -> &RoutingTable {
        &self.routing
    }
}

/// Application-facing process events.
#[derive(Debug)]
pub enum ProcessEvent {
    /// A transport event not consumed by process protocol handling.
    Transport(TransportEvent),
    /// A direct vote received over the versioned application envelope.
    DirectVoteRequest {
        /// Authenticated sender.
        peer: PeerId,
        /// Canonical vote or typed rejection.
        vote: Result<DirectVote, DirectVoteRejection>,
        /// Response capability.
        channel: ResponseChannel,
    },
    /// A valid direct vote was inserted into this authority's existing state machine.
    DirectVoteAccepted {
        /// Authenticated sender.
        peer: PeerId,
        /// Vote scope.
        content_id: ContentId,
        /// Result returned by the direct-ingest state machine.
        outcome: DirectVoteOutcome,
    },
    /// A direct vote failed canonical or authority-state validation.
    DirectVoteRejected {
        /// Authenticated sender.
        peer: PeerId,
        /// Rejection returned by the canonical decoder or ingest state machine.
        error: DirectIngestError,
    },
    /// No local authority state is installed for a direct vote or popularity query.
    NoActiveAuthority {
        /// Authenticated requester.
        peer: PeerId,
        /// Content queried or voted on.
        content_id: ContentId,
    },
    /// A popularity query was answered with a signed authority result.
    PopularityQueryServed {
        /// Authenticated requester.
        peer: PeerId,
        /// Content queried.
        content_id: ContentId,
        /// Signed approximate estimate.
        estimate: f64,
        /// Whether the daily bucket is finalized.
        finalized: bool,
    },
    /// A popularity query failed direct-ingest validation or signing.
    PopularityQueryRejected {
        /// Authenticated requester.
        peer: PeerId,
        /// Typed state-machine or signer error.
        error: DirectIngestError,
    },
    /// A delegated report was merged and acknowledged by an authority state machine.
    DelegatedReportAccepted {
        /// Authenticated reporting peer.
        peer: PeerId,
        /// Report scope.
        scope: (ContentId, UtcDay, u8),
        /// Monotonic report sequence.
        sequence: u64,
    },
    /// A delegated report failed descriptor, replay, scope, or signing validation.
    DelegatedReportRejected {
        /// Authenticated reporting peer.
        peer: PeerId,
        /// Typed delegated-ingest state-machine error.
        error: DelegatedIngestError,
    },
    /// A signed authority ACK was verified and applied to the sender's pending buffer.
    DelegatedIngestAcknowledged {
        /// Authenticated authority peer.
        peer: PeerId,
        /// Report scope.
        scope: (ContentId, UtcDay, u8),
        /// Monotonic report sequence.
        sequence: u64,
        /// Whether all four authorities have acknowledged and the buffer was reclaimed.
        completed: bool,
    },
    /// A delegated ACK failed authority identity or ingest-state validation.
    DelegatedIngestAckRejected {
        /// Authenticated responder.
        peer: PeerId,
        /// Typed delegated-ingest state-machine error.
        error: DelegatedIngestError,
    },
    /// An inbound Populus request not handled internally.
    ApplicationRequest {
        /// Authenticated sender.
        peer: PeerId,
        /// Decoded request.
        message: ApplicationMessage,
        /// Response capability.
        channel: ResponseChannel,
    },
    /// An outbound application response.
    ApplicationResponse {
        /// Authenticated responder.
        peer: PeerId,
        /// Local transport request identifier.
        transport_request_id: RequestId,
        /// Decoded response.
        message: ApplicationMessage,
    },
    /// A correlated observed-address reply updated the continuous identity manager.
    IdentityObservation {
        /// Authenticated observer.
        peer: PeerId,
        /// Verified active Populus identities associated with this connection.
        results: Vec<(NodeId, Result<IdentityLifecycle, IdentityManagerError>)>,
    },
    /// An address observation came from a peer with no verified active binding.
    UnverifiedIdentityObserver {
        /// Authenticated but not eligible observer.
        peer: PeerId,
    },
    /// An inbound frame failed envelope decoding.
    InvalidApplicationRequest {
        /// Authenticated sender.
        peer: PeerId,
        /// Protocol rejection.
        error: ProtocolError,
        /// Response capability.
        channel: ResponseChannel,
    },
    /// The transport could not send a protocol response.
    ResponseRejected {
        /// Intended recipient.
        peer: PeerId,
        /// Explicit response failure, including recoverable payload-too-large data.
        error: SendResponseError,
    },
    /// A correlated outbound response failed application-envelope decoding.
    InvalidApplicationResponse {
        /// Authenticated responder.
        peer: PeerId,
        /// Local transport request identifier.
        transport_request_id: RequestId,
        /// Decoder rejection.
        error: ProtocolError,
    },
    /// Automatic peer discovery could not enqueue a required request.
    OutboundRequestRejected {
        /// Peer for which discovery could not proceed.
        peer: PeerId,
        /// Explicit bounded-transport failure.
        error: ApplicationSendError,
    },
    /// A locally constructed application message violated its own wire contract.
    InvalidLocalApplicationMessage {
        /// Peer for which the request could not be encoded.
        peer: PeerId,
        /// Protocol encoding failure.
        error: ProtocolError,
    },
    /// A discovered contact did not pass canonical identity/address checks.
    InvalidDiscoveredContact {
        /// Peer that returned the contact set.
        peer: PeerId,
    },
    /// The bounded bootstrap/discovery contact cache is full.
    DiscoveryLimitReached {
        /// Peer that returned additional contacts.
        peer: PeerId,
    },
    /// An authenticated contact's advertised address could not be dialed.
    ContactDialRejected {
        /// Peer identity associated with the rejected address.
        peer: PeerId,
        /// Transport rejection description.
        reason: String,
    },
}

/// Errors while encoding or sending a typed application response.
#[derive(Debug)]
pub enum ApplicationResponseError {
    /// The supplied response exceeded a protocol bound; the response channel
    /// is retained for correction.
    InvalidMessage {
        /// Response capability.
        channel: ResponseChannel,
        /// Encoding rejection.
        error: ProtocolError,
    },
    /// The response channel closed or the transport rejected the payload.
    Transport(SendResponseError),
}

impl std::fmt::Display for ApplicationResponseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMessage { error, .. } => {
                write!(formatter, "invalid Populus response: {error}")
            }
            Self::Transport(error) => write!(formatter, "Populus response send failed: {error:?}"),
        }
    }
}

impl std::error::Error for ApplicationResponseError {}

#[derive(Debug, Clone, Copy)]
enum PendingRequest {
    ObservedAddress {
        nonce: [u8; 16],
    },
    FindNode {
        request_id: u64,
    },
    DelegatedIngestAck {
        scope: (ContentId, UtcDay, u8),
        authority_id: populus_types::AuthorityId,
    },
}

/// Shared transport process managing multiple independently routed logical nodes.
pub struct PopulusProcess {
    transport: Transport,
    identity_manager: IdentityManager,
    logical_nodes: HashMap<NodeId, LogicalNode>,
    known_contacts: HashMap<(NodeId, PeerId), RoutingContact>,
    verified_peer_nodes: HashMap<PeerId, HashSet<NodeId>>,
    direct_authorities: HashMap<(ContentId, UtcDay), DirectAuthority>,
    delegated_ingest_senders: HashMap<(ContentId, UtcDay, u8), DelegatedIngestSender>,
    delegated_ingest_authorities: HashMap<(ContentId, UtcDay, u8), DelegatedIngestAuthority>,
    genesis_bootstrap: Option<GenesisBootstrap>,
    pending_requests: HashMap<RequestId, PendingRequest>,
    local_addresses: Vec<Multiaddr>,
    auto_dialed: HashSet<PeerId>,
    next_nonce: u64,
    next_lookup_id: u64,
    next_observation_refresh: Instant,
    #[cfg(test)]
    test_client_identities: HashMap<PeerId, ClientId>,
}

impl PopulusProcess {
    /// Creates a process using a caller-provided persistent libp2p keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if transport or identity-manager construction fails.
    pub fn with_identity(
        keypair: Keypair,
        identity_config: IdentityManagerConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let transport = Transport::with_identity(keypair)?;
        let identity_manager = IdentityManager::new(transport.peer_id(), identity_config)?;
        Ok(Self {
            transport,
            identity_manager,
            logical_nodes: HashMap::new(),
            known_contacts: HashMap::new(),
            verified_peer_nodes: HashMap::new(),
            direct_authorities: HashMap::new(),
            delegated_ingest_senders: HashMap::new(),
            delegated_ingest_authorities: HashMap::new(),
            genesis_bootstrap: None,
            pending_requests: HashMap::new(),
            local_addresses: Vec::new(),
            auto_dialed: HashSet::new(),
            next_nonce: 0,
            next_lookup_id: 0,
            next_observation_refresh: Instant::now() + OBSERVATION_REFRESH_INTERVAL,
            #[cfg(test)]
            test_client_identities: HashMap::new(),
        })
    }

    /// Creates a process with its transport identity loaded from a persistence boundary.
    ///
    /// # Errors
    ///
    /// Returns storage, key-decoding, transport, or identity-manager errors.
    pub fn with_identity_store(
        store: &impl PeerIdentityStore,
        identity_config: IdentityManagerConfig,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let keypair = load_or_create_peer_identity(store)?;
        Self::with_identity(keypair, identity_config)
    }

    /// Returns the persistent transport `PeerId`.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.transport.peer_id()
    }

    /// Returns the number of active logical nodes.
    #[must_use]
    pub fn logical_node_count(&self) -> usize {
        self.logical_nodes.len()
    }

    /// Iterates active logical nodes in deterministic `NodeId` order.
    pub fn logical_nodes(&self) -> impl Iterator<Item = &LogicalNode> {
        let mut nodes: Vec<_> = self.logical_nodes.values().collect();
        nodes.sort_unstable_by_key(|node| node.node_id);
        nodes.into_iter()
    }

    /// Looks up a currently active logical node.
    #[must_use]
    pub fn logical_node(&self, node_id: &NodeId) -> Option<&LogicalNode> {
        self.logical_nodes.get(node_id)
    }

    /// Starts a libp2p listener.
    ///
    /// # Errors
    ///
    /// Returns a transport construction or bind error.
    pub fn listen_on(
        &mut self,
        address: Multiaddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.transport.listen_on(address)
    }

    /// Connects to bounded, explicitly configured bootstrap entry points.
    ///
    /// Bootstrap peers are only discovery sources; this method does not add
    /// claimed `NodeId`s to an eligible routing table.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied set exceeds [`MAX_BOOTSTRAP_PEERS`]
    /// or when libp2p rejects a dial request.
    pub fn bootstrap(
        &mut self,
        addresses: impl IntoIterator<Item = Multiaddr>,
    ) -> Result<usize, ProcessError> {
        let mut unique = HashSet::new();
        let mut connected = 0;
        for address in addresses {
            if !unique.insert(address.clone()) {
                continue;
            }
            if connected == MAX_BOOTSTRAP_PEERS {
                return Err(ProcessError::BootstrapLimit);
            }
            self.transport
                .dial(address)
                .map_err(|_| ProcessError::DialRejected)?;
            connected += 1;
        }
        Ok(connected)
    }

    /// Validates and stages an explicitly trusted four-member genesis manifest.
    ///
    /// Returned addresses are direct-IP bootstrap attempts for the other
    /// manifest members. A failed or partial bootstrap never activates genesis.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError`] if the trust signature, member PeerId/key
    /// binding, direct addresses, or local manifest membership is invalid.
    pub fn configure_genesis_manifest(
        &mut self,
        manifest: GenesisManifest,
        trusted_public_key: [u8; 32],
    ) -> Result<Vec<Multiaddr>, ProcessError> {
        if self.genesis_bootstrap.is_some() {
            return Err(ProcessError::GenesisManifestAlreadyConfigured);
        }
        manifest
            .verify(&trusted_public_key)
            .map_err(ProcessError::GenesisManifest)?;
        let local_peer = self.peer_id();
        let mut local_member_present = false;
        let mut bootstrap_addresses = Vec::new();
        for member in manifest.members() {
            let (peer, addresses) = validate_genesis_member(member)?;
            if peer == local_peer {
                local_member_present = true;
            } else {
                bootstrap_addresses.extend(addresses);
            }
        }
        if !local_member_present {
            return Err(ProcessError::LocalPeerNotInGenesisManifest);
        }
        self.genesis_bootstrap = Some(GenesisBootstrap {
            manifest,
            trusted_public_key,
        });
        Ok(bootstrap_addresses)
    }

    /// Attempts the manifest-authorized local genesis transition.
    ///
    /// Activation requires direct authenticated connections to the other three
    /// members and three distinct manifest members to observe the local
    /// normalized identity. Ordinary bootstrap success or failure alone never
    /// activates a `NodeId`.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError`] if a manifest-authorized state transition
    /// exceeds a local bound or contact invariants fail. Returns `Ok(None)`
    /// while direct reachability or the observation quorum is incomplete.
    pub fn try_activate_genesis_manifest(&mut self) -> Result<Option<NodeId>, ProcessError> {
        let Some(genesis) = &self.genesis_bootstrap else {
            return Ok(None);
        };
        genesis
            .manifest
            .verify(&genesis.trusted_public_key)
            .map_err(ProcessError::GenesisManifest)?;
        let local_peer = self.peer_id();
        let local_member = genesis
            .manifest
            .members()
            .iter()
            .find(|member| member.peer_id() == local_peer.to_bytes())
            .ok_or(ProcessError::LocalPeerNotInGenesisManifest)?;
        let local_identity = local_member.network_identity();
        let local_node = local_member.node_id();
        if self.logical_nodes.contains_key(&local_node) {
            return Ok(None);
        }
        if self.identity_manager.lifecycle(&local_identity) != IdentityLifecycle::Discovered {
            return Ok(None);
        }
        let directly_connected = self
            .transport
            .direct_connected_peers()
            .collect::<HashSet<_>>();
        for member in genesis.manifest.members() {
            let peer = PeerId::from_bytes(member.peer_id())
                .map_err(|_| ProcessError::InvalidGenesisMember)?;
            if peer != local_peer
                && (!directly_connected.contains(&peer)
                    || !self
                        .verified_peer_nodes
                        .get(&peer)
                        .is_some_and(|node_ids| node_ids.contains(&member.node_id())))
            {
                return Ok(None);
            }
        }
        let contacts = genesis
            .manifest
            .members()
            .iter()
            .filter(|member| member.node_id() != local_node)
            .map(|member| {
                let (peer, addresses) = validate_genesis_member(member)?;
                Ok((
                    peer,
                    RoutingContact {
                        node_id: member.node_id(),
                        identity: member.network_identity(),
                        peer_id: member.peer_id().to_vec(),
                        addresses: addresses.iter().map(ToString::to_string).collect(),
                    },
                ))
            })
            .collect::<Result<Vec<_>, ProcessError>>()?;
        let activated = self
            .identity_manager
            .activate_manifest_member(local_identity, now_millis())
            .map_err(ProcessError::IdentityManager)?;
        self.logical_nodes
            .entry(activated)
            .or_insert_with(|| LogicalNode {
                network_identity: local_identity,
                node_id: activated,
                routing: RoutingTable::new(activated),
                contacts: HashMap::new(),
            });
        for (peer, contact) in contacts {
            self.add_verified_contact(activated, contact, peer)?;
        }
        Ok(Some(activated))
    }

    /// Applies an injected direct observation from an already verified active `NodeId`.
    ///
    /// This is useful for platform adapters and deterministic simulation. It
    /// intentionally accepts a `NodeId`, not a `PeerId`; runtime observations
    /// are mapped through verified active contacts before being counted.
    ///
    /// # Errors
    ///
    /// Returns the identity manager's typed validation or resource-limit error.
    pub fn observe_address(
        &mut self,
        observer_node_id: NodeId,
        expected_nonce: [u8; 16],
        response_nonce: [u8; 16],
        endpoint: SocketAddr,
        is_direct: bool,
        now_ms: u64,
    ) -> Result<IdentityLifecycle, IdentityManagerError> {
        self.identity_manager.observe(
            observer_node_id,
            expected_nonce,
            response_nonce,
            endpoint,
            is_direct,
            now_ms,
        )
    }

    /// Starts a verifier challenge for one discovered identity.
    ///
    /// # Errors
    ///
    /// Returns a typed lifecycle or observation-quorum error.
    pub fn begin_verification(
        &mut self,
        identity: NetworkIdentity,
        verifier: NodeId,
        challenge: [u8; 16],
        now_ms: u64,
    ) -> Result<(), IdentityManagerError> {
        self.identity_manager
            .begin_verification(identity, verifier, challenge, now_ms)
    }

    /// Records a fresh authenticated direct verifier result.
    ///
    /// # Errors
    ///
    /// Returns a typed challenge, peer-identity, reachability, or consistency error.
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
        self.identity_manager.record_verification(
            identity,
            verifier,
            challenge,
            authenticated_peer,
            direct_reachable,
            identity_matches,
            valid_until_ms,
            now_ms,
        )
    }

    /// Activates a verified local identity and creates its independent routing table.
    ///
    /// A distributed active-NodeID ownership binding must be accepted before
    /// this method is called; local verification alone is not arbitration.
    ///
    /// # Errors
    ///
    /// Returns identity-manager errors for verification or capacity failures.
    pub fn activate_identity(
        &mut self,
        identity: NetworkIdentity,
        now_ms: u64,
    ) -> Result<NodeId, IdentityManagerError> {
        let node_id = self.identity_manager.activate(identity, now_ms)?;
        self.logical_nodes
            .entry(node_id)
            .or_insert_with(|| LogicalNode {
                network_identity: identity,
                node_id,
                routing: RoutingTable::new(node_id),
                contacts: HashMap::new(),
            });
        Ok(node_id)
    }

    /// Test-only bypass for isolated unit and localhost fixtures.
    ///
    /// # Errors
    ///
    /// Returns an identity-manager error if local active-node capacity is exhausted.
    #[cfg(test)]
    pub fn activate_genesis_identity(
        &mut self,
        identity: NetworkIdentity,
    ) -> Result<NodeId, IdentityManagerError> {
        let node_id = self.identity_manager.activate_genesis(identity)?;
        self.logical_nodes
            .entry(node_id)
            .or_insert_with(|| LogicalNode {
                network_identity: identity,
                node_id,
                routing: RoutingTable::new(node_id),
                contacts: HashMap::new(),
            });
        Ok(node_id)
    }

    /// Stops admitting new work for one identity while leaving sibling nodes active.
    ///
    /// The caller should perform best-effort authority/state handoff before
    /// calling [`Self::finish_identity_retirement`].
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidTransition`] unless the identity
    /// is currently Active or Suspect.
    pub fn begin_identity_retirement(
        &mut self,
        identity: NetworkIdentity,
    ) -> Result<NodeId, IdentityManagerError> {
        self.identity_manager.retire(identity)?;
        Ok(node_id(&identity))
    }

    /// Removes one already-retiring logical node without stopping its siblings.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityManagerError::InvalidTransition`] unless retirement
    /// has already begun.
    pub fn finish_identity_retirement(
        &mut self,
        identity: NetworkIdentity,
    ) -> Result<(), IdentityManagerError> {
        self.identity_manager.remove(identity)?;
        self.logical_nodes.remove(&node_id(&identity));
        Ok(())
    }

    /// Adds a contact only after the caller has verified its active binding,
    /// direct reachability, `PeerId`, and identity proof.
    ///
    /// The contact encoding is revalidated here; a claimed contact returned
    /// during bootstrap is never inserted automatically.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::InvalidContact`] for a mismatched identity,
    /// `PeerId`, empty/invalid address set, or ineligible local logical node.
    pub fn add_verified_contact(
        &mut self,
        local_node: NodeId,
        contact: RoutingContact,
        authenticated_peer: PeerId,
    ) -> Result<(), ProcessError> {
        if contact.node_id != node_id(&contact.identity)
            || contact.peer_id != authenticated_peer.to_bytes()
            || contact.node_id == local_node
            || contact.addresses.is_empty()
            || contact.addresses.len() > 8
        {
            return Err(ProcessError::InvalidContact);
        }
        let peer_from_contact =
            PeerId::from_bytes(&contact.peer_id).map_err(|_| ProcessError::InvalidContact)?;
        if peer_from_contact != authenticated_peer {
            return Err(ProcessError::InvalidContact);
        }
        for address in &contact.addresses {
            let parsed: Multiaddr = address.parse().map_err(|_| ProcessError::InvalidContact)?;
            if parsed.iter().any(
                |protocol| matches!(protocol, Protocol::P2p(peer) if peer != authenticated_peer),
            ) {
                return Err(ProcessError::InvalidContact);
            }
        }
        let contact_node_id = contact.node_id;
        let logical = self
            .logical_nodes
            .get_mut(&local_node)
            .ok_or(ProcessError::UnknownLogicalNode)?;
        match logical.routing.insert(contact_node_id) {
            Ok(()) | Err(InsertError::Duplicate) => {
                logical.contacts.insert(contact_node_id, contact);
                self.verified_peer_nodes
                    .entry(authenticated_peer)
                    .or_default()
                    .insert(contact_node_id);
                Ok(())
            }
            Err(InsertError::BucketFull) => Err(ProcessError::RoutingBucketFull),
            Err(InsertError::LocalNode) => Err(ProcessError::InvalidContact),
        }
    }

    /// Returns the nearest contacts from one logical node's verified routing state.
    #[must_use]
    pub fn closest_contacts(
        &self,
        local_node: NodeId,
        target: &RoutingKey,
        limit: usize,
    ) -> Vec<RoutingContact> {
        self.logical_nodes
            .get(&local_node)
            .map_or_else(Vec::new, |logical| {
                logical
                    .routing
                    .closest_nodes(target, limit)
                    .iter()
                    .filter_map(|node| logical.contacts.get(node).cloned())
                    .collect()
            })
    }

    /// Installs this logical node as one authority for a content/day bucket.
    ///
    /// The caller must supply a membership view already validated by the
    /// authority-membership protocol. This method checks the content routing
    /// key and exact local signing-key membership, then uses the existing
    /// `DirectIngestState` for vote validation, idempotency, rate tracking,
    /// finalization, and acknowledgement signing.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::InvalidAuthorityConfig`] for mismatched scope,
    /// unknown local node, wrong authority key, or duplicate installation.
    pub fn install_direct_authority(
        &mut self,
        local_node: NodeId,
        content_id: ContentId,
        day: UtcDay,
        membership: MembershipView,
        policy: DirectIngestPolicy,
        signer: AuthorityKeypair,
    ) -> Result<(), ProcessError> {
        let expected_routing_key = DirectIngestState::new(content_id, day, policy).routing_key();
        let member = membership.member(signer.authority_id());
        if !self.logical_nodes.contains_key(&local_node)
            || membership.routing_key() != expected_routing_key
            || member.is_none_or(|member| {
                member.node_id() != local_node || member.public_key() != &signer.public_key()
            })
            || self.direct_authorities.contains_key(&(content_id, day))
        {
            return Err(ProcessError::InvalidAuthorityConfig);
        }
        self.direct_authorities.insert(
            (content_id, day),
            DirectAuthority {
                membership,
                state: DirectIngestState::new(content_id, day, policy),
                signer,
            },
        );
        Ok(())
    }

    /// Installs one existing delegated-ingest sender state for an active logical node.
    ///
    /// The caller remains responsible for obtaining a validated authority
    /// membership. The state machine verifies the content scope and membership
    /// generation before the state is retained.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError`] if the local node, membership, scope, or
    /// bounded per-process state capacity is invalid.
    pub fn install_delegated_ingest_sender(
        &mut self,
        local_node: NodeId,
        membership: MembershipView,
        mut state: DelegatedIngestState,
    ) -> Result<(), ProcessError> {
        let scope = state.scope();
        if !self.logical_nodes.contains_key(&local_node)
            || state.node_id() != local_node
            || self.delegated_ingest_senders.contains_key(&scope)
            || self.delegated_ingest_senders.len() + self.delegated_ingest_authorities.len()
                >= MAX_DELEGATED_INGEST_SCOPES
        {
            return Err(ProcessError::InvalidDelegatedIngestConfig);
        }
        state
            .retarget_membership(&membership)
            .map_err(ProcessError::DelegatedIngest)?;
        self.delegated_ingest_senders
            .insert(scope, DelegatedIngestSender { membership, state });
        Ok(())
    }

    /// Installs one authority-side delegated report receiver and signer.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError`] when the local node is not the selected
    /// authority, the membership/scope is invalid, or the per-process state
    /// bound is exhausted.
    pub fn install_delegated_report_receiver(
        &mut self,
        local_node: NodeId,
        descriptor: &DelegationDescriptor,
        membership: MembershipView,
        signer: AuthorityKeypair,
        scope: (ContentId, UtcDay, u8),
    ) -> Result<(), ProcessError> {
        let (content_id, day, view) = scope;
        let member = membership.member(signer.authority_id());
        if !self.logical_nodes.contains_key(&local_node)
            || member.is_none_or(|member| {
                member.node_id() != local_node || member.public_key() != &signer.public_key()
            })
            || self.delegated_ingest_authorities.contains_key(&scope)
            || self.delegated_ingest_senders.len() + self.delegated_ingest_authorities.len()
                >= MAX_DELEGATED_INGEST_SCOPES
        {
            return Err(ProcessError::InvalidDelegatedIngestConfig);
        }
        let receiver = DelegatedReportReceiver::new(content_id, day, view, descriptor, &membership)
            .map_err(ProcessError::DelegatedIngest)?;
        self.delegated_ingest_authorities.insert(
            scope,
            DelegatedIngestAuthority {
                membership,
                receiver,
                signer,
            },
        );
        Ok(())
    }

    /// Records a client in the active delegated-ingest sketch.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError::UnknownDelegatedIngestState`] if the scope was
    /// not installed.
    pub fn record_delegated_client(
        &mut self,
        scope: (ContentId, UtcDay, u8),
        client_id: ClientId,
    ) -> Result<(), ProcessError> {
        let sender = self
            .delegated_ingest_senders
            .get_mut(&scope)
            .ok_or(ProcessError::UnknownDelegatedIngestState)?;
        sender.state.record_client(client_id);
        Ok(())
    }

    /// Rolls the active sketch into the immutable report buffer.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError`] if the sender scope is absent or report
    /// sequence advancement fails.
    pub fn rollover_delegated_ingest(
        &mut self,
        scope: (ContentId, UtcDay, u8),
    ) -> Result<Option<u64>, ProcessError> {
        let sender = self
            .delegated_ingest_senders
            .get_mut(&scope)
            .ok_or(ProcessError::UnknownDelegatedIngestState)?;
        sender
            .state
            .rollover()
            .map(|report| report.map(IngestReport::sequence))
            .map_err(ProcessError::DelegatedIngest)
    }

    /// Sends the pending report to one authority selected by the installed membership.
    ///
    /// Reports are retried by calling this method again; the authority receiver
    /// acknowledges exact retries without merging them twice.
    ///
    /// # Errors
    ///
    /// Returns [`ProcessError`] for missing state/report/contact, invalid
    /// contact data, or bounded transport/envelope failures.
    pub fn send_delegated_ingest_report(
        &mut self,
        local_node: NodeId,
        scope: (ContentId, UtcDay, u8),
        authority_id: populus_types::AuthorityId,
    ) -> Result<RequestId, ProcessError> {
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            return Err(ProcessError::DelegatedSendRejected(
                SendRequestError::QueueFull,
            ));
        }
        let sender = self
            .delegated_ingest_senders
            .get(&scope)
            .ok_or(ProcessError::UnknownDelegatedIngestState)?;
        if sender.state.node_id() != local_node {
            return Err(ProcessError::InvalidDelegatedIngestConfig);
        }
        let report = sender
            .state
            .pending_report()
            .ok_or(ProcessError::NoPendingIngestReport)?;
        if sender.membership.member(authority_id).is_none() {
            return Err(ProcessError::UnknownAuthority);
        }
        if !sender.state.pending_authorities().contains(&authority_id) {
            return Err(ProcessError::AuthorityNotPending);
        }
        let report = report
            .canonical_bytes()
            .map_err(ProcessError::DelegatedIngest)?;
        let authority = sender
            .membership
            .member(authority_id)
            .ok_or(ProcessError::UnknownAuthority)?;
        let contact = self
            .logical_nodes
            .get(&local_node)
            .ok_or(ProcessError::UnknownLogicalNode)?
            .contacts
            .get(&authority.node_id())
            .ok_or(ProcessError::AuthorityContactUnavailable)?;
        let peer =
            PeerId::from_bytes(&contact.peer_id).map_err(|_| ProcessError::InvalidContact)?;
        if !self
            .verified_peer_nodes
            .get(&peer)
            .is_some_and(|node_ids| node_ids.contains(&authority.node_id()))
        {
            return Err(ProcessError::AuthorityContactUnavailable);
        }
        let addresses = contact
            .addresses
            .iter()
            .map(|address| address.parse().map_err(|_| ProcessError::InvalidContact))
            .collect::<Result<Vec<Multiaddr>, _>>()?;
        let request_id = self
            .send_message(
                peer,
                addresses,
                &ApplicationMessage::DelegatedIngestReport { report },
            )
            .map_err(|error| match error {
                ApplicationSendError::Encoding(error) => {
                    ProcessError::InvalidApplicationMessage(error)
                }
                ApplicationSendError::Transport(error) => {
                    ProcessError::DelegatedSendRejected(error)
                }
            })?;
        self.pending_requests.insert(
            request_id,
            PendingRequest::DelegatedIngestAck {
                scope,
                authority_id,
            },
        );
        Ok(request_id)
    }

    /// Sends a versioned Populus message through the shared transport.
    ///
    /// # Errors
    ///
    /// Returns the transport's explicit size, capacity, or identifier error.
    pub fn send_message(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        message: &ApplicationMessage,
    ) -> Result<RequestId, ApplicationSendError> {
        let payload = message.encode().map_err(ApplicationSendError::Encoding)?;
        self.transport
            .send_request(peer, addresses, payload)
            .map_err(ApplicationSendError::Transport)
    }

    /// Sends one canonical vote to a selected authority.
    ///
    /// A client sends the same vote independently to every authority in its
    /// pinned `MembershipView` and verifies each returned signed ACK.
    ///
    /// # Errors
    ///
    /// Returns the typed message-encoding or bounded-transport error.
    pub fn send_direct_vote(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        vote: DirectVote,
    ) -> Result<RequestId, ApplicationSendError> {
        self.send_message(
            peer,
            addresses,
            &ApplicationMessage::DirectVote {
                vote: vote.canonical_bytes(),
            },
        )
    }

    /// Requests one signed popularity estimate from a selected authority.
    ///
    /// Clients should query multiple authorities and compare responses against
    /// the exact same membership generation.
    ///
    /// # Errors
    ///
    /// Returns the typed message-encoding or bounded-transport error.
    pub fn query_popularity(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        content_id: ContentId,
        day: UtcDay,
    ) -> Result<RequestId, ApplicationSendError> {
        self.send_message(
            peer,
            addresses,
            &ApplicationMessage::PopularityQuery { content_id, day },
        )
    }

    /// Encodes and sends a typed response to an inbound request.
    ///
    /// # Errors
    ///
    /// Returns the original channel and message on encoding failure, or the
    /// transport's explicit response error.
    pub fn send_response(
        &mut self,
        channel: ResponseChannel,
        message: &ApplicationMessage,
    ) -> Result<(), ApplicationResponseError> {
        let payload = match message.encode() {
            Ok(payload) => payload,
            Err(error) => {
                return Err(ApplicationResponseError::InvalidMessage { channel, error });
            }
        };
        self.transport
            .send_response(channel, payload)
            .map_err(ApplicationResponseError::Transport)
    }

    /// Waits for and processes the next process/network event.
    ///
    /// New peers trigger a correlated observed-address request and an iterative
    /// `FindNode` request even when this process has not activated a `NodeId` yet.
    pub async fn next_event(&mut self) -> ProcessEvent {
        loop {
            let refresh_at = tokio::time::Instant::from_std(self.next_observation_refresh);
            let event = tokio::select! {
                event = self.transport.next_event() => Some(event),
                () = tokio::time::sleep_until(refresh_at) => None,
            };
            let Some(event) = event else {
                self.next_observation_refresh = Instant::now() + OBSERVATION_REFRESH_INTERVAL;
                self.identity_manager.advance(now_millis());
                self.sync_genesis_peer_bindings();
                if let Some(event) = self.refresh_peer_observations() {
                    return event;
                }
                continue;
            };
            self.sync_genesis_peer_bindings();
            match event {
                TransportEvent::PeerConnected(peer) => {
                    if let Some(event) = self.start_peer_discovery(peer) {
                        return event;
                    }
                    return ProcessEvent::Transport(TransportEvent::PeerConnected(peer));
                }
                TransportEvent::Listening(address) => return self.on_listening(address),
                TransportEvent::Request {
                    peer,
                    request,
                    channel,
                } => {
                    if let Some(event) = self.on_request(peer, &request, channel) {
                        return event;
                    }
                }
                TransportEvent::Response {
                    peer,
                    request_id,
                    response,
                } => return self.on_response(peer, request_id, response),
                TransportEvent::RequestFailed {
                    peer,
                    request_id,
                    reason,
                } => {
                    self.pending_requests.remove(&request_id);
                    return ProcessEvent::Transport(TransportEvent::RequestFailed {
                        peer,
                        request_id,
                        reason,
                    });
                }
                event => return ProcessEvent::Transport(event),
            }
        }
    }

    fn refresh_peer_observations(&mut self) -> Option<ProcessEvent> {
        let peers = self
            .transport
            .connected_peers()
            .take(MAX_PERIODIC_OBSERVATION_PEERS)
            .collect::<Vec<_>>();
        for peer in peers {
            if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
                return Some(ProcessEvent::OutboundRequestRejected {
                    peer,
                    error: ApplicationSendError::Transport(SendRequestError::QueueFull),
                });
            }
            let Some(nonce) = self.next_nonce() else {
                return Some(ProcessEvent::OutboundRequestRejected {
                    peer,
                    error: ApplicationSendError::Transport(SendRequestError::IdentifierExhausted),
                });
            };
            let addresses = self
                .transport
                .remote_addresses(&peer)
                .map_or_else(Vec::new, <[Multiaddr]>::to_vec);
            match self.send_message(
                peer,
                addresses,
                &ApplicationMessage::RequestObservedAddress { nonce },
            ) {
                Ok(id) => {
                    self.pending_requests
                        .insert(id, PendingRequest::ObservedAddress { nonce });
                }
                Err(error) => {
                    return Some(ProcessEvent::OutboundRequestRejected { peer, error });
                }
            }
        }
        None
    }

    fn on_listening(&mut self, address: Multiaddr) -> ProcessEvent {
        let address = address.with(Protocol::P2p(self.peer_id()));
        if !self.local_addresses.contains(&address)
            && self.local_addresses.len() < MAX_LOCAL_ADDRESSES
        {
            self.local_addresses.push(address.clone());
        }
        ProcessEvent::Transport(TransportEvent::Listening(address))
    }

    fn sync_genesis_peer_bindings(&mut self) {
        let Some(genesis) = &self.genesis_bootstrap else {
            return;
        };
        let members = genesis.manifest.members().to_vec();
        let direct_peers = self.transport.direct_connected_peers().collect::<Vec<_>>();
        for peer in direct_peers {
            let Some(member) = members
                .iter()
                .find(|member| member.peer_id() == peer.to_bytes())
            else {
                continue;
            };
            let matches_identity =
                self.transport
                    .remote_addresses(&peer)
                    .is_some_and(|addresses| {
                        addresses.iter().any(|address| {
                            socket_addr_from_multiaddr(address)
                                .and_then(|endpoint| NetworkIdentity::from_ip(endpoint.ip()).ok())
                                == Some(member.network_identity())
                        })
                    });
            if matches_identity {
                self.verified_peer_nodes
                    .entry(peer)
                    .or_default()
                    .insert(member.node_id());
            }
        }
    }

    fn on_request(
        &mut self,
        peer: PeerId,
        request: &[u8],
        channel: ResponseChannel,
    ) -> Option<ProcessEvent> {
        let message = match ApplicationMessage::decode(request) {
            Ok(message) => message,
            Err(error) => {
                return Some(ProcessEvent::InvalidApplicationRequest {
                    peer,
                    error,
                    channel,
                });
            }
        };
        match message {
            ApplicationMessage::RequestObservedAddress { nonce } => {
                let Some(endpoint) = self.remote_socket_address(peer) else {
                    return Some(ProcessEvent::ApplicationRequest {
                        peer,
                        message: ApplicationMessage::RequestObservedAddress { nonce },
                        channel,
                    });
                };
                let response = ApplicationMessage::ObservedAddress { nonce, endpoint };
                self.send_protocol_response(peer, &response, channel)
            }
            ApplicationMessage::FindNode {
                request_id,
                target,
                limit,
            } => {
                let response = ApplicationMessage::RoutingContacts {
                    request_id,
                    contacts: self.find_node_contacts(&target, usize::from(limit)),
                };
                self.send_protocol_response(peer, &response, channel)
            }
            ApplicationMessage::DirectVote { vote } => {
                Some(self.handle_direct_vote(peer, &vote, channel))
            }
            ApplicationMessage::PopularityQuery { content_id, day } => {
                Some(self.handle_popularity_query(peer, content_id, day, channel))
            }
            ApplicationMessage::DelegatedIngestReport { report } => {
                Some(self.handle_delegated_ingest_report(peer, &report, channel))
            }
            message => Some(ProcessEvent::ApplicationRequest {
                peer,
                message,
                channel,
            }),
        }
    }

    fn handle_delegated_ingest_report(
        &mut self,
        peer: PeerId,
        payload: &[u8],
        channel: ResponseChannel,
    ) -> ProcessEvent {
        let report = match IngestReport::deserialize(payload) {
            Ok(report) => report,
            Err(error) => {
                if let Some(event) =
                    self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
                {
                    return event;
                }
                return ProcessEvent::DelegatedReportRejected { peer, error };
            }
        };
        let scope = report.scope();
        if !self
            .verified_peer_nodes
            .get(&peer)
            .is_some_and(|node_ids| node_ids.contains(&report.node_id()))
        {
            if let Some(event) =
                self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
            {
                return event;
            }
            return ProcessEvent::DelegatedReportRejected {
                peer,
                error: DelegatedIngestError::UnauthorizedIngestNode,
            };
        }
        let Some(authority) = self.delegated_ingest_authorities.get_mut(&scope) else {
            if let Some(event) =
                self.send_error_response(peer, ApplicationErrorCode::NoActiveAuthority, channel)
            {
                return event;
            }
            return ProcessEvent::DelegatedReportRejected {
                peer,
                error: DelegatedIngestError::WrongScope,
            };
        };
        match authority.receiver.accept_report(
            &report,
            report.node_id(),
            &authority.membership,
            &authority.signer,
        ) {
            Ok(acknowledgement) => {
                let response = ApplicationMessage::DelegatedIngestAck {
                    acknowledgement: acknowledgement.canonical_bytes(),
                };
                if let Some(event) = self.send_protocol_response(peer, &response, channel) {
                    return event;
                }
                ProcessEvent::DelegatedReportAccepted {
                    peer,
                    scope,
                    sequence: report.sequence(),
                }
            }
            Err(error) => {
                if let Some(event) =
                    self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
                {
                    return event;
                }
                ProcessEvent::DelegatedReportRejected { peer, error }
            }
        }
    }

    fn handle_direct_vote(
        &mut self,
        peer: PeerId,
        payload: &[u8],
        channel: ResponseChannel,
    ) -> ProcessEvent {
        let vote = match DirectVote::deserialize(payload) {
            Ok(vote) => vote,
            Err(error) => {
                if let Some(event) =
                    self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
                {
                    return event;
                }
                return ProcessEvent::DirectVoteRejected { peer, error };
            }
        };
        let content_id = vote.content_id();
        match self.resolve_client_id(peer) {
            Ok(client_id) if client_id == vote.client_id() => {}
            Ok(_) | Err(_) => {
                if let Some(event) =
                    self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
                {
                    return event;
                }
                return ProcessEvent::DirectVoteRejected {
                    peer,
                    error: DirectIngestError::ClientIdentityMismatch,
                };
            }
        }
        let scope = (content_id, vote.day());
        let Some(authority) = self.direct_authorities.get_mut(&scope) else {
            if let Some(event) =
                self.send_error_response(peer, ApplicationErrorCode::NoActiveAuthority, channel)
            {
                return event;
            }
            return ProcessEvent::NoActiveAuthority { peer, content_id };
        };
        let result = now_unix_millis_i64().and_then(|now_ms| {
            authority
                .state
                .record_vote_and_acknowledge(vote, now_ms, &authority.membership, &authority.signer)
                .map(|(outcome, acknowledgement)| (outcome, acknowledgement.canonical_bytes()))
        });
        match result {
            Ok((outcome, acknowledgement)) => {
                let response = ApplicationMessage::DirectVoteAck { acknowledgement };
                if let Some(event) = self.send_protocol_response(peer, &response, channel) {
                    return event;
                }
                ProcessEvent::DirectVoteAccepted {
                    peer,
                    content_id,
                    outcome,
                }
            }
            Err(error) => {
                if let Some(event) =
                    self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
                {
                    return event;
                }
                ProcessEvent::DirectVoteRejected { peer, error }
            }
        }
    }

    fn handle_popularity_query(
        &mut self,
        peer: PeerId,
        content_id: ContentId,
        day: UtcDay,
        channel: ResponseChannel,
    ) -> ProcessEvent {
        let Some(authority) = self.direct_authorities.get_mut(&(content_id, day)) else {
            if let Some(event) =
                self.send_error_response(peer, ApplicationErrorCode::NoActiveAuthority, channel)
            {
                return event;
            }
            return ProcessEvent::NoActiveAuthority { peer, content_id };
        };
        let result = now_unix_millis_i64().and_then(|now_ms| {
            let status = authority.state.finalize(now_ms)?;
            let (estimate, finalized) = match status {
                DailyPopularityStatus::Provisional { estimate } => (estimate, false),
                DailyPopularityStatus::Finalized { estimate } => (estimate, true),
            };
            SignedPopularityResponse::sign(
                content_id,
                day,
                &authority.membership,
                estimate,
                finalized,
                &authority.signer,
            )
            .map(|response| (estimate, finalized, response.canonical_bytes()))
        });
        match result {
            Ok((estimate, finalized, bytes)) => {
                let response = ApplicationMessage::PopularityResponse { response: bytes };
                if let Some(event) = self.send_protocol_response(peer, &response, channel) {
                    return event;
                }
                ProcessEvent::PopularityQueryServed {
                    peer,
                    content_id,
                    estimate,
                    finalized,
                }
            }
            Err(error) => {
                if let Some(event) =
                    self.send_error_response(peer, ApplicationErrorCode::InvalidRequest, channel)
                {
                    return event;
                }
                ProcessEvent::PopularityQueryRejected { peer, error }
            }
        }
    }

    fn send_error_response(
        &mut self,
        peer: PeerId,
        code: ApplicationErrorCode,
        channel: ResponseChannel,
    ) -> Option<ProcessEvent> {
        self.send_protocol_response(peer, &ApplicationMessage::Error { code }, channel)
    }

    fn resolve_client_id(&self, peer: PeerId) -> Result<ClientId, DirectIngestError> {
        #[cfg(test)]
        if let Some(client_id) = self.test_client_identities.get(&peer) {
            return Ok(*client_id);
        }
        let endpoint = self
            .remote_socket_address(peer)
            .ok_or(DirectIngestError::ClientIdentityMismatch)?;
        let identity = NetworkIdentity::from_ip(endpoint.ip())
            .map_err(|_| DirectIngestError::ClientIdentityMismatch)?;
        Ok(client_id(&identity))
    }

    fn send_protocol_response(
        &mut self,
        peer: PeerId,
        message: &ApplicationMessage,
        channel: ResponseChannel,
    ) -> Option<ProcessEvent> {
        let payload = match message.encode() {
            Ok(payload) => payload,
            Err(error) => {
                return Some(ProcessEvent::InvalidApplicationRequest {
                    peer,
                    error,
                    channel,
                });
            }
        };
        self.transport
            .send_response(channel, payload)
            .err()
            .map(|error| ProcessEvent::ResponseRejected { peer, error })
    }

    fn on_response(
        &mut self,
        peer: PeerId,
        transport_request_id: RequestId,
        response: Vec<u8>,
    ) -> ProcessEvent {
        let Some(pending) = self.pending_requests.remove(&transport_request_id) else {
            return ProcessEvent::Transport(TransportEvent::Response {
                peer,
                request_id: transport_request_id,
                response,
            });
        };
        let message = match ApplicationMessage::decode(&response) {
            Ok(message) => message,
            Err(error) => {
                return ProcessEvent::InvalidApplicationResponse {
                    peer,
                    transport_request_id,
                    error,
                };
            }
        };
        match (pending, message) {
            (
                PendingRequest::ObservedAddress { nonce },
                ApplicationMessage::ObservedAddress {
                    nonce: response_nonce,
                    endpoint,
                },
            ) => {
                let mut observer_node_ids = self
                    .verified_peer_nodes
                    .get(&peer)
                    .map_or_else(Vec::new, |nodes| nodes.iter().copied().collect());
                observer_node_ids.sort_unstable();
                if observer_node_ids.is_empty() {
                    return ProcessEvent::UnverifiedIdentityObserver { peer };
                }
                let results = observer_node_ids
                    .into_iter()
                    .map(|observer_node_id| {
                        let result = self.identity_manager.observe(
                            observer_node_id,
                            nonce,
                            response_nonce,
                            endpoint,
                            true,
                            now_millis(),
                        );
                        (observer_node_id, result)
                    })
                    .collect();
                ProcessEvent::IdentityObservation { peer, results }
            }
            (
                PendingRequest::DelegatedIngestAck {
                    scope,
                    authority_id,
                },
                ApplicationMessage::DelegatedIngestAck { acknowledgement },
            ) => self.handle_delegated_ingest_ack(peer, scope, authority_id, &acknowledgement),
            (
                PendingRequest::FindNode {
                    request_id: expected,
                },
                ApplicationMessage::RoutingContacts {
                    request_id: received,
                    contacts,
                },
            ) if expected == received => {
                if let Some(event) = self.remember_discovered_contacts(peer, &contacts) {
                    return event;
                }
                ProcessEvent::ApplicationResponse {
                    peer,
                    transport_request_id,
                    message: ApplicationMessage::RoutingContacts {
                        request_id: received,
                        contacts,
                    },
                }
            }
            (_, message) => ProcessEvent::ApplicationResponse {
                peer,
                transport_request_id,
                message,
            },
        }
    }

    fn handle_delegated_ingest_ack(
        &mut self,
        peer: PeerId,
        scope: (ContentId, UtcDay, u8),
        authority_id: populus_types::AuthorityId,
        payload: &[u8],
    ) -> ProcessEvent {
        let acknowledgement = match SignedIngestReportAck::deserialize(payload) {
            Ok(acknowledgement) => acknowledgement,
            Err(error) => {
                return ProcessEvent::DelegatedIngestAckRejected { peer, error };
            }
        };
        if acknowledgement.scope() != scope || acknowledgement.signer() != authority_id {
            return ProcessEvent::DelegatedIngestAckRejected {
                peer,
                error: DelegatedIngestError::UnexpectedAcknowledgement,
            };
        }
        let Some(sender) = self.delegated_ingest_senders.get_mut(&scope) else {
            return ProcessEvent::DelegatedIngestAckRejected {
                peer,
                error: DelegatedIngestError::WrongScope,
            };
        };
        let Some(member) = sender.membership.member(authority_id) else {
            return ProcessEvent::DelegatedIngestAckRejected {
                peer,
                error: DelegatedIngestError::UnexpectedAcknowledgement,
            };
        };
        if !self
            .verified_peer_nodes
            .get(&peer)
            .is_some_and(|node_ids| node_ids.contains(&member.node_id()))
        {
            return ProcessEvent::DelegatedIngestAckRejected {
                peer,
                error: DelegatedIngestError::UnauthorizedIngestNode,
            };
        }
        let sequence = acknowledgement.report_sequence();
        match sender
            .state
            .acknowledge(&acknowledgement, &sender.membership)
        {
            Ok(completed) => ProcessEvent::DelegatedIngestAcknowledged {
                peer,
                scope,
                sequence,
                completed,
            },
            Err(error) => ProcessEvent::DelegatedIngestAckRejected { peer, error },
        }
    }

    fn start_peer_discovery(&mut self, peer: PeerId) -> Option<ProcessEvent> {
        if self.pending_requests.len() >= MAX_PENDING_REQUESTS {
            return Some(ProcessEvent::OutboundRequestRejected {
                peer,
                error: ApplicationSendError::Transport(SendRequestError::QueueFull),
            });
        }
        let addresses = self
            .transport
            .remote_addresses(&peer)
            .map_or_else(Vec::new, <[Multiaddr]>::to_vec);
        let Some(nonce) = self.next_nonce() else {
            return Some(ProcessEvent::OutboundRequestRejected {
                peer,
                error: ApplicationSendError::Transport(SendRequestError::IdentifierExhausted),
            });
        };
        let observed_id = match self.send_message(
            peer,
            addresses.clone(),
            &ApplicationMessage::RequestObservedAddress { nonce },
        ) {
            Ok(id) => {
                self.pending_requests
                    .insert(id, PendingRequest::ObservedAddress { nonce });
                None
            }
            Err(ApplicationSendError::Transport(error)) => Some(error),
            Err(ApplicationSendError::Encoding(error)) => {
                return Some(ProcessEvent::InvalidLocalApplicationMessage { peer, error });
            }
        };
        let lookup = self.next_lookup_id;
        let Some(next_lookup_id) = self.next_lookup_id.checked_add(1) else {
            return Some(ProcessEvent::OutboundRequestRejected {
                peer,
                error: ApplicationSendError::Transport(SendRequestError::IdentifierExhausted),
            });
        };
        self.next_lookup_id = next_lookup_id;
        let lookup_result = self.send_message(
            peer,
            addresses,
            &ApplicationMessage::FindNode {
                request_id: lookup,
                target: RoutingKey::from_bytes([0; 32]),
                limit: 20,
            },
        );
        match lookup_result {
            Ok(id) => {
                self.pending_requests
                    .insert(id, PendingRequest::FindNode { request_id: lookup });
                observed_id.map(|error| ProcessEvent::OutboundRequestRejected {
                    peer,
                    error: ApplicationSendError::Transport(error),
                })
            }
            Err(ApplicationSendError::Transport(error)) => {
                Some(ProcessEvent::OutboundRequestRejected {
                    peer,
                    error: ApplicationSendError::Transport(error),
                })
            }
            Err(ApplicationSendError::Encoding(error)) => {
                Some(ProcessEvent::InvalidLocalApplicationMessage { peer, error })
            }
        }
    }

    fn next_nonce(&mut self) -> Option<[u8; 16]> {
        let current = self.next_nonce;
        self.next_nonce = current.checked_add(1)?;
        let mut nonce = [0; 16];
        nonce[..8].copy_from_slice(&current.to_be_bytes());
        nonce[8..].copy_from_slice(&now_millis().to_be_bytes());
        Some(nonce)
    }

    fn find_node_contacts(&self, target: &RoutingKey, limit: usize) -> Vec<RoutingContact> {
        let mut contacts = HashMap::<NodeId, RoutingContact>::new();
        for logical in self.logical_nodes.values() {
            if !self.local_addresses.is_empty() {
                contacts.insert(
                    logical.node_id,
                    RoutingContact {
                        node_id: logical.node_id,
                        identity: logical.network_identity,
                        peer_id: self.peer_id().to_bytes(),
                        addresses: self
                            .local_addresses
                            .iter()
                            .take(8)
                            .map(ToString::to_string)
                            .collect(),
                    },
                );
            }
            for contact in logical.contacts.values() {
                contacts.insert(contact.node_id, contact.clone());
            }
        }
        let mut contacts: Vec<_> = contacts.into_values().collect();
        contacts.sort_unstable_by_key(|contact| {
            (
                XorDistance::between_node_and_key(&contact.node_id, target),
                contact.node_id,
            )
        });
        contacts.truncate(limit);
        contacts
    }

    fn remote_socket_address(&self, peer: PeerId) -> Option<SocketAddr> {
        self.transport
            .remote_addresses(&peer)?
            .iter()
            .find_map(socket_addr_from_multiaddr)
    }

    fn remember_discovered_contacts(
        &mut self,
        source: PeerId,
        contacts: &[RoutingContact],
    ) -> Option<ProcessEvent> {
        for contact in contacts {
            let Some(peer) = PeerId::from_bytes(&contact.peer_id).ok() else {
                return Some(ProcessEvent::InvalidDiscoveredContact { peer: source });
            };
            if contact.node_id != node_id(&contact.identity)
                || contact.addresses.is_empty()
                || contact.addresses.len() > 8
            {
                return Some(ProcessEvent::InvalidDiscoveredContact { peer: source });
            }
            let mut parsed_addresses = Vec::with_capacity(contact.addresses.len());
            for address in &contact.addresses {
                let Ok(address) = address.parse::<Multiaddr>() else {
                    return Some(ProcessEvent::InvalidDiscoveredContact { peer: source });
                };
                if address
                    .iter()
                    .any(|protocol| matches!(protocol, Protocol::P2p(existing) if existing != peer))
                {
                    return Some(ProcessEvent::InvalidDiscoveredContact { peer: source });
                }
                parsed_addresses.push(address);
            }
            let key = (contact.node_id, peer);
            if self.known_contacts.len() >= MAX_DISCOVERED_CONTACTS
                && !self.known_contacts.contains_key(&key)
            {
                return Some(ProcessEvent::DiscoveryLimitReached { peer: source });
            }
            self.known_contacts.insert(key, contact.clone());
            if peer == self.peer_id()
                || peer == source
                || self.auto_dialed.contains(&peer)
                || self.auto_dialed.len() >= MAX_AUTODIALED_CONTACTS
            {
                continue;
            }
            let address = parsed_addresses.into_iter().next().map(|mut parsed| {
                let existing_peer = parsed.iter().find_map(|protocol| match protocol {
                    Protocol::P2p(peer) => Some(peer),
                    _ => None,
                });
                if existing_peer.is_none() {
                    parsed.push(Protocol::P2p(peer));
                }
                parsed
            });
            if let Some(address) = address {
                match self.transport.dial(address) {
                    Ok(()) => {
                        self.auto_dialed.insert(peer);
                    }
                    Err(error) => {
                        return Some(ProcessEvent::ContactDialRejected {
                            peer,
                            reason: error.to_string(),
                        });
                    }
                }
            } else {
                return Some(ProcessEvent::InvalidDiscoveredContact { peer: source });
            }
        }
        None
    }
}

/// Process-level failures for bounded bootstrap and routing operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessError {
    /// Too many explicit bootstrap addresses were supplied.
    BootstrapLimit,
    /// libp2p rejected one bootstrap dial request.
    DialRejected,
    /// The contact did not pass canonical identity, `PeerId`, and address checks.
    InvalidContact,
    /// The target logical node is not active in this process.
    UnknownLogicalNode,
    /// The target routing bucket cannot accept another verified contact.
    RoutingBucketFull,
    /// Authority state, membership scope, local `NodeId`, or signer is invalid.
    InvalidAuthorityConfig,
    /// Delegated-ingest sender or receiver configuration is inconsistent.
    InvalidDelegatedIngestConfig,
    /// No delegated-ingest state is installed for the requested scope.
    UnknownDelegatedIngestState,
    /// No immutable report is waiting to be transmitted.
    NoPendingIngestReport,
    /// The requested authority is absent from the installed membership.
    UnknownAuthority,
    /// The report does not currently await an acknowledgement from this authority.
    AuthorityNotPending,
    /// The selected authority has no verified contact in the local DHT view.
    AuthorityContactUnavailable,
    /// The delegated report could not be encoded as a valid application message.
    InvalidApplicationMessage(ProtocolError),
    /// The bounded transport rejected a delegated report request.
    DelegatedSendRejected(SendRequestError),
    /// The existing delegated-ingest state machine rejected a transition.
    DelegatedIngest(DelegatedIngestError),
    /// The signed genesis manifest or its trust anchor is invalid.
    GenesisManifest(GenesisManifestError),
    /// A genesis manifest was already configured for this process.
    GenesisManifestAlreadyConfigured,
    /// This process's persistent `PeerId` is not listed in the genesis manifest.
    LocalPeerNotInGenesisManifest,
    /// A genesis member's transport public key, `PeerId`, or address is inconsistent.
    InvalidGenesisMember,
    /// A genesis member's direct address does not match its normalized identity.
    InvalidGenesisAddress,
    /// A trusted-genesis transition exceeded the local identity manager's bounds.
    IdentityManager(IdentityManagerError),
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::BootstrapLimit => "bootstrap address limit exceeded",
            Self::DialRejected => "bootstrap dial request was rejected",
            Self::InvalidContact => "routing contact is invalid",
            Self::UnknownLogicalNode => "logical NodeId is not active",
            Self::RoutingBucketFull => "logical routing bucket is full",
            Self::InvalidAuthorityConfig => "direct authority configuration is invalid",
            Self::InvalidDelegatedIngestConfig => "delegated ingest configuration is invalid",
            Self::UnknownDelegatedIngestState => "delegated ingest state is not installed",
            Self::NoPendingIngestReport => "no delegated ingest report is pending",
            Self::UnknownAuthority => "authority is not in the installed membership",
            Self::AuthorityNotPending => "report is not pending at this authority",
            Self::AuthorityContactUnavailable => "authority has no verified routing contact",
            Self::InvalidApplicationMessage(error) => {
                return write!(formatter, "delegated report message is invalid: {error}");
            }
            Self::DelegatedSendRejected(error) => {
                return write!(formatter, "delegated report request failed: {error:?}");
            }
            Self::DelegatedIngest(error) => {
                return write!(formatter, "delegated ingest transition failed: {error}");
            }
            Self::GenesisManifest(error) => {
                return write!(formatter, "genesis manifest rejected: {error}");
            }
            Self::GenesisManifestAlreadyConfigured => "genesis manifest was already configured",
            Self::LocalPeerNotInGenesisManifest => {
                "local PeerId is absent from the genesis manifest"
            }
            Self::InvalidGenesisMember => "genesis member key and PeerId do not match",
            Self::InvalidGenesisAddress => {
                "genesis address is not direct or does not match its network identity"
            }
            Self::IdentityManager(error) => {
                return write!(formatter, "genesis identity activation failed: {error}");
            }
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProcessError {}

fn validate_genesis_member(
    member: &GenesisMember,
) -> Result<(PeerId, Vec<Multiaddr>), ProcessError> {
    let peer =
        PeerId::from_bytes(member.peer_id()).map_err(|_| ProcessError::InvalidGenesisMember)?;
    let public_key = libp2p::identity::ed25519::PublicKey::try_from_bytes(member.public_key())
        .map_err(|_| ProcessError::InvalidGenesisMember)?;
    if libp2p::identity::PublicKey::from(public_key).to_peer_id() != peer {
        return Err(ProcessError::InvalidGenesisMember);
    }
    let mut addresses = Vec::with_capacity(member.addresses().len());
    for address in member.addresses() {
        let mut address: Multiaddr = address
            .parse()
            .map_err(|_| ProcessError::InvalidGenesisAddress)?;
        if address.iter().any(|protocol| {
            matches!(protocol, Protocol::P2pCircuit)
                || matches!(protocol, Protocol::P2p(address_peer) if address_peer != peer)
        }) {
            return Err(ProcessError::InvalidGenesisAddress);
        }
        let endpoint =
            socket_addr_from_multiaddr(&address).ok_or(ProcessError::InvalidGenesisAddress)?;
        let identity = NetworkIdentity::from_ip(endpoint.ip())
            .map_err(|_| ProcessError::InvalidGenesisAddress)?;
        if identity != member.network_identity() {
            return Err(ProcessError::InvalidGenesisAddress);
        }
        if !address
            .iter()
            .any(|protocol| matches!(protocol, Protocol::P2p(_)))
        {
            address.push(Protocol::P2p(peer));
        }
        addresses.push(address);
    }
    Ok((peer, addresses))
}

fn socket_addr_from_multiaddr(address: &Multiaddr) -> Option<SocketAddr> {
    if address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2pCircuit))
    {
        return None;
    }
    let mut ip = None;
    let mut port = None;
    for protocol in address {
        match protocol {
            Protocol::Ip4(value) => ip = Some(IpAddr::V4(value)),
            Protocol::Ip6(value) => ip = Some(IpAddr::V6(value)),
            Protocol::Tcp(value) | Protocol::Udp(value) => port = Some(value),
            _ => {}
        }
    }
    Some(SocketAddr::new(ip?, port?))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

fn now_unix_millis_i64() -> Result<i64, DirectIngestError> {
    i64::try_from(now_millis()).map_err(|_| DirectIngestError::TimeOutOfRange)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use libp2p::identity::Keypair;
    use populus_cluster::{
        AssignmentAlgorithm, AuthorityMember, DelegatedIngestState, DelegationDescriptor,
        DirectIngestPolicy, DirectVote, GenesisManifest, GenesisMember, IngestNode, MembershipView,
        select_authorities,
    };
    use populus_crypto::AuthorityKeypair;
    use populus_types::{ClientId, ContentId, NetworkIdentity, NodeId, RoutingKey, UtcDay};

    use super::{
        ApplicationMessage, IdentityLifecycle, IdentityManagerConfig, PendingRequest,
        PopulusProcess, ProcessError, ProcessEvent, RoutingContact,
    };

    fn process() -> PopulusProcess {
        PopulusProcess::with_identity(
            Keypair::generate_ed25519(),
            IdentityManagerConfig::default(),
        )
        .expect("process")
    }

    fn signed_genesis_manifest(
        local_key: &Keypair,
        trust_key: &AuthorityKeypair,
    ) -> GenesisManifest {
        let members = ["8.8.8.8", "1.1.1.1", "4.4.4.4", "9.9.9.9"]
            .into_iter()
            .enumerate()
            .map(|(index, ip)| {
                let key = if index == 0 {
                    local_key.clone()
                } else {
                    Keypair::generate_ed25519()
                };
                let public_key = key
                    .public()
                    .try_into_ed25519()
                    .expect("Ed25519 identity")
                    .to_bytes();
                GenesisMember::new(
                    NetworkIdentity::from_ip(ip.parse().expect("public address"))
                        .expect("eligible identity"),
                    key.public().to_peer_id().to_bytes(),
                    public_key,
                    vec![format!("/ip4/{ip}/tcp/4001")],
                )
                .expect("valid genesis member")
            })
            .collect::<Vec<_>>();
        GenesisManifest::sign([7; 32], members, trust_key).expect("signed manifest")
    }

    #[test]
    fn trusted_genesis_requires_explicit_manifest_and_quorum() {
        let local_key = Keypair::generate_ed25519();
        let trust_key = AuthorityKeypair::from_secret_key([71; 32]);
        let manifest = signed_genesis_manifest(&local_key, &trust_key);
        let mut process =
            PopulusProcess::with_identity(local_key, IdentityManagerConfig::default())
                .expect("process");
        assert!(
            process
                .try_activate_genesis_manifest()
                .expect("no manifest is not an activation")
                .is_none()
        );
        assert_eq!(
            process.configure_genesis_manifest(manifest.clone(), [72; 32]),
            Err(ProcessError::GenesisManifest(
                populus_cluster::GenesisManifestError::UntrustedSigner
            ))
        );
        let bootstrap_addresses = process
            .configure_genesis_manifest(manifest, trust_key.public_key())
            .expect("trusted manifest");
        assert_eq!(bootstrap_addresses.len(), 3);
        assert_eq!(
            process
                .try_activate_genesis_manifest()
                .expect("incomplete genesis quorum"),
            None
        );
    }

    fn test_authority() -> (PopulusProcess, NodeId, ContentId, UtcDay, MembershipView) {
        let mut process = PopulusProcess::with_identity(
            Keypair::generate_ed25519(),
            IdentityManagerConfig::default(),
        )
        .expect("test process");
        let identity = NetworkIdentity::from_ip("8.8.8.8".parse().expect("public test identity"))
            .expect("identity");
        let local_node = process
            .activate_genesis_identity(identity)
            .expect("explicit test genesis activation");
        let content_id = ContentId::from_digest([42; 32]);
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time after epoch")
                .as_millis(),
        )
        .expect("current milliseconds fit i64");
        let day = UtcDay::from_unix_millis(now_ms);
        let keys: Vec<_> = (0..4)
            .map(|index| {
                AuthorityKeypair::from_secret_key(
                    [u8::try_from(index + 20).expect("key index"); 32],
                )
            })
            .collect();
        let candidates: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(index, key)| {
                let node_id = if index == 0 {
                    local_node
                } else {
                    NodeId::from_bytes([u8::try_from(index).expect("node index"); 32])
                };
                AuthorityMember::new(node_id, key.public_key()).expect("authority member")
            })
            .collect();
        let route = super::DirectIngestState::new(content_id, day, DirectIngestPolicy::default())
            .routing_key();
        let membership = MembershipView::new(
            route,
            1,
            select_authorities(&route, &candidates).expect("select initial test members"),
        )
        .expect("canonical membership");
        let local_authority_id = keys[0].authority_id();
        let local_signer = keys
            .into_iter()
            .find(|key| key.authority_id() == local_authority_id)
            .expect("local authority key");
        process
            .install_direct_authority(
                local_node,
                content_id,
                day,
                membership.clone(),
                DirectIngestPolicy::default(),
                local_signer,
            )
            .expect("install actual direct-ingest state machine");
        (process, local_node, content_id, day, membership)
    }

    #[tokio::test]
    async fn localhost_direct_vote_and_signed_popularity_use_cluster_state_machines() {
        let (mut authority, _, content_id, day, membership) = test_authority();
        let mut client = process();
        authority
            .listen_on(
                populus_network::parse_multiaddr("/ip4/127.0.0.1/tcp/0").expect("listener address"),
            )
            .expect("listen");
        let address = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let ProcessEvent::Transport(populus_network::TransportEvent::Listening(
                    address,
                )) = authority.next_event().await
                {
                    break address;
                }
            }
        })
        .await
        .expect("listener starts");
        let peer = authority.peer_id();
        let client_id = ClientId::from_bytes([7; 32]);
        authority
            .test_client_identities
            .insert(client.peer_id(), client_id);
        let vote = DirectVote::new(content_id, client_id, day);
        client
            .send_direct_vote(peer, vec![address.clone()], vote)
            .expect("send a canonical direct vote");

        let ack = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    event = authority.next_event() => {
                        assert!(
                            !matches!(event, ProcessEvent::DirectVoteRejected { .. }),
                            "authority rejected valid vote: {event:?}"
                        );
                    }
                    event = client.next_event() => {
                        if let ProcessEvent::Transport(
                            populus_network::TransportEvent::Response { response, .. }
                        ) = event
                            && let ApplicationMessage::DirectVoteAck {
                                acknowledgement,
                            } = ApplicationMessage::decode(&response)
                                .expect("typed authority response")
                        {
                            break populus_cluster::SignedDirectVoteAck::deserialize(
                                &acknowledgement,
                            )
                            .expect("signed vote acknowledgement");
                        }
                    }
                }
            }
        })
        .await
        .expect("direct vote response arrives");
        ack.verify(&membership)
            .expect("authority acknowledgement is signed by exact membership");

        client
            .query_popularity(peer, vec![address], content_id, day)
            .expect("send popularity query");
        let response = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    event = authority.next_event() => {
                        assert!(
                            !matches!(event, ProcessEvent::PopularityQueryRejected { .. }),
                            "authority rejected valid popularity query: {event:?}"
                        );
                    }
                    event = client.next_event() => {
                        if let ProcessEvent::Transport(
                            populus_network::TransportEvent::Response { response, .. }
                        ) = event
                            && let ApplicationMessage::PopularityResponse {
                                response,
                            } = ApplicationMessage::decode(&response)
                                .expect("typed popularity response")
                        {
                            break populus_cluster::SignedPopularityResponse::deserialize(
                                &response,
                            )
                            .expect("signed popularity result");
                        }
                    }
                }
            }
        })
        .await
        .expect("popularity response arrives");
        response
            .verify(&membership)
            .expect("popularity is signed under same membership");
        assert_eq!(response.scope(), (content_id, day));
        assert_eq!(response.estimate(), 1.0);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn localhost_delegated_report_uses_existing_sender_and_receiver_state_machines() {
        let content_id = ContentId::from_digest([71; 32]);
        let day = UtcDay::new(10);
        let route = super::DirectIngestState::new(content_id, day, DirectIngestPolicy::default())
            .routing_key();
        let mut authority_keys = Vec::new();
        let mut members = Vec::new();
        for (index, ip) in ["8.8.8.8", "1.1.1.1", "4.4.4.4", "9.9.9.9"]
            .into_iter()
            .enumerate()
        {
            let identity = NetworkIdentity::from_ip(ip.parse().expect("public identity"))
                .expect("eligible identity");
            let node_id = populus_crypto::node_id(&identity);
            let key = AuthorityKeypair::from_secret_key(
                [u8::try_from(index + 41).expect("key index"); 32],
            );
            members
                .push(AuthorityMember::new(node_id, key.public_key()).expect("authority member"));
            authority_keys.push((node_id, key));
        }
        let membership = MembershipView::new(
            route,
            1,
            select_authorities(&route, &members).expect("canonical authority selection"),
        )
        .expect("membership");
        let authority_identity = NetworkIdentity::from_ip("8.8.8.8".parse().expect("authority IP"))
            .expect("authority identity");
        let authority_node = populus_crypto::node_id(&authority_identity);
        let authority_id = membership
            .members()
            .iter()
            .find(|member| member.node_id() == authority_node)
            .expect("authority is in membership")
            .authority_id();
        let signer = authority_keys
            .into_iter()
            .find(|(_, key)| key.authority_id() == authority_id)
            .expect("authority signer")
            .1;

        let mut authority = PopulusProcess::with_identity(
            Keypair::generate_ed25519(),
            IdentityManagerConfig::default(),
        )
        .expect("authority process");
        authority
            .activate_genesis_identity(authority_identity)
            .expect("activate test authority");
        let ingest_identity = NetworkIdentity::from_ip("9.9.9.9".parse().expect("ingest IP"))
            .expect("ingest identity");
        let ingest_node = populus_crypto::node_id(&ingest_identity);
        let mut ingest = PopulusProcess::with_identity(
            Keypair::generate_ed25519(),
            IdentityManagerConfig::default(),
        )
        .expect("ingest process");
        ingest
            .activate_genesis_identity(ingest_identity)
            .expect("activate test ingest node");

        let descriptor = DelegationDescriptor::new(
            AssignmentAlgorithm::SaltedClientHash,
            vec![IngestNode::new(ingest_node)],
            0,
        )
        .expect("delegation descriptor");
        authority
            .install_delegated_report_receiver(
                authority_node,
                &descriptor,
                membership.clone(),
                signer,
                (content_id, day, 0),
            )
            .expect("install authority report receiver");

        authority
            .listen_on(
                populus_network::parse_multiaddr("/ip4/127.0.0.1/tcp/0")
                    .expect("authority listener"),
            )
            .expect("start authority listener");
        ingest
            .listen_on(
                populus_network::parse_multiaddr("/ip4/127.0.0.1/tcp/0").expect("ingest listener"),
            )
            .expect("start ingest listener");
        let authority_address = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let ProcessEvent::Transport(populus_network::TransportEvent::Listening(
                    address,
                )) = authority.next_event().await
                {
                    break address;
                }
            }
        })
        .await
        .expect("authority listener starts");
        let ingest_address = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let ProcessEvent::Transport(populus_network::TransportEvent::Listening(
                    address,
                )) = ingest.next_event().await
                {
                    break address;
                }
            }
        })
        .await
        .expect("ingest listener starts");

        authority
            .add_verified_contact(
                authority_node,
                RoutingContact {
                    node_id: ingest_node,
                    identity: ingest_identity,
                    peer_id: ingest.peer_id().to_bytes(),
                    addresses: vec![ingest_address.to_string()],
                },
                ingest.peer_id(),
            )
            .expect("bind authenticated ingest peer");
        ingest
            .add_verified_contact(
                ingest_node,
                RoutingContact {
                    node_id: authority_node,
                    identity: authority_identity,
                    peer_id: authority.peer_id().to_bytes(),
                    addresses: vec![authority_address.to_string()],
                },
                authority.peer_id(),
            )
            .expect("bind authenticated authority peer");

        let scope = (content_id, day, 0);
        let sender_state = DelegatedIngestState::new(content_id, day, 0, ingest_node, &membership)
            .expect("sender state");
        ingest
            .install_delegated_ingest_sender(ingest_node, membership, sender_state)
            .expect("install sender state");
        ingest
            .record_delegated_client(scope, ClientId::from_bytes([82; 32]))
            .expect("record client");
        assert_eq!(
            ingest
                .rollover_delegated_ingest(scope)
                .expect("roll over sketch"),
            Some(1)
        );
        ingest
            .send_delegated_ingest_report(ingest_node, scope, authority_id)
            .expect("send report through transport");

        let (accepted, acknowledged) = tokio::time::timeout(Duration::from_secs(15), async {
            let mut accepted = false;
            loop {
                tokio::select! {
                    event = authority.next_event() => match event {
                        ProcessEvent::DelegatedReportAccepted { sequence: 1, .. } => {
                            accepted = true;
                        }
                        ProcessEvent::DelegatedReportRejected { .. } => {
                            break (false, None);
                        }
                        _ => {}
                    },
                    event = ingest.next_event() => {
                        if let ProcessEvent::DelegatedIngestAcknowledged {
                            scope: received_scope,
                            sequence: 1,
                            completed,
                            ..
                        } = event
                        {
                            break (accepted, Some((received_scope, completed)));
                        }
                    }
                }
            }
        })
        .await
        .expect("report and signed acknowledgement complete");
        assert!(accepted, "authority rejected the report");
        let acknowledged = acknowledged.expect("sender applied signed ACK");
        assert_eq!(acknowledged, (scope, false));
    }

    #[test]
    fn logical_nodes_keep_independent_routing_tables() {
        let mut process = process();
        let identities = [
            (
                "8.8.8.8",
                NetworkIdentity::from_ip("8.8.8.8".parse().expect("IPv4")).expect("identity"),
            ),
            (
                "1.1.1.1",
                NetworkIdentity::from_ip("1.1.1.1".parse().expect("IPv4")).expect("identity"),
            ),
        ];
        let mut node_ids = Vec::new();
        let local_peer = process.peer_id();
        for (ip, identity) in identities {
            for index in 0..3 {
                process
                    .observe_address(
                        NodeId::from_bytes([index + 1; 32]),
                        [index; 16],
                        [index; 16],
                        format!("{ip}:4000").parse().expect("endpoint"),
                        true,
                        u64::from(index),
                    )
                    .expect("independent public observations");
            }
            for index in 1..=3 {
                let verifier = NodeId::from_bytes([index; 32]);
                let nonce = [index; 16];
                process
                    .begin_verification(identity, verifier, nonce, 10)
                    .expect("begin verification");
                process
                    .record_verification(identity, verifier, nonce, local_peer, true, true, 100, 10)
                    .expect("verification");
            }
            node_ids.push(process.activate_identity(identity, 11).expect("activate"));
        }
        assert_ne!(node_ids[0], node_ids[1]);
        assert_eq!(process.logical_node_count(), 2);
        assert!(
            process
                .logical_node(&node_ids[0])
                .expect("first")
                .routing_table()
                .is_empty()
        );
        assert!(
            process
                .logical_node(&node_ids[1])
                .expect("second")
                .routing_table()
                .is_empty()
        );
        process
            .begin_identity_retirement(identities[0].1)
            .expect("begin first-node retirement");
        process
            .finish_identity_retirement(identities[0].1)
            .expect("finish first-node retirement");
        assert_eq!(process.logical_node_count(), 1);
        assert!(process.logical_node(&node_ids[1]).is_some());
    }

    #[test]
    fn invalid_identity_binding_never_enters_routing_state() {
        let mut process = process();
        let identity =
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("IPv4")).expect("identity");
        let contact = RoutingContact {
            node_id: NodeId::from_bytes([0; 32]),
            identity,
            peer_id: Keypair::generate_ed25519().public().to_peer_id().to_bytes(),
            addresses: vec!["/ip4/8.8.8.8/tcp/4001".to_owned()],
        };
        assert_eq!(
            process.add_verified_contact(NodeId::from_bytes([1; 32]), contact, process.peer_id()),
            Err(ProcessError::InvalidContact)
        );
        assert_eq!(
            process.closest_contacts(
                NodeId::from_bytes([1; 32]),
                &RoutingKey::from_bytes([0; 32]),
                20,
            ),
            Vec::new()
        );
    }

    #[test]
    fn peer_ids_sharing_one_node_id_count_as_one_observer() {
        let mut process = PopulusProcess::with_identity(
            Keypair::generate_ed25519(),
            IdentityManagerConfig::default(),
        )
        .expect("test process");
        let local_identity =
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("local identity")).expect("identity");
        let local_node = process
            .activate_genesis_identity(local_identity)
            .expect("activate local test identity");
        let shared_identity = NetworkIdentity::from_ip("9.9.9.9".parse().expect("shared identity"))
            .expect("identity");
        let unique_identity = NetworkIdentity::from_ip("1.1.1.1".parse().expect("unique identity"))
            .expect("identity");
        let other_identity =
            NetworkIdentity::from_ip("8.8.4.4".parse().expect("other identity")).expect("identity");
        let endpoint = "4.4.4.4:4000".parse().expect("public endpoint");
        let mut peers = Vec::new();

        for identity in [
            shared_identity,
            shared_identity,
            unique_identity,
            other_identity,
        ] {
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            let contact = RoutingContact {
                node_id: populus_crypto::node_id(&identity),
                identity,
                peer_id: peer.to_bytes(),
                addresses: vec!["/ip4/4.4.4.4/tcp/4000".to_owned()],
            };
            let observer_node_id = contact.node_id;
            process
                .add_verified_contact(local_node, contact, peer)
                .expect("register test-verified peer");
            peers.push((peer, observer_node_id));
        }

        for (index, (peer, observer_node_id)) in peers.into_iter().enumerate() {
            let nonce = [1; 16];
            let request_id = process
                .send_message(
                    peer,
                    Vec::new(),
                    &ApplicationMessage::RequestObservedAddress { nonce },
                )
                .expect("allocate test request");
            process
                .pending_requests
                .insert(request_id, PendingRequest::ObservedAddress { nonce });
            let response = ApplicationMessage::ObservedAddress { nonce, endpoint }
                .encode()
                .expect("encode observed address");
            let event = process.on_response(peer, request_id, response);
            let results = match event {
                ProcessEvent::IdentityObservation { results, .. } => Some(results),
                _ => None,
            }
            .expect("verified peer response must be mapped to NodeId evidence");
            assert_eq!(results.len(), 1);
            assert_eq!(results[0].0, observer_node_id);
            let expected = if index == 3 {
                IdentityLifecycle::Discovered
            } else {
                IdentityLifecycle::Unknown
            };
            assert_eq!(
                results[0].1.as_ref().expect("observation accepted"),
                &expected
            );
        }
    }

    #[tokio::test]
    async fn localhost_bootstrap_discovers_an_active_node_without_a_local_node_id() {
        let mut bootstrap = process();
        let mut joining = process();
        bootstrap
            .listen_on(
                populus_network::parse_multiaddr("/ip4/127.0.0.1/tcp/0").expect("listen address"),
            )
            .expect("listen");
        let address = tokio::time::timeout(Duration::from_secs(15), async {
            loop {
                if let ProcessEvent::Transport(populus_network::TransportEvent::Listening(
                    address,
                )) = bootstrap.next_event().await
                {
                    break address;
                }
            }
        })
        .await
        .expect("bootstrap listener starts");

        let identity =
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("public IPv4")).expect("identity");
        for index in 0..3 {
            bootstrap
                .observe_address(
                    NodeId::from_bytes([index + 1; 32]),
                    [index; 16],
                    [index; 16],
                    "8.8.8.8:4000".parse().expect("observed endpoint"),
                    true,
                    u64::from(index),
                )
                .expect("identity observation");
        }
        let peer = bootstrap.peer_id();
        for index in 1..=3 {
            let verifier = NodeId::from_bytes([index; 32]);
            let challenge = [index; 16];
            bootstrap
                .begin_verification(identity, verifier, challenge, 10)
                .expect("begin verification");
            bootstrap
                .record_verification(identity, verifier, challenge, peer, true, true, 100, 10)
                .expect("verification");
        }
        let expected_node = bootstrap
            .activate_identity(identity, 11)
            .expect("activate identity");
        joining
            .bootstrap([address])
            .expect("connect to bootstrap entry point");

        let mut saw_identity_observation = false;
        let mut discovered_node = false;
        tokio::time::timeout(Duration::from_secs(15), async {
            while !saw_identity_observation || !discovered_node {
                tokio::select! {
                    event = joining.next_event() => match event {
                        ProcessEvent::UnverifiedIdentityObserver { peer: observed_peer } => {
                            assert_eq!(observed_peer, bootstrap.peer_id());
                            saw_identity_observation = true;
                        }
                        ProcessEvent::ApplicationResponse {
                            message: ApplicationMessage::RoutingContacts { contacts, .. },
                            ..
                        } => {
                            discovered_node = contacts.iter().any(|contact| {
                                contact.node_id == expected_node
                            });
                        }
                        _ => {}
                    },
                    _ = bootstrap.next_event() => {}
                }
            }
        })
        .await
        .expect("bootstrap discovers contacts and rejects loopback identity evidence");
        assert_eq!(joining.logical_node_count(), 0);
    }
}
