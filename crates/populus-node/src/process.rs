use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

use libp2p::{Multiaddr, PeerId, core::multiaddr::Protocol, identity::Keypair};
use populus_crypto::node_id;
use populus_network::{
    RequestId, ResponseChannel, SendRequestError, SendResponseError, Transport, TransportEvent,
};
use populus_protocol::{ApplicationMessage, ProtocolError, RoutingContact};
use populus_routing::{InsertError, RoutingTable};
use populus_types::{NetworkIdentity, NodeId, RoutingKey, XorDistance};

use crate::{
    ApplicationSendError, DirectVoteRejection, IdentityLifecycle, IdentityManager,
    IdentityManagerConfig, IdentityManagerError, PeerIdentityStore, load_or_create_peer_identity,
};

const MAX_BOOTSTRAP_PEERS: usize = 32;
const MAX_DISCOVERED_CONTACTS: usize = 256;
const MAX_AUTODIALED_CONTACTS: usize = 32;
const MAX_LOCAL_ADDRESSES: usize = 16;

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
        vote: Result<populus_cluster::DirectVote, DirectVoteRejection>,
        /// Response capability.
        channel: ResponseChannel,
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
        /// Normalized-identity lifecycle transition or typed rejection.
        result: Result<IdentityLifecycle, IdentityManagerError>,
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
    ObservedAddress { nonce: [u8; 16] },
    FindNode { request_id: u64 },
}

/// Shared transport process managing multiple independently routed logical nodes.
pub struct PopulusProcess {
    transport: Transport,
    identity_manager: IdentityManager,
    logical_nodes: HashMap<NodeId, LogicalNode>,
    known_contacts: HashMap<(NodeId, PeerId), RoutingContact>,
    pending_requests: HashMap<RequestId, PendingRequest>,
    local_addresses: Vec<Multiaddr>,
    auto_dialed: HashSet<PeerId>,
    next_nonce: u64,
    next_lookup_id: u64,
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
            pending_requests: HashMap::new(),
            local_addresses: Vec::new(),
            auto_dialed: HashSet::new(),
            next_nonce: 0,
            next_lookup_id: 0,
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

    /// Applies a direct remote observation to the identity manager.
    ///
    /// This is useful to inject address evidence from a platform observer or
    /// deterministic simulation. Runtime responses are nonce-correlated by
    /// [`Self::next_event`].
    ///
    /// # Errors
    ///
    /// Returns the identity manager's typed validation or resource-limit error.
    pub fn observe_address(
        &mut self,
        observer: PeerId,
        expected_nonce: [u8; 16],
        response_nonce: [u8; 16],
        endpoint: SocketAddr,
        is_direct: bool,
        now_ms: u64,
    ) -> Result<IdentityLifecycle, IdentityManagerError> {
        self.identity_manager.observe(
            observer,
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

    /// Activates an identity only under explicitly enabled genesis/test-network mode.
    ///
    /// # Errors
    ///
    /// Returns an identity-manager error if genesis mode is disabled or capacity
    /// is exhausted.
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
        let logical = self
            .logical_nodes
            .get_mut(&local_node)
            .ok_or(ProcessError::UnknownLogicalNode)?;
        match logical.routing.insert(contact.node_id) {
            Ok(()) | Err(InsertError::Duplicate) => {
                logical.contacts.insert(contact.node_id, contact);
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
            let event = self.transport.next_event().await;
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

    fn on_listening(&mut self, address: Multiaddr) -> ProcessEvent {
        let address = address.with(Protocol::P2p(self.peer_id()));
        if !self.local_addresses.contains(&address)
            && self.local_addresses.len() < MAX_LOCAL_ADDRESSES
        {
            self.local_addresses.push(address.clone());
        }
        ProcessEvent::Transport(TransportEvent::Listening(address))
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
            ApplicationMessage::DirectVote { vote } => Some(ProcessEvent::DirectVoteRequest {
                peer,
                vote: populus_cluster::DirectVote::deserialize(&vote),
                channel,
            }),
            message => Some(ProcessEvent::ApplicationRequest {
                peer,
                message,
                channel,
            }),
        }
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
                let result = self.identity_manager.observe(
                    peer,
                    nonce,
                    response_nonce,
                    endpoint,
                    true,
                    now_millis(),
                );
                ProcessEvent::IdentityObservation { peer, result }
            }
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

    fn start_peer_discovery(&mut self, peer: PeerId) -> Option<ProcessEvent> {
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
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::BootstrapLimit => "bootstrap address limit exceeded",
            Self::DialRejected => "bootstrap dial request was rejected",
            Self::InvalidContact => "routing contact is invalid",
            Self::UnknownLogicalNode => "logical NodeId is not active",
            Self::RoutingBucketFull => "logical routing bucket is full",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProcessError {}

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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use libp2p::identity::Keypair;
    use populus_types::{NetworkIdentity, NodeId, RoutingKey};

    use super::{
        IdentityManagerConfig, PopulusProcess, ProcessError, ProcessEvent, RoutingContact,
    };

    fn process() -> PopulusProcess {
        PopulusProcess::with_identity(
            Keypair::generate_ed25519(),
            IdentityManagerConfig::default(),
        )
        .expect("process")
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
                        Keypair::generate_ed25519().public().to_peer_id(),
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
                    Keypair::generate_ed25519().public().to_peer_id(),
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
                        ProcessEvent::IdentityObservation { result, .. } => {
                            assert_eq!(
                                result,
                                Err(super::IdentityManagerError::IneligibleAddress)
                            );
                            saw_identity_observation = true;
                        }
                        ProcessEvent::ApplicationResponse {
                            message: super::ApplicationMessage::RoutingContacts { contacts, .. },
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
