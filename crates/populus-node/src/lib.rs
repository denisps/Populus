//! Node-level API joining Populus identities and direct votes to the libp2p transport.

use populus_cluster::{DirectIngestError, DirectVote};
use populus_network::{Transport, TransportEvent};
use populus_types::NodeId;

pub use libp2p::{Multiaddr, PeerId};
pub use populus_network::{RequestId, ResponseChannel, SendRequestError, SendResponseError};
pub use populus_types::NetworkIdentity;

/// A malformed direct-vote payload rejected by the existing canonical decoder.
pub type DirectVoteRejection = DirectIngestError;

/// Application-facing events emitted by [`Node`].
#[derive(Debug)]
pub enum NodeEvent {
    /// An inbound request decoded as a direct vote, or rejected by its decoder.
    DirectVoteRequest {
        /// The transport peer that sent the request.
        peer: PeerId,
        /// The canonical vote or the typed reason decoding failed.
        vote: Result<DirectVote, DirectVoteRejection>,
        /// Capability used to return the transport response.
        channel: ResponseChannel,
    },
    /// A non-request event forwarded from the transport adapter.
    Transport(TransportEvent),
}

/// A Populus node owns its transport and a distinct, caller-supplied routing identity.
///
/// The transport `PeerId` authenticates a libp2p connection; the `NodeId` is the
/// scarce-network-derived position used by Populus routing. No conversion exists
/// between these identities.
///
/// ```compile_fail
/// use populus_node::Node;
/// use populus_types::NodeId;
///
/// let node = Node::new(NodeId::from_bytes([0; 32])).unwrap();
/// let _node_id = NodeId::from_bytes(node.peer_id().to_bytes());
/// ```
pub struct Node {
    transport: Transport,
    node_id: NodeId,
}

impl Node {
    /// Creates a node with a fresh libp2p transport and the supplied Populus `NodeId`.
    ///
    /// # Errors
    ///
    /// Returns an error if the transport cannot be constructed.
    pub fn new(node_id: NodeId) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            transport: Transport::new()?,
            node_id,
        })
    }

    /// Returns this node's libp2p transport identity.
    #[must_use]
    pub fn peer_id(&self) -> PeerId {
        self.transport.peer_id()
    }

    /// Returns this node's caller-supplied Populus routing identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Starts listening on a multiaddress.
    ///
    /// # Errors
    ///
    /// Returns an error if the address cannot be bound.
    pub fn listen_on(
        &mut self,
        address: Multiaddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.transport.listen_on(address)
    }

    /// Starts dialing a multiaddress.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid for dialing.
    pub fn dial(
        &mut self,
        address: Multiaddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.transport.dial(address)
    }

    /// Sends an application request through the bounded transport queue.
    ///
    /// # Errors
    ///
    /// Returns the transport's typed size, queue, or identifier-capacity error.
    pub fn send_request(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        request: Vec<u8>,
    ) -> Result<RequestId, SendRequestError> {
        self.transport.send_request(peer, addresses, request)
    }

    /// Sends a canonical direct-vote request through the transport.
    ///
    /// # Errors
    ///
    /// Returns the transport's typed size, queue, or identifier-capacity error.
    pub fn send_direct_vote(
        &mut self,
        peer: PeerId,
        addresses: Vec<Multiaddr>,
        vote: DirectVote,
    ) -> Result<RequestId, SendRequestError> {
        self.send_request(peer, addresses, vote.canonical_bytes())
    }

    /// Replies to an inbound request.
    ///
    /// # Errors
    ///
    /// Returns the transport's typed response error.
    pub fn send_response(
        &mut self,
        channel: ResponseChannel,
        response: Vec<u8>,
    ) -> Result<(), SendResponseError> {
        self.transport.send_response(channel, response)
    }

    /// Waits for the next event, decoding every inbound request as a direct vote.
    ///
    /// Invalid requests are returned as [`NodeEvent::DirectVoteRequest`] with a
    /// typed [`DirectVoteRejection`]; they are never presented as successful votes.
    pub async fn next_event(&mut self) -> NodeEvent {
        match self.transport.next_event().await {
            TransportEvent::Request {
                peer,
                request,
                channel,
            } => NodeEvent::DirectVoteRequest {
                peer,
                vote: DirectVote::deserialize(&request),
                channel,
            },
            event => NodeEvent::Transport(event),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use libp2p::core::multiaddr::Protocol;
    use populus_cluster::DirectVote;
    use populus_types::{ClientId, ContentId, NodeId, UtcDay};

    use super::{NetworkIdentity, Node, NodeEvent};

    const EVENT_TIMEOUT: Duration = Duration::from_secs(15);

    async fn listening_address(node: &mut Node) -> super::Multiaddr {
        let peer = node.peer_id();
        tokio::time::timeout(EVENT_TIMEOUT, async {
            loop {
                if let NodeEvent::Transport(super::TransportEvent::Listening(address)) =
                    node.next_event().await
                {
                    break address.with(Protocol::P2p(peer));
                }
            }
        })
        .await
        .expect("node begins listening")
    }

    async fn direct_vote_round_trip(protocol: &str) {
        let mut server = Node::new(NodeId::from_bytes([1; 32])).expect("server node");
        let mut client = Node::new(NodeId::from_bytes([2; 32])).expect("client node");
        server
            .listen_on(populus_network::parse_multiaddr(protocol).expect("listen address"))
            .expect("listen");
        let address = listening_address(&mut server).await;

        let vote = DirectVote::new(
            ContentId::from_digest([3; 32]),
            ClientId::from_bytes([4; 32]),
            UtcDay::new(20_000),
        );
        let request_id = client
            .send_direct_vote(server.peer_id(), vec![address], vote)
            .expect("direct vote fits the transport queue");

        tokio::time::timeout(EVENT_TIMEOUT, async {
            let mut response_received = false;
            while !response_received {
                tokio::select! {
                    event = server.next_event() => {
                        if let NodeEvent::DirectVoteRequest {
                            vote: Ok(received),
                            channel,
                            ..
                        } = event
                        {
                            assert_eq!(received.content_id(), vote.content_id());
                            assert_eq!(received.client_id(), vote.client_id());
                            assert_eq!(received.day(), vote.day());
                            server.send_response(channel, Vec::new())
                                .expect("response channel is open");
                        }
                    }
                    event = client.next_event() => {
                        if let NodeEvent::Transport(super::TransportEvent::Response {
                            request_id: received_id,
                            response,
                            ..
                        }) = event
                        {
                            assert_eq!(received_id, request_id);
                            assert_eq!(response, Vec::<u8>::new());
                            response_received = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("direct vote exchange completes");
    }

    #[tokio::test]
    async fn tcp_loopback_exchanges_and_decodes_direct_vote() {
        direct_vote_round_trip("/ip4/127.0.0.1/tcp/0").await;
    }

    #[tokio::test]
    async fn quic_loopback_exchanges_and_decodes_direct_vote() {
        direct_vote_round_trip("/ip4/127.0.0.1/udp/0/quic-v1").await;
    }

    #[tokio::test]
    async fn malformed_inbound_payload_is_a_typed_rejection() {
        let mut server = Node::new(NodeId::from_bytes([5; 32])).expect("server node");
        let mut client = Node::new(NodeId::from_bytes([6; 32])).expect("client node");
        server
            .listen_on(
                populus_network::parse_multiaddr("/ip4/127.0.0.1/tcp/0").expect("listen address"),
            )
            .expect("listen");
        let address = listening_address(&mut server).await;
        client
            .send_request(
                server.peer_id(),
                vec![address],
                b"not a canonical direct vote".to_vec(),
            )
            .expect("malformed payload fits the transport queue");

        tokio::time::timeout(EVENT_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = server.next_event() => {
                        if let NodeEvent::DirectVoteRequest { vote, .. } = event {
                            assert_eq!(
                                vote,
                                Err(super::DirectVoteRejection::InvalidStateEncoding)
                            );
                            break;
                        }
                    }
                    _ = client.next_event() => {}
                }
            }
        })
        .await
        .expect("malformed vote is rejected by the node decoder");
    }

    #[test]
    fn peer_id_and_node_id_remain_distinct() {
        let identity = NetworkIdentity::from_ip("8.8.8.8".parse().expect("IPv4 address"))
            .expect("public address is eligible");
        let node_id = populus_crypto::node_id(&identity);
        let node = Node::new(node_id).expect("node");

        assert_ne!(
            node.peer_id().to_bytes().as_slice(),
            node.node_id().as_bytes()
        );
    }

    #[tokio::test]
    async fn identify_or_ping_event_is_observed_on_loopback() {
        let mut server = Node::new(NodeId::from_bytes([7; 32])).expect("server node");
        let mut client = Node::new(NodeId::from_bytes([8; 32])).expect("client node");
        server
            .listen_on(
                populus_network::parse_multiaddr("/ip4/127.0.0.1/tcp/0").expect("listen address"),
            )
            .expect("listen");
        let address = listening_address(&mut server).await;
        client.dial(address).expect("dial");

        tokio::time::timeout(EVENT_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = server.next_event() => {
                        if matches!(event, NodeEvent::Transport(
                            super::TransportEvent::Identify(_) | super::TransportEvent::Ping(_)
                        )) {
                            break;
                        }
                    }
                    event = client.next_event() => {
                        if matches!(event, NodeEvent::Transport(
                            super::TransportEvent::Identify(_) | super::TransportEvent::Ping(_)
                        )) {
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("identify or ping behaviour event is forwarded");
    }
}
