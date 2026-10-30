//! Bounded request-response transport over libp2p TCP and QUIC.

use std::{
    collections::{HashMap, VecDeque},
    io,
    time::Duration,
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{
    Multiaddr, StreamProtocol, SwarmBuilder, identify, noise, ping, request_response,
    swarm::{NetworkBehaviour, Swarm},
    tcp, yamux,
};

/// Maximum request or response payload size, excluding the four-byte frame header.
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
/// Maximum number of outbound requests active at the transport layer.
pub const MAX_CONCURRENT_REQUESTS: usize = 64;
/// Maximum number of outbound requests buffered while the active limit is full.
pub const MAX_QUEUED_REQUESTS: usize = 64;
const PROTOCOL_ID: &str = "/populus/transport/1";

struct PendingRequest {
    id: RequestId,
    peer: libp2p::PeerId,
    addresses: Vec<Multiaddr>,
    request: Vec<u8>,
}

/// Reads one length-prefixed frame, rejecting oversized input before allocation.
///
/// The wire format is a four-byte unsigned big-endian byte length followed by
/// exactly that many payload bytes.
///
/// # Errors
///
/// Returns an I/O error for truncated input or when the declared size exceeds
/// [`MAX_FRAME_SIZE`].
pub async fn read_frame<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0; 4];
    reader.read_exact(&mut header).await?;
    let length = usize::try_from(u32::from_be_bytes(header))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame length overflow"))?;
    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds maximum size",
        ));
    }

    let mut payload = Vec::new();
    (&mut *reader)
        .take(length as u64)
        .read_to_end(&mut payload)
        .await?;
    if payload.len() != length {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated frame payload",
        ));
    }
    Ok(payload)
}

/// Writes one length-prefixed frame.
///
/// # Errors
///
/// Returns an I/O error when the payload exceeds [`MAX_FRAME_SIZE`] or when
/// writing to the underlying stream fails.
pub async fn write_frame<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds maximum size",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame length overflow"))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await
}

/// Codec for the bounded length-prefixed request-response format.
#[derive(Clone, Default)]
struct FrameCodec;

impl request_response::Codec for FrameCodec {
    type Protocol = StreamProtocol;
    type Request = Vec<u8>;
    type Response = Vec<u8>;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io).await
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &request).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &response).await
    }
}

/// Combined libp2p health, peer-identification, and application request behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "BehaviourEvent")]
struct Behaviour {
    /// Application messages; deliberately independent of Populus routing identities.
    pub requests: request_response::Behaviour<FrameCodec>,
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

/// Events emitted by the network behaviours.
#[derive(Debug)]
enum BehaviourEvent {
    /// Application request-response event.
    Requests(request_response::Event<Vec<u8>, Vec<u8>>),
    /// Peer identification event.
    Identify(Box<identify::Event>),
    /// Ping health event.
    Ping(ping::Event),
}

impl From<request_response::Event<Vec<u8>, Vec<u8>>> for BehaviourEvent {
    fn from(event: request_response::Event<Vec<u8>, Vec<u8>>) -> Self {
        Self::Requests(event)
    }
}

impl From<identify::Event> for BehaviourEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}

impl From<ping::Event> for BehaviourEvent {
    fn from(event: ping::Event) -> Self {
        Self::Ping(event)
    }
}

impl Behaviour {
    fn new(key: &libp2p::identity::Keypair) -> Self {
        Self {
            requests: request_response::Behaviour::with_codec(
                FrameCodec,
                [(
                    StreamProtocol::new(PROTOCOL_ID),
                    request_response::ProtocolSupport::Full,
                )],
                request_response::Config::default()
                    .with_request_timeout(Duration::from_secs(30))
                    .with_max_concurrent_streams(64),
            ),
            identify: identify::Behaviour::new(identify::Config::new(
                PROTOCOL_ID.to_owned(),
                key.public(),
            )),
            ping: ping::Behaviour::default(),
        }
    }
}

/// Request identifier scoped to one local transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(u64);

/// Failure to accept an outbound request into the bounded transport queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendRequestError {
    /// The request payload exceeds [`MAX_FRAME_SIZE`].
    PayloadTooLarge,
    /// The combined active, queued, and pending-failure capacity is full.
    QueueFull,
    /// The local request identifier space is exhausted.
    IdentifierExhausted,
}

/// A pending inbound response capability.
#[derive(Debug)]
pub struct ResponseChannel(request_response::ResponseChannel<Vec<u8>>);

/// Failure to send an inbound response.
#[derive(Debug)]
pub enum SendResponseError {
    /// The payload exceeds [`MAX_FRAME_SIZE`]; both values are available for retry.
    PayloadTooLarge {
        /// The pending response capability.
        channel: ResponseChannel,
        /// The rejected response payload.
        response: Vec<u8>,
    },
    /// The request expired or disconnected before the response could be sent.
    ChannelClosed(Vec<u8>),
}

/// Observable events from the transport adapter.
#[derive(Debug)]
pub enum TransportEvent {
    /// A listening address became available.
    Listening(Multiaddr),
    /// A peer established a connection.
    PeerConnected(libp2p::PeerId),
    /// A peer connection closed.
    PeerDisconnected(libp2p::PeerId),
    /// An inbound request is ready for application processing.
    Request {
        /// The sending transport peer.
        peer: libp2p::PeerId,
        /// The request payload.
        request: Vec<u8>,
        /// Capability used to return the response.
        channel: ResponseChannel,
    },
    /// A response to an outbound request arrived.
    Response {
        /// The responding transport peer.
        peer: libp2p::PeerId,
        /// The identifier returned by [`Transport::send_request`].
        request_id: RequestId,
        /// The response payload.
        response: Vec<u8>,
    },
    /// An outbound request failed.
    RequestFailed {
        /// The target transport peer.
        peer: libp2p::PeerId,
        /// The identifier returned by [`Transport::send_request`].
        request_id: RequestId,
        /// Failure description.
        reason: String,
    },
    /// Peer identify data was received.
    Identify(Box<identify::Event>),
    /// Ping health information was received.
    Ping(ping::Event),
}

/// Swarm-independent façade for Populus transport operations.
///
/// The underlying libp2p Swarm and its behaviours are private; callers work
/// with peer identities, addresses, payloads, and transport events.
pub struct Transport {
    swarm: Swarm<Behaviour>,
    active_requests: HashMap<request_response::OutboundRequestId, RequestId>,
    queued_requests: VecDeque<PendingRequest>,
    failed_requests: VecDeque<(libp2p::PeerId, RequestId)>,
    next_request_id: u64,
}

impl Transport {
    /// Creates a transport configured for TCP and QUIC.
    ///
    /// # Errors
    ///
    /// Returns an error if a configured transport or DNS resolver cannot be built.
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            swarm: build_swarm()?,
            active_requests: HashMap::new(),
            queued_requests: VecDeque::new(),
            failed_requests: VecDeque::new(),
            next_request_id: 0,
        })
    }

    /// Returns this transport's libp2p peer identity.
    #[must_use]
    pub fn peer_id(&self) -> libp2p::PeerId {
        *self.swarm.local_peer_id()
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
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
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
        self.swarm
            .dial(address)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
    }

    /// Disconnects from a peer if currently connected.
    ///
    /// Returns `true` when the peer had an established connection that is
    /// being closed.
    pub fn disconnect(&mut self, peer: libp2p::PeerId) -> bool {
        let disconnected = self.swarm.disconnect_peer_id(peer).is_ok();
        if disconnected {
            self.fail_queued_for(peer);
        }
        disconnected
    }

    fn fail_queued_for(&mut self, peer: libp2p::PeerId) {
        let mut retained = VecDeque::with_capacity(self.queued_requests.len());
        while let Some(request) = self.queued_requests.pop_front() {
            if request.peer == peer {
                self.failed_requests.push_back((request.peer, request.id));
            } else {
                retained.push_back(request);
            }
        }
        self.queued_requests = retained;
    }

    /// Sends a request and returns its local identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SendRequestError::PayloadTooLarge`] when the payload exceeds
    /// [`MAX_FRAME_SIZE`], [`SendRequestError::QueueFull`] when the combined
    /// active, queued, and pending-failure capacity is exhausted, or
    /// [`SendRequestError::IdentifierExhausted`] if the local identifier space
    /// is exhausted.
    pub fn send_request(
        &mut self,
        peer: libp2p::PeerId,
        addresses: Vec<Multiaddr>,
        request: Vec<u8>,
    ) -> Result<RequestId, SendRequestError> {
        if request.len() > MAX_FRAME_SIZE {
            return Err(SendRequestError::PayloadTooLarge);
        }
        let buffered_requests = self
            .active_requests
            .len()
            .saturating_add(self.queued_requests.len())
            .saturating_add(self.failed_requests.len());
        if buffered_requests >= MAX_CONCURRENT_REQUESTS + MAX_QUEUED_REQUESTS {
            return Err(SendRequestError::QueueFull);
        }
        let next_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(SendRequestError::IdentifierExhausted)?;
        let id = RequestId(self.next_request_id);
        self.next_request_id = next_id;
        let request = PendingRequest {
            id,
            peer,
            addresses,
            request,
        };
        if self.active_requests.len() < MAX_CONCURRENT_REQUESTS {
            self.dispatch(request);
        } else {
            self.queued_requests.push_back(request);
        }
        Ok(id)
    }

    /// Replies to an inbound request.
    ///
    /// # Errors
    ///
    /// Returns the channel and response if the payload exceeds [`MAX_FRAME_SIZE`].
    /// If the request has expired or disconnected, returns the response payload.
    pub fn send_response(
        &mut self,
        channel: ResponseChannel,
        response: Vec<u8>,
    ) -> Result<(), SendResponseError> {
        if response.len() > MAX_FRAME_SIZE {
            return Err(SendResponseError::PayloadTooLarge { channel, response });
        }
        self.swarm
            .behaviour_mut()
            .requests
            .send_response(channel.0, response)
            .map_err(SendResponseError::ChannelClosed)
    }

    /// Waits for the next application-relevant transport event.
    pub async fn next_event(&mut self) -> TransportEvent {
        loop {
            if let Some((peer, request_id)) = self.failed_requests.pop_front() {
                return TransportEvent::RequestFailed {
                    peer,
                    request_id,
                    reason: "peer disconnected before dispatch".to_owned(),
                };
            }
            match self.swarm.select_next_some().await {
                libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                    return TransportEvent::Listening(address);
                }
                libp2p::swarm::SwarmEvent::ConnectionEstablished {
                    peer_id,
                    num_established,
                    ..
                } if num_established.get() == 1 => {
                    return TransportEvent::PeerConnected(peer_id);
                }
                libp2p::swarm::SwarmEvent::ConnectionClosed {
                    peer_id,
                    num_established: 0,
                    ..
                } => {
                    self.fail_queued_for(peer_id);
                    return TransportEvent::PeerDisconnected(peer_id);
                }
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Requests(
                    request_response::Event::Message { peer, message, .. },
                )) => match message {
                    request_response::Message::Request {
                        request, channel, ..
                    } => {
                        return TransportEvent::Request {
                            peer,
                            request,
                            channel: ResponseChannel(channel),
                        };
                    }
                    request_response::Message::Response {
                        request_id,
                        response,
                    } => {
                        let Some(request_id) = self.active_requests.remove(&request_id) else {
                            continue;
                        };
                        self.dispatch_queued();
                        return TransportEvent::Response {
                            peer,
                            request_id,
                            response,
                        };
                    }
                },
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Requests(
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    },
                )) => {
                    let Some(request_id) = self.active_requests.remove(&request_id) else {
                        continue;
                    };
                    self.dispatch_queued();
                    return TransportEvent::RequestFailed {
                        peer,
                        request_id,
                        reason: error.to_string(),
                    };
                }
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Identify(event)) => {
                    return TransportEvent::Identify(event);
                }
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Ping(event)) => {
                    return TransportEvent::Ping(event);
                }
                _ => {}
            }
        }
    }

    fn dispatch(&mut self, request: PendingRequest) {
        let network_id = self
            .swarm
            .behaviour_mut()
            .requests
            .send_request_with_addresses(&request.peer, request.request, request.addresses);
        self.active_requests.insert(network_id, request.id);
    }

    fn dispatch_queued(&mut self) {
        while self.active_requests.len() < MAX_CONCURRENT_REQUESTS {
            let Some(request) = self.queued_requests.pop_front() else {
                break;
            };
            self.dispatch(request);
        }
    }
}

fn build_swarm() -> Result<Swarm<Behaviour>, Box<dyn std::error::Error + Send + Sync>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
        .with_quic()
        .with_dns()
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
        .with_behaviour(Behaviour::new)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
        .build();
    Ok(swarm)
}

/// Parses a multiaddress, preserving libp2p's detailed parse error.
///
/// This small convenience keeps transport callers independent of routing types.
///
/// # Errors
///
/// Returns an error when `address` is not a valid multiaddress.
pub fn parse_multiaddr(address: &str) -> Result<Multiaddr, libp2p::multiaddr::Error> {
    address.parse()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::{
        collections::HashSet,
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{
        StreamExt,
        executor::block_on,
        io::{AsyncRead, Cursor},
    };
    use libp2p::{
        Multiaddr,
        core::multiaddr::Protocol,
        request_response::{self, Message},
        swarm::SwarmEvent,
    };

    use super::{MAX_FRAME_SIZE, build_swarm, read_frame, write_frame};

    struct ObservedReader {
        inner: Cursor<Vec<u8>>,
        largest_read: usize,
    }

    impl AsyncRead for ObservedReader {
        fn poll_read(
            self: Pin<&mut Self>,
            context: &mut Context<'_>,
            buffer: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            this.largest_read = this.largest_read.max(buffer.len());
            Pin::new(&mut this.inner).poll_read(context, buffer)
        }
    }

    #[test]
    fn framing_round_trips_payload_and_empty_message() {
        block_on(async {
            for payload in [&b"populus"[..], &[]] {
                let mut writer = Cursor::new(Vec::new());
                write_frame(&mut writer, payload)
                    .await
                    .expect("write frame");
                let mut reader = Cursor::new(writer.into_inner());
                assert_eq!(read_frame(&mut reader).await.expect("read frame"), payload);
            }

            let payload = vec![0; MAX_FRAME_SIZE];
            let mut writer = Cursor::new(Vec::new());
            write_frame(&mut writer, &payload)
                .await
                .expect("maximum-sized frame");
            let mut reader = Cursor::new(writer.into_inner());
            assert_eq!(read_frame(&mut reader).await.expect("read frame"), payload);
        });
    }

    #[test]
    fn framing_reads_payload_incrementally() {
        block_on(async {
            let payload = vec![0x42; MAX_FRAME_SIZE];
            let mut frame = u32::try_from(payload.len())
                .expect("test size fits u32")
                .to_be_bytes()
                .to_vec();
            frame.extend_from_slice(&payload);
            let mut reader = ObservedReader {
                inner: Cursor::new(frame),
                largest_read: 0,
            };

            assert_eq!(read_frame(&mut reader).await.expect("read frame"), payload);
            assert!(reader.largest_read < MAX_FRAME_SIZE);
        });
    }

    #[test]
    fn framing_rejects_oversized_and_truncated_frames() {
        block_on(async {
            let mut reader = Cursor::new(
                u32::try_from(MAX_FRAME_SIZE + 1)
                    .expect("test size fits u32")
                    .to_be_bytes()
                    .to_vec(),
            );
            assert_eq!(
                read_frame(&mut reader)
                    .await
                    .expect_err("oversized frame")
                    .kind(),
                io::ErrorKind::InvalidData
            );

            let mut reader = Cursor::new(vec![0, 0, 0, 2, b'x']);
            assert_eq!(
                read_frame(&mut reader)
                    .await
                    .expect_err("truncated payload")
                    .kind(),
                io::ErrorKind::UnexpectedEof
            );

            let mut writer = Cursor::new(Vec::new());
            assert_eq!(
                write_frame(&mut writer, &vec![0; MAX_FRAME_SIZE + 1])
                    .await
                    .expect_err("oversized write")
                    .kind(),
                io::ErrorKind::InvalidInput
            );
        });
    }

    #[test]
    fn oversized_request_is_rejected_without_consuming_an_identifier() {
        let mut transport = super::Transport::new().expect("transport");
        let peer = transport.peer_id();
        assert_eq!(
            transport
                .send_request(peer, Vec::new(), vec![0; MAX_FRAME_SIZE + 1],)
                .expect_err("oversized request"),
            super::SendRequestError::PayloadTooLarge
        );
        assert_eq!(
            transport
                .send_request(peer, Vec::new(), vec![0; MAX_FRAME_SIZE])
                .expect("maximum-sized request is within the frame limit"),
            super::RequestId(0)
        );
    }

    #[test]
    fn pending_failures_share_the_bounded_request_capacity() {
        let mut transport = super::Transport::new().expect("transport");
        let peer = transport.peer_id();
        transport.failed_requests.extend(
            (0..(super::MAX_CONCURRENT_REQUESTS + super::MAX_QUEUED_REQUESTS)).map(|id| {
                (
                    peer,
                    super::RequestId(u64::try_from(id).expect("test ID fits u64")),
                )
            }),
        );

        assert_eq!(
            transport
                .send_request(peer, Vec::new(), Vec::new())
                .expect_err("pending failures exhaust the combined capacity"),
            super::SendRequestError::QueueFull
        );
    }

    async fn request_response_round_trip(protocol: &str) {
        let mut server = build_swarm().expect("server swarm");
        let mut client = build_swarm().expect("client swarm");
        let server_peer = *server.local_peer_id();
        let address: Multiaddr = protocol.parse().expect("loopback multiaddress");
        server.listen_on(address).expect("listen");

        let listen_address = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };
        let request = b"bounded request-response".to_vec();
        client.behaviour_mut().requests.send_request_with_addresses(
            &server_peer,
            request.clone(),
            vec![listen_address],
        );

        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            loop {
                tokio::select! {
                    event = server.select_next_some() => {
                        if let SwarmEvent::Behaviour(
                            super::BehaviourEvent::Requests(request_response::Event::Message {
                                message: Message::Request { request, channel, .. },
                                ..
                            })
                        ) = event
                        {
                            server
                                .behaviour_mut()
                                .requests
                                .send_response(channel, request)
                                .expect("response channel open");
                        }
                    }
                    event = client.select_next_some() => {
                        if let SwarmEvent::Behaviour(
                            super::BehaviourEvent::Requests(request_response::Event::Message {
                                message: Message::Response { response, .. },
                                ..
                            })
                        ) = event
                        {
                            assert_eq!(response, request);
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("request-response completes");

        assert!(client.disconnect_peer_id(server_peer).is_ok());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if matches!(
                    client.select_next_some().await,
                    SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == server_peer
                ) {
                    break;
                }
            }
        })
        .await
        .expect("peer disconnect completes");
    }

    #[tokio::test]
    async fn tcp_loopback_request_response() {
        request_response_round_trip("/ip4/127.0.0.1/tcp/0").await;
    }

    #[tokio::test]
    async fn transport_adapter_exchanges_requests_without_exposing_swarm() {
        let mut server = super::Transport::new().expect("server transport");
        let mut client = super::Transport::new().expect("client transport");
        let server_peer = server.peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("listen");

        let address = loop {
            if let super::TransportEvent::Listening(address) = server.next_event().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };
        client
            .send_request(server_peer, vec![address], b"adapter request".to_vec())
            .expect("request capacity available");

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = server.next_event() => {
                        if let super::TransportEvent::Request { request, channel, .. } = event {
                            server.send_response(channel, request).expect("response channel open");
                        }
                    }
                    event = client.next_event() => {
                        if let super::TransportEvent::Response { response, .. } = event {
                            assert_eq!(response, b"adapter request");
                            break;
                        }
                    }
                }
            }
        })
        .await
        .expect("adapter request-response completes");
    }

    #[tokio::test]
    async fn quic_loopback_request_response() {
        request_response_round_trip("/ip4/127.0.0.1/udp/0/quic-v1").await;
    }

    #[tokio::test]
    async fn tcp_loopback_applies_bounded_request_backpressure() {
        let mut server = super::Transport::new().expect("server transport");
        let mut client = super::Transport::new().expect("client transport");
        let server_peer = server.peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("listen");
        let address = loop {
            if let super::TransportEvent::Listening(address) = server.next_event().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };

        let messages: Vec<_> = (0_u16..=128).map(u16::to_be_bytes).map(Vec::from).collect();
        for request in &messages[..128] {
            client
                .send_request(server_peer, vec![address.clone()], request.clone())
                .expect("active or queued request capacity");
        }
        assert_eq!(
            client
                .send_request(server_peer, vec![address.clone()], messages[128].clone())
                .expect_err("bounded queue is full"),
            super::SendRequestError::QueueFull
        );

        let mut responses = HashSet::new();
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            while responses.len() < messages.len() - 1 {
                tokio::select! {
                    event = server.next_event() => {
                        if let super::TransportEvent::Request { request, channel, .. } = event {
                            server.send_response(channel, request).expect("response channel open");
                        }
                    }
                    event = client.next_event() => {
                        if let super::TransportEvent::Response { response, .. } = event {
                            responses.insert(response);
                        }
                    }
                }
            }
        })
        .await
        .expect("accepted active and queued requests complete");

        client
            .send_request(server_peer, vec![address], messages[128].clone())
            .expect("capacity available after responses");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while responses.len() < messages.len() {
                tokio::select! {
                    event = server.next_event() => {
                        if let super::TransportEvent::Request { request, channel, .. } = event {
                            server.send_response(channel, request).expect("response channel open");
                        }
                    }
                    event = client.next_event() => {
                        if let super::TransportEvent::Response { response, .. } = event {
                            responses.insert(response);
                        }
                    }
                }
            }
        })
        .await
        .expect("retried request completes");
        assert_eq!(responses.len(), messages.len());
        assert!(messages.iter().all(|message| responses.contains(message)));
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn oversized_response_can_be_retried_with_the_same_channel() {
        let mut server = super::Transport::new().expect("server transport");
        let mut client = super::Transport::new().expect("client transport");
        let server_peer = server.peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("listen");
        let address = loop {
            if let super::TransportEvent::Listening(address) = server.next_event().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };
        let request_id = client
            .send_request(server_peer, vec![address], b"request".to_vec())
            .expect("request capacity available");

        let channel = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    event = server.next_event() => {
                        if let super::TransportEvent::Request { channel, .. } = event {
                            break channel;
                        }
                    }
                    _ = client.next_event() => {}
                }
            }
        })
        .await
        .expect("request arrives");
        let oversized_response = vec![0x42; MAX_FRAME_SIZE + 1];
        let super::SendResponseError::PayloadTooLarge {
            channel,
            mut response,
        } = server
            .send_response(channel, oversized_response.clone())
            .expect_err("oversized response is rejected")
        else {
            panic!("oversized response must retain its channel");
        };
        assert_eq!(response, oversized_response);
        response.truncate(MAX_FRAME_SIZE);
        server
            .send_response(channel, response.clone())
            .expect("maximum-sized response is accepted on the same channel");

        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                tokio::select! {
                    _ = server.next_event() => {}
                    event = client.next_event() => {
                        match event {
                            super::TransportEvent::Response { request_id: received_id, response: received, .. } => {
                                assert_eq!(received_id, request_id);
                                assert_eq!(received, response);
                                break;
                            }
                            super::TransportEvent::RequestFailed { request_id: failed_id, .. } if failed_id == request_id => {
                                panic!("request failed before receiving the retried response");
                            }
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .expect("retried response arrives");
    }

    #[tokio::test]
    #[allow(clippy::panic)]
    async fn tcp_loopback_cancels_pending_request_on_disconnect() {
        let mut server = super::Transport::new().expect("server transport");
        let mut client = super::Transport::new().expect("client transport");
        let server_peer = server.peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("listen");
        let address = loop {
            if let super::TransportEvent::Listening(address) = server.next_event().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };
        client
            .send_request(server_peer, vec![address], b"cancel me".to_vec())
            .expect("request capacity available");

        let mut response_channel = None;
        let mut connected = false;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while response_channel.is_none() || !connected {
                tokio::select! {
                    event = server.next_event(), if response_channel.is_none() => {
                        if let super::TransportEvent::Request { channel, .. } = event {
                            response_channel = Some(channel);
                        }
                    }
                    event = client.next_event(), if !connected => {
                        if matches!(event, super::TransportEvent::PeerConnected(peer) if peer == server_peer) {
                            connected = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("request is established");
        assert!(response_channel.is_some());
        assert!(client.disconnect(server_peer));

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut connection_closed = false;
            let mut request_failed = false;
            while !connection_closed || !request_failed {
                match client.next_event().await {
                    super::TransportEvent::PeerDisconnected(peer) if peer == server_peer => {
                        connection_closed = true;
                    }
                    super::TransportEvent::RequestFailed { peer, .. } if peer == server_peer => {
                        request_failed = true;
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("pending request is cancelled with the connection");
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if matches!(
                    server.next_event().await,
                    super::TransportEvent::PeerDisconnected(_)
                ) {
                    break;
                }
            }
        })
        .await
        .expect("server observes disconnect");
        let response = b"too late".to_vec();
        let error = server
            .send_response(response_channel.expect("request channel"), response.clone())
            .expect_err("closed channel rejects response");
        match error {
            super::SendResponseError::ChannelClosed(returned) => assert_eq!(returned, response),
            super::SendResponseError::PayloadTooLarge { .. } => {
                panic!("response is within the limit")
            }
        }
    }

    #[tokio::test]
    async fn tcp_loopback_fails_queued_request_on_disconnect() {
        let mut server = super::Transport::new().expect("server transport");
        let mut second_server = super::Transport::new().expect("second server transport");
        let mut client = super::Transport::new().expect("client transport");
        let server_peer = server.peer_id();
        let second_peer = second_server.peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("listen");
        second_server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("second server listen");
        let address = loop {
            if let super::TransportEvent::Listening(address) = server.next_event().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };
        let second_address = loop {
            if let super::TransportEvent::Listening(address) = second_server.next_event().await {
                break address.with(Protocol::P2p(second_peer));
            }
        };

        let mut request_ids = Vec::new();
        for index in 0..=super::MAX_CONCURRENT_REQUESTS {
            request_ids.push(
                client
                    .send_request(
                        server_peer,
                        vec![address.clone()],
                        index.to_be_bytes().to_vec(),
                    )
                    .expect("request capacity available"),
            );
        }
        let other_peer_request_id = client
            .send_request(
                second_peer,
                vec![second_address],
                b"preserve queued request".to_vec(),
            )
            .expect("other peer request remains within the queue bound");

        let mut response_channels = Vec::new();
        let mut connected = false;
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            while response_channels.len() < super::MAX_CONCURRENT_REQUESTS || !connected {
                tokio::select! {
                    event = server.next_event(), if response_channels.len() < super::MAX_CONCURRENT_REQUESTS => {
                        if let super::TransportEvent::Request { channel, .. } = event {
                            response_channels.push(channel);
                        }
                    }
                    event = client.next_event(), if !connected => {
                        if matches!(event, super::TransportEvent::PeerConnected(peer) if peer == server_peer) {
                            connected = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("all active requests are delivered");
        assert!(client.disconnect(server_peer));

        let queued_request_id = request_ids[super::MAX_CONCURRENT_REQUESTS];
        let mut failed_requests = Vec::new();
        let mut disconnected = false;
        let mut other_peer_response_sent = false;
        let mut other_peer_response_received = false;
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while failed_requests.len() < request_ids.len()
                || !disconnected
                || !other_peer_response_received
            {
                tokio::select! {
                    event = client.next_event() => match event {
                        super::TransportEvent::RequestFailed {
                            peer,
                            request_id,
                            reason,
                        } if peer == server_peer => failed_requests.push((request_id, reason)),
                        super::TransportEvent::PeerDisconnected(peer) if peer == server_peer => {
                            disconnected = true;
                        }
                        super::TransportEvent::Response {
                            peer,
                            request_id,
                            response,
                        } if peer == second_peer => {
                            assert_eq!(request_id, other_peer_request_id);
                            assert_eq!(response, b"preserve queued request");
                            other_peer_response_received = true;
                        }
                        _ => {}
                    },
                    event = second_server.next_event(), if !other_peer_response_sent => {
                        if let super::TransportEvent::Request { request, channel, .. } = event {
                            second_server
                                .send_response(channel, request)
                                .expect("other peer response channel open");
                            other_peer_response_sent = true;
                        }
                    }
                }
            }
        })
        .await
        .expect("active and queued requests fail on disconnect");

        assert!(
            request_ids
                .iter()
                .all(|id| failed_requests.iter().any(|(failed_id, _)| id == failed_id))
        );
        assert_eq!(
            failed_requests
                .iter()
                .find(|(id, _)| *id == queued_request_id)
                .map(|(_, reason)| reason.as_str()),
            Some("peer disconnected before dispatch")
        );
        drop(response_channels);
    }

    #[tokio::test]
    async fn tcp_loopback_fails_queued_requests_on_remote_disconnect() {
        let mut server = super::Transport::new().expect("server transport");
        let mut client = super::Transport::new().expect("client transport");
        let server_peer = server.peer_id();
        let client_peer = client.peer_id();
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().expect("loopback address"))
            .expect("listen");
        let address = loop {
            if let super::TransportEvent::Listening(address) = server.next_event().await {
                break address.with(Protocol::P2p(server_peer));
            }
        };
        let request_ids: Vec<_> = (0..=super::MAX_CONCURRENT_REQUESTS)
            .map(|index| {
                client
                    .send_request(
                        server_peer,
                        vec![address.clone()],
                        index.to_be_bytes().to_vec(),
                    )
                    .expect("request capacity available")
            })
            .collect();

        let mut response_channels = Vec::new();
        let mut closed = false;
        let mut failed = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while failed.len() < request_ids.len() || !closed {
                tokio::select! {
                    event = server.next_event(), if response_channels.len() < super::MAX_CONCURRENT_REQUESTS => {
                        if let super::TransportEvent::Request { channel, .. } = event {
                            response_channels.push(channel);
                            if response_channels.len() == super::MAX_CONCURRENT_REQUESTS {
                                assert!(server.disconnect(client_peer));
                            }
                        }
                    }
                    event = client.next_event() => match event {
                        super::TransportEvent::RequestFailed { request_id, .. } => failed.push(request_id),
                        super::TransportEvent::PeerDisconnected(peer) if peer == server_peer => closed = true,
                        _ => {}
                    },
                }
            }
        })
        .await
        .expect("queued requests fail when the remote closes the connection");
        assert!(request_ids.iter().all(|id| failed.contains(id)));
    }

    #[test]
    fn multiaddress_helper_parses_loopback() {
        assert!(super::parse_multiaddr("/ip4/127.0.0.1/tcp/1234").is_ok());
    }
}
