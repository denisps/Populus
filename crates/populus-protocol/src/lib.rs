//! Versioned, bounded application messages for Populus request-response streams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use populus_types::{ContentId, NetworkId, NetworkIdentity, NodeId, RoutingKey, UtcDay};

const MAGIC: &[u8; 3] = b"POP";
const VERSION: u8 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1 + 32 + 1;
const MESSAGE_TAG_OFFSET: usize = MAGIC.len() + 1 + 32;
/// Fixed public-network identifier: SHA-256 of `populus/public-network/v1`.
pub const PUBLIC_NETWORK_ID: NetworkId = NetworkId::from_bytes([
    0x1f, 0x0b, 0x23, 0xdb, 0xc0, 0x89, 0x98, 0xaa, 0xde, 0x8b, 0x8d, 0x78, 0xd8, 0x08, 0x63, 0x17,
    0x46, 0x7b, 0x8e, 0x1d, 0x57, 0xdd, 0x25, 0x5c, 0xed, 0x5c, 0xd2, 0x90, 0x8b, 0x61, 0x77, 0x4f,
]);
/// Maximum encoded application message size.
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;
/// Maximum contacts returned by one lookup response.
pub const MAX_ROUTING_CONTACTS: usize = 20;
/// Maximum transport addresses advertised by one contact.
pub const MAX_CONTACT_ADDRESSES: usize = 8;
/// Maximum encoded multiaddress length.
pub const MAX_MULTIADDR_BYTES: usize = 256;
/// Maximum encoded `PeerId` length.
pub const MAX_PEER_ID_BYTES: usize = 128;

const FIND_NODE: u8 = 1;
const ROUTING_CONTACTS: u8 = 2;
const OBSERVED_ADDRESS_REQUEST: u8 = 3;
const OBSERVED_ADDRESS: u8 = 4;
const DIRECT_VOTE: u8 = 5;
const ERROR_RESPONSE: u8 = 6;
const DIRECT_VOTE_ACK: u8 = 7;
const POPULARITY_QUERY: u8 = 8;
const POPULARITY_RESPONSE: u8 = 9;
const DELEGATED_INGEST_REPORT: u8 = 10;
const DELEGATED_INGEST_ACK: u8 = 11;
const CANDIDATE_REGISTRATION: u8 = 12;
const CANDIDATE_REGISTRATION_ACK: u8 = 13;

/// Typed refusal codes for requests that cannot be handled by the selected process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ApplicationErrorCode {
    /// No eligible authority is currently configured for the requested operation.
    NoActiveAuthority = 1,
    /// The peer requested a protocol operation not supported by this node.
    UnsupportedOperation = 2,
    /// The request payload is invalid for the selected operation.
    InvalidRequest = 3,
}

/// A routing contact advertised by a peer.
///
/// The identity is a claim only. Callers must verify the derived `NodeId`,
/// authenticated `PeerId`, and reachability before inserting it as an eligible
/// routing contact.
#[derive(Clone, PartialEq, Eq)]
pub struct RoutingContact {
    /// Scarcity-derived Populus routing position.
    pub node_id: NodeId,
    /// Canonical network identity from which `node_id` must be derived.
    pub identity: NetworkIdentity,
    /// Canonical libp2p `PeerId` bytes.
    pub peer_id: Vec<u8>,
    /// Dialable libp2p multiaddresses.
    pub addresses: Vec<String>,
}

impl std::fmt::Debug for RoutingContact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RoutingContact")
            .field("node_id", &self.node_id)
            .field("identity", &self.identity.as_bytes())
            .field("peer_id", &self.peer_id)
            .field("addresses", &self.addresses)
            .finish()
    }
}

/// Version 1 messages carried inside the bounded libp2p request-response frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationMessage {
    /// Request the closest known contacts for a target key.
    FindNode {
        /// Correlates the response with this request.
        request_id: u64,
        /// XOR-routing target.
        target: RoutingKey,
        /// Requested number of contacts, from 1 through [`MAX_ROUTING_CONTACTS`].
        limit: u8,
    },
    /// Contacts returned by a `FindNode` request.
    RoutingContacts {
        /// Request identifier from the corresponding `FindNode`.
        request_id: u64,
        /// Bounded routing contacts.
        contacts: Vec<RoutingContact>,
    },
    /// Ask the remote peer to report the source endpoint it sees for this request.
    RequestObservedAddress {
        /// Fresh caller-generated nonce.
        nonce: [u8; 16],
    },
    /// Report the connection endpoint observed by the authenticated responder.
    ObservedAddress {
        /// Nonce copied from the corresponding request.
        nonce: [u8; 16],
        /// Endpoint observed on the direct connection.
        endpoint: SocketAddr,
    },
    /// Canonical direct-vote payload.
    DirectVote {
        /// Vote bytes decoded by `populus-cluster`.
        vote: Vec<u8>,
    },
    /// Explicit refusal instead of an empty success-shaped response.
    Error {
        /// Typed refusal reason.
        code: ApplicationErrorCode,
    },
    /// Authority-signed acknowledgement of an accepted direct vote.
    DirectVoteAck {
        /// Canonical signed acknowledgement from `populus-cluster`.
        acknowledgement: Vec<u8>,
    },
    /// Request the approximate popularity estimate for one content/day bucket.
    PopularityQuery {
        /// Immutable content identifier.
        content_id: ContentId,
        /// UTC-day bucket.
        day: UtcDay,
    },
    /// Authority-signed popularity response.
    PopularityResponse {
        /// Canonical signed response from `populus-cluster`.
        response: Vec<u8>,
    },
    /// Immutable delegated-ingest report sent to one authority.
    DelegatedIngestReport {
        /// Canonical report from `populus-cluster`.
        report: Vec<u8>,
    },
    /// Authority-signed acknowledgement of one delegated-ingest report.
    DelegatedIngestAck {
        /// Canonical signed acknowledgement from `populus-cluster`.
        acknowledgement: Vec<u8>,
    },
    /// Signed, expiring `NodeId` candidate registration.
    CandidateRegistration {
        /// Canonical registration bytes from `populus-cluster`.
        registration: Vec<u8>,
    },
    /// Acknowledgement that the candidate registration was indexed.
    CandidateRegistrationAck {
        /// Hash of the exact signed registration.
        registration_hash: [u8; 32],
    },
}

/// Errors returned when an application message is malformed or exceeds bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    /// Message is shorter than its fixed header.
    Truncated,
    /// The fixed application-message marker is absent.
    InvalidMagic,
    /// The message is for a different configured Populus network.
    NetworkMismatch,
    /// The wire version is not supported.
    UnsupportedVersion(u8),
    /// The message tag is not defined by this version.
    UnknownMessage(u8),
    /// An encoded field violates a protocol bound or invariant.
    InvalidField,
    /// The message exceeds [`MAX_MESSAGE_SIZE`].
    MessageTooLarge,
    /// The message has trailing bytes after its decoded value.
    TrailingBytes,
}

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => formatter.write_str("truncated Populus application message"),
            Self::InvalidMagic => formatter.write_str("invalid Populus application marker"),
            Self::NetworkMismatch => {
                formatter.write_str("Populus message belongs to another network")
            }
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported Populus application version {version}"
                )
            }
            Self::UnknownMessage(tag) => {
                write!(formatter, "unknown Populus application message {tag}")
            }
            Self::InvalidField => formatter.write_str("invalid Populus application field"),
            Self::MessageTooLarge => formatter.write_str("Populus message exceeds size limit"),
            Self::TrailingBytes => formatter.write_str("trailing bytes in Populus message"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl ApplicationMessage {
    /// Encodes this message using the canonical v1 application envelope.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if a field is invalid or the encoded message
    /// exceeds [`MAX_MESSAGE_SIZE`].
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.encode_for_network(PUBLIC_NETWORK_ID)
    }

    /// Encodes this message with the configured network identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] if a field is invalid or the encoded message
    /// exceeds [`MAX_MESSAGE_SIZE`].
    pub fn encode_for_network(&self, network_id: NetworkId) -> Result<Vec<u8>, ProtocolError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(network_id.as_bytes());
        match self {
            Self::FindNode {
                request_id,
                target,
                limit,
            } => {
                if *limit == 0 || usize::from(*limit) > MAX_ROUTING_CONTACTS {
                    return Err(ProtocolError::InvalidField);
                }
                bytes.push(FIND_NODE);
                bytes.extend_from_slice(&request_id.to_be_bytes());
                bytes.extend_from_slice(target.as_bytes());
                bytes.push(*limit);
            }
            Self::RoutingContacts {
                request_id,
                contacts,
            } => {
                if contacts.len() > MAX_ROUTING_CONTACTS {
                    return Err(ProtocolError::InvalidField);
                }
                bytes.push(ROUTING_CONTACTS);
                bytes.extend_from_slice(&request_id.to_be_bytes());
                bytes.push(u8::try_from(contacts.len()).map_err(|_| ProtocolError::InvalidField)?);
                for contact in contacts {
                    encode_contact(&mut bytes, contact)?;
                }
            }
            Self::RequestObservedAddress { nonce } => {
                bytes.push(OBSERVED_ADDRESS_REQUEST);
                bytes.extend_from_slice(nonce);
            }
            Self::ObservedAddress { nonce, endpoint } => {
                bytes.push(OBSERVED_ADDRESS);
                bytes.extend_from_slice(nonce);
                match endpoint {
                    SocketAddr::V4(endpoint) => {
                        bytes.push(4);
                        bytes.extend_from_slice(&endpoint.ip().octets());
                    }
                    SocketAddr::V6(endpoint) => {
                        if endpoint.scope_id() != 0 || endpoint.flowinfo() != 0 {
                            return Err(ProtocolError::InvalidField);
                        }
                        bytes.push(6);
                        bytes.extend_from_slice(&endpoint.ip().octets());
                    }
                }
                bytes.extend_from_slice(&endpoint.port().to_be_bytes());
            }
            Self::DirectVote { vote } => {
                bytes.push(DIRECT_VOTE);
                append_payload(&mut bytes, vote)?;
            }
            Self::Error { code } => {
                bytes.push(ERROR_RESPONSE);
                bytes.push(*code as u8);
            }
            Self::DirectVoteAck { acknowledgement } => {
                bytes.push(DIRECT_VOTE_ACK);
                append_payload(&mut bytes, acknowledgement)?;
            }
            Self::PopularityQuery { content_id, day } => {
                bytes.push(POPULARITY_QUERY);
                bytes.extend_from_slice(content_id.as_bytes());
                bytes.extend_from_slice(&day.to_bytes());
            }
            Self::PopularityResponse { response } => {
                bytes.push(POPULARITY_RESPONSE);
                append_payload(&mut bytes, response)?;
            }
            Self::DelegatedIngestReport { report } => {
                bytes.push(DELEGATED_INGEST_REPORT);
                append_payload(&mut bytes, report)?;
            }
            Self::DelegatedIngestAck { acknowledgement } => {
                bytes.push(DELEGATED_INGEST_ACK);
                append_payload(&mut bytes, acknowledgement)?;
            }
            Self::CandidateRegistration { registration } => {
                bytes.push(CANDIDATE_REGISTRATION);
                append_payload(&mut bytes, registration)?;
            }
            Self::CandidateRegistrationAck { registration_hash } => {
                bytes.push(CANDIDATE_REGISTRATION_ACK);
                bytes.extend_from_slice(registration_hash);
            }
        }
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes a canonical v1 application envelope without allocating from
    /// untrusted lengths before validating their bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] for malformed, unsupported, or oversized input.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        Self::decode_for_network(bytes, PUBLIC_NETWORK_ID)
    }

    /// Decodes a message only when it is bound to the expected network.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError`] for malformed, unsupported, oversized, or
    /// wrong-network input.
    pub fn decode_for_network(
        bytes: &[u8],
        expected_network_id: NetworkId,
    ) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge);
        }
        if bytes.len() < HEADER_LEN {
            return Err(ProtocolError::Truncated);
        }
        if bytes.get(..MAGIC.len()) != Some(MAGIC.as_slice()) {
            return Err(ProtocolError::InvalidMagic);
        }
        let version = *bytes.get(3).ok_or(ProtocolError::Truncated)?;
        if version != VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }
        if bytes.get(MAGIC.len() + 1..MESSAGE_TAG_OFFSET)
            != Some(expected_network_id.as_bytes().as_slice())
        {
            return Err(ProtocolError::NetworkMismatch);
        }
        let tag = *bytes
            .get(MESSAGE_TAG_OFFSET)
            .ok_or(ProtocolError::Truncated)?;
        let mut decoder = Decoder {
            bytes,
            position: HEADER_LEN,
        };
        let message = match tag {
            FIND_NODE => {
                let request_id = decoder.u64()?;
                let target = RoutingKey::from_bytes(decoder.array()?);
                let limit = decoder.u8()?;
                if limit == 0 || usize::from(limit) > MAX_ROUTING_CONTACTS {
                    return Err(ProtocolError::InvalidField);
                }
                Self::FindNode {
                    request_id,
                    target,
                    limit,
                }
            }
            ROUTING_CONTACTS => {
                let request_id = decoder.u64()?;
                let count = usize::from(decoder.u8()?);
                if count > MAX_ROUTING_CONTACTS {
                    return Err(ProtocolError::InvalidField);
                }
                let mut contacts = Vec::with_capacity(count);
                for _ in 0..count {
                    contacts.push(decoder.contact()?);
                }
                Self::RoutingContacts {
                    request_id,
                    contacts,
                }
            }
            OBSERVED_ADDRESS_REQUEST => Self::RequestObservedAddress {
                nonce: decoder.array()?,
            },
            OBSERVED_ADDRESS => {
                let nonce = decoder.array()?;
                let family = decoder.u8()?;
                let ip = match family {
                    4 => IpAddr::V4(Ipv4Addr::from(decoder.array::<4>()?)),
                    6 => IpAddr::V6(Ipv6Addr::from(decoder.array::<16>()?)),
                    _ => return Err(ProtocolError::InvalidField),
                };
                let endpoint = SocketAddr::new(ip, decoder.u16()?);
                Self::ObservedAddress { nonce, endpoint }
            }
            DIRECT_VOTE => Self::DirectVote {
                vote: decode_payload(&mut decoder)?,
            },
            ERROR_RESPONSE => {
                let code = match decoder.u8()? {
                    1 => ApplicationErrorCode::NoActiveAuthority,
                    2 => ApplicationErrorCode::UnsupportedOperation,
                    3 => ApplicationErrorCode::InvalidRequest,
                    _ => return Err(ProtocolError::InvalidField),
                };
                Self::Error { code }
            }
            DIRECT_VOTE_ACK => Self::DirectVoteAck {
                acknowledgement: decode_payload(&mut decoder)?,
            },
            POPULARITY_QUERY => Self::PopularityQuery {
                content_id: ContentId::from_bytes(decoder.array::<36>()?)
                    .map_err(|_| ProtocolError::InvalidField)?,
                day: UtcDay::from_bytes(decoder.array()?),
            },
            POPULARITY_RESPONSE => Self::PopularityResponse {
                response: decode_payload(&mut decoder)?,
            },
            DELEGATED_INGEST_REPORT => Self::DelegatedIngestReport {
                report: decode_payload(&mut decoder)?,
            },
            DELEGATED_INGEST_ACK => Self::DelegatedIngestAck {
                acknowledgement: decode_payload(&mut decoder)?,
            },
            CANDIDATE_REGISTRATION => Self::CandidateRegistration {
                registration: decode_payload(&mut decoder)?,
            },
            CANDIDATE_REGISTRATION_ACK => Self::CandidateRegistrationAck {
                registration_hash: decoder.array()?,
            },
            _ => return Err(ProtocolError::UnknownMessage(tag)),
        };
        if decoder.position != bytes.len() {
            return Err(ProtocolError::TrailingBytes);
        }
        Ok(message)
    }
}

fn append_payload(bytes: &mut Vec<u8>, payload: &[u8]) -> Result<(), ProtocolError> {
    let length = u32::try_from(payload.len()).map_err(|_| ProtocolError::MessageTooLarge)?;
    if payload
        .len()
        .checked_add(bytes.len())
        .and_then(|length| length.checked_add(size_of::<u32>()))
        .is_none_or(|length| length > MAX_MESSAGE_SIZE)
    {
        return Err(ProtocolError::MessageTooLarge);
    }
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(payload);
    Ok(())
}

fn decode_payload(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, ProtocolError> {
    let length = decoder.payload_length()?;
    Ok(decoder.take(length)?.to_vec())
}

fn encode_contact(bytes: &mut Vec<u8>, contact: &RoutingContact) -> Result<(), ProtocolError> {
    if contact.peer_id.is_empty()
        || contact.peer_id.len() > MAX_PEER_ID_BYTES
        || contact.addresses.is_empty()
        || contact.addresses.len() > MAX_CONTACT_ADDRESSES
        || contact.node_id != populus_crypto::node_id(&contact.identity)
    {
        return Err(ProtocolError::InvalidField);
    }
    bytes.extend_from_slice(contact.node_id.as_bytes());
    let identity = contact.identity.as_bytes();
    bytes.push(u8::try_from(identity.len()).map_err(|_| ProtocolError::InvalidField)?);
    bytes.extend_from_slice(identity);
    bytes.push(u8::try_from(contact.peer_id.len()).map_err(|_| ProtocolError::InvalidField)?);
    bytes.extend_from_slice(&contact.peer_id);
    bytes.push(u8::try_from(contact.addresses.len()).map_err(|_| ProtocolError::InvalidField)?);
    for address in &contact.addresses {
        let address = address.as_bytes();
        if address.is_empty() || address.len() > MAX_MULTIADDR_BYTES {
            return Err(ProtocolError::InvalidField);
        }
        bytes.extend_from_slice(
            &u16::try_from(address.len())
                .map_err(|_| ProtocolError::InvalidField)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(address);
    }
    Ok(())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl Decoder<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], ProtocolError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ProtocolError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(ProtocolError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProtocolError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn payload_length(&mut self) -> Result<usize, ProtocolError> {
        let length = usize::try_from(self.u32()?).map_err(|_| ProtocolError::MessageTooLarge)?;
        if length > MAX_MESSAGE_SIZE {
            return Err(ProtocolError::MessageTooLarge);
        }
        Ok(length)
    }

    fn contact(&mut self) -> Result<RoutingContact, ProtocolError> {
        let node_id = NodeId::from_bytes(self.array()?);
        let identity_length = usize::from(self.u8()?);
        if !matches!(identity_length, 5 | 7) {
            return Err(ProtocolError::InvalidField);
        }
        let identity = NetworkIdentity::from_bytes(self.take(identity_length)?)
            .map_err(|_| ProtocolError::InvalidField)?;
        let peer_id_length = usize::from(self.u8()?);
        if peer_id_length == 0 || peer_id_length > MAX_PEER_ID_BYTES {
            return Err(ProtocolError::InvalidField);
        }
        let peer_id = self.take(peer_id_length)?.to_vec();
        let address_count = usize::from(self.u8()?);
        if address_count == 0 || address_count > MAX_CONTACT_ADDRESSES {
            return Err(ProtocolError::InvalidField);
        }
        let mut addresses = Vec::with_capacity(address_count);
        for _ in 0..address_count {
            let length = usize::from(self.u16()?);
            if length == 0 || length > MAX_MULTIADDR_BYTES {
                return Err(ProtocolError::InvalidField);
            }
            let address =
                std::str::from_utf8(self.take(length)?).map_err(|_| ProtocolError::InvalidField)?;
            addresses.push(address.to_owned());
        }
        if node_id != populus_crypto::node_id(&identity) {
            return Err(ProtocolError::InvalidField);
        }
        Ok(RoutingContact {
            node_id,
            identity,
            peer_id,
            addresses,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::net::SocketAddr;

    use populus_types::{ContentId, NetworkId, NetworkIdentity, NodeId, RoutingKey, UtcDay};

    use super::{
        ApplicationErrorCode, ApplicationMessage, PUBLIC_NETWORK_ID, ProtocolError, RoutingContact,
    };

    fn contact() -> RoutingContact {
        let identity =
            NetworkIdentity::from_ip("8.8.8.8".parse().expect("public IPv4")).expect("identity");
        RoutingContact {
            node_id: populus_crypto::node_id(&identity),
            identity,
            peer_id: vec![1, 2, 3],
            addresses: vec!["/ip4/8.8.8.8/tcp/4001".to_owned()],
        }
    }

    fn application_vector(message_name: &str) -> Option<Vec<u8>> {
        let mut selected = false;
        for line in include_str!("../../../testvectors/populus-application-v1.txt").lines() {
            if let Some(name) = line.strip_prefix("message = ") {
                selected = name == message_name;
            } else if selected && let Some(encoded) = line.strip_prefix("encoded = ") {
                let (pairs, remainder) = encoded.as_bytes().as_chunks::<2>();
                assert!(
                    remainder.is_empty(),
                    "application vector must have even-length hex"
                );
                return Some(
                    pairs
                        .iter()
                        .map(|pair| {
                            u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII hex"), 16)
                                .expect("valid hex byte")
                        })
                        .collect(),
                );
            }
        }
        None
    }

    #[test]
    fn find_node_and_routing_contacts_round_trip() {
        let request = ApplicationMessage::FindNode {
            request_id: 7,
            target: RoutingKey::from_bytes([9; 32]),
            limit: 20,
        };
        assert_eq!(
            ApplicationMessage::decode(&request.encode().expect("encode")).expect("decode"),
            request
        );
        let response = ApplicationMessage::RoutingContacts {
            request_id: 7,
            contacts: vec![contact()],
        };
        assert_eq!(
            ApplicationMessage::decode(&response.encode().expect("encode")).expect("decode"),
            response
        );
    }

    #[test]
    fn observed_address_and_vote_round_trip() {
        for endpoint in [
            "8.8.8.8:4001".parse::<SocketAddr>().expect("IPv4 endpoint"),
            "[2001:4860:4860::8888]:4001"
                .parse::<SocketAddr>()
                .expect("IPv6 endpoint"),
        ] {
            let message = ApplicationMessage::ObservedAddress {
                nonce: [3; 16],
                endpoint,
            };
            assert_eq!(
                ApplicationMessage::decode(&message.encode().expect("encode")).expect("decode"),
                message
            );
            for message in [
                ApplicationMessage::DirectVoteAck {
                    acknowledgement: vec![0xaa, 0xbb],
                },
                ApplicationMessage::PopularityQuery {
                    content_id: ContentId::from_digest([0; 32]),
                    day: UtcDay::new(0),
                },
                ApplicationMessage::PopularityResponse {
                    response: vec![0xcc, 0xdd, 0xee],
                },
                ApplicationMessage::DelegatedIngestReport {
                    report: vec![0x11, 0x22],
                },
                ApplicationMessage::DelegatedIngestAck {
                    acknowledgement: vec![0x33, 0x44],
                },
                ApplicationMessage::CandidateRegistration {
                    registration: vec![0x55, 0x66, 0x77],
                },
                ApplicationMessage::CandidateRegistrationAck {
                    registration_hash: [0x88; 32],
                },
            ] {
                assert_eq!(
                    ApplicationMessage::decode(&message.encode().expect("encode")).expect("decode"),
                    message
                );
            }
        }

        let vote = ApplicationMessage::DirectVote {
            vote: vec![4, 5, 6],
        };
        assert_eq!(
            ApplicationMessage::decode(&vote.encode().expect("encode")).expect("decode"),
            vote
        );
    }

    #[test]
    fn candidate_registration_envelope_rejects_oversized_payloads() {
        let message = ApplicationMessage::CandidateRegistration {
            registration: vec![0; super::MAX_MESSAGE_SIZE + 1],
        };
        assert_eq!(message.encode(), Err(ProtocolError::MessageTooLarge));
    }

    #[test]
    fn observed_address_rejects_ipv6_socket_metadata_not_carried_on_wire() {
        let endpoint = SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().expect("IPv6 address"),
            4001,
            0,
            2,
        ));
        assert_eq!(
            ApplicationMessage::ObservedAddress {
                nonce: [1; 16],
                endpoint,
            }
            .encode(),
            Err(ProtocolError::InvalidField)
        );
    }

    #[test]
    fn popularity_response_matches_independent_v1_vector() {
        let response = ApplicationMessage::PopularityResponse {
            response: vec![0xcc, 0xdd, 0xee],
        };
        let fixture = application_vector("PopularityResponse").expect("popularity vector exists");
        assert_eq!(response.encode().expect("encode response"), fixture);
        assert_eq!(
            ApplicationMessage::decode(&fixture).expect("decode response fixture"),
            response
        );
    }

    #[test]
    fn application_messages_are_bound_to_the_expected_network() {
        let message = ApplicationMessage::RequestObservedAddress { nonce: [4; 16] };
        let other_network = NetworkId::from_bytes([0x42; 32]);
        let encoded = message
            .encode_for_network(other_network)
            .expect("encode on alternate network");
        assert_eq!(
            ApplicationMessage::decode_for_network(&encoded, other_network),
            Ok(message)
        );
        assert_eq!(
            ApplicationMessage::decode_for_network(&encoded, PUBLIC_NETWORK_ID),
            Err(ProtocolError::NetworkMismatch)
        );
    }

    #[test]
    fn delegated_ingest_envelopes_match_golden_vectors() {
        let report = ApplicationMessage::DelegatedIngestReport {
            report: vec![0x11, 0x22],
        };
        let report_fixture =
            application_vector("DelegatedIngestReport").expect("report vector exists");
        assert_eq!(report.encode().expect("encode report"), report_fixture);
        assert_eq!(
            ApplicationMessage::decode(&report_fixture).expect("decode report fixture"),
            report
        );
        let acknowledgement = ApplicationMessage::DelegatedIngestAck {
            acknowledgement: vec![0x33, 0x44],
        };
        let acknowledgement_fixture =
            application_vector("DelegatedIngestAck").expect("delegated ACK vector exists");
        assert_eq!(
            acknowledgement.encode().expect("encode acknowledgement"),
            acknowledgement_fixture
        );
        assert_eq!(
            ApplicationMessage::decode(&acknowledgement_fixture)
                .expect("decode acknowledgement fixture"),
            acknowledgement
        );
    }

    #[test]
    fn candidate_registry_envelopes_match_golden_vectors() {
        let registration = ApplicationMessage::CandidateRegistration {
            registration: vec![0x55, 0x66],
        };
        let registration_fixture =
            application_vector("CandidateRegistration").expect("registration vector exists");
        assert_eq!(
            registration.encode().expect("encode registration"),
            registration_fixture
        );
        assert_eq!(
            ApplicationMessage::decode(&registration_fixture).expect("decode registration fixture"),
            registration
        );
        let acknowledgement = ApplicationMessage::CandidateRegistrationAck {
            registration_hash: [0x88; 32],
        };
        let acknowledgement_fixture =
            application_vector("CandidateRegistrationAck").expect("registration ACK vector exists");
        assert_eq!(
            acknowledgement.encode().expect("encode acknowledgement"),
            acknowledgement_fixture
        );
        assert_eq!(
            ApplicationMessage::decode(&acknowledgement_fixture)
                .expect("decode registration acknowledgement fixture"),
            acknowledgement
        );
    }

    #[test]
    fn malformed_versions_and_bounds_are_rejected() {
        let mut unsupported_version =
            [b"POP\x02".as_slice(), PUBLIC_NETWORK_ID.as_bytes()].concat();
        unsupported_version.push(super::FIND_NODE);
        assert_eq!(
            ApplicationMessage::decode(&unsupported_version),
            Err(ProtocolError::UnsupportedVersion(2))
        );
        let mut message = ApplicationMessage::FindNode {
            request_id: 1,
            target: RoutingKey::from_bytes([0; 32]),
            limit: 1,
        }
        .encode()
        .expect("encode");
        message.push(0);
        assert_eq!(
            ApplicationMessage::decode(&message),
            Err(ProtocolError::TrailingBytes)
        );
        let invalid = ApplicationMessage::FindNode {
            request_id: 1,
            target: RoutingKey::from_bytes([0; 32]),
            limit: 0,
        };
        assert_eq!(invalid.encode(), Err(ProtocolError::InvalidField));
        assert_eq!(
            ApplicationMessage::decode(&vec![0; 1024 * 1024 + 1]),
            Err(ProtocolError::MessageTooLarge)
        );
    }

    #[test]
    fn contacts_must_bind_node_id_to_network_identity() {
        let mut invalid = contact();
        invalid.node_id = NodeId::from_bytes([0; 32]);
        let message = ApplicationMessage::RoutingContacts {
            request_id: 0,
            contacts: vec![invalid],
        };
        assert_eq!(message.encode(), Err(ProtocolError::InvalidField));
    }

    #[test]
    fn error_responses_are_typed_and_round_trip() {
        let message = ApplicationMessage::Error {
            code: ApplicationErrorCode::NoActiveAuthority,
        };
        assert_eq!(
            ApplicationMessage::decode(&message.encode().expect("encode")).expect("decode"),
            message
        );
    }

    #[test]
    fn observed_address_request_matches_the_v1_golden_vector() {
        let message = ApplicationMessage::RequestObservedAddress {
            nonce: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        };
        assert_eq!(
            message.encode().expect("encode"),
            [
                b"POP\x01".as_slice(),
                PUBLIC_NETWORK_ID.as_bytes(),
                &[3, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            ]
            .concat()
        );
    }

    #[test]
    fn direct_vote_envelope_matches_the_v1_golden_vector() {
        let message = ApplicationMessage::DirectVote {
            vote: [0xde, 0xad, 0xbe, 0xef].to_vec(),
        };
        assert_eq!(
            message.encode().expect("encode"),
            [
                b"POP\x01".as_slice(),
                PUBLIC_NETWORK_ID.as_bytes(),
                &[5, 0, 0, 0, 4, 0xde, 0xad, 0xbe, 0xef],
            ]
            .concat()
        );
    }
}
