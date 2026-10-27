//! Foundational, non-cryptographic protocol types for Populus.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// Error returned when a fixed-width identifier has malformed bytes or hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdParseError {
    /// The input has a byte or character length other than the required fixed width.
    WrongLength {
        /// Required byte or character count.
        expected: usize,
        /// Supplied byte or character count.
        actual: usize,
    },
    /// The input contains a non-lowercase hexadecimal character.
    InvalidHex {
        /// Byte offset of the invalid character.
        index: usize,
    },
}

impl fmt::Display for IdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(formatter, "expected {expected} bytes or hex characters, got {actual}")
            }
            Self::InvalidHex { index } => {
                write!(formatter, "invalid lowercase hexadecimal character at byte {index}")
            }
        }
    }
}

impl std::error::Error for IdParseError {}

fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], IdParseError> {
    if text.len() != N.saturating_mul(2) {
        return Err(IdParseError::WrongLength {
            expected: N.saturating_mul(2),
            actual: text.len(),
        });
    }

    let mut result = [0; N];
    for (index, (destination, pair)) in result
        .iter_mut()
        .zip(text.as_bytes().chunks_exact(2))
        .enumerate()
    {
        let Some((&high, &low)) = pair.first().zip(pair.get(1)) else {
            return Err(IdParseError::InvalidHex {
                index: index.saturating_mul(2),
            });
        };
        *destination = (hex_nibble(high, index.saturating_mul(2))? << 4)
            | hex_nibble(low, index.saturating_mul(2).saturating_add(1))?;
    }
    Ok(result)
}

fn hex_nibble(byte: u8, index: usize) -> Result<u8, IdParseError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(IdParseError::InvalidHex { index }),
    }
}

macro_rules! fixed_id {
    ($name:ident, $meaning:literal) => {
        #[doc = $meaning]
        ///
        /// The value is an opaque 32-byte identifier. Ordering is lexicographic
        /// over its bytes, equivalent to big-endian unsigned ordering.
        ///
        /// No conversions exist between this type and other identifier types.
        ///
        /// ```compile_fail
        /// use populus_types::{ClientId, NodeId};
        /// let node = NodeId::from_bytes([0; 32]);
        /// let _: ClientId = node;
        /// ```
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs the identifier from exactly 32 bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the identifier's bytes in protocol order.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Copies the identifier's bytes in protocol order.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = IdParseError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                if bytes.len() != 32 {
                    return Err(IdParseError::WrongLength {
                        expected: 32,
                        actual: bytes.len(),
                    });
                }
                let mut value = [0; 32];
                value.copy_from_slice(bytes);
                Ok(Self(value))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                for byte in self.0 {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(text: &str) -> Result<Self, Self::Err> {
                parse_hex(text).map(Self)
            }
        }
    };
}

fixed_id!(
    NodeId,
    "A `NodeId` is the v1 scarce-network-derived position of a node in Populus XOR routing."
);
fixed_id!(
    ClientId,
    "A `ClientId` is the v1 scarce-network-derived voting and deduplication identity."
);
fixed_id!(
    ProducerId,
    "A `ProducerId` identifies a cryptographic content producer, independently of network identity."
);
fixed_id!(
    AuthorityId,
    "An `AuthorityId` identifies an authority signing key under its own versioned hash domain."
);
fixed_id!(
    MutableContentId,
    "A `MutableContentId` is the stable v1 identity derived from a mutable object's genesis CID."
);
fixed_id!(
    RoutingKey,
    "A `RoutingKey` is a uniformly distributed 32-byte key used for Populus XOR routing."
);

/// A v1 immutable content identifier using the restricted CIDv1 dag-cbor/sha2-256 profile.
///
/// The wire form is exactly `0x01 || 0x71 || 0x12 || 0x20 || digest[32]`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentId([u8; 36]);

/// Error returned when a CID is not in the restricted Populus v1 profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentIdParseError {
    /// The encoded CID does not contain exactly 36 bytes.
    WrongLength {
        /// Required byte or character count.
        expected: usize,
        /// Supplied byte or character count.
        actual: usize,
    },
    /// The version, codec, multihash code, or digest length is unsupported.
    InvalidProfile,
    /// A hex representation contains an invalid lowercase hexadecimal character.
    InvalidHex {
        /// Byte offset of the invalid character.
        index: usize,
    },
}

impl fmt::Display for ContentIdParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(formatter, "expected {expected} bytes or hex characters, got {actual}")
            }
            Self::InvalidProfile => formatter.write_str("unsupported ContentId profile"),
            Self::InvalidHex { index } => {
                write!(formatter, "invalid lowercase hexadecimal character at byte {index}")
            }
        }
    }
}

impl std::error::Error for ContentIdParseError {}

impl ContentId {
    /// Constructs a v1 CID from a 32-byte sha2-256 digest.
    #[must_use]
    pub const fn from_digest(digest: [u8; 32]) -> Self {
        let mut bytes = [0; 36];
        bytes[0] = 0x01;
        bytes[1] = 0x71;
        bytes[2] = 0x12;
        bytes[3] = 0x20;
        let mut index = 0;
        while index < 32 {
            bytes[index + 4] = digest[index];
            index += 1;
        }
        Self(bytes)
    }

    /// Parses a complete 36-byte CID, rejecting unsupported profiles and trailing bytes.
    pub fn from_bytes(bytes: [u8; 36]) -> Result<Self, ContentIdParseError> {
        if bytes[..4] != [0x01, 0x71, 0x12, 0x20] {
            return Err(ContentIdParseError::InvalidProfile);
        }
        Ok(Self(bytes))
    }

    /// Returns the complete 36-byte CID in protocol order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 36] {
        &self.0
    }

    /// Returns the 32-byte sha2-256 digest carried by this CID.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.0[4..]
    }
}

impl TryFrom<&[u8]> for ContentId {
    type Error = ContentIdParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 36 {
            return Err(ContentIdParseError::WrongLength {
                expected: 36,
                actual: bytes.len(),
            });
        }
        let mut value = [0; 36];
        value.copy_from_slice(bytes);
        Self::from_bytes(value)
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for ContentId {
    type Err = ContentIdParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let bytes = parse_hex::<36>(text).map_err(|error| match error {
            IdParseError::WrongLength { expected, actual } => {
                ContentIdParseError::WrongLength { expected, actual }
            }
            IdParseError::InvalidHex { index } => ContentIdParseError::InvalidHex { index },
        })?;
        Self::from_bytes(bytes)
    }
}

/// Typed rejection classes for the v1 scarce-network identity policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkIdentityError {
    /// IPv4 address belongs to 10/8, 172.16/12, or 192.168/16.
    Ipv4Private,
    /// IPv4 address belongs to 127/8.
    Ipv4Loopback,
    /// IPv4 address belongs to 169.254/16.
    Ipv4LinkLocal,
    /// IPv4 address belongs to 100.64/10.
    Ipv4CarrierGradeNat,
    /// IPv4 address belongs to 224/4.
    Ipv4Multicast,
    /// IPv4 address belongs to 240/4, including limited broadcast.
    Ipv4Reserved,
    /// IPv4 address belongs to 0/8.
    Ipv4Unspecified,
    /// IPv4 address belongs to 192.0.2/24, 198.51.100/24, or 203.0.113/24.
    Ipv4Documentation,
    /// IPv6 address is the unspecified address.
    Ipv6Unspecified,
    /// IPv6 address is the loopback address.
    Ipv6Loopback,
    /// IPv6 address belongs to fe80::/10.
    Ipv6LinkLocal,
    /// IPv6 address belongs to ff00::/8.
    Ipv6Multicast,
    /// IPv6 address belongs to fc00::/7.
    Ipv6UniqueLocal,
    /// IPv6 address belongs to 2001:db8::/32.
    Ipv6Documentation,
    /// IPv6 address belongs to fec0::/10.
    Ipv6SiteLocal,
    /// IPv6 address belongs to 100::/64.
    Ipv6Discard,
    /// IPv6 address belongs to the deprecated 2001::/32 Teredo range.
    Ipv6Teredo,
    /// IPv6 address belongs to one of the specified NAT64 ranges.
    Ipv6Nat64,
    /// IPv6 address belongs to the deprecated IPv4-compatible ::/96 range.
    Ipv4Compatible,
    /// Ordinary IPv6 address is outside the v1 global-unicast 2000::/3 range.
    Ipv6NotGlobalUnicast,
}

impl fmt::Display for NetworkIdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = match self {
            Self::Ipv4Private => "private IPv4 address",
            Self::Ipv4Loopback => "loopback IPv4 address",
            Self::Ipv4LinkLocal => "link-local IPv4 address",
            Self::Ipv4CarrierGradeNat => "carrier-grade NAT IPv4 address",
            Self::Ipv4Multicast => "multicast IPv4 address",
            Self::Ipv4Reserved => "reserved IPv4 address",
            Self::Ipv4Unspecified => "unspecified IPv4 address",
            Self::Ipv4Documentation => "documentation IPv4 address",
            Self::Ipv6Unspecified => "unspecified IPv6 address",
            Self::Ipv6Loopback => "loopback IPv6 address",
            Self::Ipv6LinkLocal => "link-local IPv6 address",
            Self::Ipv6Multicast => "multicast IPv6 address",
            Self::Ipv6UniqueLocal => "unique-local IPv6 address",
            Self::Ipv6Documentation => "documentation IPv6 address",
            Self::Ipv6SiteLocal => "site-local IPv6 address",
            Self::Ipv6Discard => "discard IPv6 address",
            Self::Ipv6Teredo => "Teredo IPv6 address",
            Self::Ipv6Nat64 => "NAT64 IPv6 address",
            Self::Ipv4Compatible => "IPv4-compatible IPv6 address",
            Self::Ipv6NotGlobalUnicast => "IPv6 address outside global unicast",
        };
        formatter.write_str(description)
    }
}

impl std::error::Error for NetworkIdentityError {}

/// Canonical scarcity identity derived from an eligible public network allocation.
///
/// IPv4 identities encode as `0x04 || address[4]`; ordinary IPv6 identities encode
/// as `0x06 || /48-prefix[6]`. Mapped and 6to4 IPv6 forms are classified as IPv4
/// before IPv6 eligibility is checked (ID-002).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkIdentity {
    encoded: [u8; 7],
    length: u8,
}

/// Error returned when canonical network-identity bytes are malformed or ineligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkIdentityParseError {
    /// The input is not a five-byte IPv4 or seven-byte IPv6 canonical encoding.
    WrongLength,
    /// The family tag is not 0x04 or 0x06.
    InvalidFamilyTag,
    /// The represented address fails the v1 eligibility policy.
    Ineligible(NetworkIdentityError),
    /// The encoding is valid in form but is not the canonical normalized value.
    NonCanonical,
}

impl fmt::Display for NetworkIdentityParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength => formatter.write_str("invalid NetworkIdentity length"),
            Self::InvalidFamilyTag => formatter.write_str("invalid NetworkIdentity family tag"),
            Self::Ineligible(error) => write!(formatter, "ineligible network identity: {error}"),
            Self::NonCanonical => formatter.write_str("non-canonical NetworkIdentity encoding"),
        }
    }
}

impl std::error::Error for NetworkIdentityParseError {}

impl NetworkIdentity {
    /// Classifies and normalizes one address according to the v1 ID-002 policy.
    ///
    /// IPv4-mapped and 6to4 forms are converted to their embedded IPv4 scarcity
    /// resource first, then checked using native IPv4 eligibility rules. All other
    /// IPv6 addresses must be eligible global unicast in 2000::/3 and are reduced
    /// to their /48. The function is pure and performs no network lookup.
    pub fn from_ip(address: IpAddr) -> Result<Self, NetworkIdentityError> {
        let normalize_v4 = |address: Ipv4Addr| -> Result<Self, NetworkIdentityError> {
            let [first, second, third, _] = address.octets();
            let rejected = if first == 10
                || (first == 172 && (16..=31).contains(&second))
                || (first == 192 && second == 168)
            {
                Some(NetworkIdentityError::Ipv4Private)
            } else if first == 127 {
                Some(NetworkIdentityError::Ipv4Loopback)
            } else if first == 169 && second == 254 {
                Some(NetworkIdentityError::Ipv4LinkLocal)
            } else if first == 100 && (64..=127).contains(&second) {
                Some(NetworkIdentityError::Ipv4CarrierGradeNat)
            } else if (224..=239).contains(&first) {
                Some(NetworkIdentityError::Ipv4Multicast)
            } else if first >= 240 {
                Some(NetworkIdentityError::Ipv4Reserved)
            } else if first == 0 {
                Some(NetworkIdentityError::Ipv4Unspecified)
            } else if (first == 192 && second == 0 && third == 2)
                || (first == 198 && second == 51 && third == 100)
                || (first == 203 && second == 0 && third == 113)
            {
                Some(NetworkIdentityError::Ipv4Documentation)
            } else {
                None
            };
            if let Some(error) = rejected {
                return Err(error);
            }

            let mut encoded = [0; 7];
            encoded[0] = 0x04;
            encoded[1..5].copy_from_slice(&address.octets());
            Ok(Self { encoded, length: 5 })
        };

        match address {
            IpAddr::V4(address) => normalize_v4(address),
            IpAddr::V6(address) => {
                if let Some(embedded) = address.to_ipv4_mapped() {
                    return normalize_v4(embedded);
                }

                let octets = address.octets();
                if octets[0] == 0x20 && octets[1] == 0x02 {
                    return normalize_v4(Ipv4Addr::new(
                        octets[2], octets[3], octets[4], octets[5],
                    ));
                }

                let segments = address.segments();
                let rejected = if address.is_unspecified() {
                    Some(NetworkIdentityError::Ipv6Unspecified)
                } else if address.is_loopback() {
                    Some(NetworkIdentityError::Ipv6Loopback)
                } else if segments[0] & 0xffc0 == 0xfe80 {
                    Some(NetworkIdentityError::Ipv6LinkLocal)
                } else if segments[0] & 0xff00 == 0xff00 {
                    Some(NetworkIdentityError::Ipv6Multicast)
                } else if segments[0] & 0xfe00 == 0xfc00 {
                    Some(NetworkIdentityError::Ipv6UniqueLocal)
                } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                    Some(NetworkIdentityError::Ipv6Documentation)
                } else if segments[0] & 0xffc0 == 0xfec0 {
                    Some(NetworkIdentityError::Ipv6SiteLocal)
                } else if octets[..8] == [0x01, 0, 0, 0, 0, 0, 0, 0] {
                    Some(NetworkIdentityError::Ipv6Discard)
                } else if segments[0] == 0x2001 && segments[1] == 0 {
                    Some(NetworkIdentityError::Ipv6Teredo)
                } else if octets[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
                    || segments[..3] == [0x0064, 0xff9b, 0x0001]
                {
                    Some(NetworkIdentityError::Ipv6Nat64)
                } else if octets[..12].iter().all(|byte| *byte == 0) {
                    Some(NetworkIdentityError::Ipv4Compatible)
                } else if segments[0] & 0xe000 != 0x2000 {
                    Some(NetworkIdentityError::Ipv6NotGlobalUnicast)
                } else {
                    None
                };
                if let Some(error) = rejected {
                    return Err(error);
                }

                let mut encoded = [0; 7];
                encoded[0] = 0x06;
                encoded[1..7].copy_from_slice(&octets[..6]);
                Ok(Self { encoded, length: 7 })
            }
        }
    }

    /// Returns the canonical family-tagged byte encoding used by identifier hashes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded[..usize::from(self.length)]
    }

    /// Parses a canonical family-tagged encoding and revalidates its v1 eligibility.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NetworkIdentityParseError> {
        match (bytes.first(), bytes.len()) {
            (Some(0x04), 5) => {
                let octets = [bytes[1], bytes[2], bytes[3], bytes[4]];
                Self::from_ip(IpAddr::V4(Ipv4Addr::from(octets)))
                    .map_err(NetworkIdentityParseError::Ineligible)
            }
            (Some(0x06), 7) => {
                let mut octets = [0; 16];
                octets[..6].copy_from_slice(&bytes[1..7]);
                let normalized = Self::from_ip(IpAddr::V6(Ipv6Addr::from(octets)))
                    .map_err(NetworkIdentityParseError::Ineligible)?;
                if normalized.as_bytes() != bytes {
                    return Err(NetworkIdentityParseError::NonCanonical);
                }
                Ok(normalized)
            }
            (Some(0x04) | Some(0x06), _) => Err(NetworkIdentityParseError::WrongLength),
            (Some(_), _) => Err(NetworkIdentityParseError::InvalidFamilyTag),
            (None, _) => Err(NetworkIdentityParseError::WrongLength),
        }
    }
}

impl TryFrom<&[u8]> for NetworkIdentity {
    type Error = NetworkIdentityParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

/// Big-endian XOR distance between routing identifiers.
///
/// Distances may be computed between a `NodeId` and either a `RoutingKey` or
/// another `NodeId`; these are the two protocol-defined routing comparisons.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XorDistance([u8; 32]);

impl XorDistance {
    /// Computes the distance from a node position to a logical routing key.
    #[must_use]
    pub fn between_node_and_key(node: &NodeId, key: &RoutingKey) -> Self {
        let mut distance = [0; 32];
        for (output, (left, right)) in distance
            .iter_mut()
            .zip(node.as_bytes().iter().zip(key.as_bytes()))
        {
            *output = left ^ right;
        }
        Self(distance)
    }

    /// Computes the distance between two node positions.
    #[must_use]
    pub fn between_nodes(left: &NodeId, right: &NodeId) -> Self {
        let mut distance = [0; 32];
        for (output, (left, right)) in distance
            .iter_mut()
            .zip(left.as_bytes().iter().zip(right.as_bytes()))
        {
            *output = left ^ right;
        }
        Self(distance)
    }

    /// Returns the distance bytes in big-endian comparison order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the number of zero bits preceding the first set bit, from 0 to 256.
    #[must_use]
    pub fn leading_zero_bits(&self) -> u16 {
        let mut count = 0_u16;
        for byte in self.0 {
            if byte == 0 {
                count += 8;
            } else {
                count += u16::try_from(byte.leading_zeros()).unwrap_or(0);
                break;
            }
        }
        count
    }
}

impl Default for XorDistance {
    fn default() -> Self {
        Self([0; 32])
    }
}

/// An opaque unsigned 64-bit protocol epoch, not a wall-clock timestamp.
///
/// Its wire representation is exactly eight bytes in big-endian order. The
/// protocol assigns meaning to epoch progression; this type performs no time logic.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Epoch(u64);

impl Epoch {
    /// Constructs an epoch from its numeric protocol value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the numeric protocol value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the eight-byte big-endian wire representation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Parses exactly eight bytes of big-endian epoch encoding.
    pub fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

impl TryFrom<&[u8]> for Epoch {
    type Error = IdParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 8 {
            return Err(IdParseError::WrongLength {
                expected: 8,
                actual: bytes.len(),
            });
        }
        let mut value = [0; 8];
        value.copy_from_slice(bytes);
        Ok(Self::from_bytes(value))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityId, ClientId, ContentId, ContentIdParseError, Epoch, IdParseError,
        MutableContentId, NetworkIdentity, NetworkIdentityError, NetworkIdentityParseError,
        NodeId, ProducerId, RoutingKey, XorDistance,
    };
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, RngSeed};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn id_hex_and_byte_round_trips() {
        let bytes = [0xabu8; 32];
        let ids = [
            NodeId::from_bytes(bytes).to_string(),
            ClientId::from_bytes(bytes).to_string(),
            ProducerId::from_bytes(bytes).to_string(),
            AuthorityId::from_bytes(bytes).to_string(),
            MutableContentId::from_bytes(bytes).to_string(),
            RoutingKey::from_bytes(bytes).to_string(),
        ];
        assert!(ids.iter().all(|text| text == &"ab".repeat(32)));
        assert!(NodeId::from_str(&ids[0]).is_ok_and(|id| id.as_bytes() == &bytes));
        assert!(ClientId::try_from(bytes.as_slice()).is_ok_and(|id| id.as_bytes() == &bytes));
        assert!(ProducerId::try_from(&bytes[..31]).is_err());
        assert!(AuthorityId::try_from(&bytes[..31]).is_err());
        assert!(MutableContentId::try_from(&bytes[..31]).is_err());
        assert!(RoutingKey::try_from(&bytes[..31]).is_err());
        assert!(NodeId::from_str(&"A".repeat(64)).is_err());
        assert!(NodeId::from_str("00").is_err());
        assert!(matches!(
            NodeId::try_from(&bytes[..31]),
            Err(IdParseError::WrongLength {
                expected: 32,
                actual: 31
            })
        ));
    }

    #[test]
    fn content_id_profile_is_strict() {
        let cid = ContentId::from_digest([0x42; 32]);
        assert!(ContentId::try_from(cid.as_bytes().as_slice()).is_ok_and(|parsed| parsed == cid));
        assert!(ContentId::from_str(&cid.to_string()).is_ok_and(|parsed| parsed == cid));
        assert!(matches!(
            ContentId::try_from(&cid.as_bytes()[..35]),
            Err(ContentIdParseError::WrongLength { .. })
        ));

        for index in 0..4 {
            let mut unsupported = *cid.as_bytes();
            unsupported[index] ^= 1;
            assert!(matches!(
                ContentId::from_bytes(unsupported),
                Err(ContentIdParseError::InvalidProfile)
            ));
        }
        let mut trailing = cid.as_bytes().to_vec();
        trailing.push(0);
        assert!(ContentId::try_from(trailing.as_slice()).is_err());
        assert!(ContentId::from_str(&"A".repeat(72)).is_err());
    }

    #[test]
    fn epoch_is_big_endian_and_opaque() {
        let epoch = Epoch::new(0x0102_0304_0506_0708);
        assert!(epoch.to_bytes() == [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(Epoch::try_from(epoch.to_bytes().as_slice()).is_ok_and(|decoded| decoded == epoch));
        assert!(Epoch::try_from(&[0; 7][..]).is_err());
        assert!(Epoch::new(2) < Epoch::new(3));
    }

    #[test]
    fn network_identity_encodings_round_trip() {
        let ipv4 = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(ipv4.is_ok());
        if let Ok(identity) = ipv4 {
            assert!(identity.as_bytes() == [0x04, 8, 8, 8, 8]);
            assert!(NetworkIdentity::from_bytes(identity.as_bytes()).is_ok_and(|decoded| decoded == identity));
        }

        let ipv6 = NetworkIdentity::from_ip(IpAddr::V6(
            Ipv6Addr::from_str("2001:4860:1234:abcd::1").unwrap_or(Ipv6Addr::UNSPECIFIED),
        ));
        assert!(ipv6.is_ok());
        if let Ok(identity) = ipv6 {
            assert!(identity.as_bytes() == [0x06, 0x20, 0x01, 0x48, 0x60, 0x12, 0x34]);
            assert!(NetworkIdentity::from_bytes(identity.as_bytes()).is_ok_and(|decoded| decoded == identity));
        }
        assert!(matches!(
            NetworkIdentity::from_bytes(&[0x06, 0x10, 0, 0, 0, 0, 0]),
            Err(NetworkIdentityParseError::Ineligible(
                NetworkIdentityError::Ipv6NotGlobalUnicast
            ))
        ));
        assert!(matches!(
            NetworkIdentity::from_bytes(&[0x05, 0, 0, 0, 0]),
            Err(NetworkIdentityParseError::InvalidFamilyTag)
        ));
    }

    #[test]
    fn ipv4_and_mapped_ipv4_apply_the_same_eligibility_policy() {
        let rejected = [
            ("10.0.0.1", NetworkIdentityError::Ipv4Private),
            ("172.16.0.1", NetworkIdentityError::Ipv4Private),
            ("192.168.0.1", NetworkIdentityError::Ipv4Private),
            ("127.0.0.1", NetworkIdentityError::Ipv4Loopback),
            ("169.254.1.1", NetworkIdentityError::Ipv4LinkLocal),
            ("100.64.0.1", NetworkIdentityError::Ipv4CarrierGradeNat),
            ("224.0.0.1", NetworkIdentityError::Ipv4Multicast),
            ("240.0.0.1", NetworkIdentityError::Ipv4Reserved),
            ("255.255.255.255", NetworkIdentityError::Ipv4Reserved),
            ("0.1.2.3", NetworkIdentityError::Ipv4Unspecified),
            ("192.0.2.1", NetworkIdentityError::Ipv4Documentation),
            ("198.51.100.1", NetworkIdentityError::Ipv4Documentation),
            ("203.0.113.1", NetworkIdentityError::Ipv4Documentation),
        ];
        for (address, expected) in rejected {
            let parsed = Ipv4Addr::from_str(address);
            assert!(parsed.is_ok());
            if let Ok(ipv4) = parsed {
                assert!(NetworkIdentity::from_ip(IpAddr::V4(ipv4)) == Err(expected));
                let mapped = ipv4.to_ipv6_mapped();
                assert!(NetworkIdentity::from_ip(IpAddr::V6(mapped)) == Err(expected));
            }
        }

        let loopback = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
        assert!(NetworkIdentity::from_ip(IpAddr::V6(loopback))
            == Err(NetworkIdentityError::Ipv4Loopback));
        let documentation = Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped();
        assert!(NetworkIdentity::from_ip(IpAddr::V6(documentation))
            == Err(NetworkIdentityError::Ipv4Documentation));

        let native = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let mapped = NetworkIdentity::from_ip(IpAddr::V6(
            Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped(),
        ));
        assert!(native.is_ok() && native == mapped);
    }

    #[test]
    fn six_to_four_applies_ipv4_eligibility_before_ipv6_policy() {
        let public = Ipv6Addr::new(0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1);
        let native = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(native.is_ok());
        assert!(NetworkIdentity::from_ip(IpAddr::V6(public)) == native);

        let private = Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1);
        assert!(NetworkIdentity::from_ip(IpAddr::V6(private))
            == Err(NetworkIdentityError::Ipv4Private));
        let documentation = Ipv6Addr::new(0x2002, 0xc000, 0x0201, 0, 0, 0, 0, 1);
        assert!(NetworkIdentity::from_ip(IpAddr::V6(documentation))
            == Err(NetworkIdentityError::Ipv4Documentation));
    }

    #[test]
    fn ipv6_exclusion_classes_are_rejected_after_transition_classification() {
        let rejected = [
            ("::", NetworkIdentityError::Ipv6Unspecified),
            ("::1", NetworkIdentityError::Ipv6Loopback),
            ("fe80::1", NetworkIdentityError::Ipv6LinkLocal),
            ("ff02::1", NetworkIdentityError::Ipv6Multicast),
            ("fc00::1", NetworkIdentityError::Ipv6UniqueLocal),
            ("2001:db8::1", NetworkIdentityError::Ipv6Documentation),
            ("fec0::1", NetworkIdentityError::Ipv6SiteLocal),
            ("100::1", NetworkIdentityError::Ipv6Discard),
            ("2001::1", NetworkIdentityError::Ipv6Teredo),
            ("64:ff9b::808:808", NetworkIdentityError::Ipv6Nat64),
            ("64:ff9b:1::1", NetworkIdentityError::Ipv6Nat64),
            ("::8.8.8.8", NetworkIdentityError::Ipv4Compatible),
            ("1000::1", NetworkIdentityError::Ipv6NotGlobalUnicast),
        ];
        for (address, expected) in rejected {
            let parsed = Ipv6Addr::from_str(address);
            assert!(parsed.is_ok());
            if let Ok(ipv6) = parsed {
                assert!(NetworkIdentity::from_ip(IpAddr::V6(ipv6)) == Err(expected));
            }
        }
    }

    #[test]
    fn ipv6_prefix_normalization_and_family_separation() {
        let first = NetworkIdentity::from_ip(IpAddr::V6(Ipv6Addr::from_str(
            "2001:4860:1234:abcd::1",
        ).unwrap_or(Ipv6Addr::UNSPECIFIED)));
        let same_prefix = NetworkIdentity::from_ip(IpAddr::V6(Ipv6Addr::from_str(
            "2001:4860:1234:ffff::1234",
        ).unwrap_or(Ipv6Addr::UNSPECIFIED)));
        let adjacent = NetworkIdentity::from_ip(IpAddr::V6(Ipv6Addr::from_str(
            "2001:4860:1235::1",
        ).unwrap_or(Ipv6Addr::UNSPECIFIED)));
        assert!(first.is_ok() && first == same_prefix);
        assert!(first.is_ok() && first != adjacent);

        let ipv4 = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let ipv6 = NetworkIdentity::from_ip(IpAddr::V6(Ipv6Addr::from_str(
            "2001:4860::1",
        ).unwrap_or(Ipv6Addr::UNSPECIFIED)));
        assert!(ipv4.is_ok() && ipv6.is_ok() && ipv4 != ipv6);
        assert!(matches!(
            NetworkIdentity::from_ip(IpAddr::V6(Ipv6Addr::from_str("2001:4860::1").unwrap_or(Ipv6Addr::UNSPECIFIED))),
            Ok(_)
        ));
    }

    #[test]
    fn xor_distance_has_big_endian_order_and_prefix_count() {
        let zero = NodeId::from_bytes([0; 32]);
        let same = XorDistance::between_nodes(&zero, &zero);
        assert!(same.as_bytes() == &[0; 32]);
        assert!(same.leading_zero_bits() == 256);

        let mut far_bytes = [0; 32];
        far_bytes[0] = 0x80;
        let mut near_bytes = [0; 32];
        near_bytes[0] = 0x7f;
        let far = XorDistance::between_nodes(&zero, &NodeId::from_bytes(far_bytes));
        let near = XorDistance::between_nodes(&zero, &NodeId::from_bytes(near_bytes));
        assert!(near < far);
        assert!(near.leading_zero_bits() == 1);
        let key = RoutingKey::from_bytes(near_bytes);
        assert!(XorDistance::between_node_and_key(&zero, &key).as_bytes() == near.as_bytes());
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            rng_seed: RngSeed::Fixed(0x504f_5055_4c55_5301),
            ..ProptestConfig::default()
        })]

        #[test]
        fn xor_identity_symmetry_and_order_match_big_endian(
            left in any::<[u8; 32]>(),
            right in any::<[u8; 32]>(),
            target in any::<[u8; 32]>(),
        ) {
            let a = NodeId::from_bytes(left);
            let b = NodeId::from_bytes(right);
            let key = RoutingKey::from_bytes(target);
            let zero = XorDistance::between_nodes(&a, &a);
            prop_assert!(zero.as_bytes() == &[0; 32]);
            let ab = XorDistance::between_nodes(&a, &b);
            let ba = XorDistance::between_nodes(&b, &a);
            prop_assert!(ab == ba);
            let to_key = XorDistance::between_node_and_key(&a, &key);
            let manual: [u8; 32] = std::array::from_fn(|index| left[index] ^ target[index]);
            prop_assert!(to_key.as_bytes() == &manual);
            prop_assert_eq!(to_key.cmp(&ab), manual.cmp(ab.as_bytes()));
        }

        #[test]
        fn arbitrary_id_bytes_round_trip(bytes in any::<[u8; 32]>()) {
            let id = NodeId::from_bytes(bytes);
            prop_assert!(NodeId::try_from(id.as_bytes().as_slice()).is_ok_and(|parsed| parsed == id));
            let client = ClientId::from_bytes(bytes);
            prop_assert!(ClientId::try_from(client.as_bytes().as_slice()).is_ok_and(|parsed| parsed == client));
        }

        #[test]
        fn arbitrary_parser_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=80)) {
            let _ = NodeId::try_from(bytes.as_slice());
            let _ = ContentId::try_from(bytes.as_slice());
            let _ = NetworkIdentity::try_from(bytes.as_slice());
            let _ = Epoch::try_from(bytes.as_slice());
            let text = String::from_utf8_lossy(&bytes);
            let _ = NodeId::from_str(&text);
            let _ = ContentId::from_str(&text);
        }
    }
}
