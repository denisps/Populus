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
                write!(
                    formatter,
                    "expected {expected} bytes or hex characters, got {actual}"
                )
            }
            Self::InvalidHex { index } => {
                write!(
                    formatter,
                    "invalid lowercase hexadecimal character at byte {index}"
                )
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
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    for (index, (destination, pair)) in result.iter_mut().zip(pairs).enumerate() {
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
    "A `NodeId` is the v1 scarce-network-derived position of a node in Populus XOR routing. \
     It is exactly 32 bytes and remains associated with the normalized address resource; \
     it does not authenticate a transport peer or conceal enumerable IP inputs."
);
fixed_id!(
    ClientId,
    "A `ClientId` is the v1 scarce-network-derived voting and deduplication identity. \
     It is exactly 32 bytes and persists for the normalized scarcity resource under v1; \
     hashing is not anonymization and the IPv4 source space is enumerable."
);
fixed_id!(
    ProducerId,
    "A `ProducerId` identifies an Ed25519 public key for authorship, independently of \
     network identity. It is exactly 32 bytes and remains stable for that key under v1; \
     the identifier does not itself prove a signature."
);
fixed_id!(
    AuthorityId,
    "An `AuthorityId` identifies an authority Ed25519 signing key under its own v1 \
     hash domain. It is exactly 32 bytes and remains stable for that key; the ID is \
     identity, not proof that the key is trusted."
);
fixed_id!(
    MutableContentId,
    "A `MutableContentId` is the stable v1 identity derived from a mutable object's \
     36-byte genesis CID. It is exactly 32 bytes and lasts for the object's lifetime; \
     later revision CIDs do not change it."
);
fixed_id!(
    RoutingKey,
    "A `RoutingKey` is a v1 domain-separated hash of a typed logical identifier. \
     It is exactly 32 bytes and is used only as a fixed-width Populus XOR target."
);

/// A v1 immutable content identifier using the restricted `CIDv1` `dag-cbor`/`sha2-256` profile.
///
/// The wire form is exactly `0x01 || 0x71 || 0x12 || 0x20 || digest[32]` (36 bytes).
/// It is stable for the addressed immutable object; only this codec and hash profile
/// are accepted in v1. Phase 3 may widen the profile as a versioned protocol change.
///
/// ```compile_fail
/// use populus_types::{ContentId, MutableContentId};
/// let content = ContentId::from_digest([0; 32]);
/// let _: MutableContentId = content;
/// ```
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
                write!(
                    formatter,
                    "expected {expected} bytes or hex characters, got {actual}"
                )
            }
            Self::InvalidProfile => formatter.write_str("unsupported ContentId profile"),
            Self::InvalidHex { index } => {
                write!(
                    formatter,
                    "invalid lowercase hexadecimal character at byte {index}"
                )
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
    ///
    /// # Errors
    ///
    /// Returns [`ContentIdParseError::InvalidProfile`] when the prefix is not the
    /// v1 dag-cbor/sha2-256 profile.
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
    /// IPv6 address belongs to `fe80::/10`.
    Ipv6LinkLocal,
    /// IPv6 address belongs to `ff00::/8`.
    Ipv6Multicast,
    /// IPv6 address belongs to `fc00::/7`.
    Ipv6UniqueLocal,
    /// IPv6 address belongs to `2001:db8::/32`.
    Ipv6Documentation,
    /// IPv6 address belongs to `fec0::/10`.
    Ipv6SiteLocal,
    /// IPv6 address belongs to `100::/64`.
    Ipv6Discard,
    /// IPv6 address belongs to the deprecated `2001::/32` Teredo range.
    Ipv6Teredo,
    /// IPv6 address belongs to one of the specified NAT64 ranges.
    Ipv6Nat64,
    /// IPv6 address belongs to the deprecated IPv4-compatible `::/96` range.
    Ipv4Compatible,
    /// Ordinary IPv6 address is outside the v1 global-unicast `2000::/3` range.
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
/// before IPv6 eligibility is checked (ID-002). It exists for the lifetime of the
/// normalized public address resource under v1; over-merging is intentional, and
/// the encoding/hash is not a privacy boundary.
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
    /// IPv6 addresses must be eligible global unicast in `2000::/3` and are reduced
    /// to their /48. The function is pure and performs no network lookup.
    ///
    /// # Errors
    ///
    /// Returns the precise IPv4 or IPv6 eligibility rejection class.
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
                    return normalize_v4(Ipv4Addr::new(octets[2], octets[3], octets[4], octets[5]));
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
    ///
    /// # Errors
    ///
    /// Returns [`NetworkIdentityParseError`] for malformed, ineligible, or
    /// non-canonical encodings.
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
            (Some(0x04 | 0x06) | None, _) => Err(NetworkIdentityParseError::WrongLength),
            (Some(_), _) => Err(NetworkIdentityParseError::InvalidFamilyTag),
        }
    }
}

impl TryFrom<&[u8]> for NetworkIdentity {
    type Error = NetworkIdentityParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes)
    }
}

/// Big-endian 256-bit XOR distance between routing identifiers.
///
/// Distances may be computed between a `NodeId` and either a `RoutingKey` or
/// another `NodeId`; these are the two protocol-defined routing comparisons.
/// Ordering is unsigned big-endian numeric ordering and leading-zero counts use bits.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
                let mut mask = 0x80;
                while byte & mask == 0 {
                    count += 1;
                    mask >>= 1;
                }
                break;
            }
        }
        count
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
    #[must_use]
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
mod tests;
