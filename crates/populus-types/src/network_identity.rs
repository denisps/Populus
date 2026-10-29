use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
