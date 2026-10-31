use std::fmt;
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

pub(crate) fn parse_hex<const N: usize>(text: &str) -> Result<[u8; N], IdParseError> {
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
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
