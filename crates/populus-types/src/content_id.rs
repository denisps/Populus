use crate::id::{IdParseError, parse_hex};
use std::fmt;
use std::str::FromStr;

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
