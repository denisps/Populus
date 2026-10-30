use crate::IdParseError;

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
