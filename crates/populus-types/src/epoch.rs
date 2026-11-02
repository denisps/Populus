use crate::IdParseError;

/// Milliseconds in one UTC calendar day.
pub const MILLIS_PER_UTC_DAY: i64 = 86_400_000;

/// An opaque unsigned 64-bit protocol epoch, not a wall-clock timestamp.
///
/// Its wire representation is exactly eight bytes in big-endian order. The
/// protocol assigns meaning to epoch progression; this type performs no time logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// A UTC calendar day represented as signed days since 1970-01-01.
///
/// The signed big-endian value is the canonical v1 wire form. A day is derived
/// from Unix milliseconds with Euclidean division, including for pre-epoch dates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UtcDay(i64);

impl UtcDay {
    /// Constructs a UTC day from its signed day offset from 1970-01-01.
    #[must_use]
    pub const fn new(days_since_unix_epoch: i64) -> Self {
        Self(days_since_unix_epoch)
    }

    /// Derives the UTC day containing a Unix timestamp in milliseconds.
    #[must_use]
    pub const fn from_unix_millis(timestamp_ms: i64) -> Self {
        Self(timestamp_ms.div_euclid(MILLIS_PER_UTC_DAY))
    }

    /// Returns the signed number of days since 1970-01-01.
    #[must_use]
    pub const fn value(self) -> i64 {
        self.0
    }

    /// Returns the canonical eight-byte big-endian encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the first Unix millisecond of this day when representable.
    #[must_use]
    pub const fn start_unix_millis(self) -> Option<i64> {
        self.0.checked_mul(MILLIS_PER_UTC_DAY)
    }

    /// Returns the first Unix millisecond after this day when representable.
    #[must_use]
    pub const fn end_unix_millis(self) -> Option<i64> {
        match self.start_unix_millis() {
            Some(start) => start.checked_add(MILLIS_PER_UTC_DAY),
            None => None,
        }
    }

    /// Decodes the canonical eight-byte big-endian form.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(i64::from_be_bytes(bytes))
    }
}
