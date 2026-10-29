//! Deterministic, mergeable distinct-client sketches for Populus.

use populus_types::ClientId;
use std::fmt;

/// HLL precision. The sketch has `2^14` registers.
pub const PRECISION: u8 = 14;
/// Number of HLL registers.
pub const REGISTER_COUNT: usize = 1 << PRECISION;
/// Maximum client count retained exactly before promotion to dense HLL.
pub const SPARSE_LIMIT: usize = 256;

const HEADER: [u8; 4] = *b"PHLL";
const FORMAT_VERSION: u8 = 1;
const HEADER_LENGTH: usize = 6;
const BITS_PER_REGISTER: usize = 6;
const DENSE_LENGTH: usize = REGISTER_COUNT * BITS_PER_REGISTER / 8;
const MAX_REGISTER: u8 = 64 - PRECISION + 1;
const MAX_ENCODED_LENGTH: usize = HEADER_LENGTH
    + if SPARSE_LIMIT * 32 > DENSE_LENGTH {
        SPARSE_LIMIT * 32
    } else {
        DENSE_LENGTH
    };

/// A mergeable distinct-client counter using exact sparse storage and dense HLL.
///
/// Client IDs are already domain-separated SHA-256 outputs, so their first
/// 64 bits provide the HLL input without another runtime hash or dependency.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientSketch {
    representation: Representation,
}

#[derive(Clone, PartialEq, Eq)]
enum Representation {
    Sparse(Vec<ClientId>),
    Dense(Vec<u8>),
}

impl Default for ClientSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ClientSketch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSketch")
            .field("estimate", &self.estimate())
            .finish_non_exhaustive()
    }
}

impl ClientSketch {
    /// Creates an empty sketch.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            representation: Representation::Sparse(Vec::new()),
        }
    }

    /// Inserts a voting identity. Repeated insertions are idempotent.
    pub fn insert(&mut self, client_id: ClientId) {
        match &mut self.representation {
            Representation::Sparse(client_ids) => match client_ids.binary_search(&client_id) {
                Ok(_) => {}
                Err(index) => {
                    client_ids.insert(index, client_id);
                    if client_ids.len() > SPARSE_LIMIT {
                        self.promote();
                    }
                }
            },
            Representation::Dense(registers) => update_registers(registers, client_id),
        }
    }

    /// Returns the estimated distinct-client count.
    ///
    /// Sparse sketches are exact. Dense sketches use the HLL estimator with
    /// small- and large-range corrections.
    #[must_use]
    #[allow(
        clippy::cast_precision_loss,
        reason = "sparse populations are capped at 256, exactly representable in f64"
    )]
    pub fn estimate(&self) -> f64 {
        match &self.representation {
            Representation::Sparse(client_ids) => client_ids.len() as f64,
            Representation::Dense(registers) => estimate_dense(registers),
        }
    }

    /// Merges another sketch into this one.
    pub fn merge(&mut self, other: &Self) {
        match &other.representation {
            Representation::Sparse(other_ids) => match &mut self.representation {
                Representation::Sparse(client_ids) => {
                    let merged = merge_sorted(client_ids, other_ids);
                    if merged.len() > SPARSE_LIMIT {
                        self.representation = Representation::Dense(dense_from_ids(&merged));
                    } else {
                        self.representation = Representation::Sparse(merged);
                    }
                }
                Representation::Dense(registers) => {
                    for client_id in other_ids {
                        update_registers(registers, *client_id);
                    }
                }
            },
            Representation::Dense(other_registers) => {
                let registers = match &mut self.representation {
                    Representation::Sparse(client_ids) => {
                        let mut registers = dense_from_ids(client_ids);
                        merge_registers(&mut registers, other_registers);
                        registers
                    }
                    Representation::Dense(registers) => {
                        merge_registers(registers, other_registers);
                        return;
                    }
                };
                self.representation = Representation::Dense(registers);
            }
        }
    }

    /// Encodes the sketch in the canonical v1 format.
    ///
    /// The format is `PHLL`, version, representation tag, then either sorted
    /// 32-byte `ClientIds` or the packed six-bit dense register array.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&HEADER);
        encoded.push(FORMAT_VERSION);
        match &self.representation {
            Representation::Sparse(client_ids) => {
                encoded.push(0);
                for client_id in client_ids {
                    encoded.extend_from_slice(client_id.as_bytes());
                }
            }
            Representation::Dense(registers) => {
                encoded.push(1);
                encoded.extend_from_slice(registers);
            }
        }
        encoded
    }

    /// Decodes a canonical v1 sketch, rejecting malformed or oversized input.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported format, invalid length, noncanonical
    /// sparse IDs, or dense registers outside the v1 range.
    pub fn deserialize(encoded: &[u8]) -> Result<Self, SketchDecodeError> {
        if encoded.len() > MAX_ENCODED_LENGTH {
            return Err(SketchDecodeError::InputTooLarge);
        }
        if encoded.len() < HEADER_LENGTH || encoded[..4] != HEADER {
            return Err(SketchDecodeError::InvalidHeader);
        }
        if encoded[4] != FORMAT_VERSION {
            return Err(SketchDecodeError::UnsupportedVersion(encoded[4]));
        }

        match encoded[5] {
            0 => {
                let payload = &encoded[HEADER_LENGTH..];
                let (id_chunks, remainder) = payload.as_chunks::<32>();
                if !remainder.is_empty() {
                    return Err(SketchDecodeError::InvalidLength);
                }
                let count = id_chunks.len();
                if count > SPARSE_LIMIT {
                    return Err(SketchDecodeError::SparsePopulationTooLarge);
                }
                let mut client_ids = Vec::with_capacity(count);
                for bytes in id_chunks {
                    let mut id = [0; 32];
                    id.copy_from_slice(bytes);
                    let client_id = ClientId::from_bytes(id);
                    if client_ids
                        .last()
                        .is_some_and(|previous| *previous >= client_id)
                    {
                        return Err(SketchDecodeError::SparseIdsNotStrictlyIncreasing);
                    }
                    client_ids.push(client_id);
                }
                Ok(Self {
                    representation: Representation::Sparse(client_ids),
                })
            }
            1 => {
                let payload = &encoded[HEADER_LENGTH..];
                if payload.len() != DENSE_LENGTH {
                    return Err(SketchDecodeError::InvalidLength);
                }
                for index in 0..REGISTER_COUNT {
                    let value = read_packed_register(payload, index);
                    if value > MAX_REGISTER {
                        return Err(SketchDecodeError::RegisterOutOfRange { index, value });
                    }
                }
                Ok(Self {
                    representation: Representation::Dense(payload.to_vec()),
                })
            }
            kind => Err(SketchDecodeError::InvalidRepresentation(kind)),
        }
    }

    /// Returns the value of one register, or `None` when the index is invalid.
    #[must_use]
    pub fn register(&self, index: usize) -> Option<u8> {
        if index >= REGISTER_COUNT {
            return None;
        }
        Some(self.register_value(index))
    }

    /// Iterates over registers in ascending register-index order.
    pub fn registers(&self) -> impl ExactSizeIterator<Item = u8> + '_ {
        (0..REGISTER_COUNT).map(|index| self.register_value(index))
    }

    /// Returns the bytes occupied by the sketch's owned backing buffer.
    ///
    /// Allocator metadata and the inline enum/struct representation are not
    /// included. Sparse storage is reported at vector capacity.
    #[must_use]
    pub fn memory_usage(&self) -> usize {
        match &self.representation {
            Representation::Sparse(client_ids) => client_ids.capacity() * 32,
            Representation::Dense(registers) => registers.capacity(),
        }
    }

    /// Clears the sketch and returns it to exact sparse representation.
    pub fn reset(&mut self) {
        self.representation = Representation::Sparse(Vec::new());
    }

    fn promote(&mut self) {
        if let Representation::Sparse(client_ids) = &self.representation {
            self.representation = Representation::Dense(dense_from_ids(client_ids));
        }
    }

    fn register_value(&self, index: usize) -> u8 {
        match &self.representation {
            Representation::Sparse(client_ids) => client_ids
                .iter()
                .map(|client_id| register_for(*client_id))
                .filter(|(candidate, _)| *candidate == index)
                .fold(0, |maximum, (_, value)| maximum.max(value)),
            Representation::Dense(registers) => read_packed_register(registers, index),
        }
    }
}

/// Error returned when a serialized sketch is malformed or unsupported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SketchDecodeError {
    /// The input does not start with the `PHLL` magic bytes.
    InvalidHeader,
    /// The input uses an unsupported serialization version.
    UnsupportedVersion(u8),
    /// The representation tag is not defined by v1.
    InvalidRepresentation(u8),
    /// The encoded length does not match the selected representation.
    InvalidLength,
    /// The serialized input exceeds the maximum supported sketch size.
    InputTooLarge,
    /// A sparse representation contains more than the supported exact limit.
    SparsePopulationTooLarge,
    /// Sparse `ClientIds` are not in strictly increasing canonical order.
    SparseIdsNotStrictlyIncreasing,
    /// A dense register exceeds the maximum value supported by v1.
    RegisterOutOfRange {
        /// Register index containing the invalid value.
        index: usize,
        /// Invalid register value.
        value: u8,
    },
}

impl fmt::Display for SketchDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHeader => formatter.write_str("invalid sketch header"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported sketch version {version}")
            }
            Self::InvalidRepresentation(kind) => {
                write!(formatter, "invalid sketch representation {kind}")
            }
            Self::InvalidLength => formatter.write_str("invalid sketch length"),
            Self::InputTooLarge => formatter.write_str("serialized sketch is too large"),
            Self::SparsePopulationTooLarge => {
                formatter.write_str("sparse sketch exceeds its population limit")
            }
            Self::SparseIdsNotStrictlyIncreasing => {
                formatter.write_str("sparse ClientIds are not strictly increasing")
            }
            Self::RegisterOutOfRange { index, value } => {
                write!(formatter, "register {index} has invalid value {value}")
            }
        }
    }
}

impl std::error::Error for SketchDecodeError {}

fn merge_sorted(left: &[ClientId], right: &[ClientId]) -> Vec<ClientId> {
    let mut merged = Vec::with_capacity(left.len() + right.len());
    let (mut left_index, mut right_index) = (0, 0);
    while left_index < left.len() && right_index < right.len() {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => {
                merged.push(left[left_index]);
                left_index += 1;
            }
            std::cmp::Ordering::Greater => {
                merged.push(right[right_index]);
                right_index += 1;
            }
            std::cmp::Ordering::Equal => {
                merged.push(left[left_index]);
                left_index += 1;
                right_index += 1;
            }
        }
    }
    merged.extend_from_slice(&left[left_index..]);
    merged.extend_from_slice(&right[right_index..]);
    merged
}

fn dense_from_ids(client_ids: &[ClientId]) -> Vec<u8> {
    let mut registers = vec![0; DENSE_LENGTH];
    for client_id in client_ids {
        update_registers(&mut registers, *client_id);
    }
    registers
}

fn merge_registers(registers: &mut [u8], other: &[u8]) {
    for index in 0..REGISTER_COUNT {
        let value = read_packed_register(other, index);
        if value > read_packed_register(registers, index) {
            write_packed_register(registers, index, value);
        }
    }
}

fn update_registers(registers: &mut [u8], client_id: ClientId) {
    let (index, rank) = register_for(client_id);
    if rank > read_packed_register(registers, index) {
        write_packed_register(registers, index, rank);
    }
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "the index is 14 bits and rank is clamped to 51"
)]
fn register_for(client_id: ClientId) -> (usize, u8) {
    let bytes = client_id.as_bytes();
    let hash = u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    let index = (hash >> (64 - PRECISION)) as usize;
    let rank = ((hash << PRECISION).leading_zeros() + 1).min(u32::from(MAX_REGISTER)) as u8;
    (index, rank)
}

fn read_packed_register(registers: &[u8], index: usize) -> u8 {
    let bit_offset = index * BITS_PER_REGISTER;
    let byte_index = bit_offset / 8;
    let shift = bit_offset % 8;
    let mut value = u16::from(registers[byte_index]) >> shift;
    if shift + BITS_PER_REGISTER > 8 {
        value |= u16::from(registers[byte_index + 1]) << (8 - shift);
    }
    (value & 0x3f) as u8
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "each cast intentionally selects one byte of a bounded 6-bit value"
)]
fn write_packed_register(registers: &mut [u8], index: usize, value: u8) {
    let bit_offset = index * BITS_PER_REGISTER;
    let byte_index = bit_offset / 8;
    let shift = bit_offset % 8;
    let bits = u16::from(value) << shift;
    let low_mask = (0x3f_u16 << shift) as u8;
    registers[byte_index] = (registers[byte_index] & !low_mask) | bits as u8;
    if shift + BITS_PER_REGISTER > 8 {
        let high_mask = (0x3f_u16 << shift >> 8) as u8;
        registers[byte_index + 1] = (registers[byte_index + 1] & !high_mask) | (bits >> 8) as u8;
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "register counts are bounded by 16,384 and exactly representable in f64"
)]
fn estimate_dense(registers: &[u8]) -> f64 {
    let register_count = REGISTER_COUNT as f64;
    let harmonic_sum = (0..REGISTER_COUNT)
        .map(|index| 2_f64.powi(-i32::from(read_packed_register(registers, index))))
        .sum::<f64>();
    let alpha = 0.7213 / (1.0 + 1.079 / register_count);
    let raw_estimate = alpha * register_count * register_count / harmonic_sum;
    let zero_registers = (0..REGISTER_COUNT)
        .filter(|index| read_packed_register(registers, *index) == 0)
        .count();

    if raw_estimate <= 2.5 * register_count && zero_registers > 0 {
        register_count * (register_count / zero_registers as f64).ln()
    } else {
        let hash_space = 2_f64.powi(64);
        if raw_estimate > hash_space / 30.0 && raw_estimate < hash_space {
            -hash_space * (1.0 - raw_estimate / hash_space).ln()
        } else {
            raw_estimate
        }
    }
}

#[cfg(test)]
mod tests;
