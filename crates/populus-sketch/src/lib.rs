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
mod tests {
    use super::{ClientSketch, REGISTER_COUNT, SPARSE_LIMIT, SketchDecodeError};
    use populus_types::ClientId;
    use std::collections::HashSet;

    fn client_id(seed: u64, index: u64) -> ClientId {
        let mut bytes = [0; 32];
        for (lane, lane_tag) in [0_u64, 1, 2, 3].into_iter().enumerate() {
            let value = mix64(seed ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ lane_tag);
            bytes[lane * 8..lane * 8 + 8].copy_from_slice(&value.to_be_bytes());
        }
        ClientId::from_bytes(bytes)
    }

    fn mix64(mut value: u64) -> u64 {
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn sketch_for(seed: u64, count: u64) -> ClientSketch {
        let mut sketch = ClientSketch::new();
        for index in 0..count {
            sketch.insert(client_id(seed, index));
        }
        sketch
    }

    #[test]
    fn hll_001_duplicate_client_insert_is_idempotent() {
        let mut sketch = ClientSketch::new();
        for index in 0..100 {
            sketch.insert(client_id(1, index));
        }
        let before = sketch.serialize();
        sketch.insert(client_id(1, 25));
        assert_eq!(sketch.estimate(), 100.0);
        assert_eq!(sketch.serialize(), before);
    }

    #[test]
    #[allow(
        clippy::cast_precision_loss,
        reason = "this test population is fixed at 257"
    )]
    fn promotion_retains_population_estimate_within_hll_error() {
        let sketch = sketch_for(11, (SPARSE_LIMIT + 1) as u64);
        assert!(
            (sketch.estimate() - (SPARSE_LIMIT + 1) as f64).abs() < 20.0,
            "estimate={}",
            sketch.estimate()
        );
        assert_eq!(sketch.registers().len(), REGISTER_COUNT);
        assert_eq!(sketch.memory_usage(), REGISTER_COUNT * 6 / 8);
        assert_eq!(sketch.register(REGISTER_COUNT), None);
    }

    #[test]
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the reference rank is bounded by the 64-bit hash width"
    )]
    fn register_values_match_independent_reference_calculation() {
        let mut sketch = ClientSketch::new();
        let mut expected = vec![0; REGISTER_COUNT];
        for index in 0..2_000 {
            let id = client_id(9, index);
            let bytes = id.to_bytes();
            let hash = u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            let register_index = (hash >> 50) as usize;
            let remainder = hash & ((1_u64 << 50) - 1);
            let rank = (0_u8..50)
                .find(|bit| remainder & (1_u64 << (49 - *bit)) != 0)
                .map_or(51_u8, |leading_zeroes| leading_zeroes + 1);
            expected[register_index] = expected[register_index].max(rank);
            sketch.insert(id);
        }
        assert_eq!(sketch.registers().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn hll_002_merge_is_commutative_associative_and_idempotent() {
        let a = sketch_for(1, 200);
        let b = sketch_for(2, 200);
        let c = sketch_for(3, 200);

        let mut ab = a.clone();
        ab.merge(&b);
        let mut ba = b.clone();
        ba.merge(&a);
        assert_eq!(ab, ba);

        let mut left = ab.clone();
        left.merge(&c);
        let mut identical = a.clone();
        identical.merge(&a.clone());
        assert_eq!(identical, a);

        let mut right = b.clone();
        right.merge(&c);
        let mut associated_right = a.clone();
        associated_right.merge(&right);
        assert_eq!(left, associated_right);
    }

    #[test]
    fn dense_merge_matches_direct_union_and_partitioned_insertions() {
        let mut merged = sketch_for(7, 700);
        let mut second = sketch_for(8, 700);
        merged.merge(&second);

        let mut direct = ClientSketch::new();
        for seed in [7, 8] {
            for index in 0..700 {
                direct.insert(client_id(seed, index));
            }
        }
        assert_eq!(merged, direct);

        second.merge(&second.clone());
        assert_eq!(second, sketch_for(8, 700));
    }

    #[test]
    fn sparse_and_dense_sketches_merge_in_either_direction() {
        let sparse_a = sketch_for(41, 64);
        let sparse_b = sketch_for(42, 64);
        let mut sparse_union = sparse_a.clone();
        sparse_union.merge(&sparse_b);
        let mut direct_sparse_union = ClientSketch::new();
        for seed in [41, 42] {
            for index in 0..64 {
                direct_sparse_union.insert(client_id(seed, index));
            }
        }
        assert_eq!(sparse_union, direct_sparse_union);

        let dense = sketch_for(43, 512);
        let mut dense_then_sparse = dense.clone();
        dense_then_sparse.merge(&sparse_a);
        let mut sparse_then_dense = sparse_a;
        sparse_then_dense.merge(&dense);
        let mut direct_union = dense;
        for index in 0..64 {
            direct_union.insert(client_id(41, index));
        }
        assert_eq!(dense_then_sparse, direct_union);
        assert_eq!(sparse_then_dense, direct_union);
    }

    #[test]
    #[allow(
        clippy::expect_used,
        reason = "a failed round trip means the test fixture itself is invalid"
    )]
    fn serialization_round_trips_sparse_and_dense_sketches() {
        for sketch in [sketch_for(4, 100), sketch_for(5, 2_000)] {
            let encoded = sketch.serialize();
            let decoded = ClientSketch::deserialize(&encoded).expect("valid serialized sketch");
            assert_eq!(decoded, sketch);
            assert_eq!(decoded.estimate(), sketch.estimate());
            assert_eq!(decoded.serialize(), encoded);
        }
    }

    #[test]
    fn malformed_serialized_sketches_are_rejected() {
        assert_eq!(
            ClientSketch::deserialize(b"nope"),
            Err(SketchDecodeError::InvalidHeader)
        );
        assert_eq!(
            ClientSketch::deserialize(b"PHLL\x02\x00"),
            Err(SketchDecodeError::UnsupportedVersion(2))
        );
        assert_eq!(
            ClientSketch::deserialize(b"PHLL\x01\x02"),
            Err(SketchDecodeError::InvalidRepresentation(2))
        );
        assert_eq!(
            ClientSketch::deserialize(&vec![0; 6 + REGISTER_COUNT * 6 / 8 + 1]),
            Err(SketchDecodeError::InputTooLarge)
        );

        let mut oversized_sparse = b"PHLL\x01\x00".to_vec();
        oversized_sparse.resize(6 + (SPARSE_LIMIT + 1) * 32, 0);
        assert_eq!(
            ClientSketch::deserialize(&oversized_sparse),
            Err(SketchDecodeError::SparsePopulationTooLarge)
        );

        let mut duplicate_sparse = b"PHLL\x01\x00".to_vec();
        duplicate_sparse.extend_from_slice(&[0; 32]);
        duplicate_sparse.extend_from_slice(&[0; 32]);
        assert_eq!(
            ClientSketch::deserialize(&duplicate_sparse),
            Err(SketchDecodeError::SparseIdsNotStrictlyIncreasing)
        );

        let mut invalid_dense = b"PHLL\x01\x01".to_vec();
        invalid_dense.resize(6 + REGISTER_COUNT * 6 / 8, 0xff);
        assert!(matches!(
            ClientSketch::deserialize(&invalid_dense),
            Err(SketchDecodeError::RegisterOutOfRange { .. })
        ));
    }

    #[test]
    #[allow(
        clippy::cast_precision_loss,
        reason = "test populations are bounded below 2^32"
    )]
    fn estimates_match_exact_oracle_at_small_cardinalities() {
        for count in [0, 1, 10, 100, 256] {
            let mut sketch = ClientSketch::new();
            let mut oracle = HashSet::new();
            for index in 0..count {
                let id = client_id(17, index);
                sketch.insert(id);
                oracle.insert(id);
            }
            assert_eq!(sketch.estimate(), oracle.len() as f64);
            assert!(sketch.memory_usage() >= oracle.len() * 32);
        }
    }

    #[test]
    #[allow(
        clippy::cast_precision_loss,
        reason = "test populations are bounded below 2^32"
    )]
    fn dense_estimates_stay_within_statistical_bounds_for_seeded_populations() {
        for seed in 0..8 {
            for count in [1_000_u64, 10_000] {
                let sketch = sketch_for(seed, count);
                let relative_error = (sketch.estimate() - count as f64).abs() / count as f64;
                assert!(
                    relative_error < 0.04,
                    "seed={seed}, count={count}, estimate={}, relative_error={relative_error}",
                    sketch.estimate()
                );
            }
        }

        let sketch = sketch_for(22, 1_000_000);
        let relative_error = (sketch.estimate() - 1_000_000.0).abs() / 1_000_000.0;
        assert!(
            relative_error < 0.04,
            "count=1000000, estimate={}, relative_error={relative_error}",
            sketch.estimate()
        );
    }

    #[test]
    fn audience_set_statistics_approximate_known_overlapping_sets() {
        let mut a = ClientSketch::new();
        let mut b = ClientSketch::new();
        for index in 0..8_000 {
            a.insert(client_id(31, index));
        }
        for index in 4_000..10_000 {
            b.insert(client_id(31, index));
        }
        let mut union = a.clone();
        union.merge(&b);

        let estimated_intersection = a.estimate() + b.estimate() - union.estimate();
        assert!(
            (estimated_intersection - 4_000.0).abs() / 4_000.0 < 0.15,
            "estimated intersection={estimated_intersection}"
        );
    }

    #[test]
    fn reset_returns_to_empty_sparse_state() {
        let mut sketch = sketch_for(2, 1_000);
        sketch.reset();
        assert_eq!(sketch.estimate(), 0.0);
        assert_eq!(sketch.serialize(), b"PHLL\x01\x00");
    }
}
