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
