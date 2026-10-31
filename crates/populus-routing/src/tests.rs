use super::{
    BUCKET_CAPACITY, BUCKET_COUNT, InsertError, RoutingTable, bucket_index,
    closest_nodes_brute_force,
};
use populus_types::{NodeId, RoutingKey};
use proptest::prelude::*;

fn node(bytes: [u8; 32]) -> NodeId {
    NodeId::from_bytes(bytes)
}

fn virtual_node(index: u64) -> NodeId {
    let mut bytes = [0; 32];
    for (chunk, offset) in bytes[..24].as_chunks_mut::<8>().0.iter_mut().zip(0_u64..) {
        let value = mix64(index.wrapping_add(offset));
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    node(bytes)
}

fn mix64(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn assert_lookup_matches_oracle(table: &RoutingTable, target: RoutingKey) {
    let contacts: Vec<_> = table.known_nodes().copied().collect();
    for limit in [
        0,
        1,
        4,
        20,
        contacts.len(),
        contacts.len().saturating_add(1),
    ] {
        assert_eq!(
            table.closest_nodes(&target, limit),
            closest_nodes_brute_force(&target, &contacts, limit)
        );
    }
}

#[test]
fn distance_buckets_follow_most_significant_differing_bit() {
    let local = node([0; 32]);
    let mut nearest = [0; 32];
    nearest[31] = 1;
    let mut farthest = [0; 32];
    farthest[0] = 0x80;

    assert_eq!(bucket_index(&local, &node(nearest)), 0);
    assert_eq!(bucket_index(&local, &node(farthest)), BUCKET_COUNT - 1);
}

#[test]
fn insert_rejects_local_duplicate_and_full_bucket() {
    let local = node([0; 32]);
    let mut table = RoutingTable::new(local);
    assert_eq!(table.insert(local), Err(InsertError::LocalNode));

    let mut contacts = Vec::new();
    for value in 0..BUCKET_CAPACITY {
        let mut bytes = [0; 32];
        bytes[31] = 0x80 | value.to_le_bytes()[0];
        let contact = node(bytes);
        assert!(table.insert(contact).is_ok());
        contacts.push(contact);
    }
    assert_eq!(table.insert(contacts[0]), Err(InsertError::Duplicate));

    let mut overflow = [0; 32];
    overflow[31] = 0x80 | BUCKET_CAPACITY.to_le_bytes()[0];
    assert_eq!(table.insert(node(overflow)), Err(InsertError::BucketFull));
    assert_eq!(table.len(), BUCKET_CAPACITY);
    assert!(table.bucket_sizes().all(|size| size <= BUCKET_CAPACITY));
}

#[test]
fn remove_and_reinsert_preserves_membership_and_lookup() {
    let local = node([0; 32]);
    let mut table = RoutingTable::new(local);
    let contact = virtual_node(42);

    assert!(!table.remove(&local));
    assert!(table.is_empty());
    assert!(table.insert(contact).is_ok());
    assert!(table.contains(&contact));
    assert!(table.remove(&contact));
    assert!(!table.contains(&contact));
    assert!(!table.remove(&contact));
    assert!(table.insert(contact).is_ok());

    assert_lookup_matches_oracle(&table, RoutingKey::from_bytes([7; 32]));
}

#[test]
fn insertion_order_does_not_change_logical_nearest_nodes() {
    let local = node([0; 32]);
    let contacts: Vec<_> = (0_u8..128)
        .map(|index| {
            let mut bytes = [0; 32];
            bytes[0] = 1 << (index % 8);
            bytes[31] = index;
            node(bytes)
        })
        .collect();
    let mut forward = RoutingTable::new(local);
    let mut reverse = RoutingTable::new(local);
    for contact in &contacts {
        assert!(forward.insert(*contact).is_ok());
    }
    for contact in contacts.iter().rev() {
        assert!(reverse.insert(*contact).is_ok());
    }

    let target = RoutingKey::from_bytes([0x5a; 32]);
    assert_eq!(
        forward.closest_nodes(&target, 32),
        reverse.closest_nodes(&target, 32)
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bucketed_nearest_lookup_matches_brute_force(
        local_bytes in any::<[u8; 32]>(),
        target_bytes in any::<[u8; 32]>(),
        candidate_bytes in prop::collection::vec(any::<[u8; 32]>(), 0..400),
        limit in 0_usize..200,
    ) {
        let mut table = RoutingTable::new(node(local_bytes));
        for bytes in candidate_bytes {
            let _ = table.insert(node(bytes));
        }

        let target = RoutingKey::from_bytes(target_bytes);
        let contacts: Vec<_> = table.known_nodes().copied().collect();
        prop_assert!(
            table.closest_nodes(&target, limit)
                == closest_nodes_brute_force(&target, &contacts, limit)
        );
        prop_assert!(table.bucket_sizes().all(|size| size <= BUCKET_CAPACITY));
    }
}

#[test]
fn virtual_network_sizes_survive_churn_and_recovery() {
    for size in [100_u64, 1_000, 10_000] {
        let mut table = RoutingTable::new(node([0; 32]));
        let mut accepted = Vec::new();
        for index in 1..=size {
            let contact = virtual_node(index);
            if table.insert(contact).is_ok() {
                accepted.push(contact);
            }
        }
        assert!(table.len() <= BUCKET_COUNT * BUCKET_CAPACITY);
        assert!(table.bucket_sizes().all(|count| count <= BUCKET_CAPACITY));

        let removed: Vec<_> = accepted.iter().step_by(4).copied().collect();
        for contact in &removed {
            assert!(table.remove(contact));
        }
        assert_lookup_matches_oracle(&table, RoutingKey::from_bytes([0x35; 32]));

        for contact in removed {
            assert!(table.insert(contact).is_ok());
        }
        assert_lookup_matches_oracle(&table, RoutingKey::from_bytes([0xa7; 32]));
        assert_eq!(table.len(), accepted.len());
    }
}
