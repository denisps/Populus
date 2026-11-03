#![allow(clippy::expect_used)]

use std::collections::BTreeMap;

use crate::rng::{SeededRandom, random_identifier};
use crate::virtual_time::VirtualTime;
use populus_routing::{
    BUCKET_CAPACITY, BUCKET_COUNT, InsertError, RoutingTable, closest_nodes_brute_force,
};
use populus_types::{NodeId, RoutingKey};

#[test]
fn phase_4_routing_lifecycle_scales_cover_joins_leaves_churn_partitions_and_recovery() {
    for (node_count, scale_seed) in [(100, 100_u64), (1_000, 1_000), (10_000, 10_000)] {
        let seed = 0x5048_4153_4534_u64 ^ scale_seed;
        let mut network = RoutingLifecycle::new(node_count, seed);

        for index in 0..node_count {
            network.join(index);
        }

        network.assert_routing_invariants("after joins");

        let leaves: Vec<_> = (0..node_count).filter(|index| index % 5 == 1).collect();
        for &index in &leaves {
            network.leave(index);
        }
        network.assert_routing_invariants("after leaves");

        for round in 0..4 {
            for index in (round..node_count).step_by(17) {
                if network.alive[index] {
                    network.leave(index);
                } else {
                    network.join(index);
                }
            }
            network.assert_routing_invariants("after churn round");
        }

        network.partition();
        network.assert_routing_invariants("during partition");

        let partition_leaves: Vec<_> = (0..node_count)
            .filter(|&index| {
                network.alive[index] && network.component[index] == 0 && index % 23 == 0
            })
            .collect();
        for &index in &partition_leaves {
            network.leave(index);
        }
        network.assert_routing_invariants("after leaves during partition");

        network.heal_partition();
        network.assert_routing_invariants("after partition recovery");

        for index in leaves.into_iter().chain(partition_leaves) {
            if !network.alive[index] {
                network.join(index);
            }
        }
        network.assert_routing_invariants("after node recovery");
    }
}

#[test]
fn modest_routing_lifecycle_uses_virtual_time_and_brute_force_oracle() {
    const SEED: u64 = 0x5048_4153_4535;
    let mut random = SeededRandom::new(SEED);
    let ids: Vec<_> = (0..24)
        .map(|index| {
            NodeId::from_bytes(random_identifier(
                &mut random,
                u64::try_from(index).expect("small node index fits"),
            ))
        })
        .collect();
    let mut tables = [RoutingTable::new(ids[0]), RoutingTable::new(ids[1])];
    let mut alive = vec![false; ids.len()];
    let groups: Vec<_> = (0..ids.len()).map(|index| index % 2).collect();
    let mut partitioned = false;
    let mut clock = VirtualTime::new();
    for node in 0..ids.len() {
        clock
            .schedule(
                u64::try_from(node).expect("small virtual timestamp fits"),
                RoutingLifecycleEvent::Join(node),
            )
            .expect("join event is not in the past");
    }
    clock
        .schedule(20, RoutingLifecycleEvent::Leave(7))
        .expect("leave");
    clock
        .schedule(25, RoutingLifecycleEvent::Partition)
        .expect("partition");
    clock
        .schedule(30, RoutingLifecycleEvent::Heal)
        .expect("heal");

    while let Some((_at_ms, event)) = clock.next() {
        let previous_sizes = tables.each_ref().map(RoutingTable::len);
        match event {
            RoutingLifecycleEvent::Join(node) => alive[node] = true,
            RoutingLifecycleEvent::Leave(node) => alive[node] = false,
            RoutingLifecycleEvent::Partition => partitioned = true,
            RoutingLifecycleEvent::Heal => partitioned = false,
        }
        reconcile_routing_contacts(&mut tables, &ids, &alive, &groups, partitioned, SEED);
        if matches!(event, RoutingLifecycleEvent::Partition) {
            assert!(
                tables
                    .iter()
                    .zip(previous_sizes)
                    .all(|(table, before)| table.len() < before),
                "seed={SEED}: partition did not remove cross-component contacts"
            );
        }
        for (table_index, table) in tables.iter().enumerate() {
            let contacts: Vec<_> = table.known_nodes().copied().collect();
            let expected: Vec<_> = ids
                .iter()
                .enumerate()
                .filter(|(index, id)| {
                    alive[*index]
                        && **id != table.local_node()
                        && (!partitioned || groups[*index] == table_index)
                })
                .map(|(_, id)| *id)
                .collect();
            assert_eq!(contacts.len(), expected.len(), "seed={SEED}");
            for target in [
                RoutingKey::from_bytes([0x21; 32]),
                RoutingKey::from_bytes([0x82; 32]),
            ] {
                assert_eq!(
                    table.closest_nodes(&target, 7),
                    closest_nodes_brute_force(&target, &expected, 7),
                    "seed={SEED}: nearest lookup disagreed with the retained-contact oracle"
                );
            }
        }
    }
    assert_eq!(clock.now_ms(), 30, "seed={SEED}");
}

fn reconcile_routing_contacts(
    tables: &mut [RoutingTable; 2],
    ids: &[NodeId],
    alive: &[bool],
    groups: &[usize],
    partitioned: bool,
    seed: u64,
) {
    for (table_index, table) in tables.iter_mut().enumerate() {
        for node in 0..ids.len() {
            let should_retain = alive[node] && (!partitioned || groups[node] == table_index);
            if should_retain {
                match table.insert(ids[node]) {
                    Ok(())
                    | Err(
                        InsertError::LocalNode | InsertError::Duplicate | InsertError::BucketFull,
                    ) => {}
                }
            } else {
                table.remove(&ids[node]);
            }
            assert!(
                table.contains(&ids[node]) || ids[node] == table.local_node() || !should_retain,
                "seed={seed}: expected contact was not retained"
            );
        }
    }
}

#[derive(Clone, Copy)]
enum RoutingLifecycleEvent {
    Join(usize),
    Leave(usize),
    Partition,
    Heal,
}

struct RoutingLifecycle {
    seed: u64,
    ids: Vec<NodeId>,
    indexes: BTreeMap<NodeId, usize>,
    alive: Vec<bool>,
    component: Vec<usize>,
    partitioned: bool,
    tables: [RoutingTable; 2],
}

impl RoutingLifecycle {
    fn new(node_count: usize, seed: u64) -> Self {
        let mut random = SeededRandom::new(seed);
        let ids: Vec<_> = (1_u64..)
            .take(node_count)
            .map(|index| NodeId::from_bytes(random_identifier(&mut random, index)))
            .collect();
        let indexes = ids
            .iter()
            .copied()
            .enumerate()
            .map(|(index, id)| (id, index))
            .collect();
        let tables = [
            RoutingTable::new(NodeId::from_bytes([0xfa; 32])),
            RoutingTable::new(NodeId::from_bytes([0xfb; 32])),
        ];
        Self {
            seed,
            ids,
            indexes,
            alive: vec![false; node_count],
            component: vec![0; node_count],
            partitioned: false,
            tables,
        }
    }

    fn visible(&self, node: usize, table: usize) -> bool {
        self.alive[node] && (!self.partitioned || self.component[node] == table)
    }

    fn join(&mut self, node: usize) {
        assert!(
            !self.alive[node],
            "seed {}, node {node} already joined",
            self.seed
        );
        let before = [self.visible(node, 0), self.visible(node, 1)];
        self.alive[node] = true;
        self.apply_visibility_change(node, before);
    }

    fn leave(&mut self, node: usize) {
        assert!(
            self.alive[node],
            "seed {}, node {node} already left",
            self.seed
        );
        let before = [self.visible(node, 0), self.visible(node, 1)];
        self.alive[node] = false;
        self.apply_visibility_change(node, before);
    }

    fn partition(&mut self) {
        assert!(!self.partitioned, "seed {} already partitioned", self.seed);
        let before_sizes = self.tables.each_ref().map(RoutingTable::len);
        for (table_index, table) in self.tables.iter().enumerate() {
            assert!(
                table.known_nodes().any(|contact| {
                    self.indexes
                        .get(contact)
                        .is_some_and(|&node| node % 2 != table_index)
                }),
                "seed {} has no cross-partition contacts to remove",
                self.seed
            );
        }
        self.partitioned = true;
        for node in 0..self.ids.len() {
            let was_visible = [self.alive[node]; 2];
            self.component[node] = node % 2;
            self.apply_visibility_change(node, was_visible);
        }
        for (table, before_size) in self.tables.iter().zip(before_sizes) {
            assert!(
                table.len() < before_size,
                "seed {} partition did not remove unreachable contacts",
                self.seed
            );
        }
    }

    fn heal_partition(&mut self) {
        assert!(self.partitioned, "seed {} is not partitioned", self.seed);
        let before_sizes = self.tables.each_ref().map(RoutingTable::len);
        let previous: Vec<_> = (0..self.ids.len())
            .map(|node| [self.visible(node, 0), self.visible(node, 1)])
            .collect();
        self.partitioned = false;
        for (node, before) in previous.into_iter().enumerate() {
            self.apply_visibility_change(node, before);
        }
        for (table, before_size) in self.tables.iter().zip(before_sizes) {
            assert!(
                table.len() > before_size,
                "seed {} partition recovery did not restore reachable contacts",
                self.seed
            );
        }
    }

    fn apply_visibility_change(&mut self, node: usize, before: [bool; 2]) {
        for (table_index, table) in self.tables.iter_mut().enumerate() {
            let after =
                self.alive[node] && (!self.partitioned || self.component[node] == table_index);
            match (before[table_index], after) {
                (true, false) => {
                    if table.contains(&self.ids[node]) {
                        assert!(
                            table.remove(&self.ids[node]),
                            "seed {}, node {node} remained after route removal",
                            self.seed
                        );
                    }
                }
                (false, true) => match table.insert(self.ids[node]) {
                    Ok(()) | Err(InsertError::BucketFull) => {}
                    Err(error) => assert_eq!(
                        error,
                        InsertError::BucketFull,
                        "seed {}, node {node} could not join routing table",
                        self.seed
                    ),
                },
                (false, false) | (true, true) => {}
            }
        }
    }

    fn assert_routing_invariants(&self, stage: &str) {
        for (table_index, table) in self.tables.iter().enumerate() {
            let contacts: Vec<_> = table.known_nodes().copied().collect();
            assert!(
                table.bucket_sizes().all(|size| size <= BUCKET_CAPACITY),
                "seed {}, {stage}: bucket capacity exceeded",
                self.seed
            );
            assert!(
                table.len() <= BUCKET_COUNT * BUCKET_CAPACITY,
                "seed {}, {stage}: routing table capacity exceeded",
                self.seed
            );
            for contact in &contacts {
                let node = self.indexes.get(contact).copied();
                assert!(
                    node.is_some(),
                    "seed {}, {stage}: routing table contains an unknown node",
                    self.seed
                );
                if let Some(node) = node {
                    assert!(
                        self.visible(node, table_index),
                        "seed {}, {stage}: stale or cross-partition route retained",
                        self.seed
                    );
                    assert!(
                        table.contains(contact),
                        "seed {}, {stage}: contact iteration disagrees with membership",
                        self.seed
                    );
                }
            }

            let target_ids = [
                RoutingKey::from_bytes([0; 32]),
                RoutingKey::from_bytes([0x5a; 32]),
                RoutingKey::from_bytes(self.ids[table_index].to_bytes()),
            ];
            for target in target_ids {
                for limit in [0, 1, 4, 20, contacts.len(), contacts.len() + 1] {
                    let actual = table.closest_nodes(&target, limit);
                    let expected = closest_nodes_brute_force(&target, &contacts, limit);
                    assert!(
                        actual == expected,
                        "seed {}, {stage}: nearest lookup differs from oracle at size {}",
                        self.seed,
                        self.ids.len()
                    );
                }
            }
        }
    }
}
