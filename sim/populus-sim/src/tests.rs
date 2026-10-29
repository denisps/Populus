use std::collections::BTreeMap;

use populus_routing::{
    BUCKET_CAPACITY, BUCKET_COUNT, InsertError, RoutingTable, closest_nodes_brute_force,
};
use populus_types::{NodeId, RoutingKey};

use super::{
    ClockSkewDistribution, FailureAction, FailureEvent, LatencyDistribution, MaliciousStrategy,
    SeededRandom, SimulationConfig, SimulationError, VIEW_COUNT, random_identifier, run_simulation,
};

fn small_config() -> SimulationConfig {
    SimulationConfig {
        seed: 0x5eed,
        node_count: 12,
        client_count: 90,
        content_count: 3,
        latency: LatencyDistribution::Uniform {
            min_ms: 0,
            max_ms: 25,
        },
        clock_skew: ClockSkewDistribution::Uniform {
            min_ms: -70_000,
            max_ms: 70_000,
        },
        ..SimulationConfig::default()
    }
}

#[test]
fn seeded_scenario_is_reproducible_and_exercises_protocol_implementations()
-> Result<(), SimulationError> {
    let config = small_config();
    let first = run_simulation(&config)?;
    let second = run_simulation(&config)?;

    assert_eq!(first, second);
    assert_eq!(first.seed, config.seed);
    assert_eq!(first.contents.len(), config.content_count);
    assert_eq!(first.view_content.len(), VIEW_COUNT * config.content_count);
    assert_eq!(first.sent_messages, config.client_count * VIEW_COUNT);
    assert_eq!(first.delivered_messages, first.sent_messages);
    assert!(
        first
            .contents
            .iter()
            .all(|content| content.closest_known_node.is_some())
    );
    for summary in &first.view_content {
        assert_eq!(summary.distinct_client_estimate, 30.0);
        assert!(summary.report_windows > 0);
    }
    Ok(())
}

#[test]
fn duplicate_and_replayed_messages_do_not_inflate_distinct_client_sketches()
-> Result<(), SimulationError> {
    let config = SimulationConfig {
        seed: 3,
        node_count: 1,
        client_count: 40,
        content_count: 1,
        malicious_nodes: vec![0],
        malicious_strategy: MaliciousStrategy::DuplicateMessages,
        ..SimulationConfig::default()
    };
    let report = run_simulation(&config)?;

    assert_eq!(report.sent_messages, 40 * VIEW_COUNT);
    assert_eq!(report.delivered_messages, 80 * VIEW_COUNT);
    assert_eq!(report.duplicate_deliveries, 40 * VIEW_COUNT);
    for summary in &report.view_content {
        assert_eq!(summary.distinct_client_estimate, 40.0);
    }

    let replay_config = SimulationConfig {
        malicious_strategy: MaliciousStrategy::ReplayMessages { replay_after_ms: 5 },
        ..config.clone()
    };
    let replay = run_simulation(&replay_config)?;
    assert_eq!(replay.replayed_messages, 40 * VIEW_COUNT);
    for summary in &replay.view_content {
        assert_eq!(summary.distinct_client_estimate, 40.0);
    }

    let drop_config = SimulationConfig {
        malicious_strategy: MaliciousStrategy::DropMessages,
        ..config.clone()
    };
    let dropped = run_simulation(&drop_config)?;
    assert_eq!(dropped.dropped_messages, 40 * VIEW_COUNT);
    assert_eq!(dropped.delivered_messages, 0);

    let delayed_config = SimulationConfig {
        malicious_strategy: MaliciousStrategy::DelayMessages { extra_delay_ms: 8 },
        latency: LatencyDistribution::Fixed(0),
        ..config
    };
    let delayed = run_simulation(&delayed_config)?;
    assert_eq!(delayed.delayed_messages, 40 * VIEW_COUNT);
    assert_eq!(delayed.completed_at_ms, 8);
    for summary in &delayed.view_content {
        assert_eq!(summary.distinct_client_estimate, 40.0);
    }
    Ok(())
}

#[test]
fn crash_schedule_drops_messages_and_recovery_restores_delivery() -> Result<(), SimulationError> {
    let mut config = SimulationConfig {
        seed: 11,
        node_count: 1,
        client_count: 25,
        content_count: 1,
        latency: LatencyDistribution::Fixed(20),
        failure_schedule: vec![
            FailureEvent {
                at_ms: 0,
                node: 0,
                action: FailureAction::Crash,
            },
            FailureEvent {
                at_ms: 30,
                node: 0,
                action: FailureAction::Recover,
            },
        ],
        ..SimulationConfig::default()
    };
    let failed = run_simulation(&config)?;
    assert_eq!(failed.dropped_messages, 25 * VIEW_COUNT);
    assert_eq!(failed.delivered_messages, 0);

    config.failure_schedule[1].at_ms = 10;
    let recovered = run_simulation(&config)?;
    assert_eq!(recovered.delivered_messages, 25 * VIEW_COUNT);
    assert_eq!(recovered.dropped_messages, 0);
    Ok(())
}

#[test]
fn clock_skew_splits_local_windows_without_losing_the_merged_population()
-> Result<(), SimulationError> {
    let config = SimulationConfig {
        seed: 29,
        node_count: 3,
        client_count: 120,
        content_count: 1,
        latency: LatencyDistribution::Fixed(0),
        clock_skew: ClockSkewDistribution::Uniform {
            min_ms: -120_000,
            max_ms: 120_000,
        },
        ..SimulationConfig::default()
    };
    let report = run_simulation(&config)?;

    assert!(
        report
            .view_content
            .iter()
            .any(|summary| summary.report_windows > 1)
    );
    for summary in report.view_content {
        assert_eq!(summary.distinct_client_estimate, 120.0);
    }
    Ok(())
}

#[test]
fn malformed_counts_distributions_and_failure_events_are_rejected() {
    assert!(matches!(
        run_simulation(&SimulationConfig {
            node_count: 0,
            ..SimulationConfig::default()
        }),
        Err(SimulationError::NoNodes)
    ));
    assert!(matches!(
        run_simulation(&SimulationConfig {
            latency: LatencyDistribution::Uniform {
                min_ms: 5,
                max_ms: 4,
            },
            ..SimulationConfig::default()
        }),
        Err(SimulationError::InvalidDistribution)
    ));
    assert!(matches!(
        run_simulation(&SimulationConfig {
            node_count: 2,
            malicious_nodes: vec![2],
            ..SimulationConfig::default()
        }),
        Err(SimulationError::NodeIndexOutOfRange(2))
    ));
    assert!(matches!(
        run_simulation(&SimulationConfig {
            node_count: 2,
            failure_schedule: vec![
                FailureEvent {
                    at_ms: 10,
                    node: 1,
                    action: FailureAction::Crash,
                },
                FailureEvent {
                    at_ms: 10,
                    node: 1,
                    action: FailureAction::Recover,
                },
            ],
            ..SimulationConfig::default()
        }),
        Err(SimulationError::ConflictingFailureEvents { .. })
    ));
}

#[test]
fn rescheduled_events_are_bounded_and_report_the_seed() {
    let config = SimulationConfig {
        seed: 77,
        node_count: 1,
        client_count: 200_000,
        content_count: 1,
        malicious_nodes: vec![0],
        malicious_strategy: MaliciousStrategy::ReplayMessages { replay_after_ms: 1 },
        ..SimulationConfig::default()
    };
    let result = run_simulation(&config);

    assert!(matches!(
        result,
        Err(SimulationError::Scenario { seed: 77, source })
            if matches!(*source, SimulationError::CountLimitExceeded("event count"))
    ));
}

#[test]
fn randomized_run_errors_include_the_reproduction_seed() {
    let config = SimulationConfig {
        seed: 0xcafe,
        node_count: 1,
        client_count: 1,
        content_count: 1,
        latency: LatencyDistribution::Fixed(u64::MAX),
        malicious_nodes: vec![0],
        malicious_strategy: MaliciousStrategy::DelayMessages { extra_delay_ms: 1 },
        ..SimulationConfig::default()
    };
    let error = run_simulation(&config).err().map(|error| error.to_string());

    assert_eq!(
        error,
        Some(format!(
            "simulation failed (seed {}): virtual time or event sequence overflowed",
            config.seed
        ))
    );
}

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
