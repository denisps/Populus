#![allow(clippy::expect_used)]

use super::{
    ByzantineAction, ByzantineScript, ClockSkewDistribution, FailureAction, FailureEvent,
    LatencyDistribution, LifecycleAction, LifecycleEvent, MaliciousStrategy, PACKET_LOSS_SCALE,
    PartitionAction, PartitionEvent, SIMULATED_PAYLOAD_BYTES, SimulationConfig, SimulationError,
    VIEW_COUNT, run_simulation,
};
use populus_cluster::{AssignmentAlgorithm, DelegationDescriptor, IngestNode};
use populus_types::{ClientId, NodeId};

fn assignment_descriptors(node_ids: &[NodeId]) -> Vec<DelegationDescriptor> {
    vec![
        DelegationDescriptor::new(
            AssignmentAlgorithm::XorNearest,
            node_ids.iter().copied().map(IngestNode::new).collect(),
            0,
        )
        .expect("simulated nodes form a valid assignment descriptor"),
    ]
}

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
fn each_assignment_candidate_is_exercised_with_balanced_three_view_loads()
-> Result<(), SimulationError> {
    let algorithms = [
        AssignmentAlgorithm::SaltedClientHash,
        AssignmentAlgorithm::DisjointClientRanges,
        AssignmentAlgorithm::XorNearest,
        AssignmentAlgorithm::MatchBits,
    ];
    let mut observed_loads = Vec::new();
    for algorithm in algorithms {
        let config = SimulationConfig {
            assignment_algorithm: algorithm,
            offered_votes_per_minute: 100,
            max_votes_per_node_per_minute: 100,
            ..small_config()
        };
        let report = run_simulation(&config)?;
        assert_eq!(report.assignment_algorithm, algorithm);
        assert_eq!(
            report.assignment_version,
            populus_cluster::ASSIGNMENT_VERSION
        );
        assert_eq!(
            report.assignment_candidate_count,
            config.node_count.min(populus_routing::BUCKET_CAPACITY)
        );
        assert_eq!(
            report.assignment_descriptor_estimated_bytes,
            Some(report.assignment_candidate_count * 32 + 4)
        );
        assert_eq!(report.assignment_loads.len(), config.node_count);
        for view in 0..VIEW_COUNT {
            let total: usize = report
                .assignment_loads
                .iter()
                .map(|load| load.assignments_by_view[view])
                .sum();
            assert_eq!(total, config.client_count);
            let maximum = report
                .assignment_loads
                .iter()
                .map(|load| load.assignments_by_view[view])
                .max()
                .unwrap_or_default();
            assert!(
                maximum <= 30,
                "seed={}: {algorithm:?} view {view} overloaded one node ({maximum} clients)",
                config.seed
            );
        }
        assert_eq!(
            report,
            run_simulation(&config)?,
            "seed={}: assignment report was not deterministic",
            config.seed
        );
        if algorithm == AssignmentAlgorithm::MatchBits {
            assert_eq!(report.assignment_match_bits, 3);
        } else {
            assert_eq!(report.assignment_match_bits, 0);
        }
        observed_loads.push(report.assignment_loads);
    }

    assert!(
        observed_loads.windows(2).any(|pair| pair[0] != pair[1]),
        "all experimental candidates produced identical assignments"
    );
    Ok(())
}

#[test]
fn match_bits_rejects_missing_capacity_measurements() {
    assert!(matches!(
        run_simulation(&SimulationConfig {
            assignment_algorithm: AssignmentAlgorithm::MatchBits,
            offered_votes_per_minute: 0,
            ..SimulationConfig::default()
        }),
        Err(SimulationError::Assignment(
            populus_cluster::AssignmentError::InvalidCapacityInput
        ))
    ));
}

#[test]
fn match_bits_uses_the_observed_content_neighborhood_population() -> Result<(), SimulationError> {
    let report = run_simulation(&SimulationConfig {
        node_count: populus_routing::BUCKET_CAPACITY + 4,
        client_count: 60,
        content_count: 2,
        assignment_algorithm: AssignmentAlgorithm::MatchBits,
        offered_votes_per_minute: 100,
        max_votes_per_node_per_minute: 100,
        ..SimulationConfig::default()
    })?;
    assert_eq!(
        report.assignment_candidate_count,
        populus_routing::BUCKET_CAPACITY
    );
    assert_eq!(report.assignment_match_bits, 4);
    for view in 0..VIEW_COUNT {
        assert_eq!(
            report
                .assignment_loads
                .iter()
                .map(|load| load.assignments_by_view[view])
                .sum::<usize>(),
            60
        );
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
    for node_count in 1..4 {
        assert!(matches!(
            run_simulation(&SimulationConfig {
                node_count,
                byzantine_scripts: vec![ByzantineScript {
                    node: 0,
                    action: ByzantineAction::SendConflictingAuthorityStates,
                }],
                ..SimulationConfig::default()
            }),
            Err(SimulationError::InvalidByzantineScript)
        ));
    }
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
fn seeded_jitter_loss_and_reordering_are_reproducible_and_observable() {
    const SEED: u64 = 0xFA17_0001;
    let control = SimulationConfig {
        seed: SEED,
        node_count: 7,
        client_count: 35,
        latency: LatencyDistribution::Fixed(0),
        ..SimulationConfig::default()
    };
    let faulted = SimulationConfig {
        jitter: Some(LatencyDistribution::Uniform {
            min_ms: 0,
            max_ms: 40,
        }),
        packet_loss_probability: 200_000,
        reordering: Some(LatencyDistribution::Uniform {
            min_ms: 0,
            max_ms: 100,
        }),
        ..control.clone()
    };
    let first = run_simulation(&faulted).expect("faulted scenario runs");
    let second = run_simulation(&faulted).expect("same seeded scenario runs");
    let baseline = run_simulation(&control).expect("control scenario runs");
    assert_eq!(first, second, "seed={SEED}");
    assert!(first.dropped_messages > 0, "seed={SEED}");
    assert!(
        first.completed_at_ms != baseline.completed_at_ms
            || first.delivered_messages != baseline.delivered_messages,
        "seed={SEED}: jitter/loss did not change the control outcome"
    );
    assert!(
        first.reordered_deliveries > 0,
        "seed={SEED}: configured reordering did not invert delivery order"
    );
}

#[test]
fn fixed_jitter_and_certain_loss_change_the_disabled_control() {
    const SEED: u64 = 0xFA17_0002;
    let control = SimulationConfig {
        seed: SEED,
        node_count: 5,
        client_count: 12,
        latency: LatencyDistribution::Fixed(0),
        ..SimulationConfig::default()
    };
    let jittered = run_simulation(&SimulationConfig {
        jitter: Some(LatencyDistribution::Fixed(25)),
        ..control.clone()
    })
    .expect("jittered scenario runs");
    let lossy = run_simulation(&SimulationConfig {
        packet_loss_probability: PACKET_LOSS_SCALE,
        ..control.clone()
    })
    .expect("lossy scenario runs");
    let baseline = run_simulation(&control).expect("control scenario runs");
    assert_eq!(
        jittered.completed_at_ms,
        baseline.completed_at_ms + 25,
        "seed={SEED}"
    );
    assert_eq!(lossy.delivered_messages, 0, "seed={SEED}");
    assert_eq!(lossy.dropped_messages, lossy.sent_messages, "seed={SEED}");
}

#[test]
fn partition_drops_cross_group_messages_and_heal_restores_delivery() {
    const SEED: u64 = 0xFA17_0003;
    let config = SimulationConfig {
        seed: SEED,
        node_count: 2,
        client_count: 40,
        latency: LatencyDistribution::Uniform {
            min_ms: 0,
            max_ms: 40,
        },
        partition_schedule: vec![
            PartitionEvent {
                at_ms: 0,
                action: PartitionAction::Split { groups: vec![0, 1] },
            },
            PartitionEvent {
                at_ms: 20,
                action: PartitionAction::Heal,
            },
        ],
        ..SimulationConfig::default()
    };
    let report = run_simulation(&config).expect("partition scenario runs");
    assert!(report.partition_drops > 0, "seed={SEED}");
    assert!(
        report.delivered_messages > 0,
        "seed={SEED}: heal did not restore delivery"
    );
    assert!(
        report.partition_drops < report.sent_messages,
        "seed={SEED}: all traffic remained partitioned after heal"
    );
}

#[test]
fn restart_clears_state_while_crash_recovery_and_leave_keep_it() {
    const SEED: u64 = 0xFA17_0004;
    let base = SimulationConfig {
        seed: SEED,
        node_count: 1,
        client_count: 1,
        latency: LatencyDistribution::Fixed(0),
        malicious_nodes: vec![0],
        malicious_strategy: MaliciousStrategy::ReplayMessages {
            replay_after_ms: 20,
        },
        ..SimulationConfig::default()
    };
    let restarted = run_simulation(&SimulationConfig {
        lifecycle_schedule: vec![LifecycleEvent {
            at_ms: 10,
            node: 0,
            action: LifecycleAction::Restart,
        }],
        ..base.clone()
    })
    .expect("restart scenario runs");
    let recovered = run_simulation(&SimulationConfig {
        failure_schedule: vec![
            FailureEvent {
                at_ms: 10,
                node: 0,
                action: FailureAction::Crash,
            },
            FailureEvent {
                at_ms: 15,
                node: 0,
                action: FailureAction::Recover,
            },
        ],
        ..base.clone()
    })
    .expect("crash-recovery scenario runs");
    let absent = run_simulation(&SimulationConfig {
        initially_joined_nodes: Some(Vec::new()),
        ..base.clone()
    })
    .expect("unjoined-node scenario runs");
    let rejoined = run_simulation(&SimulationConfig {
        lifecycle_schedule: vec![
            LifecycleEvent {
                at_ms: 10,
                node: 0,
                action: LifecycleAction::Leave,
            },
            LifecycleEvent {
                at_ms: 15,
                node: 0,
                action: LifecycleAction::Join,
            },
        ],
        ..base.clone()
    })
    .expect("join-leave-join scenario runs");
    assert_eq!(restarted.node_restarts, 1, "seed={SEED}");
    assert_eq!(
        restarted.restart_reinsertions, VIEW_COUNT,
        "seed={SEED}: restart did not reinsert the same client identities"
    );
    assert_eq!(recovered.restart_reinsertions, 0, "seed={SEED}");
    assert_eq!(rejoined.restart_reinsertions, 0, "seed={SEED}");
    assert_eq!(absent.delivered_messages, 0, "seed={SEED}");
    assert_eq!(absent.dropped_messages, absent.sent_messages, "seed={SEED}");
    assert_eq!(recovered.delivered_messages, 2 * VIEW_COUNT, "seed={SEED}");
    assert_eq!(rejoined.delivered_messages, 2 * VIEW_COUNT, "seed={SEED}");
}

#[test]
fn bandwidth_and_connection_limits_affect_virtual_delivery() {
    const SEED: u64 = 0xFA17_0005;
    let control = SimulationConfig {
        seed: SEED,
        node_count: 6,
        client_count: 24,
        latency: LatencyDistribution::Fixed(0),
        ..SimulationConfig::default()
    };
    let bandwidth_config = SimulationConfig {
        seed: SEED,
        node_count: 1,
        client_count: 1_000,
        content_count: 1,
        latency: LatencyDistribution::Fixed(0),
        ..SimulationConfig::default()
    };
    let bandwidth_baseline = run_simulation(&SimulationConfig {
        ..bandwidth_config.clone()
    })
    .expect("unlimited-bandwidth scenario runs");
    let messages_per_source = bandwidth_config.client_count * VIEW_COUNT;
    let egress_ticks = u128::try_from(messages_per_source)
        .expect("message count fits")
        .checked_mul(u128::from(SIMULATED_PAYLOAD_BYTES))
        .expect("total simulated bytes fit")
        .checked_mul(1_000)
        .expect("rate-scaled egress duration fits");
    assert_eq!(bandwidth_baseline.completed_at_ms, 0, "seed={SEED}");
    assert_eq!(
        bandwidth_baseline.delivered_messages, messages_per_source,
        "seed={SEED}"
    );
    for (bytes_per_second, expected_ms) in [(1_000_000_u64, 384_u64), (1_000_000_000, 1)] {
        let bandwidth = run_simulation(&SimulationConfig {
            bandwidth_bytes_per_second: Some(bytes_per_second),
            ..bandwidth_config.clone()
        })
        .expect("bounded-bandwidth scenario runs");
        let exact_finish_ms = u64::try_from(egress_ticks.div_ceil(u128::from(bytes_per_second)))
            .expect("simulated egress time fits");
        assert_eq!(exact_finish_ms, expected_ms, "seed={SEED}");
        assert_eq!(
            bandwidth.completed_at_ms, exact_finish_ms,
            "seed={SEED}: egress rounded each transmission before event delivery"
        );
        assert_eq!(
            bandwidth.delivered_messages, bandwidth_baseline.delivered_messages,
            "seed={SEED}"
        );
    }
    let limited = run_simulation(&SimulationConfig {
        connection_limit: Some(1),
        ..control
    })
    .expect("bounded-connection scenario runs");
    assert!(limited.rejected_connections > 0, "seed={SEED}");
    assert!(
        limited.delivered_messages < limited.sent_messages,
        "seed={SEED}: connection limit did not reject excess attempts"
    );
}

#[test]
fn packet_latency_does_not_delay_later_egress_reservations() {
    const SEED: u64 = 2;
    let config = SimulationConfig {
        seed: SEED,
        node_count: 1,
        client_count: 1,
        content_count: 1,
        latency: LatencyDistribution::Uniform {
            min_ms: 0,
            max_ms: 5_000,
        },
        bandwidth_bytes_per_second: Some(128_000_000),
        ..SimulationConfig::default()
    };
    let mut random = crate::rng::SeededRandom::new(SEED);
    let mut delivery_times = Vec::new();
    let node_ids = [NodeId::from_bytes([0; 32])];
    let descriptors = assignment_descriptors(&node_ids);
    let (expected_by_content, _) = crate::workload::schedule_votes(
        &config,
        vec![ClientId::from_bytes([1; 32])],
        &mut random,
        &node_ids,
        &descriptors,
        |at_ms, _, _, _, _, _, _| {
            delivery_times.push(at_ms);
            Ok(())
        },
    )
    .expect("scheduled votes fit the virtual timeline");

    assert_eq!(expected_by_content, [1]);
    assert_eq!(
        delivery_times,
        [2_835, 4_534, 568],
        "seed={SEED}: one high-latency packet delayed later egress"
    );
}

#[test]
fn injected_reordering_delay_is_applied_to_scheduled_votes() {
    const SEED: u64 = 2;
    let config = SimulationConfig {
        seed: SEED,
        node_count: 1,
        client_count: 1,
        content_count: 1,
        latency: LatencyDistribution::Fixed(0),
        reordering: Some(LatencyDistribution::Uniform {
            min_ms: 10,
            max_ms: 10,
        }),
        ..SimulationConfig::default()
    };
    let mut random = crate::rng::SeededRandom::new(SEED);
    let mut delivery_times = Vec::new();
    let node_ids = [NodeId::from_bytes([0; 32])];
    let descriptors = assignment_descriptors(&node_ids);

    crate::workload::schedule_votes(
        &config,
        vec![ClientId::from_bytes([1; 32])],
        &mut random,
        &node_ids,
        &descriptors,
        |at_ms, _, _, _, _, _, _| {
            delivery_times.push(at_ms);
            Ok(())
        },
    )
    .expect("scheduled votes fit the virtual timeline");

    assert_eq!(delivery_times, [10, 10, 10], "seed={SEED}");
}

#[test]
fn byzantine_script_emits_conflicting_signed_states_but_not_a_conflicting_quorum() {
    const SEED: u64 = 0xFA17_0006;
    let config = SimulationConfig {
        seed: SEED,
        node_count: 5,
        client_count: 8,
        latency: LatencyDistribution::Fixed(0),
        byzantine_scripts: vec![ByzantineScript {
            node: 0,
            action: ByzantineAction::SendConflictingAuthorityStates,
        }],
        ..SimulationConfig::default()
    };
    let report = run_simulation(&config).expect("signed equivocation scenario runs");
    assert_eq!(report.byzantine_state_messages, 2, "seed={SEED}");
}

#[test]
fn byzantine_one_shot_drop_duplicate_and_delay_scripts_are_observable() {
    const SEED: u64 = 0xFA17_0007;
    let base = SimulationConfig {
        seed: SEED,
        node_count: 1,
        client_count: 1,
        latency: LatencyDistribution::Fixed(0),
        ..SimulationConfig::default()
    };
    let dropped = run_simulation(&SimulationConfig {
        byzantine_scripts: vec![ByzantineScript {
            node: 0,
            action: ByzantineAction::DropNext,
        }],
        ..base.clone()
    })
    .expect("scripted drop scenario runs");
    let duplicated = run_simulation(&SimulationConfig {
        byzantine_scripts: vec![ByzantineScript {
            node: 0,
            action: ByzantineAction::DuplicateNext,
        }],
        ..base.clone()
    })
    .expect("scripted duplicate scenario runs");
    let delayed = run_simulation(&SimulationConfig {
        byzantine_scripts: vec![ByzantineScript {
            node: 0,
            action: ByzantineAction::DelayNext { extra_delay_ms: 12 },
        }],
        ..base
    })
    .expect("scripted delay scenario runs");
    assert_eq!(dropped.dropped_messages, 1, "seed={SEED}");
    assert_eq!(duplicated.duplicate_deliveries, 1, "seed={SEED}");
    assert_eq!(duplicated.delivered_messages, 4, "seed={SEED}");
    assert_eq!(delayed.delayed_messages, 1, "seed={SEED}");
    assert_eq!(delayed.completed_at_ms, 12, "seed={SEED}");
}
