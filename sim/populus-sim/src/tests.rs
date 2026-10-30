use super::{
    ClockSkewDistribution, FailureAction, FailureEvent, LatencyDistribution, MaliciousStrategy,
    SimulationConfig, SimulationError, VIEW_COUNT, run_simulation,
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
