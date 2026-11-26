#![allow(clippy::expect_used)]

use super::{
    ByzantineAction, ByzantineScript, ClockSkewDistribution, FailureAction, FailureEvent,
    LatencyDistribution, LifecycleAction, LifecycleEvent, MaliciousStrategy, PACKET_LOSS_SCALE,
    PartitionAction, PartitionEvent, SIMULATED_PAYLOAD_BYTES, SimulationConfig, SimulationError,
    VIEW_COUNT, run_simulation,
};
use populus_cluster::{
    AUTHORITY_COUNT, AssignmentAlgorithm, AuthorityMember, AuthorityMode,
    DELEGATION_REPORT_INTERVALS_MS, DelegatedIngestState, DelegatedReportReceiver,
    DelegationControlConfig, DelegationController, DelegationDescriptor, DelegationParameters,
    DelegationRateSample, IngestNode, IngestReport, MembershipView, select_authorities,
};
use populus_crypto::{AuthorityKeypair, RoutingIdentifier, routing_key};
use populus_sketch::ClientSketch;
use populus_types::{ClientId, ContentId, NodeId, UtcDay};

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

#[derive(Default)]
struct DelegatedDeliveryFaults {
    lost_report_retried: bool,
    lost_ack_retried: bool,
    duplicate_report_retried: bool,
    restarts: DelegatedRestartFaults,
}

#[derive(Default)]
struct DelegatedRestartFaults {
    authority_crash_retried: bool,
    sender_crash_retried: bool,
}

struct DelegatedDeliveryContext<'a> {
    descriptor: &'a DelegationDescriptor,
    membership: &'a MembershipView,
    keys: &'a [AuthorityKeypair],
}

#[allow(clippy::too_many_lines)]
fn deliver_delegated_report(
    report: &IngestReport,
    ingest: &mut DelegatedIngestState,
    (view, node_id): (usize, NodeId),
    receivers: &mut [DelegatedReportReceiver],
    context: &DelegatedDeliveryContext<'_>,
    faults: &mut DelegatedDeliveryFaults,
) {
    let descriptor = context.descriptor;
    let membership = context.membership;
    let keys = context.keys;
    let mut lost_report_authority = None;
    for (authority_index, receiver) in receivers.iter_mut().enumerate() {
        let authority_id = membership.members()[authority_index].authority_id();
        let signer = keys
            .iter()
            .find(|key| key.authority_id() == authority_id)
            .expect("membership authority has a signing key");
        if view == 0
            && report.sequence() == 1
            && authority_index == 0
            && !faults.lost_report_retried
        {
            assert_eq!(ingest.pending_report(), Some(report));
            assert!(ingest.pending_authorities().contains(&authority_id));
            let sequence_before_delivery = receiver.last_sequence(node_id);
            assert_eq!(sequence_before_delivery, 0);
            assert_eq!(receiver.last_sequence(node_id), sequence_before_delivery);
            lost_report_authority = Some(authority_index);
            continue;
        }
        let ack = receiver
            .accept_report(report, node_id, membership, signer)
            .expect("authenticated report is accepted or idempotently retried");
        if view == 1 && report.sequence() == 1 && authority_index == 0 && !faults.lost_ack_retried {
            let retry_ack = receiver
                .accept_report(report, node_id, membership, signer)
                .expect("lost ACK retry is idempotently acknowledged");
            assert_eq!(retry_ack, ack);
            assert_eq!(ingest.pending_report(), Some(report));
            assert!(ingest.pending_authorities().contains(&authority_id));
            faults.lost_ack_retried = true;
            ingest
                .acknowledge(&retry_ack, membership)
                .expect("replayed ACK applies after the original ACK is lost");
            assert!(!ingest.pending_authorities().contains(&authority_id));
            assert_eq!(ingest.pending_report(), Some(report));
        } else if view == 1
            && report.sequence() == 1
            && authority_index == 1
            && !faults.restarts.authority_crash_retried
        {
            let snapshot = receiver
                .serialize()
                .expect("authority snapshot persists before ACK delivery");
            *receiver = DelegatedReportReceiver::deserialize(&snapshot, descriptor, membership)
                .expect("authority restart restores sequence and report digest");
            assert_eq!(receiver.last_sequence(node_id), report.sequence());
            let retry_ack = receiver
                .accept_report(report, node_id, membership, signer)
                .expect("restored authority re-acknowledges the same report");
            assert_eq!(retry_ack, ack);
            faults.restarts.authority_crash_retried = true;
            ingest
                .acknowledge(&retry_ack, membership)
                .expect("ACK from restored authority applies");
        } else if view == 2
            && report.sequence() == 1
            && authority_index == 1
            && !faults.restarts.sender_crash_retried
        {
            assert_eq!(ingest.pending_report(), Some(report));
            assert!(ingest.pending_authorities().contains(&authority_id));
            let snapshot = ingest
                .serialize()
                .expect("sender snapshot persists with an outstanding ACK");
            *ingest = DelegatedIngestState::deserialize(&snapshot)
                .expect("sender restart restores the pending report");
            assert_eq!(ingest.pending_report(), Some(report));
            assert!(ingest.pending_authorities().contains(&authority_id));
            let retry_ack = receiver
                .accept_report(report, node_id, membership, signer)
                .expect("authority retries ACK after sender restart");
            assert_eq!(retry_ack, ack);
            faults.restarts.sender_crash_retried = true;
            assert!(
                !ingest
                    .acknowledge(&retry_ack, membership)
                    .expect("missing ACK applies after sender restart")
            );
            assert!(!ingest.pending_authorities().contains(&authority_id));
            assert_eq!(ingest.pending_report(), Some(report));
        } else if view == 2
            && report.sequence() == 1
            && authority_index == 0
            && !faults.duplicate_report_retried
        {
            let duplicate_ack = receiver
                .accept_report(report, node_id, membership, signer)
                .expect("duplicate report is acknowledged without a second merge");
            assert_eq!(duplicate_ack, ack);
            faults.duplicate_report_retried = true;
            ingest
                .acknowledge(&ack, membership)
                .expect("signed ACK applies to the pending report");
        } else {
            ingest
                .acknowledge(&ack, membership)
                .expect("signed ACK applies to the pending report");
        }
    }

    if let Some(authority_index) = lost_report_authority {
        let authority_id = membership.members()[authority_index].authority_id();
        let receiver = &mut receivers[authority_index];
        assert_eq!(receiver.last_sequence(node_id), 0);
        assert_eq!(ingest.pending_report(), Some(report));
        assert!(ingest.pending_authorities().contains(&authority_id));
        let signer = keys
            .iter()
            .find(|key| key.authority_id() == authority_id)
            .expect("membership authority has a signing key");
        let retry_ack = receiver
            .accept_report(report, node_id, membership, signer)
            .expect("lost report is accepted when the pending report is retried");
        assert_eq!(receiver.last_sequence(node_id), report.sequence());
        assert!(
            ingest
                .acknowledge(&retry_ack, membership)
                .expect("retried report ACK completes delivery")
        );
        assert!(!ingest.pending_authorities().contains(&authority_id));
        assert!(ingest.pending_report().is_none());
        faults.lost_report_retried = true;
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
fn match_bits_varies_from_xor_nearest_in_a_large_content_neighborhood()
-> Result<(), SimulationError> {
    let common = SimulationConfig {
        seed: 0x9a71,
        node_count: 20_000,
        client_count: 2_000,
        content_count: 1,
        offered_votes_per_minute: 100,
        max_votes_per_node_per_minute: 100,
        ..SimulationConfig::default()
    };
    let match_bits = run_simulation(&SimulationConfig {
        assignment_algorithm: AssignmentAlgorithm::MatchBits,
        ..common.clone()
    })?;
    let xor_nearest = run_simulation(&SimulationConfig {
        assignment_algorithm: AssignmentAlgorithm::XorNearest,
        ..common
    })?;

    assert_eq!(
        match_bits.assignment_candidate_count,
        populus_routing::BUCKET_CAPACITY
    );
    assert_eq!(match_bits.assignment_match_bits, 4);
    assert_ne!(
        match_bits.assignment_loads, xor_nearest.assignment_loads,
        "relative-prefix MatchBits assignments collapsed to XorNearest"
    );
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
#[allow(clippy::too_many_lines)]
fn delegated_reports_survive_seeded_timing_loss_retry_restart_and_reordering() {
    let content_id = ContentId::from_digest([0x33; 32]);
    let day = UtcDay::new(10);
    let keys: Vec<_> = (1..=4)
        .map(|value| AuthorityKeypair::from_secret_key([value; 32]))
        .collect();
    let members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            AuthorityMember::new(
                NodeId::from_bytes(
                    [u8::try_from(index + 1).expect("four fixture members fit in u8"); 32],
                ),
                key.public_key(),
            )
            .expect("generated authority member is valid")
        })
        .collect();
    let routing_key = routing_key(RoutingIdentifier::Content(&content_id));
    let membership = MembershipView::new(
        routing_key,
        1,
        select_authorities(&routing_key, &members).expect("fixture members are unique"),
    )
    .expect("fixture membership is canonical");
    let candidate_ids = [
        NodeId::from_bytes([0x40; 32]),
        NodeId::from_bytes([0x41; 32]),
        NodeId::from_bytes([0x42; 32]),
    ];
    let descriptor = DelegationDescriptor::new(
        AssignmentAlgorithm::XorNearest,
        candidate_ids.iter().copied().map(IngestNode::new).collect(),
        0,
    )
    .expect("three candidates form a valid descriptor");
    let mut ingest: Vec<Vec<_>> = (0..VIEW_COUNT)
        .map(|view| {
            candidate_ids
                .iter()
                .map(|node_id| {
                    DelegatedIngestState::new(
                        content_id,
                        day,
                        u8::try_from(view).expect("three views fit in u8"),
                        *node_id,
                        &membership,
                    )
                    .expect("valid delegated-ingest state")
                })
                .collect()
        })
        .collect();
    let mut random = super::rng::SeededRandom::new(0x10_10_10);
    let latency = LatencyDistribution::Uniform {
        min_ms: 0,
        max_ms: 10_000,
    };
    let clock_offsets = [-30_000_i64, 0, 30_000];
    let mut arrivals = vec![vec![Vec::new(); candidate_ids.len()]; VIEW_COUNT];
    for client_index in 0..60_u8 {
        let client_id = ClientId::from_bytes([client_index + 1; 32]);
        let destinations = descriptor
            .assign_views(client_id)
            .expect("descriptor assigns each client in all views");
        for (view, destination) in destinations.into_iter().enumerate() {
            let node_index = candidate_ids
                .iter()
                .position(|node_id| *node_id == destination.node_id())
                .expect("assigned node belongs to the descriptor");
            let network_delay = latency.sample(&mut random);
            let local_time = 59_000_i64
                + i64::try_from(network_delay).expect("configured delay fits in i64")
                + clock_offsets[node_index];
            arrivals[view][node_index].push((local_time, client_id));
        }
    }

    let mut reports_by_node = vec![vec![Vec::new(); candidate_ids.len()]; VIEW_COUNT];
    let mut receivers: Vec<Vec<_>> = (0..VIEW_COUNT)
        .map(|view| {
            (0..AUTHORITY_COUNT)
                .map(|_| {
                    DelegatedReportReceiver::new(
                        content_id,
                        day,
                        u8::try_from(view).expect("three views fit in u8"),
                        &descriptor,
                        &membership,
                    )
                    .expect("valid authority receiver")
                })
                .collect()
        })
        .collect();
    let mut delivery_faults = DelegatedDeliveryFaults::default();
    let delivery_context = DelegatedDeliveryContext {
        descriptor: &descriptor,
        membership: &membership,
        keys: &keys,
    };
    for view in 0..VIEW_COUNT {
        for node_index in 0..candidate_ids.len() {
            let node_arrivals = &mut arrivals[view][node_index];
            if node_arrivals.is_empty() {
                continue;
            }
            node_arrivals.sort_by_key(|(local_time, _)| *local_time);
            let mut active_window = None;
            let mut expected_sketch = ClientSketch::new();
            for (local_time, client_id) in node_arrivals {
                let window = local_time.div_euclid(60_000);
                if active_window.is_some_and(|active| active != window) {
                    let report = ingest[view][node_index]
                        .rollover()
                        .expect("rollover succeeds")
                        .expect("previous report window has clients")
                        .clone();
                    assert_eq!(report.sketch(), &expected_sketch);
                    reports_by_node[view][node_index].push(report);
                    deliver_delegated_report(
                        reports_by_node[view][node_index]
                            .last()
                            .expect("report was recorded"),
                        &mut ingest[view][node_index],
                        (view, candidate_ids[node_index]),
                        &mut receivers[view],
                        &delivery_context,
                        &mut delivery_faults,
                    );
                    expected_sketch = ClientSketch::new();
                }
                active_window = Some(window);
                ingest[view][node_index].record_client(*client_id);
                expected_sketch.insert(*client_id);
            }
            if expected_sketch.estimate() > 0.0 {
                let report = ingest[view][node_index]
                    .rollover()
                    .expect("final window rollover succeeds")
                    .expect("candidate received clients in its final window")
                    .clone();
                assert_eq!(report.sketch(), &expected_sketch);
                reports_by_node[view][node_index].push(report);
                deliver_delegated_report(
                    reports_by_node[view][node_index]
                        .last()
                        .expect("report was recorded"),
                    &mut ingest[view][node_index],
                    (view, candidate_ids[node_index]),
                    &mut receivers[view],
                    &delivery_context,
                    &mut delivery_faults,
                );
            }
        }
    }
    assert!(
        reports_by_node
            .iter()
            .flatten()
            .any(|reports| reports.len() > 1),
        "clock skew and latency roll at least one ingest node into a later window"
    );
    let (split_view, split_node) = reports_by_node
        .iter()
        .enumerate()
        .find_map(|(view, view_reports)| {
            view_reports
                .iter()
                .position(|reports| reports.len() > 1)
                .map(|node_index| (view, node_index))
        })
        .expect("at least one candidate emitted multiple report windows");
    let first_window = arrivals[split_view][split_node][0].0.div_euclid(60_000);
    let second_window = arrivals[split_view][split_node]
        .iter()
        .find(|(local_time, _)| local_time.div_euclid(60_000) > first_window)
        .expect("node has an arrival after its first report boundary")
        .0
        .div_euclid(60_000);
    let mut later_window_clients = ClientSketch::new();
    for (local_time, client_id) in &arrivals[split_view][split_node] {
        if local_time.div_euclid(60_000) == second_window {
            later_window_clients.insert(*client_id);
        }
    }
    assert!(later_window_clients.estimate() > 0.0);
    assert_eq!(
        reports_by_node[split_view][split_node][1].sketch(),
        &later_window_clients,
        "boundary-delayed clients appear in the later report"
    );
    assert!(delivery_faults.lost_report_retried);
    assert!(delivery_faults.lost_ack_retried);
    assert!(delivery_faults.duplicate_report_retried);
    assert!(delivery_faults.restarts.authority_crash_retried);
    assert!(delivery_faults.restarts.sender_crash_retried);

    for view_states in &mut ingest {
        for state in view_states {
            let snapshot = state
                .serialize()
                .expect("pending report snapshot is bounded");
            *state = DelegatedIngestState::deserialize(&snapshot).expect("sender restart restores");
        }
    }
    assert!(
        ingest
            .iter()
            .flatten()
            .all(|state| state.pending_report().is_none())
    );

    for view_receivers in &mut receivers {
        *view_receivers = view_receivers
            .iter()
            .map(|receiver| {
                let snapshot = receiver.serialize().expect("authority snapshot is bounded");
                DelegatedReportReceiver::deserialize(&snapshot, &descriptor, &membership)
                    .expect("authority restart restores replay state")
            })
            .collect();
    }

    let second_client = ClientId::from_bytes([0xFE; 32]);
    for (view, destination) in descriptor
        .assign_views(second_client)
        .expect("second client has three destinations")
        .into_iter()
        .enumerate()
    {
        let node_index = candidate_ids
            .iter()
            .position(|node_id| *node_id == destination.node_id())
            .expect("assigned node belongs to the descriptor");
        ingest[view][node_index].record_client(second_client);
        let second_report = ingest[view][node_index]
            .rollover()
            .expect("second rollover succeeds")
            .expect("second client is buffered")
            .clone();
        let first_report = reports_by_node[view][node_index].first().cloned();
        reports_by_node[view][node_index].push(second_report.clone());
        deliver_delegated_report(
            &second_report,
            &mut ingest[view][node_index],
            (view, candidate_ids[node_index]),
            &mut receivers[view],
            &delivery_context,
            &mut delivery_faults,
        );
        for (authority_index, receiver) in receivers[view].iter_mut().enumerate() {
            let authority_id = membership.members()[authority_index].authority_id();
            let signer = keys
                .iter()
                .find(|key| key.authority_id() == authority_id)
                .expect("membership authority has a signing key");
            if let Some(first_report) = &first_report {
                assert_eq!(
                    receiver.accept_report(
                        first_report,
                        candidate_ids[node_index],
                        &membership,
                        signer,
                    ),
                    Err(populus_cluster::DelegatedIngestError::StaleReport),
                    "a delayed prior sequence cannot be merged after the next report"
                );
            }
        }
    }
    assert!(
        ingest
            .iter()
            .flatten()
            .all(|state| state.pending_report().is_none())
    );
    for (view, authority_receivers) in receivers.iter().enumerate() {
        assert!(
            authority_receivers
                .iter()
                .all(|receiver| (receiver.estimate() - 61.0).abs() < f64::EPSILON),
            "view {view} converges despite timing and delivery faults"
        );
    }
}

#[test]
fn delegated_view_reports_keep_inflated_and_suppressed_sketches_isolated() {
    let content_id = ContentId::from_digest([0x34; 32]);
    let day = UtcDay::new(10);
    let keys: Vec<_> = (1..=4)
        .map(|value| AuthorityKeypair::from_secret_key([value; 32]))
        .collect();
    let members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            AuthorityMember::new(
                NodeId::from_bytes(
                    [u8::try_from(index + 1).expect("four fixture members fit in u8"); 32],
                ),
                key.public_key(),
            )
            .expect("generated authority member is valid")
        })
        .collect();
    let routing_key = routing_key(RoutingIdentifier::Content(&content_id));
    let membership = MembershipView::new(
        routing_key,
        1,
        select_authorities(&routing_key, &members).expect("fixture members are unique"),
    )
    .expect("fixture membership is canonical");
    let candidate_ids = [
        NodeId::from_bytes([0x50; 32]),
        NodeId::from_bytes([0x51; 32]),
        NodeId::from_bytes([0x52; 32]),
    ];
    let descriptor = DelegationDescriptor::new(
        AssignmentAlgorithm::XorNearest,
        candidate_ids.iter().copied().map(IngestNode::new).collect(),
        0,
    )
    .expect("three candidates form a valid descriptor");
    let signer_id = membership.members()[0].authority_id();
    let signer = keys
        .iter()
        .find(|key| key.authority_id() == signer_id)
        .expect("membership authority has a signing key");

    for (malicious_view, add_inflated_clients) in [(0, false), (2, true)] {
        let mut receivers: Vec<_> = (0..VIEW_COUNT)
            .map(|view| {
                DelegatedReportReceiver::new(
                    content_id,
                    day,
                    u8::try_from(view).expect("three views fit in u8"),
                    &descriptor,
                    &membership,
                )
                .expect("valid authority receiver")
            })
            .collect();
        for (view, receiver) in receivers.iter_mut().enumerate() {
            let mut sketch = ClientSketch::new();
            if view != malicious_view || add_inflated_clients {
                for client_index in 0..20_u8 {
                    sketch.insert(ClientId::from_bytes([client_index + 1; 32]));
                }
            }
            if view == malicious_view && add_inflated_clients {
                for client_index in 20..120_u8 {
                    sketch.insert(ClientId::from_bytes([client_index + 1; 32]));
                }
            }
            let report = IngestReport::new(
                content_id,
                day,
                u8::try_from(view).expect("three views fit in u8"),
                candidate_ids[0],
                1,
                sketch,
            )
            .expect("valid report");
            receiver
                .accept_report(&report, candidate_ids[0], &membership, signer)
                .expect("descriptor candidate report is accepted");
        }
        let estimates: Vec<_> = receivers
            .iter()
            .map(DelegatedReportReceiver::estimate)
            .collect();
        if add_inflated_clients {
            assert_eq!(estimates, [20.0, 20.0, 120.0]);
        } else {
            assert_eq!(estimates, [0.0, 20.0, 20.0]);
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn delegation_controller_stabilizes_across_load_shapes_and_report_faults() {
    let direct = || {
        DelegationParameters::new(
            AuthorityMode::Direct,
            0,
            AssignmentAlgorithm::MatchBits,
            0,
            DELEGATION_REPORT_INTERVALS_MS[2],
        )
        .expect("valid direct control parameters")
    };
    let new_controller = |initial, dwell_ms| {
        DelegationController::new(
            DelegationControlConfig::new(1_000, dwell_ms).expect("positive target rate"),
            initial,
            0,
        )
    };
    let sample = |at_ms, rates, per_node, candidates| {
        DelegationRateSample::new(at_ms, rates, per_node, candidates)
    };

    let mut steady = new_controller(direct(), 0);
    let mut stable_parameters = None;
    for minute in 0..20 {
        let decision = steady
            .observe(sample(
                minute * 60_000,
                [Some(1_200); 3],
                [Some(900); 3],
                64,
            ))
            .expect("steady rate sample");
        if minute >= 10 {
            if let Some(previous) = stable_parameters {
                assert_eq!(decision.parameters(), previous);
            }
            stable_parameters = Some(decision.parameters());
        }
    }
    assert_eq!(
        steady.parameters().mode(),
        AuthorityMode::Delegated,
        "stable offered load above direct capacity eventually delegates"
    );

    let mut slow_ramp = new_controller(direct(), 0);
    for (sample_index, rate) in (1_000_u64..=5_000).step_by(1_000).enumerate() {
        let candidate_count = slow_ramp.parameters().candidate_count().max(1);
        let per_node_rate = rate
            .saturating_mul(3)
            .div_ceil(u64::try_from(candidate_count).expect("small candidate count"));
        slow_ramp
            .observe(sample(
                u64::try_from(sample_index).expect("few samples") * 60_000,
                [Some(rate); 3],
                [Some(per_node_rate); 3],
                64,
            ))
            .expect("slow-ramp sample");
    }
    assert_eq!(slow_ramp.parameters().mode(), AuthorityMode::Delegated);
    let converged_per_node_rate = 5_000_u64
        .saturating_mul(3)
        .div_ceil(u64::try_from(slow_ramp.parameters().candidate_count()).expect("small count"));
    assert!(
        converged_per_node_rate <= 1_000,
        "available capacity converges below the target"
    );

    let mut ramp = new_controller(direct(), 0);
    for (sample_index, rate) in [1_000_u64, 10_000, 1_000_000, 100_000_000]
        .into_iter()
        .enumerate()
    {
        ramp.observe(sample(
            u64::try_from(sample_index).expect("few samples") * 60_000,
            [Some(rate); 3],
            [Some(rate); 3],
            128,
        ))
        .expect("ramp sample");
    }
    assert_eq!(ramp.parameters().mode(), AuthorityMode::Delegated);
    assert_eq!(ramp.parameters().candidate_count(), 128);
    assert_eq!(
        ramp.parameters().reporting_interval_ms(),
        DELEGATION_REPORT_INTERVALS_MS[0]
    );

    let delegated = DelegationParameters::new(
        AuthorityMode::Delegated,
        16,
        AssignmentAlgorithm::XorNearest,
        0,
        DELEGATION_REPORT_INTERVALS_MS[0],
    )
    .expect("valid delegated control parameters");
    let mut collapse = new_controller(delegated, 120_000);
    for step in 0..=4 {
        collapse
            .observe(sample(step * 60_000, [Some(100); 3], [Some(100); 3], 64))
            .expect("collapse sample");
    }
    assert_eq!(collapse.parameters().mode(), AuthorityMode::Direct);

    let mut alternating = new_controller(direct(), 120_000);
    let mut changes = 0;
    for index in 0..24 {
        let rate = if index % 2 == 0 { 900 } else { 1_100 };
        let decision = alternating
            .observe(sample(
                index * 10_000,
                [Some(rate); 3],
                [Some(rate / 2); 3],
                64,
            ))
            .expect("oscillating boundary sample");
        changes += usize::from(decision.changed());
    }
    assert!(
        changes <= 1,
        "dwell and smoothing prevent threshold flapping"
    );

    let mut faulty = new_controller(direct(), 60_000);
    let missing = faulty
        .observe(sample(0, [Some(100_000), None, None], [None; 3], 64))
        .expect("one delayed view is insufficient to change mode");
    assert_eq!(missing.observed_rate_per_minute(), None);
    assert_eq!(missing.parameters().mode(), AuthorityMode::Direct);

    let malicious_high = faulty
        .observe(sample(
            1,
            [Some(900), Some(1_000), Some(100_000_000)],
            [Some(400), Some(500), Some(100_000_000)],
            64,
        ))
        .expect("a single malicious high report does not dominate");
    assert_eq!(malicious_high.observed_rate_per_minute(), Some(1_000));
    assert!(!malicious_high.hard_overload());
    assert_eq!(malicious_high.parameters().mode(), AuthorityMode::Direct);

    let malicious_low = faulty
        .observe(sample(
            2,
            [Some(1_000), Some(1_100), Some(0)],
            [Some(500), Some(600), Some(0)],
            64,
        ))
        .expect("a single malicious low report does not suppress the median");
    assert_eq!(malicious_low.observed_rate_per_minute(), Some(1_000));
    assert_eq!(malicious_low.parameters().mode(), AuthorityMode::Direct);

    assert!(
        faulty
            .observe(sample(1, [Some(1_000); 3], [Some(500); 3], 64))
            .is_err(),
        "delayed out-of-order samples are rejected"
    );
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
