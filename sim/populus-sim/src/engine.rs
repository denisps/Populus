use crate::config::{
    FailureAction, FailureEvent, MAX_SIMULATION_MESSAGES, MaliciousStrategy, SimulationConfig,
    SimulationError, VIEW_COUNT,
};
use crate::report::{ContentSummary, SimulationReport, ViewContentSummary};
use crate::rng::SeededRandom;
use crate::workload::{generate_client_ids, generate_contents, generate_node_ids};
use populus_sketch::ClientSketch;
use populus_types::ClientId;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

const REPORT_WINDOW_MS: i128 = 60_000;

/// Runs a deterministic routing/content/sketch workload without sockets or wall-clock time.
///
/// Every client submits one vote for a deterministically selected content in each
/// of three workload views. Destinations are sampled independently while avoiding
/// duplicate nodes for a client when at least three nodes are available. This
/// placement is only a load generator and does not select a protocol assignment
/// algorithm.
///
/// Node crashes and recoveries occur before vote deliveries at the same timestamp.
/// A failure is not retried. Clock skew partitions received votes into local
/// one-minute sketches; the report merges all windows to expose eventual
/// distinct-client convergence despite boundary skew.
///
/// # Errors
///
/// Returns an error for invalid distributions or node indices, conflicting
/// same-time availability events, excessive workload sizes, virtual-time
/// overflow, invalid generated content, or a routing/oracle disagreement.
pub fn run_simulation(config: &SimulationConfig) -> Result<SimulationReport, SimulationError> {
    crate::config::validate_config(config)?;
    run_validated_simulation(config).map_err(|source| SimulationError::Scenario {
        seed: config.seed,
        source: Box::new(source),
    })
}

fn run_validated_simulation(
    config: &SimulationConfig,
) -> Result<SimulationReport, SimulationError> {
    let message_count = if config.content_count == 0 {
        0
    } else {
        config
            .client_count
            .checked_mul(VIEW_COUNT)
            .ok_or(SimulationError::CountLimitExceeded("message count"))?
    };
    validate_event_budget(config, message_count)?;

    let mut random = SeededRandom::new(config.seed);
    let node_ids = generate_node_ids(config.node_count, &mut random)?;
    let client_ids = if config.content_count == 0 {
        Vec::new()
    } else {
        generate_client_ids(config.client_count, &mut random)?
    };
    let mut nodes: Vec<_> = node_ids
        .iter()
        .copied()
        .map(|_| SimNode {
            clock_skew_ms: config.clock_skew.sample(&mut random),
            alive: true,
            reports: BTreeMap::new(),
        })
        .collect();

    let contents = generate_contents(config, &node_ids)?;
    let mut events = ScheduledEvents::new();
    events.schedule_failures(&config.failure_schedule)?;
    let expected_by_content = crate::workload::schedule_votes(
        config,
        client_ids,
        &mut random,
        |at_ms, node, client, content, view| {
            events.push(
                at_ms,
                1,
                ScheduledAction::Vote {
                    node,
                    client,
                    content,
                    view,
                    delayed: false,
                    replayed: false,
                },
            )
        },
    )?;
    let metrics = process_events(&mut nodes, events, config)?;
    let view_content = summarize_views(&nodes, &contents, &expected_by_content, &metrics);

    Ok(SimulationReport {
        seed: config.seed,
        node_count: config.node_count,
        client_count: config.client_count,
        content_count: config.content_count,
        sent_messages: message_count,
        delivered_messages: metrics.delivered_messages,
        dropped_messages: metrics.dropped_messages,
        delayed_messages: metrics.delayed_messages,
        duplicate_deliveries: metrics.duplicate_deliveries,
        replayed_messages: metrics.replayed_messages,
        completed_at_ms: metrics.completed_at_ms,
        contents,
        view_content,
    })
}

fn validate_event_budget(
    config: &SimulationConfig,
    message_count: usize,
) -> Result<(), SimulationError> {
    let rescheduled_messages = if config.malicious_nodes.is_empty()
        || !matches!(
            config.malicious_strategy,
            MaliciousStrategy::DelayMessages { .. } | MaliciousStrategy::ReplayMessages { .. }
        ) {
        0
    } else {
        message_count
    };
    let event_count = message_count
        .checked_add(rescheduled_messages)
        .and_then(|count| count.checked_add(config.failure_schedule.len()))
        .ok_or(SimulationError::CountLimitExceeded("event count"))?;
    if event_count > MAX_SIMULATION_MESSAGES {
        return Err(SimulationError::CountLimitExceeded("event count"));
    }
    Ok(())
}

/// Merges per-node report sketches into one summary per (view, content) pair.
fn summarize_views(
    nodes: &[SimNode],
    contents: &[ContentSummary],
    expected_by_content: &[usize],
    metrics: &EventMetrics,
) -> Vec<ViewContentSummary> {
    // Group reports once, preserving node order then window order per key.
    let mut grouped: BTreeMap<(usize, usize), (ClientSketch, BTreeSet<_>)> = BTreeMap::new();
    for node in nodes {
        for (&(node_view, node_content, window), sketch) in &node.reports {
            let (merged, windows) = grouped
                .entry((usize::from(node_view), node_content))
                .or_insert_with(|| (ClientSketch::new(), BTreeSet::new()));
            merged.merge(sketch);
            windows.insert(window);
        }
    }
    let empty = (ClientSketch::new(), BTreeSet::new());
    let mut view_content = Vec::with_capacity(VIEW_COUNT.saturating_mul(contents.len()));
    for (view, view_counts) in metrics.accepted_by_view_content.iter().enumerate() {
        for (content_index, content) in contents.iter().enumerate() {
            let (merged, report_windows) = grouped.get(&(view, content_index)).unwrap_or(&empty);
            view_content.push(ViewContentSummary {
                view,
                content_id: content.content_id,
                expected_clients: expected_by_content[content_index],
                distinct_client_estimate: merged.estimate(),
                accepted_deliveries: view_counts[content_index],
                report_windows: report_windows.len(),
            });
        }
    }
    view_content
}

/// Drains the scheduled event queue, applying failures and votes in order.
fn process_events(
    nodes: &mut [SimNode],
    mut events: ScheduledEvents,
    config: &SimulationConfig,
) -> Result<EventMetrics, SimulationError> {
    let malicious_nodes: BTreeSet<_> = config.malicious_nodes.iter().copied().collect();
    let mut metrics = EventMetrics::new(config.content_count);
    while let Some(Reverse(event)) = events.queue.pop() {
        metrics.completed_at_ms = event.at_ms;
        match event.action {
            ScheduledAction::Failure { node, action } => {
                nodes[node].alive = action == FailureAction::Recover;
            }
            action @ ScheduledAction::Vote { .. } => process_vote_event(
                nodes,
                &mut events,
                &mut metrics,
                config.malicious_strategy,
                &malicious_nodes,
                event.at_ms,
                action,
            )?,
        }
    }
    Ok(metrics)
}

/// Applies one vote event, honoring node liveness and malicious strategy.
fn process_vote_event(
    nodes: &mut [SimNode],
    events: &mut ScheduledEvents,
    metrics: &mut EventMetrics,
    strategy: MaliciousStrategy,
    malicious_nodes: &BTreeSet<usize>,
    at_ms: u64,
    action: ScheduledAction,
) -> Result<(), SimulationError> {
    let ScheduledAction::Vote {
        node,
        client,
        content,
        view,
        delayed,
        replayed,
    } = action
    else {
        return Err(SimulationError::RoutingInvariant);
    };

    if !nodes[node].alive {
        metrics.dropped_messages += 1;
        return Ok(());
    }
    let is_malicious = malicious_nodes.contains(&node);
    if is_malicious && strategy == MaliciousStrategy::DropMessages {
        metrics.dropped_messages += 1;
        return Ok(());
    }
    if let MaliciousStrategy::DelayMessages { extra_delay_ms } = strategy
        && is_malicious
        && !delayed
    {
        metrics.delayed_messages += 1;
        let delayed_at = at_ms
            .checked_add(extra_delay_ms)
            .ok_or(SimulationError::TimeOrSequenceOverflow)?;
        events.push(
            delayed_at,
            1,
            ScheduledAction::Vote {
                node,
                client,
                content,
                view,
                delayed: true,
                replayed: false,
            },
        )?;
        return Ok(());
    }

    accept_vote(nodes, metrics, node, client, content, view, at_ms);
    if !is_malicious || replayed {
        return Ok(());
    }
    match strategy {
        MaliciousStrategy::DuplicateMessages => {
            accept_vote(nodes, metrics, node, client, content, view, at_ms);
            metrics.duplicate_deliveries += 1;
        }
        MaliciousStrategy::ReplayMessages { replay_after_ms } => {
            let replay_at = at_ms
                .checked_add(replay_after_ms)
                .ok_or(SimulationError::TimeOrSequenceOverflow)?;
            events.push(
                replay_at,
                1,
                ScheduledAction::Vote {
                    node,
                    client,
                    content,
                    view,
                    delayed: false,
                    replayed: true,
                },
            )?;
            metrics.replayed_messages += 1;
        }
        MaliciousStrategy::None
        | MaliciousStrategy::DropMessages
        | MaliciousStrategy::DelayMessages { .. } => {}
    }
    Ok(())
}

fn accept_vote(
    nodes: &mut [SimNode],
    metrics: &mut EventMetrics,
    node_index: usize,
    client: ClientId,
    content: usize,
    view: u8,
    at_ms: u64,
) {
    let node = &mut nodes[node_index];
    let local_time = i128::from(at_ms) + i128::from(node.clock_skew_ms);
    let window = local_time.div_euclid(REPORT_WINDOW_MS);
    node.reports
        .entry((view, content, window))
        .or_default()
        .insert(client);
    metrics.accepted_by_view_content[usize::from(view)][content] += 1;
    metrics.delivered_messages += 1;
}

fn push_event(
    queue: &mut BinaryHeap<Reverse<ScheduledEvent>>,
    next_sequence: &mut u64,
    at_ms: u64,
    priority: u8,
    action: ScheduledAction,
) -> Result<(), SimulationError> {
    let sequence = *next_sequence;
    *next_sequence = next_sequence
        .checked_add(1)
        .ok_or(SimulationError::TimeOrSequenceOverflow)?;
    queue.push(Reverse(ScheduledEvent {
        at_ms,
        priority,
        sequence,
        action,
    }));
    Ok(())
}

struct ScheduledEvents {
    queue: BinaryHeap<Reverse<ScheduledEvent>>,
    next_sequence: u64,
}

impl ScheduledEvents {
    fn new() -> Self {
        Self {
            queue: BinaryHeap::new(),
            next_sequence: 0,
        }
    }

    fn push(
        &mut self,
        at_ms: u64,
        priority: u8,
        action: ScheduledAction,
    ) -> Result<(), SimulationError> {
        push_event(
            &mut self.queue,
            &mut self.next_sequence,
            at_ms,
            priority,
            action,
        )
    }

    fn schedule_failures(
        &mut self,
        failure_schedule: &[FailureEvent],
    ) -> Result<(), SimulationError> {
        let mut failures = failure_schedule.to_vec();
        failures.sort_unstable();
        for failure in failures {
            self.push(
                failure.at_ms,
                0,
                ScheduledAction::Failure {
                    node: failure.node,
                    action: failure.action,
                },
            )?;
        }
        Ok(())
    }
}

struct EventMetrics {
    accepted_by_view_content: Vec<Vec<usize>>,
    delivered_messages: usize,
    dropped_messages: usize,
    delayed_messages: usize,
    duplicate_deliveries: usize,
    replayed_messages: usize,
    completed_at_ms: u64,
}

impl EventMetrics {
    fn new(content_count: usize) -> Self {
        Self {
            accepted_by_view_content: vec![vec![0; content_count]; VIEW_COUNT],
            delivered_messages: 0,
            dropped_messages: 0,
            delayed_messages: 0,
            duplicate_deliveries: 0,
            replayed_messages: 0,
            completed_at_ms: 0,
        }
    }
}

struct SimNode {
    clock_skew_ms: i64,
    alive: bool,
    reports: BTreeMap<(u8, usize, i128), ClientSketch>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ScheduledEvent {
    at_ms: u64,
    priority: u8,
    sequence: u64,
    action: ScheduledAction,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ScheduledAction {
    Failure {
        node: usize,
        action: FailureAction,
    },
    Vote {
        node: usize,
        client: ClientId,
        content: usize,
        view: u8,
        delayed: bool,
        replayed: bool,
    },
}
