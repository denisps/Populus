use crate::config::{
    ByzantineAction, FailureAction, FailureEvent, LifecycleAction, LifecycleEvent,
    MAX_SIMULATION_MESSAGES, MaliciousStrategy, PartitionAction, PartitionEvent, SimulationConfig,
    SimulationError, VIEW_COUNT,
};
use crate::report::{ContentSummary, SimulationReport, ViewContentSummary};
use crate::rng::SeededRandom;
use crate::workload::{generate_client_ids, generate_contents, generate_node_ids};
use populus_cluster::{
    AuthorityComponents, AuthorityMember, AuthorityState, EquivocationProof, MembershipView,
    SignedAuthorityState, StateResolution, resolve_authority_state, select_authorities,
};
use populus_crypto::AuthorityKeypair;
use populus_sketch::ClientSketch;
use populus_types::{ClientId, Epoch, NodeId, RoutingKey};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};

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

fn disconnect_node(node: usize, connections: &mut [BTreeSet<usize>]) {
    let peers = std::mem::take(&mut connections[node]);
    for peer in peers {
        connections[peer].remove(&node);
    }
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
            joined: config.initially_joined_nodes.is_none(),
            alive: true,
            reports: BTreeMap::new(),
            present_clients: BTreeSet::new(),
            historical_clients: BTreeSet::new(),
        })
        .collect();
    if let Some(joined_nodes) = &config.initially_joined_nodes {
        for node in &mut nodes {
            node.joined = false;
            node.alive = false;
        }
        for &node in joined_nodes {
            nodes[node].joined = true;
            nodes[node].alive = true;
        }
    }

    let contents = generate_contents(config, &node_ids)?;
    let mut events = ScheduledEvents::new();
    events.schedule_failures(&config.failure_schedule)?;
    events.schedule_lifecycle(&config.lifecycle_schedule)?;
    events.schedule_partitions(&config.partition_schedule)?;
    let mut message_id = 0_usize;
    let expected_by_content = crate::workload::schedule_votes(
        config,
        client_ids,
        &mut random,
        |at_ms, source, node, client, content, view, loss_dropped| {
            let current_message_id = message_id;
            message_id = message_id
                .checked_add(1)
                .ok_or(SimulationError::TimeOrSequenceOverflow)?;
            events.push(
                at_ms,
                1,
                ScheduledAction::Vote {
                    source,
                    node,
                    client,
                    content,
                    view,
                    delayed: false,
                    replayed: false,
                    loss_dropped,
                    message_id: current_message_id,
                    script_processed: false,
                    ordering_counted: false,
                },
            )
        },
    )?;
    let equivocation_context = if config
        .byzantine_scripts
        .iter()
        .any(|script| script.action == ByzantineAction::SendConflictingAuthorityStates)
    {
        Some(EquivocationContext::new(&node_ids)?)
    } else {
        None
    };
    let metrics = process_events(&mut nodes, events, config, equivocation_context.as_ref())?;
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
        partition_drops: metrics.partition_drops,
        rejected_connections: metrics.rejected_connections,
        reordered_deliveries: metrics.reordered_deliveries,
        byzantine_state_messages: metrics.byzantine_state_messages,
        node_restarts: metrics.node_restarts,
        restart_reinsertions: metrics.restart_reinsertions,
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
        .and_then(|count| {
            count.checked_add(
                config
                    .byzantine_scripts
                    .iter()
                    .filter(|script| matches!(script.action, ByzantineAction::DelayNext { .. }))
                    .count(),
            )
        })
        .and_then(|count| count.checked_add(config.failure_schedule.len()))
        .and_then(|count| count.checked_add(config.lifecycle_schedule.len()))
        .and_then(|count| count.checked_add(config.partition_schedule.len()))
        .and_then(|count| count.checked_add(config.byzantine_scripts.len()))
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
    equivocation_context: Option<&EquivocationContext>,
) -> Result<EventMetrics, SimulationError> {
    let mut scripts = vec![VecDeque::new(); nodes.len()];
    for script in &config.byzantine_scripts {
        scripts[script.node].push_back(script.action);
    }
    let mut vote_context = VoteProcessingContext {
        strategy: config.malicious_strategy,
        malicious_nodes: config.malicious_nodes.iter().copied().collect(),
        scripts,
        partition_groups: None,
        connections: vec![BTreeSet::new(); nodes.len()],
        connection_limit: config.connection_limit,
        reordering_enabled: config.reordering.is_some(),
        equivocation_context,
    };
    let mut metrics = EventMetrics::new(config.content_count);
    while let Some(Reverse(event)) = events.queue.pop() {
        metrics.completed_at_ms = event.at_ms;
        match event.action {
            ScheduledAction::Failure { node, action } => {
                if nodes[node].joined {
                    nodes[node].alive = action == FailureAction::Recover;
                    if action == FailureAction::Crash {
                        disconnect_node(node, &mut vote_context.connections);
                    }
                }
            }
            ScheduledAction::Lifecycle { node, action } => match action {
                LifecycleAction::Join => {
                    nodes[node].joined = true;
                    nodes[node].alive = true;
                }
                LifecycleAction::Leave => {
                    nodes[node].joined = false;
                    nodes[node].alive = false;
                    disconnect_node(node, &mut vote_context.connections);
                }
                LifecycleAction::Restart => {
                    nodes[node].reports.clear();
                    nodes[node].present_clients.clear();
                    nodes[node].joined = true;
                    nodes[node].alive = true;
                    disconnect_node(node, &mut vote_context.connections);
                    metrics.node_restarts += 1;
                }
            },
            ScheduledAction::Partition(action) => match action {
                PartitionAction::Split { groups } => {
                    vote_context.partition_groups = Some(groups);
                }
                PartitionAction::Heal => vote_context.partition_groups = None,
            },
            action @ ScheduledAction::Vote { .. } => process_vote_event(
                nodes,
                &mut events,
                &mut metrics,
                &mut vote_context,
                event.at_ms,
                action,
            )?,
        }
    }
    Ok(metrics)
}

struct VoteProcessingContext<'a> {
    strategy: MaliciousStrategy,
    malicious_nodes: BTreeSet<usize>,
    scripts: Vec<VecDeque<ByzantineAction>>,
    partition_groups: Option<Vec<usize>>,
    connections: Vec<BTreeSet<usize>>,
    connection_limit: Option<usize>,
    reordering_enabled: bool,
    equivocation_context: Option<&'a EquivocationContext>,
}

/// Applies one vote event, honoring node liveness and malicious strategy.
#[allow(clippy::too_many_lines)]
fn process_vote_event(
    nodes: &mut [SimNode],
    events: &mut ScheduledEvents,
    metrics: &mut EventMetrics,
    context: &mut VoteProcessingContext<'_>,
    at_ms: u64,
    action: ScheduledAction,
) -> Result<(), SimulationError> {
    let ScheduledAction::Vote {
        source,
        node,
        client,
        content,
        view,
        delayed,
        replayed,
        loss_dropped,
        message_id,
        script_processed,
        ordering_counted,
    } = action
    else {
        return Err(SimulationError::RoutingInvariant);
    };
    drop(action);

    if loss_dropped {
        metrics.dropped_messages += 1;
        return Ok(());
    }
    if let Some(groups) = &context.partition_groups
        && groups[source] != groups[node]
    {
        metrics.dropped_messages += 1;
        metrics.partition_drops += 1;
        return Ok(());
    }
    if !nodes[node].joined || !nodes[node].alive {
        metrics.dropped_messages += 1;
        return Ok(());
    }
    if let Some(limit) = context.connection_limit
        && source != node
        && !context.connections[source].contains(&node)
    {
        if context.connections[source].len() >= limit || context.connections[node].len() >= limit {
            metrics.dropped_messages += 1;
            metrics.rejected_connections += 1;
            return Ok(());
        }
        context.connections[source].insert(node);
        context.connections[node].insert(source);
    }
    let scripted_action = if script_processed {
        None
    } else {
        context.scripts[node].pop_front()
    };
    if let Some(ByzantineAction::SendConflictingAuthorityStates) = scripted_action {
        let equivocation_context = context
            .equivocation_context
            .ok_or(SimulationError::InvalidByzantineScript)?;
        metrics.byzantine_state_messages += equivocation_context
            .emit_conflicting_states(node)
            .map_err(|_| SimulationError::AuthorityScenario)?;
    }
    if scripted_action == Some(ByzantineAction::DropNext) {
        metrics.dropped_messages += 1;
        return Ok(());
    }
    if let Some(ByzantineAction::DelayNext { extra_delay_ms }) = scripted_action {
        metrics.delayed_messages += 1;
        let delayed_at = at_ms
            .checked_add(extra_delay_ms)
            .ok_or(SimulationError::TimeOrSequenceOverflow)?;
        events.push(
            delayed_at,
            1,
            ScheduledAction::Vote {
                source,
                node,
                client,
                content,
                view,
                delayed: true,
                replayed: false,
                loss_dropped: false,
                message_id,
                script_processed: true,
                ordering_counted,
            },
        )?;
        return Ok(());
    }
    let is_malicious = context.malicious_nodes.contains(&node);
    if is_malicious && context.strategy == MaliciousStrategy::DropMessages {
        metrics.dropped_messages += 1;
        return Ok(());
    }
    if let MaliciousStrategy::DelayMessages { extra_delay_ms } = context.strategy
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
                source,
                node,
                client,
                content,
                view,
                delayed: true,
                replayed: false,
                loss_dropped: false,
                message_id,
                script_processed: true,
                ordering_counted,
            },
        )?;
        return Ok(());
    }

    if context.reordering_enabled && !replayed && !ordering_counted {
        let previous_max = metrics.latest_message_id;
        if previous_max.is_some_and(|previous| message_id < previous) {
            metrics.reordered_deliveries += 1;
        }
        metrics.latest_message_id =
            Some(previous_max.map_or(message_id, |previous| previous.max(message_id)));
    }
    accept_vote(nodes, metrics, node, client, content, view, at_ms);
    if scripted_action == Some(ByzantineAction::DuplicateNext) {
        accept_vote(nodes, metrics, node, client, content, view, at_ms);
        metrics.duplicate_deliveries += 1;
    }
    if !is_malicious || replayed {
        return Ok(());
    }
    match context.strategy {
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
                    source,
                    client,
                    content,
                    view,
                    delayed: false,
                    replayed: true,
                    loss_dropped: false,
                    message_id,
                    script_processed: true,
                    ordering_counted: true,
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
    let client_key = (view, content, client);
    if node.present_clients.insert(client_key) && !node.historical_clients.insert(client_key) {
        metrics.restart_reinsertions += 1;
    }
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

    fn schedule_lifecycle(&mut self, schedule: &[LifecycleEvent]) -> Result<(), SimulationError> {
        let mut transitions = schedule.to_vec();
        transitions.sort_unstable();
        for event in transitions {
            self.push(
                event.at_ms,
                0,
                ScheduledAction::Lifecycle {
                    node: event.node,
                    action: event.action,
                },
            )?;
        }
        Ok(())
    }

    fn schedule_partitions(&mut self, schedule: &[PartitionEvent]) -> Result<(), SimulationError> {
        let mut transitions = schedule.to_vec();
        transitions.sort_by_key(|event| event.at_ms);
        for event in transitions {
            self.push(
                event.at_ms,
                0,
                ScheduledAction::Partition(event.action.clone()),
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
    partition_drops: usize,
    rejected_connections: usize,
    reordered_deliveries: usize,
    byzantine_state_messages: usize,
    node_restarts: usize,
    restart_reinsertions: usize,
    latest_message_id: Option<usize>,
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
            partition_drops: 0,
            rejected_connections: 0,
            reordered_deliveries: 0,
            byzantine_state_messages: 0,
            node_restarts: 0,
            restart_reinsertions: 0,
            latest_message_id: None,
            completed_at_ms: 0,
        }
    }
}

struct SimNode {
    clock_skew_ms: i64,
    joined: bool,
    alive: bool,
    reports: BTreeMap<(u8, usize, i128), ClientSketch>,
    present_clients: BTreeSet<(u8, usize, ClientId)>,
    historical_clients: BTreeSet<(u8, usize, ClientId)>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ScheduledEvent {
    at_ms: u64,
    priority: u8,
    sequence: u64,
    action: ScheduledAction,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ScheduledAction {
    Failure {
        node: usize,
        action: FailureAction,
    },
    Lifecycle {
        node: usize,
        action: LifecycleAction,
    },
    Partition(PartitionAction),
    Vote {
        source: usize,
        node: usize,
        client: ClientId,
        content: usize,
        view: u8,
        delayed: bool,
        replayed: bool,
        loss_dropped: bool,
        message_id: usize,
        script_processed: bool,
        ordering_counted: bool,
    },
}

struct EquivocationContext {
    node_ids: Vec<NodeId>,
    members: Vec<AuthorityMember>,
    keys: Vec<AuthorityKeypair>,
}

impl EquivocationContext {
    fn new(node_ids: &[NodeId]) -> Result<Self, SimulationError> {
        let keys: Vec<_> = node_ids
            .iter()
            .map(|node| AuthorityKeypair::from_secret_key(node.to_bytes()))
            .collect();
        let members = node_ids
            .iter()
            .copied()
            .zip(&keys)
            .map(|(node, key)| {
                AuthorityMember::new(node, key.public_key())
                    .map_err(|_| SimulationError::AuthorityScenario)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            node_ids: node_ids.to_vec(),
            members,
            keys,
        })
    }

    fn emit_conflicting_states(&self, signer_node: usize) -> Result<usize, SimulationError> {
        let routing_key = RoutingKey::from_bytes(self.node_ids[signer_node].to_bytes());
        let selected = select_authorities(&routing_key, &self.members)
            .map_err(|_| SimulationError::AuthorityScenario)?;
        if selected.len() < 4 {
            return Err(SimulationError::InvalidByzantineScript);
        }
        let membership = MembershipView::new(routing_key, 1, selected.clone())
            .map_err(|_| SimulationError::AuthorityScenario)?;
        let signer_id = self.keys[signer_node].authority_id();
        if membership.member(signer_id).is_none() {
            return Err(SimulationError::InvalidByzantineScript);
        }
        let state = AuthorityState::new(routing_key, Epoch::new(1), membership.clone(), 1);
        let conflict = state
            .clone()
            .with_components(
                populus_cluster::AuthorityMode::Direct,
                AuthorityComponents {
                    rate_state: vec![1],
                    ..AuthorityComponents::default()
                },
            )
            .map_err(|_| SimulationError::AuthorityScenario)?;
        let first = SignedAuthorityState::sign(state.clone(), &self.keys[signer_node])
            .map_err(|_| SimulationError::AuthorityScenario)?;
        let second = SignedAuthorityState::sign(conflict, &self.keys[signer_node])
            .map_err(|_| SimulationError::AuthorityScenario)?;
        EquivocationProof::new(first.clone(), second.clone())
            .map_err(|_| SimulationError::AuthorityScenario)?
            .verify()
            .map_err(|_| SimulationError::AuthorityScenario)?;

        let mut expected = Vec::with_capacity(3);
        let mut responses = vec![first, second];
        for member in selected.iter().take(3) {
            expected.push(member.authority_id());
            if member.authority_id() == signer_id {
                continue;
            }
            let key = self
                .keys
                .iter()
                .find(|key| key.authority_id() == member.authority_id())
                .ok_or(SimulationError::AuthorityScenario)?;
            responses.push(
                SignedAuthorityState::sign(state.clone(), key)
                    .map_err(|_| SimulationError::AuthorityScenario)?,
            );
        }
        let resolution = resolve_authority_state(&membership, &expected, &responses)
            .map_err(|_| SimulationError::AuthorityScenario)?;
        match resolution {
            StateResolution::Quorum(quorum) if quorum.state() == &state => Ok(2),
            _ => Err(SimulationError::AuthorityScenario),
        }
    }
}
