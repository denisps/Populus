//! Seeded, virtual-time scenarios for the implemented Populus protocol layers.
//!
//! The workload assigns each client one content and sends that vote through
//! three seeded, distinct destinations when the node count permits. This is a
//! simulator workload, not the protocol's delegated-ingest assignment algorithm.
//! Authority-cluster and ingest-buffer state machines can be exercised here once
//! those pure protocol APIs are implemented.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::error::Error;
use std::fmt;

use populus_content::{ContentBody, ContentError, SignedContent};
use populus_crypto::{RoutingIdentifier, routing_key};
use populus_routing::{BUCKET_CAPACITY, InsertError, RoutingTable, closest_nodes_brute_force};
use populus_sketch::ClientSketch;
use populus_types::{ClientId, ContentId, NodeId, RoutingKey};

/// Number of independently sampled workload destinations per client.
pub const VIEW_COUNT: usize = 3;
/// Maximum number of queued simulation events, including failures and reschedules.
pub const MAX_SIMULATION_MESSAGES: usize = 1_000_000;
/// Maximum number of simulated nodes.
pub const MAX_SIMULATION_NODES: usize = 100_000;
/// Maximum number of simulated clients.
pub const MAX_SIMULATION_CLIENTS: usize = 1_000_000;
/// Maximum number of generated contents.
pub const MAX_SIMULATION_CONTENTS: usize = 100_000;

const REPORT_WINDOW_MS: i128 = 60_000;

/// Inclusive latency range sampled independently for each vote message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LatencyDistribution {
    /// Deliver every message after the same number of virtual milliseconds.
    Fixed(u64),
    /// Sample uniformly from the inclusive range.
    Uniform {
        /// Inclusive lower bound in milliseconds.
        min_ms: u64,
        /// Inclusive upper bound in milliseconds.
        max_ms: u64,
    },
}

impl LatencyDistribution {
    fn sample(self, random: &mut SeededRandom) -> u64 {
        match self {
            Self::Fixed(value) => value,
            Self::Uniform { min_ms, max_ms } => {
                if min_ms == 0 && max_ms == u64::MAX {
                    return random.next_u64();
                }
                min_ms + random.sample_below(max_ms - min_ms + 1)
            }
        }
    }

    fn is_valid(self) -> bool {
        match self {
            Self::Fixed(_) => true,
            Self::Uniform { min_ms, max_ms } => min_ms <= max_ms,
        }
    }
}

/// Inclusive signed clock-offset range sampled independently for each node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClockSkewDistribution {
    /// Apply the same signed offset to every node.
    Fixed(i64),
    /// Sample uniformly from the inclusive range.
    Uniform {
        /// Inclusive lower signed offset in milliseconds.
        min_ms: i64,
        /// Inclusive upper signed offset in milliseconds.
        max_ms: i64,
    },
}

impl ClockSkewDistribution {
    fn sample(self, random: &mut SeededRandom) -> i64 {
        match self {
            Self::Fixed(value) => value,
            Self::Uniform { min_ms, max_ms } => {
                let min_ordered = ordered_i64(min_ms);
                let max_ordered = ordered_i64(max_ms);
                if min_ordered == 0 && max_ordered == u64::MAX {
                    return from_ordered_i64(random.next_u64());
                }
                let width = max_ordered - min_ordered + 1;
                from_ordered_i64(min_ordered + random.sample_below(width))
            }
        }
    }

    fn is_valid(self) -> bool {
        match self {
            Self::Fixed(_) => true,
            Self::Uniform { min_ms, max_ms } => min_ms <= max_ms,
        }
    }
}

/// A node's scheduled availability transition at a virtual timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FailureEvent {
    /// Virtual time in milliseconds.
    pub at_ms: u64,
    /// Index into [`SimulationConfig::node_count`]'s generated node list.
    pub node: usize,
    /// The node transition to apply.
    pub action: FailureAction,
}

/// Availability transition used by a [`FailureEvent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FailureAction {
    /// Stop accepting messages until a later recovery event.
    Crash,
    /// Resume accepting messages.
    Recover,
}

/// Behavior applied to messages addressed to configured malicious nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaliciousStrategy {
    /// Do not alter messages.
    None,
    /// Drop every message addressed to a malicious node.
    DropMessages,
    /// Deliver each message twice; the sketch must remain duplicate-safe.
    DuplicateMessages,
    /// Delay each message once by this many virtual milliseconds.
    DelayMessages {
        /// Additional delay in virtual milliseconds.
        extra_delay_ms: u64,
    },
    /// Replay each delivered message once after this many virtual milliseconds.
    ReplayMessages {
        /// Virtual time between the original delivery and its replay.
        replay_after_ms: u64,
    },
}

/// Inputs for one reproducible distributed workload.
#[derive(Clone, Debug)]
pub struct SimulationConfig {
    /// Seed for all generated identities, message destinations, and samples.
    pub seed: u64,
    /// Number of virtual nodes.
    pub node_count: usize,
    /// Number of virtual clients.
    pub client_count: usize,
    /// Number of generated immutable contents.
    pub content_count: usize,
    /// Per-message virtual network latency.
    pub latency: LatencyDistribution,
    /// Per-node virtual clock offset.
    pub clock_skew: ClockSkewDistribution,
    /// Ordered logically by `(at_ms, node, action)` before execution.
    pub failure_schedule: Vec<FailureEvent>,
    /// Node indices that apply [`malicious_strategy`](Self::malicious_strategy).
    pub malicious_nodes: Vec<usize>,
    /// Message behavior for the configured malicious nodes.
    pub malicious_strategy: MaliciousStrategy,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            node_count: 8,
            client_count: 32,
            content_count: 1,
            latency: LatencyDistribution::Uniform {
                min_ms: 0,
                max_ms: 20,
            },
            clock_skew: ClockSkewDistribution::Uniform {
                min_ms: -50,
                max_ms: 50,
            },
            failure_schedule: Vec::new(),
            malicious_nodes: Vec::new(),
            malicious_strategy: MaliciousStrategy::None,
        }
    }
}

/// Error returned when a simulation configuration or generated workload is invalid.
#[derive(Debug)]
pub enum SimulationError {
    /// At least one node is required.
    NoNodes,
    /// A configured simulation count exceeds its documented bound.
    CountLimitExceeded(&'static str),
    /// A uniform distribution has its minimum greater than its maximum.
    InvalidDistribution,
    /// A failure or malicious-node index is outside the generated node list.
    NodeIndexOutOfRange(usize),
    /// A node has more than one availability transition at the same timestamp.
    ConflictingFailureEvents {
        /// Node index with conflicting events.
        node: usize,
        /// Virtual timestamp of the conflicting events.
        at_ms: u64,
    },
    /// Virtual time or event ordering overflowed its integer representation.
    TimeOrSequenceOverflow,
    /// The routing implementation disagreed with its brute-force oracle.
    RoutingInvariant,
    /// The generated content failed canonical validation.
    Content(ContentError),
    /// A randomized run failed; rerun the same configuration with this seed.
    Scenario {
        /// Seed for reproducing the failing run.
        seed: u64,
        /// Underlying scenario error.
        source: Box<SimulationError>,
    },
}

impl fmt::Display for SimulationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoNodes => formatter.write_str("a simulation requires at least one node"),
            Self::CountLimitExceeded(name) => {
                write!(formatter, "simulation {name} exceeds its configured limit")
            }
            Self::InvalidDistribution => {
                formatter.write_str("a uniform distribution has min greater than max")
            }
            Self::NodeIndexOutOfRange(index) => {
                write!(formatter, "node index {index} is outside the simulation")
            }
            Self::ConflictingFailureEvents { node, at_ms } => write!(
                formatter,
                "node {node} has conflicting failure events at virtual time {at_ms}"
            ),
            Self::TimeOrSequenceOverflow => {
                formatter.write_str("virtual time or event sequence overflowed")
            }
            Self::RoutingInvariant => {
                formatter.write_str("routing lookup disagreed with the brute-force oracle")
            }
            Self::Content(error) => write!(formatter, "generated content is invalid: {error}"),
            Self::Scenario { seed, source } => {
                write!(formatter, "simulation failed (seed {seed}): {source}")
            }
        }
    }
}

impl Error for SimulationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Content(error) => Some(error),
            Self::Scenario { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ContentError> for SimulationError {
    fn from(error: ContentError) -> Self {
        Self::Content(error)
    }
}

/// Reproducible summary of a completed simulation.
#[derive(Clone, PartialEq)]
pub struct SimulationReport {
    /// Seed used to reproduce this report with the same simulation configuration.
    pub seed: u64,
    /// Input population sizes.
    pub node_count: usize,
    /// Input client count.
    pub client_count: usize,
    /// Input content count.
    pub content_count: usize,
    /// Number of initially scheduled vote messages.
    pub sent_messages: usize,
    /// Number of vote insertions, including duplicate deliveries and replays.
    pub delivered_messages: usize,
    /// Number of messages dropped by an offline or malicious destination.
    pub dropped_messages: usize,
    /// Number of messages delayed by malicious behavior.
    pub delayed_messages: usize,
    /// Number of extra deliveries caused by duplication or replay.
    pub duplicate_deliveries: usize,
    /// Number of explicit replay events scheduled.
    pub replayed_messages: usize,
    /// Timestamp of the final processed event.
    pub completed_at_ms: u64,
    /// Generated content and its closest known bootstrap contact.
    pub contents: Vec<ContentSummary>,
    /// Per-view, per-content sketch estimates and report-window coverage.
    pub view_content: Vec<ViewContentSummary>,
}

impl fmt::Debug for SimulationReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SimulationReport")
            .field("seed", &self.seed)
            .field("node_count", &self.node_count)
            .field("client_count", &self.client_count)
            .field("content_count", &self.content_count)
            .field("sent_messages", &self.sent_messages)
            .field("delivered_messages", &self.delivered_messages)
            .field("dropped_messages", &self.dropped_messages)
            .field("delayed_messages", &self.delayed_messages)
            .field("duplicate_deliveries", &self.duplicate_deliveries)
            .field("replayed_messages", &self.replayed_messages)
            .field("completed_at_ms", &self.completed_at_ms)
            .field("contents_count", &self.contents.len())
            .field("view_content_count", &self.view_content.len())
            .finish()
    }
}

/// Content generated and validated by the content and routing implementations.
#[derive(Clone, PartialEq, Eq)]
pub struct ContentSummary {
    /// Canonical immutable content identifier.
    pub content_id: ContentId,
    /// Closest contact known to the bootstrap routing table, if any.
    pub closest_known_node: Option<NodeId>,
}

impl fmt::Debug for ContentSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContentSummary")
            .field("content_id", &self.content_id.to_string())
            .field(
                "closest_known_node",
                &self.closest_known_node.map(|node| node.to_string()),
            )
            .finish()
    }
}

/// Aggregated ingest workload observed for one view and content.
#[derive(Clone, PartialEq)]
pub struct ViewContentSummary {
    /// Zero-based shuffled workload view.
    pub view: usize,
    /// Content identifier receiving this view's client votes.
    pub content_id: ContentId,
    /// Number of clients assigned this content by the workload generator.
    pub expected_clients: usize,
    /// Distinct-client estimate after merging all node/window sketches.
    pub distinct_client_estimate: f64,
    /// Accepted deliveries, including repeats.
    pub accepted_deliveries: usize,
    /// Distinct local-clock report windows represented in the merged sketch.
    pub report_windows: usize,
}

impl fmt::Debug for ViewContentSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ViewContentSummary")
            .field("view", &self.view)
            .field("content_id", &self.content_id.to_string())
            .field("expected_clients", &self.expected_clients)
            .field("distinct_client_estimate", &self.distinct_client_estimate)
            .field("accepted_deliveries", &self.accepted_deliveries)
            .field("report_windows", &self.report_windows)
            .finish()
    }
}

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
    validate_config(config)?;
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
    let expected_by_content = events.schedule_votes(config, client_ids, &mut random)?;
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

fn generate_contents(
    config: &SimulationConfig,
    node_ids: &[NodeId],
) -> Result<Vec<ContentSummary>, SimulationError> {
    let mut bootstrap_table = RoutingTable::new(node_ids[0]);
    let local_key = RoutingKey::from_bytes(node_ids[0].to_bytes());
    let bootstrap_contacts = closest_nodes_brute_force(&local_key, &node_ids[1..], BUCKET_CAPACITY);
    for node in bootstrap_contacts {
        match bootstrap_table.insert(node) {
            Ok(()) | Err(InsertError::BucketFull) => {}
            Err(InsertError::LocalNode | InsertError::Duplicate) => {
                return Err(SimulationError::RoutingInvariant);
            }
        }
    }
    let known_contacts: Vec<_> = bootstrap_table.known_nodes().copied().collect();
    let mut contents = Vec::with_capacity(config.content_count);
    for index in 0..config.content_count {
        let body = ContentBody::new(
            u64::try_from(index)
                .map_err(|_| SimulationError::CountLimitExceeded("content count"))?,
            "application/octet-stream",
            content_payload(config.seed, index)?,
        );
        let content = SignedContent::new(body, Vec::new())?;
        let encoded = content.canonical_bytes()?;
        let decoded = SignedContent::from_bytes(&encoded)?;
        let content_id = decoded.cid()?;
        let key = routing_key(RoutingIdentifier::Content(&content_id));
        let nearest = bootstrap_table.closest_nodes(&key, 1);
        if nearest != closest_nodes_brute_force(&key, &known_contacts, 1) {
            return Err(SimulationError::RoutingInvariant);
        }
        contents.push(ContentSummary {
            content_id,
            closest_known_node: nearest.first().copied(),
        });
    }
    Ok(contents)
}

fn summarize_views(
    nodes: &[SimNode],
    contents: &[ContentSummary],
    expected_by_content: &[usize],
    metrics: &EventMetrics,
) -> Vec<ViewContentSummary> {
    let mut view_content = Vec::with_capacity(VIEW_COUNT.saturating_mul(contents.len()));
    for (view, view_counts) in metrics.accepted_by_view_content.iter().enumerate() {
        for (content_index, content) in contents.iter().enumerate() {
            let mut merged = ClientSketch::new();
            let mut report_windows = BTreeSet::new();
            for node in nodes {
                for (&(node_view, node_content, window), sketch) in &node.reports {
                    if usize::from(node_view) == view && node_content == content_index {
                        merged.merge(sketch);
                        report_windows.insert(window);
                    }
                }
            }
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

fn validate_config(config: &SimulationConfig) -> Result<(), SimulationError> {
    if config.node_count == 0 {
        return Err(SimulationError::NoNodes);
    }
    if config.node_count > MAX_SIMULATION_NODES {
        return Err(SimulationError::CountLimitExceeded("node count"));
    }
    if config.client_count > MAX_SIMULATION_CLIENTS {
        return Err(SimulationError::CountLimitExceeded("client count"));
    }
    if config.content_count > MAX_SIMULATION_CONTENTS {
        return Err(SimulationError::CountLimitExceeded("content count"));
    }
    if !config.latency.is_valid() || !config.clock_skew.is_valid() {
        return Err(SimulationError::InvalidDistribution);
    }
    if config
        .client_count
        .checked_mul(VIEW_COUNT)
        .is_none_or(|count| count > MAX_SIMULATION_MESSAGES)
        && config.content_count != 0
    {
        return Err(SimulationError::CountLimitExceeded("message count"));
    }
    for &node in config
        .malicious_nodes
        .iter()
        .chain(config.failure_schedule.iter().map(|event| &event.node))
    {
        if node >= config.node_count {
            return Err(SimulationError::NodeIndexOutOfRange(node));
        }
    }
    let mut transitions = BTreeSet::new();
    for event in &config.failure_schedule {
        if !transitions.insert((event.node, event.at_ms)) {
            return Err(SimulationError::ConflictingFailureEvents {
                node: event.node,
                at_ms: event.at_ms,
            });
        }
    }
    if config.failure_schedule.len() > MAX_SIMULATION_MESSAGES {
        return Err(SimulationError::CountLimitExceeded("failure schedule"));
    }
    Ok(())
}

fn generate_node_ids(
    count: usize,
    random: &mut SeededRandom,
) -> Result<Vec<NodeId>, SimulationError> {
    (0..count)
        .map(|index| {
            let index = u64::try_from(index)
                .map_err(|_| SimulationError::CountLimitExceeded("node count"))?;
            Ok(NodeId::from_bytes(random_identifier(random, index)))
        })
        .collect()
}

fn generate_client_ids(
    count: usize,
    random: &mut SeededRandom,
) -> Result<Vec<ClientId>, SimulationError> {
    (0..count)
        .map(|index| {
            let index = u64::try_from(index)
                .map_err(|_| SimulationError::CountLimitExceeded("client count"))?;
            Ok(ClientId::from_bytes(random_identifier(random, index)))
        })
        .collect()
}

fn random_identifier(random: &mut SeededRandom, index: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    for chunk in bytes[..24].as_chunks_mut::<8>().0 {
        chunk.copy_from_slice(&random.next_u64().to_be_bytes());
    }
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn content_payload(seed: u64, index: usize) -> Result<Vec<u8>, SimulationError> {
    let index =
        u64::try_from(index).map_err(|_| SimulationError::CountLimitExceeded("content count"))?;
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&seed.to_be_bytes());
    payload.extend_from_slice(&index.to_be_bytes());
    Ok(payload)
}

fn choose_destinations(
    node_count: usize,
    random: &mut SeededRandom,
) -> Result<Vec<usize>, SimulationError> {
    let destination_count = node_count.min(VIEW_COUNT);
    let mut destinations = Vec::with_capacity(VIEW_COUNT);
    for _ in 0..destination_count {
        let mut candidate = random.index(node_count)?;
        while destinations.contains(&candidate) {
            candidate = (candidate + 1) % node_count;
        }
        destinations.push(candidate);
    }
    while destinations.len() < VIEW_COUNT {
        destinations.push(destinations[destinations.len() % destination_count]);
    }
    Ok(destinations)
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

    fn schedule_votes(
        &mut self,
        config: &SimulationConfig,
        clients: Vec<ClientId>,
        random: &mut SeededRandom,
    ) -> Result<Vec<usize>, SimulationError> {
        let mut expected_by_content = vec![0_usize; config.content_count];
        for (client_index, client_id) in clients.into_iter().enumerate() {
            let content_index = client_index % config.content_count;
            expected_by_content[content_index] += 1;
            let destinations = choose_destinations(config.node_count, random)?;
            for (view, node) in destinations.into_iter().enumerate() {
                self.push(
                    config.latency.sample(random),
                    1,
                    ScheduledAction::Vote {
                        node,
                        client: client_id,
                        content: content_index,
                        view: u8::try_from(view)
                            .map_err(|_| SimulationError::CountLimitExceeded("view count"))?,
                        delayed: false,
                        replayed: false,
                    },
                )?;
            }
        }
        Ok(expected_by_content)
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

struct SeededRandom {
    state: u64,
}

impl SeededRandom {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn index(&mut self, length: usize) -> Result<usize, SimulationError> {
        let length =
            u64::try_from(length).map_err(|_| SimulationError::CountLimitExceeded("node count"))?;
        if length == 0 {
            return Err(SimulationError::NoNodes);
        }
        usize::try_from(self.sample_below(length))
            .map_err(|_| SimulationError::CountLimitExceeded("node count"))
    }

    fn sample_below(&mut self, bound: u64) -> u64 {
        let rejection_threshold = bound.wrapping_neg() % bound;
        loop {
            let value = self.next_u64();
            if value >= rejection_threshold {
                return value % bound;
            }
        }
    }
}

fn ordered_i64(value: i64) -> u64 {
    let mut bytes = value.to_be_bytes();
    bytes[0] ^= 0x80;
    u64::from_be_bytes(bytes)
}

fn from_ordered_i64(value: u64) -> i64 {
    let mut bytes = value.to_be_bytes();
    bytes[0] ^= 0x80;
    i64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use populus_routing::{
        BUCKET_CAPACITY, BUCKET_COUNT, InsertError, RoutingTable, closest_nodes_brute_force,
    };
    use populus_types::{NodeId, RoutingKey};

    use super::{
        ClockSkewDistribution, FailureAction, FailureEvent, LatencyDistribution, MaliciousStrategy,
        SeededRandom, SimulationConfig, SimulationError, VIEW_COUNT, random_identifier,
        run_simulation,
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
    fn crash_schedule_drops_messages_and_recovery_restores_delivery() -> Result<(), SimulationError>
    {
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
}
