use populus_content::ContentError;
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

/// Maximum number of queued simulation events, including failures and reschedules.
pub const MAX_SIMULATION_MESSAGES: usize = 1_000_000;
/// Maximum number of simulated nodes.
pub const MAX_SIMULATION_NODES: usize = 100_000;
/// Maximum number of simulated clients.
pub const MAX_SIMULATION_CLIENTS: usize = 1_000_000;
/// Maximum number of generated contents.
pub const MAX_SIMULATION_CONTENTS: usize = 100_000;
/// Number of independently sampled workload destinations per client.
pub const VIEW_COUNT: usize = 3;
/// Fixed vote payload used to model bounded-bandwidth transmission.
pub const SIMULATED_PAYLOAD_BYTES: u64 = 128;
/// Packet-loss probability scale; `1_000_000` means certain loss.
pub const PACKET_LOSS_SCALE: u32 = 1_000_000;

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
    fn is_valid(self) -> bool {
        match self {
            Self::Fixed(_) => true,
            Self::Uniform { min_ms, max_ms } => min_ms <= max_ms,
        }
    }
}

/// A node's scheduled join, leave, or clean restart transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LifecycleEvent {
    /// Virtual time in milliseconds.
    pub at_ms: u64,
    /// Index into [`SimulationConfig::node_count`]'s generated node list.
    pub node: usize,
    /// The lifecycle transition to apply.
    pub action: LifecycleAction,
}

/// Lifecycle transition used by a [`LifecycleEvent`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LifecycleAction {
    /// Add a previously absent node to the simulation.
    Join,
    /// Remove a node without clearing its local state.
    Leave,
    /// Clear local sketch state and resume the node.
    Restart,
}

/// A scheduled network partition transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionEvent {
    /// Virtual time in milliseconds.
    pub at_ms: u64,
    /// Partition operation to apply.
    pub action: PartitionAction,
}

/// Partition state transition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PartitionAction {
    /// Assign every configured node to a network group. Messages crossing
    /// groups are dropped until a later [`Self::Heal`] event.
    Split {
        /// Group identifier for each node, indexed by node number.
        groups: Vec<usize>,
    },
    /// Restore delivery between all network groups.
    Heal,
}

/// One scripted Byzantine behavior, consumed on that node's next received vote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByzantineScript {
    /// Node that performs the one-shot behavior.
    pub node: usize,
    /// Behavior to perform on its next received vote.
    pub action: ByzantineAction,
}

/// One-shot behavior applied by a configured Byzantine node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByzantineAction {
    /// Drop the next received vote.
    DropNext,
    /// Deliver the next received vote twice.
    DuplicateNext,
    /// Add a deterministic virtual delay to the next received vote.
    DelayNext {
        /// Additional delay in virtual milliseconds.
        extra_delay_ms: u64,
    },
    /// Emit conflicting signed authority snapshots; the quorum resolver
    /// must reject the duplicate signer and retain the supported state.
    SendConflictingAuthorityStates,
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
    /// Nodes initially present. `None` preserves the legacy behavior where
    /// every node is present; an explicit list starts all other nodes absent.
    pub initially_joined_nodes: Option<Vec<usize>>,
    /// Scheduled join, leave, and clean-restart transitions.
    pub lifecycle_schedule: Vec<LifecycleEvent>,
    /// Scheduled partition and heal transitions. Cross-group messages are
    /// dropped and included in `SimulationReport::partition_drops`.
    pub partition_schedule: Vec<PartitionEvent>,
    /// Additional seeded latency, sampled only when configured.
    pub jitter: Option<LatencyDistribution>,
    /// Packet-loss probability in millionths; zero disables sampling.
    pub packet_loss_probability: u32,
    /// Additional seeded delay used to reorder deliveries when configured.
    pub reordering: Option<LatencyDistribution>,
    /// Maximum concurrent peer connections per node; `None` is unlimited.
    pub connection_limit: Option<usize>,
    /// Per-node egress bandwidth in bytes per second. Messages from one source
    /// occupy that link serially. `None` is unlimited and does not consume RNG.
    pub bandwidth_bytes_per_second: Option<u64>,
    /// One-shot scripted behaviors for Byzantine nodes.
    pub byzantine_scripts: Vec<ByzantineScript>,
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
            initially_joined_nodes: None,
            lifecycle_schedule: Vec::new(),
            partition_schedule: Vec::new(),
            jitter: None,
            packet_loss_probability: 0,
            reordering: None,
            connection_limit: None,
            bandwidth_bytes_per_second: None,
            byzantine_scripts: Vec::new(),
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
    /// A partition transition has the wrong number of group assignments.
    InvalidPartition,
    /// A connection limit or bandwidth limit is zero.
    InvalidResourceLimit,
    /// A packet-loss probability exceeds its millionths scale.
    InvalidProbability,
    /// A state-equivocation script cannot use a valid four-member authority view.
    InvalidByzantineScript,
    /// A public authority-cluster API rejected a simulator-generated state.
    AuthorityScenario,
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
            Self::InvalidPartition => {
                formatter.write_str("a partition must assign every simulated node")
            }
            Self::InvalidResourceLimit => {
                formatter.write_str("connection and bandwidth limits must be nonzero")
            }
            Self::InvalidProbability => {
                formatter.write_str("packet-loss probability exceeds its millionths scale")
            }
            Self::InvalidByzantineScript => {
                formatter.write_str("a Byzantine script cannot be applied to this authority view")
            }
            Self::AuthorityScenario => {
                formatter.write_str("the authority API rejected a simulated signed state")
            }
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

pub(super) fn validate_config(config: &SimulationConfig) -> Result<(), SimulationError> {
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
    if !config.latency.is_valid()
        || !config.clock_skew.is_valid()
        || config.jitter.is_some_and(|jitter| !jitter.is_valid())
        || config.reordering.is_some_and(|delay| !delay.is_valid())
    {
        return Err(SimulationError::InvalidDistribution);
    }
    if config.packet_loss_probability > PACKET_LOSS_SCALE {
        return Err(SimulationError::InvalidProbability);
    }
    if config.connection_limit == Some(0) || config.bandwidth_bytes_per_second == Some(0) {
        return Err(SimulationError::InvalidResourceLimit);
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
        .chain(config.lifecycle_schedule.iter().map(|event| &event.node))
        .chain(config.byzantine_scripts.iter().map(|script| &script.node))
        .chain(config.initially_joined_nodes.iter().flatten())
    {
        if node >= config.node_count {
            return Err(SimulationError::NodeIndexOutOfRange(node));
        }
    }
    if config.node_count < 4
        && config.byzantine_scripts.iter().any(|script| {
            matches!(
                script.action,
                ByzantineAction::SendConflictingAuthorityStates
            )
        })
    {
        return Err(SimulationError::InvalidByzantineScript);
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
    let mut lifecycle_events = BTreeSet::new();
    for event in &config.lifecycle_schedule {
        if !lifecycle_events.insert((event.node, event.at_ms)) {
            return Err(SimulationError::ConflictingFailureEvents {
                node: event.node,
                at_ms: event.at_ms,
            });
        }
    }
    for event in &config.partition_schedule {
        if let PartitionAction::Split { groups } = &event.action
            && groups.len() != config.node_count
        {
            return Err(SimulationError::InvalidPartition);
        }
    }
    if config.lifecycle_schedule.len() > MAX_SIMULATION_MESSAGES
        || config.partition_schedule.len() > MAX_SIMULATION_MESSAGES
        || config.byzantine_scripts.len() > MAX_SIMULATION_MESSAGES
        || config.initially_joined_nodes.as_ref().is_some_and(|nodes| {
            nodes.iter().copied().collect::<BTreeSet<_>>().len() != nodes.len()
        })
    {
        return Err(SimulationError::CountLimitExceeded("simulation schedule"));
    }
    Ok(())
}
