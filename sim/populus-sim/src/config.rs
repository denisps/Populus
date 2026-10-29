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
