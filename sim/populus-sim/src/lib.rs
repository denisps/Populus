//! Seeded, virtual-time scenarios for the implemented Populus protocol layers.
//!
//! The workload sends each synthetic client through three seeded destinations,
//! distinct when at least three simulated nodes exist. This is load generation,
//! not delegated-ingest protocol assignment; future phases integrate their pure
//! state machines here without duplicating their behavior.

#[cfg(test)]
mod authority;
mod config;
mod engine;
mod report;
mod rng;
#[cfg(test)]
mod routing;
mod workload;

pub use config::{
    ByzantineAction, ByzantineScript, ClockSkewDistribution, FailureAction, FailureEvent,
    LatencyDistribution, LifecycleAction, LifecycleEvent, MAX_SIMULATION_CLIENTS,
    MAX_SIMULATION_CONTENTS, MAX_SIMULATION_MESSAGES, MAX_SIMULATION_NODES, MaliciousStrategy,
    PACKET_LOSS_SCALE, PartitionAction, PartitionEvent, SIMULATED_PAYLOAD_BYTES, SimulationConfig,
    SimulationError, VIEW_COUNT,
};
pub use engine::run_simulation;
pub use report::{ContentSummary, SimulationReport, ViewContentSummary};

#[cfg(test)]
mod tests;
#[cfg(test)]
mod virtual_time;
