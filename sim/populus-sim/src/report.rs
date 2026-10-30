use populus_types::{ContentId, NodeId};
use std::fmt;

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
