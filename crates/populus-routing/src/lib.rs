//! Populus XOR-distance routing over scarce-network-derived [`NodeId`] values.

use std::collections::BinaryHeap;

use populus_types::{NodeId, RoutingKey, XorDistance};

/// Number of distance buckets in a 256-bit routing table.
pub const BUCKET_COUNT: usize = 256;

/// Maximum number of nodes retained in each distance bucket.
pub const BUCKET_CAPACITY: usize = 20;

/// Error returned when a node cannot be added to a routing table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertError {
    /// The local node cannot be stored as a remote contact.
    LocalNode,
    /// The node is already present in the routing table.
    Duplicate,
    /// The node's distance bucket already contains [`BUCKET_CAPACITY`] contacts.
    BucketFull,
}

/// Kademlia-style table of known Populus node positions.
///
/// Contacts are grouped by the most-significant differing bit from the local
/// [`NodeId`]. A full bucket rejects new contacts instead of evicting an
/// existing node without connection-liveness information.
#[derive(Clone)]
pub struct RoutingTable {
    local_node: NodeId,
    buckets: [Vec<NodeId>; BUCKET_COUNT],
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Candidate {
    distance: XorDistance,
    node: NodeId,
}

impl RoutingTable {
    /// Creates an empty routing table for `local_node`.
    #[must_use]
    pub fn new(local_node: NodeId) -> Self {
        Self {
            local_node,
            buckets: std::array::from_fn(|_| Vec::new()),
        }
    }

    /// Returns the local node position.
    #[must_use]
    pub const fn local_node(&self) -> NodeId {
        self.local_node
    }

    /// Adds a node to its distance bucket.
    ///
    /// Duplicate contacts, the local node, and contacts that exceed the bucket
    /// capacity are rejected without changing the table.
    ///
    /// # Errors
    ///
    /// Returns [`InsertError::LocalNode`], [`InsertError::Duplicate`], or
    /// [`InsertError::BucketFull`] when the contact cannot be stored.
    pub fn insert(&mut self, node: NodeId) -> Result<(), InsertError> {
        if node == self.local_node {
            return Err(InsertError::LocalNode);
        }

        let index = bucket_index(&self.local_node, &node);
        let bucket = &mut self.buckets[index];
        if bucket.contains(&node) {
            return Err(InsertError::Duplicate);
        }
        if bucket.len() == BUCKET_CAPACITY {
            return Err(InsertError::BucketFull);
        }

        bucket.push(node);
        Ok(())
    }

    /// Removes a known node, returning whether it was present.
    pub fn remove(&mut self, node: &NodeId) -> bool {
        if node == &self.local_node {
            return false;
        }
        let index = bucket_index(&self.local_node, node);
        let bucket = &mut self.buckets[index];
        if let Some(position) = bucket.iter().position(|candidate| candidate == node) {
            bucket.swap_remove(position);
            true
        } else {
            false
        }
    }

    /// Returns whether `node` is present in the table.
    #[must_use]
    pub fn contains(&self, node: &NodeId) -> bool {
        if node == &self.local_node {
            return false;
        }
        self.buckets[bucket_index(&self.local_node, node)].contains(node)
    }

    /// Returns the number of remote contacts currently retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(Vec::len).sum()
    }

    /// Returns whether the table contains no remote contacts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(Vec::is_empty)
    }

    /// Iterates over the retained node positions.
    pub fn known_nodes(&self) -> impl Iterator<Item = &NodeId> {
        self.buckets.iter().flat_map(|bucket| bucket.iter())
    }

    /// Returns the contact count in each of the 256 distance buckets.
    pub fn bucket_sizes(&self) -> impl Iterator<Item = usize> + '_ {
        self.buckets.iter().map(Vec::len)
    }

    /// Returns the closest retained nodes to `target`, ordered by XOR distance.
    ///
    /// The bounded max-heap selects the nearest `limit` nodes across the
    /// bucketed contact set. This returns the closest known contacts; it does
    /// not claim to know nodes absent from this routing table.
    #[must_use]
    pub fn closest_nodes(&self, target: &RoutingKey, limit: usize) -> Vec<NodeId> {
        if limit == 0 {
            return Vec::new();
        }

        let mut nearest = BinaryHeap::with_capacity(limit.min(self.len()));
        for node in self.known_nodes().copied() {
            let candidate = Candidate {
                distance: XorDistance::between_node_and_key(&node, target),
                node,
            };
            if nearest.len() < limit {
                nearest.push(candidate);
            } else if nearest.peek().is_some_and(|farthest| candidate < *farthest) {
                nearest.pop();
                nearest.push(candidate);
            }
        }

        nearest
            .into_sorted_vec()
            .into_iter()
            .map(|candidate| candidate.node)
            .collect()
    }
}

/// Returns the most-significant differing-bit bucket for two distinct nodes.
fn bucket_index(local_node: &NodeId, node: &NodeId) -> usize {
    let leading_zero_bits = XorDistance::between_nodes(local_node, node).leading_zero_bits();
    BUCKET_COUNT - 1 - usize::from(leading_zero_bits)
}

/// Brute-force nearest-node reference implementation.
///
/// This deliberately sorts every supplied node and serves as the correctness
/// oracle for [`RoutingTable::closest_nodes`].
#[must_use]
pub fn closest_nodes_brute_force(
    target: &RoutingKey,
    nodes: &[NodeId],
    limit: usize,
) -> Vec<NodeId> {
    let mut candidates: Vec<_> = nodes
        .iter()
        .copied()
        .map(|node| Candidate {
            distance: XorDistance::between_node_and_key(&node, target),
            node,
        })
        .collect();
    candidates.sort_unstable();
    candidates
        .into_iter()
        .take(limit)
        .map(|candidate| candidate.node)
        .collect()
}

#[cfg(test)]
mod tests;
