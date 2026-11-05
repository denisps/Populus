//! Experimental delegated-ingest assignment candidates.

use populus_types::{ClientId, NodeId};
use sha2::{Digest, Sha256};
use std::fmt;

/// Number of independent client assignment views.
pub const INGEST_VIEW_COUNT: u8 = 3;
const INGEST_VIEW_COUNT_USIZE: usize = INGEST_VIEW_COUNT as usize;
/// Maximum number of leading identifier bits considered by `MatchBits`.
pub const MATCH_BITS_MAX: u16 = 256;
const HASH_DOMAIN: &[u8] = b"populus/ingest-assignment/v1";

/// A node eligible to receive delegated ingest traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IngestNode(NodeId);

impl IngestNode {
    /// Marks a Populus node as an eligible ingest destination.
    #[must_use]
    pub const fn new(node_id: NodeId) -> Self {
        Self(node_id)
    }

    /// Returns the Populus node identity for this ingest destination.
    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.0
    }
}

/// Assignment candidate selected by a delegation descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AssignmentAlgorithm {
    /// Hash the client and view, then select an index in canonical candidate order.
    SaltedClientHash,
    /// Select using a separate 64-bit range of the `ClientId` for each view.
    DisjointClientRanges,
    /// Select the candidate nearest to the view-salted client hash in XOR space.
    XorNearest,
    /// Prefer candidates sharing a configured hash prefix, with sparse fallback.
    MatchBits,
}

/// Immutable assignment inputs published as part of a delegation descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationDescriptor {
    algorithm: AssignmentAlgorithm,
    candidates: Vec<IngestNode>,
    match_bits: u16,
}

impl DelegationDescriptor {
    /// Creates a descriptor with a canonical, unique candidate set.
    ///
    /// Candidates are sorted by `NodeId` so assignment does not depend on the
    /// order in which authorities discovered them.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty candidate set, duplicate `NodeId`s, or an
    /// invalid `MatchBits` width.
    pub fn new(
        algorithm: AssignmentAlgorithm,
        mut candidates: Vec<IngestNode>,
        match_bits: u16,
    ) -> Result<Self, AssignmentError> {
        if candidates.is_empty() {
            return Err(AssignmentError::NoCandidates);
        }
        if match_bits > MATCH_BITS_MAX {
            return Err(AssignmentError::InvalidMatchBits(match_bits));
        }
        candidates.sort_unstable();
        if candidates.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(AssignmentError::DuplicateCandidate);
        }
        Ok(Self {
            algorithm,
            candidates,
            match_bits,
        })
    }

    /// Returns the assignment candidate encoded in this descriptor.
    #[must_use]
    pub const fn algorithm(&self) -> AssignmentAlgorithm {
        self.algorithm
    }

    /// Returns the canonical candidate set.
    #[must_use]
    pub fn candidates(&self) -> &[IngestNode] {
        &self.candidates
    }

    /// Returns the `MatchBits` prefix width (ignored by other candidates).
    #[must_use]
    pub const fn match_bits(&self) -> u16 {
        self.match_bits
    }

    /// Assigns one client to one candidate using the encoded algorithm.
    ///
    /// # Errors
    ///
    /// Returns [`AssignmentError::InvalidView`] for views outside `0..3`.
    pub fn assign(&self, client_id: ClientId, view: u8) -> Result<IngestNode, AssignmentError> {
        self.algorithm.assign(client_id, view, self)
    }

    /// Assigns one destination per view, avoiding repeats while the pool permits.
    ///
    /// A collision is resolved by scanning the canonical candidate list from
    /// the collided candidate, so the result remains deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`AssignmentError::InvalidView`] if an algorithm rejects one
    /// of the three defined views.
    pub fn assign_views(
        &self,
        client_id: ClientId,
    ) -> Result<[IngestNode; INGEST_VIEW_COUNT_USIZE], AssignmentError> {
        let mut destinations = [self.candidates[0]; INGEST_VIEW_COUNT_USIZE];
        for view_index in 0..destinations.len() {
            let (assigned, remaining) = destinations.split_at_mut(view_index);
            let destination = &mut remaining[0];
            let view =
                u8::try_from(view_index).map_err(|_| AssignmentError::InvalidView(u8::MAX))?;
            let preferred = self.assign(client_id, view)?;
            let preferred_index = self
                .candidates
                .binary_search(&preferred)
                .map_err(|_| AssignmentError::NoCandidates)?;
            let candidate_count = self.candidates.len();
            *destination = (0..candidate_count)
                .map(|offset| self.candidates[(preferred_index + offset) % candidate_count])
                .find(|candidate| !assigned.contains(candidate))
                .unwrap_or(preferred);
        }
        Ok(destinations)
    }
}

/// Assignment interface kept open while candidates are compared in simulation.
pub trait IngestAssignment {
    /// Assigns one client and view to exactly one candidate from the descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`AssignmentError::InvalidView`] for views outside `0..3`.
    fn assign(
        &self,
        client_id: ClientId,
        view: u8,
        descriptor: &DelegationDescriptor,
    ) -> Result<IngestNode, AssignmentError>;
}

impl IngestAssignment for AssignmentAlgorithm {
    fn assign(
        &self,
        client_id: ClientId,
        view: u8,
        descriptor: &DelegationDescriptor,
    ) -> Result<IngestNode, AssignmentError> {
        validate_view(view)?;
        let candidates = &descriptor.candidates;
        match self {
            Self::SaltedClientHash => {
                let digest = client_view_hash(client_id, view);
                let mut index_bytes = [0; 8];
                index_bytes.copy_from_slice(&digest[..8]);
                let index = u64::from_be_bytes(index_bytes)
                    % u64::try_from(candidates.len())
                        .map_err(|_| AssignmentError::CandidateCountOverflow)?;
                let index =
                    usize::try_from(index).map_err(|_| AssignmentError::CandidateCountOverflow)?;
                Ok(candidates[index])
            }
            Self::DisjointClientRanges => {
                let start = usize::from(view) * 8;
                let mut range = [0; 8];
                range.copy_from_slice(&client_id.as_bytes()[start..start + 8]);
                let index = u64::from_be_bytes(range)
                    % u64::try_from(candidates.len())
                        .map_err(|_| AssignmentError::CandidateCountOverflow)?;
                let index =
                    usize::try_from(index).map_err(|_| AssignmentError::CandidateCountOverflow)?;
                Ok(candidates[index])
            }
            Self::XorNearest => {
                let target = client_view_hash(client_id, view);
                closest_xor(candidates, &target)
            }
            Self::MatchBits => {
                let target = client_view_hash(client_id, view);
                closest_matching(candidates, &target, descriptor.match_bits)
                    .or_else(|| closest_xor(candidates, &target).ok())
                    .ok_or(AssignmentError::NoCandidates)
            }
        }
    }
}

/// Chooses a `MatchBits` width from the observed candidate count and offered rate.
///
/// The selected width targets the smallest prefix population whose expected
/// node count can serve the offered rate at `max_votes_per_node_per_minute`.
/// It does not interpret `2^bits` as the number of available nodes.
///
/// # Errors
///
/// Returns [`AssignmentError::InvalidCapacityInput`] for zero candidates or
/// zero rates.
pub fn select_match_bits(
    candidate_count: usize,
    offered_votes_per_minute: u64,
    max_votes_per_node_per_minute: u64,
) -> Result<u16, AssignmentError> {
    if candidate_count == 0 || offered_votes_per_minute == 0 || max_votes_per_node_per_minute == 0 {
        return Err(AssignmentError::InvalidCapacityInput);
    }

    let required_nodes =
        u128::from(offered_votes_per_minute).div_ceil(u128::from(max_votes_per_node_per_minute));
    let candidate_count =
        u128::try_from(candidate_count).map_err(|_| AssignmentError::CandidateCountOverflow)?;
    if required_nodes >= candidate_count {
        return Ok(0);
    }
    let prefix_population = candidate_count / required_nodes;
    let bits = u128::BITS - 1 - prefix_population.leading_zeros();
    u16::try_from(bits.min(u32::from(MATCH_BITS_MAX)))
        .map_err(|_| AssignmentError::InvalidMatchBits(MATCH_BITS_MAX))
}

/// Errors while validating descriptors or assigning an ingest destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignmentError {
    /// A descriptor must contain at least one candidate.
    NoCandidates,
    /// A candidate `NodeId` appears more than once.
    DuplicateCandidate,
    /// A `MatchBits` width exceeds the 256-bit `NodeId`/hash width.
    InvalidMatchBits(u16),
    /// A view is not one of the three defined assignment views.
    InvalidView(u8),
    /// A candidate count cannot be represented by the algorithm.
    CandidateCountOverflow,
    /// Capacity inputs must all be nonzero.
    InvalidCapacityInput,
}

impl fmt::Display for AssignmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidates => formatter.write_str("delegation descriptor has no candidates"),
            Self::DuplicateCandidate => {
                formatter.write_str("delegation descriptor repeats a candidate NodeId")
            }
            Self::InvalidMatchBits(bits) => {
                write!(formatter, "MatchBits width {bits} exceeds 256 bits")
            }
            Self::InvalidView(view) => write!(formatter, "ingest view {view} is outside 0..3"),
            Self::CandidateCountOverflow => {
                formatter.write_str("candidate count exceeds the assignment algorithm limit")
            }
            Self::InvalidCapacityInput => {
                formatter.write_str("candidate count and ingest rates must be nonzero")
            }
        }
    }
}

impl std::error::Error for AssignmentError {}

fn validate_view(view: u8) -> Result<(), AssignmentError> {
    if view >= INGEST_VIEW_COUNT {
        return Err(AssignmentError::InvalidView(view));
    }
    Ok(())
}

fn client_view_hash(client_id: ClientId, view: u8) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(client_id.as_bytes());
    hasher.update([view]);
    hasher.finalize().into()
}

fn closest_xor(
    candidates: &[IngestNode],
    target: &[u8; 32],
) -> Result<IngestNode, AssignmentError> {
    candidates
        .iter()
        .copied()
        .min_by_key(|candidate| {
            let mut distance = [0; 32];
            for ((output, node), target) in distance
                .iter_mut()
                .zip(candidate.node_id().as_bytes())
                .zip(target)
            {
                *output = node ^ target;
            }
            distance
        })
        .ok_or(AssignmentError::NoCandidates)
}

fn closest_matching(
    candidates: &[IngestNode],
    target: &[u8; 32],
    match_bits: u16,
) -> Option<IngestNode> {
    candidates
        .iter()
        .copied()
        .filter(|candidate| shares_prefix(candidate.node_id().as_bytes(), target, match_bits))
        .min_by_key(|candidate| xor_distance(candidate.node_id().as_bytes(), target))
}

fn xor_distance(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut distance = [0; 32];
    for ((output, left), right) in distance.iter_mut().zip(left).zip(right) {
        *output = left ^ right;
    }
    distance
}

fn shares_prefix(left: &[u8; 32], right: &[u8; 32], bits: u16) -> bool {
    let full_bytes = usize::from(bits / 8);
    let partial_bits = bits % 8;
    if left[..full_bytes] != right[..full_bytes] {
        return false;
    }
    if partial_bits == 0 {
        return true;
    }
    let mask = u8::MAX << (8 - partial_bits);
    left[full_bytes] & mask == right[full_bytes] & mask
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn node(index: u8) -> IngestNode {
        let mut bytes = [0; 32];
        bytes[31] = index;
        IngestNode::new(NodeId::from_bytes(bytes))
    }

    fn descriptor(
        algorithm: AssignmentAlgorithm,
        candidates: Vec<IngestNode>,
        match_bits: u16,
    ) -> DelegationDescriptor {
        DelegationDescriptor::new(algorithm, candidates, match_bits)
            .expect("valid assignment descriptor")
    }

    #[test]
    fn descriptor_canonicalizes_candidates_and_rejects_invalid_sets() {
        let first = descriptor(AssignmentAlgorithm::XorNearest, vec![node(2), node(1)], 0);
        let second = descriptor(AssignmentAlgorithm::XorNearest, vec![node(1), node(2)], 0);
        assert_eq!(first, second);
        assert_eq!(first.candidates(), &[node(1), node(2)]);
        assert_eq!(
            DelegationDescriptor::new(AssignmentAlgorithm::XorNearest, Vec::new(), 0),
            Err(AssignmentError::NoCandidates)
        );
        assert_eq!(
            DelegationDescriptor::new(AssignmentAlgorithm::MatchBits, vec![node(1), node(1)], 0),
            Err(AssignmentError::DuplicateCandidate)
        );
        assert_eq!(
            DelegationDescriptor::new(
                AssignmentAlgorithm::MatchBits,
                vec![node(1)],
                MATCH_BITS_MAX + 1
            ),
            Err(AssignmentError::InvalidMatchBits(MATCH_BITS_MAX + 1))
        );
    }

    #[test]
    fn each_candidate_is_deterministic_and_returns_a_descriptor_member() {
        let client = ClientId::from_bytes([7; 32]);
        for algorithm in [
            AssignmentAlgorithm::SaltedClientHash,
            AssignmentAlgorithm::DisjointClientRanges,
            AssignmentAlgorithm::XorNearest,
            AssignmentAlgorithm::MatchBits,
        ] {
            let descriptor = descriptor(algorithm, vec![node(1), node(2), node(3)], 3);
            for view in 0..INGEST_VIEW_COUNT {
                let first = algorithm.assign(client, view, &descriptor);
                assert_eq!(first, algorithm.assign(client, view, &descriptor));
                assert!(descriptor.candidates().contains(&first.unwrap()));
            }
        }
    }

    #[test]
    fn three_views_are_distinct_when_candidate_population_allows() {
        let client = ClientId::from_bytes([7; 32]);
        for algorithm in [
            AssignmentAlgorithm::SaltedClientHash,
            AssignmentAlgorithm::DisjointClientRanges,
            AssignmentAlgorithm::XorNearest,
            AssignmentAlgorithm::MatchBits,
        ] {
            let descriptor = descriptor(algorithm, vec![node(1), node(2), node(3), node(4)], 2);
            let destinations = descriptor.assign_views(client).unwrap();
            assert_ne!(destinations[0], destinations[1]);
            assert_ne!(destinations[0], destinations[2]);
            assert_ne!(destinations[1], destinations[2]);
        }
    }

    #[test]
    fn three_views_reuse_destinations_only_when_population_is_too_small() {
        let client = ClientId::from_bytes([7; 32]);
        let descriptor = descriptor(
            AssignmentAlgorithm::DisjointClientRanges,
            vec![node(1), node(2)],
            0,
        );
        let destinations = descriptor.assign_views(client).unwrap();
        assert_ne!(destinations[0], destinations[1]);
        assert!(destinations.contains(&destinations[2]));
    }

    #[test]
    fn all_algorithms_reject_unknown_views() {
        let client = ClientId::from_bytes([4; 32]);
        for algorithm in [
            AssignmentAlgorithm::SaltedClientHash,
            AssignmentAlgorithm::DisjointClientRanges,
            AssignmentAlgorithm::XorNearest,
            AssignmentAlgorithm::MatchBits,
        ] {
            let descriptor = descriptor(algorithm, vec![node(1)], 0);
            assert_eq!(
                algorithm.assign(client, INGEST_VIEW_COUNT, &descriptor),
                Err(AssignmentError::InvalidView(INGEST_VIEW_COUNT))
            );
        }
    }

    #[test]
    fn match_bits_falls_back_when_sparse_prefixes_have_no_candidates() {
        let client = ClientId::from_bytes([0; 32]);
        let descriptor = descriptor(
            AssignmentAlgorithm::MatchBits,
            vec![node(1), node(2), node(3)],
            MATCH_BITS_MAX,
        );
        for view in 0..INGEST_VIEW_COUNT {
            let assigned = AssignmentAlgorithm::MatchBits
                .assign(client, view, &descriptor)
                .expect("sparse prefixes fall back to a known candidate");
            assert!(descriptor.candidates().contains(&assigned));
        }
    }

    #[test]
    fn match_bits_width_uses_observed_population_and_capacity() {
        assert_eq!(select_match_bits(16, 100, 100).unwrap(), 4);
        assert_eq!(select_match_bits(16, 1_600, 100).unwrap(), 0);
        assert_eq!(select_match_bits(10, 100, 100).unwrap(), 3);
        assert_eq!(
            select_match_bits(0, 100, 100),
            Err(AssignmentError::InvalidCapacityInput)
        );
        assert_eq!(
            select_match_bits(10, 100, 0),
            Err(AssignmentError::InvalidCapacityInput)
        );
    }
}
