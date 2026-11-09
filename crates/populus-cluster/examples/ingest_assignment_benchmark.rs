//! Microbenchmark for the experimental delegated-ingest assignment candidates.

use populus_cluster::{AssignmentAlgorithm, DelegationDescriptor, IngestNode};
use populus_types::{ClientId, NodeId};
use std::hint::black_box;
use std::time::Instant;

const CANDIDATE_COUNT: usize = 100;
const CLIENT_COUNT: usize = 10_000;
const ITERATIONS: usize = 5;
const SAMPLE_COUNT: usize = 7;

fn identifier(mut state: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    for chunk in bytes.as_chunks_mut::<8>().0 {
        state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        chunk.copy_from_slice(&(value ^ (value >> 31)).to_be_bytes());
    }
    bytes
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut candidates = Vec::with_capacity(CANDIDATE_COUNT);
    for index in 0..CANDIDATE_COUNT {
        let seed = u64::try_from(index)?;
        let mut node_id = identifier(seed);
        node_id[..3].copy_from_slice(&[0x5a, 0xc3, 0x17]);
        candidates.push(IngestNode::new(NodeId::from_bytes(node_id)));
    }
    let mut clients = Vec::with_capacity(CLIENT_COUNT);
    for index in 0..CLIENT_COUNT {
        let seed = u64::try_from(index)?.wrapping_add(0x517c_c1b7_2722_0a95);
        clients.push(ClientId::from_bytes(identifier(seed)));
    }

    let algorithms = [
        AssignmentAlgorithm::SaltedClientHash,
        AssignmentAlgorithm::DisjointClientRanges,
        AssignmentAlgorithm::XorNearest,
        AssignmentAlgorithm::MatchBits,
    ];
    for sample in 0..SAMPLE_COUNT {
        for order in 0..algorithms.len() {
            let algorithm = algorithms[(order + sample) % algorithms.len()];
            let descriptor = DelegationDescriptor::new(algorithm, candidates.clone(), 7)?;
            let start = Instant::now();
            let mut checksum = 0_u64;
            for _ in 0..ITERATIONS {
                for client in &clients {
                    for view in 0..3 {
                        let assigned = descriptor.assign(black_box(*client), view)?;
                        checksum ^= u64::from(assigned.node_id().as_bytes()[31]);
                    }
                }
            }
            let elapsed_ns = start.elapsed().as_nanos();
            println!(
                "sample={sample} order={order} algorithm={algorithm:?} assignments={} elapsed_ns={elapsed_ns} checksum={checksum}",
                CLIENT_COUNT * ITERATIONS * 3
            );
        }
    }
    Ok(())
}
