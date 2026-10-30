//! Phase-5 synthetic workload generation.
//!
//! Destination selection is only a load generator; it is not delegated-ingest protocol assignment.

use crate::config::{SimulationConfig, SimulationError, VIEW_COUNT};
use crate::report::ContentSummary;
use crate::rng::{SeededRandom, random_identifier};
use populus_content::{ContentBody, SignedContent};
use populus_crypto::{RoutingIdentifier, routing_key};
use populus_routing::{BUCKET_CAPACITY, InsertError, RoutingTable, closest_nodes_brute_force};
use populus_types::{ClientId, NodeId, RoutingKey};

pub(super) fn generate_contents(
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

pub(super) fn generate_node_ids(
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

pub(super) fn generate_client_ids(
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

pub(super) fn content_payload(seed: u64, index: usize) -> Result<Vec<u8>, SimulationError> {
    let index =
        u64::try_from(index).map_err(|_| SimulationError::CountLimitExceeded("content count"))?;
    let mut payload = Vec::with_capacity(16);
    payload.extend_from_slice(&seed.to_be_bytes());
    payload.extend_from_slice(&index.to_be_bytes());
    Ok(payload)
}

pub(super) fn choose_destinations(
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

pub(super) fn schedule_votes(
    config: &SimulationConfig,
    clients: Vec<ClientId>,
    random: &mut SeededRandom,
    mut schedule: impl FnMut(u64, usize, ClientId, usize, u8) -> Result<(), SimulationError>,
) -> Result<Vec<usize>, SimulationError> {
    let mut expected_by_content = vec![0_usize; config.content_count];
    for (client_index, client_id) in clients.into_iter().enumerate() {
        let content_index = client_index % config.content_count;
        expected_by_content[content_index] += 1;
        let destinations = choose_destinations(config.node_count, random)?;
        for (view, node) in destinations.into_iter().enumerate() {
            let at_ms = config.latency.sample(random);
            let view = u8::try_from(view)
                .map_err(|_| SimulationError::CountLimitExceeded("view count"))?;
            schedule(at_ms, node, client_id, content_index, view)?;
        }
    }
    Ok(expected_by_content)
}
