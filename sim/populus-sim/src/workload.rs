//! Phase-5 synthetic workload generation.
//!
//! Destination selection is only a load generator; it is not delegated-ingest protocol assignment.

use crate::config::{PACKET_LOSS_SCALE, SimulationConfig, SimulationError, VIEW_COUNT};
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
    mut schedule: impl FnMut(
        u64,
        usize,
        usize,
        ClientId,
        usize,
        u8,
        bool,
    ) -> Result<(), SimulationError>,
) -> Result<Vec<usize>, SimulationError> {
    let mut expected_by_content = vec![0_usize; config.content_count];
    let mut egress_free_ms = vec![0_u64; config.node_count];
    for (client_index, client_id) in clients.into_iter().enumerate() {
        let content_index = client_index % config.content_count;
        expected_by_content[content_index] += 1;
        let destinations = choose_destinations(config.node_count, random)?;
        for (view, node) in destinations.into_iter().enumerate() {
            let mut at_ms = config.latency.sample(random);
            if let Some(jitter) = config.jitter {
                at_ms = at_ms
                    .checked_add(jitter.sample(random))
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?;
            }
            if let Some(bytes_per_second) = config.bandwidth_bytes_per_second {
                let transmission_ms = crate::config::SIMULATED_PAYLOAD_BYTES
                    .checked_mul(1_000)
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?
                    / bytes_per_second;
                let source = client_index % config.node_count;
                let start_ms = at_ms.max(egress_free_ms[source]);
                let finish_ms = start_ms
                    .checked_add(transmission_ms)
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?;
                egress_free_ms[source] = finish_ms;
                at_ms = finish_ms;
            }
            if let Some(reorder_delay) = config.reordering {
                at_ms = at_ms
                    .checked_add(reorder_delay.sample(random))
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?;
            }
            let loss_dropped = config.packet_loss_probability != 0
                && random.sample_below(u64::from(PACKET_LOSS_SCALE))
                    < u64::from(config.packet_loss_probability);
            let view = u8::try_from(view)
                .map_err(|_| SimulationError::CountLimitExceeded("view count"))?;
            schedule(
                at_ms,
                client_index % config.node_count,
                node,
                client_id,
                content_index,
                view,
                loss_dropped,
            )?;
        }
    }
    Ok(expected_by_content)
}
