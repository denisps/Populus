//! Seeded workload generation and Phase-9 assignment placement.

use crate::config::{PACKET_LOSS_SCALE, SimulationConfig, SimulationError, VIEW_COUNT};
use crate::report::{AssignmentLoad, ContentSummary};
use crate::rng::{SeededRandom, random_identifier};
use populus_cluster::DelegationDescriptor;
use populus_content::{ContentBody, SignedContent};
use populus_crypto::{RoutingIdentifier, routing_key};
use populus_routing::{BUCKET_CAPACITY, InsertError, RoutingTable, closest_nodes_brute_force};
use populus_types::{ClientId, NodeId, RoutingKey};
use std::collections::BTreeMap;

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

pub(super) fn schedule_votes(
    config: &SimulationConfig,
    clients: Vec<ClientId>,
    random: &mut SeededRandom,
    node_ids: &[NodeId],
    descriptors: &[DelegationDescriptor],
    mut schedule: impl FnMut(
        u64,
        usize,
        usize,
        ClientId,
        usize,
        u8,
        bool,
    ) -> Result<(), SimulationError>,
) -> Result<(Vec<usize>, Vec<AssignmentLoad>), SimulationError> {
    let mut expected_by_content = vec![0_usize; config.content_count];
    let node_index_by_id: BTreeMap<_, _> = node_ids
        .iter()
        .copied()
        .enumerate()
        .map(|(index, node_id)| (node_id, index))
        .collect();
    let mut assignments_by_node = vec![[0; VIEW_COUNT]; node_ids.len()];
    // At rate R, one millisecond is R ticks and one payload occupies
    // payload_bytes * 1,000 ticks. This keeps fractional-ms egress exact.
    let mut egress_free_ticks = vec![0_u128; config.node_count];
    for (client_index, client_id) in clients.into_iter().enumerate() {
        let content_index = client_index % config.content_count;
        expected_by_content[content_index] += 1;
        let descriptor = descriptors
            .get(content_index)
            .ok_or(SimulationError::RoutingInvariant)?;
        let destinations = descriptor.assign_views(client_id)?;
        for (view, node) in destinations.into_iter().enumerate() {
            let node = node_index_by_id
                .get(&node.node_id())
                .copied()
                .ok_or(SimulationError::RoutingInvariant)?;
            assignments_by_node[node][view] += 1;
            let mut latency_ms = config.latency.sample(random);
            if let Some(jitter) = config.jitter {
                latency_ms = latency_ms
                    .checked_add(jitter.sample(random))
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?;
            }
            let mut at_ms = 0_u64;
            if let Some(bytes_per_second) = config.bandwidth_bytes_per_second {
                let ticks_per_ms = u128::from(bytes_per_second);
                let source = client_index % config.node_count;
                let transmission_ticks = u128::from(crate::config::SIMULATED_PAYLOAD_BYTES)
                    .checked_mul(1_000)
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?;
                let finish_ticks = egress_free_ticks[source]
                    .checked_add(transmission_ticks)
                    .ok_or(SimulationError::TimeOrSequenceOverflow)?;
                egress_free_ticks[source] = finish_ticks;
                at_ms = u64::try_from(finish_ticks.div_ceil(ticks_per_ms))
                    .map_err(|_| SimulationError::TimeOrSequenceOverflow)?;
            }
            at_ms = at_ms
                .checked_add(latency_ms)
                .ok_or(SimulationError::TimeOrSequenceOverflow)?;
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
    let loads = node_ids
        .iter()
        .copied()
        .zip(assignments_by_node)
        .map(|(node_id, assignments_by_view)| AssignmentLoad {
            node_id,
            assignments_by_view,
        })
        .collect();
    Ok((expected_by_content, loads))
}
