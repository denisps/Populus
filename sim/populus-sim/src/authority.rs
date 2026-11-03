#![allow(clippy::expect_used, clippy::panic)]

use crate::rng::{SeededRandom, random_identifier};
use populus_cluster::{
    AuthorityMember, AuthorityReplica, AuthorityState, DailyPopularityStatus, DirectIngestPolicy,
    DirectIngestState, DirectVote, MembershipView, PersistentLike, SignedAuthorityState,
    SignedDirectVoteAck, StateResolution, resolve_authority_state, select_authorities,
};
use populus_crypto::{AuthorityKeypair, RoutingIdentifier, routing_key};
use populus_types::{AuthorityId, ClientId, ContentId, Epoch, NodeId, RoutingKey, UtcDay};
use std::collections::{BTreeMap, BTreeSet};

use crate::virtual_time::VirtualTime;

const DAY_MS: i64 = 86_400_000;

#[test]
fn seeded_authority_failover_initializes_from_two_matching_replicas() {
    const SEED: u64 = 0xA117_0A17;
    let mut random = SeededRandom::new(SEED);
    let keys: Vec<_> = (0..5)
        .map(|_| AuthorityKeypair::from_secret_key(random_identifier(&mut random, SEED)))
        .collect();
    let known_members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            AuthorityMember::new(
                NodeId::from_bytes(random_identifier(
                    &mut random,
                    u64::try_from(index).unwrap_or(0),
                )),
                key.public_key(),
            )
            .expect("seeded Ed25519 public key is valid")
        })
        .collect();
    let routing_key = RoutingKey::from_bytes(random_identifier(&mut random, SEED + 1));
    let initial_members = select_authorities(&routing_key, &known_members)
        .expect("simulated membership has unique nodes");
    let previous_view = MembershipView::new(routing_key, 6, initial_members.clone())
        .expect("four closest are unique");
    let snapshot = AuthorityState::new(routing_key, Epoch::new(24), previous_view.clone(), 91);
    let responders = &initial_members[..3];
    let state_responses: Vec<_> = responders
        .iter()
        .take(2)
        .map(|member| {
            let key = keys
                .iter()
                .find(|key| key.authority_id() == member.authority_id())
                .expect("member key exists");
            SignedAuthorityState::sign(snapshot.clone(), key).expect("member can sign state")
        })
        .chain(responders.iter().skip(2).map(|member| {
            let key = keys
                .iter()
                .find(|key| key.authority_id() == member.authority_id())
                .expect("member key exists");
            let conflicting =
                AuthorityState::new(routing_key, Epoch::new(24), previous_view.clone(), 91)
                    .with_components(
                        populus_cluster::AuthorityMode::Direct,
                        populus_cluster::AuthorityComponents {
                            rate_state: vec![1],
                            ..populus_cluster::AuthorityComponents::default()
                        },
                    )
                    .expect("conflicting snapshot remains valid");
            SignedAuthorityState::sign(conflicting, key).expect("member can sign conflicting state")
        }))
        .collect();
    let expected: Vec<_> = responders
        .iter()
        .map(AuthorityMember::authority_id)
        .collect();
    let StateResolution::Quorum(quorum) =
        resolve_authority_state(&previous_view, &expected, &state_responses)
            .expect("responses are signed by expected members")
    else {
        panic!("two matching states out of three must initialize the replacement; seed={SEED}");
    };
    assert_eq!(quorum.state(), &snapshot, "seed={SEED}");
    let replacement = AuthorityReplica::from_quorum(*quorum);
    assert_eq!(replacement.state(), &snapshot, "seed={SEED}");

    let replacement_members: Vec<_> = initial_members
        .iter()
        .take(3)
        .copied()
        .chain(
            known_members
                .iter()
                .copied()
                .filter(|candidate| !initial_members.contains(candidate))
                .take(1),
        )
        .collect();
    let replacement_view = MembershipView::new(routing_key, 7, replacement_members)
        .expect("replacement joins the remaining authority cluster");
    assert_eq!(
        replacement_view.generation(),
        previous_view.generation() + 1
    );
    assert_eq!(
        replacement_view
            .members()
            .iter()
            .filter(|member| previous_view.member(member.authority_id()).is_some())
            .count(),
        3
    );
}

#[test]
fn direct_ingest_converges_across_authority_skew_latency_retry_and_restart() {
    const SEED: u64 = 0xD1EC_7008;
    let mut random = SeededRandom::new(SEED);
    let content_id = ContentId::from_digest(random_identifier(&mut random, SEED));
    let clients: Vec<_> = (0..2)
        .map(|index| {
            ClientId::from_bytes(random_identifier(
                &mut random,
                SEED + u64::try_from(index).unwrap_or(0) + 1,
            ))
        })
        .collect();
    let day = UtcDay::new(0);
    let policy = DirectIngestPolicy::new(1_000, 5 * 60_000, 60_000)
        .expect("simulation uses a nonzero direct-rate target");
    let mut authorities: Vec<_> = (0..4)
        .map(|_| DirectIngestState::new(content_id, day, policy))
        .collect();
    let first_vote = DirectVote::new(content_id, clients[0], day);
    let boundary_arrivals = [
        DAY_MS - 20_000,
        DAY_MS - 1_000,
        DAY_MS + 25_000,
        DAY_MS + 45_000,
    ];

    for (index, received_at) in boundary_arrivals.into_iter().enumerate() {
        authorities[index]
            .record_vote(first_vote, received_at)
            .expect("boundary-delayed vote remains inside configured grace");
        if index == 3 {
            let crashed = authorities[index]
                .serialize()
                .expect("daily authority state fits the replicated-state limit");
            authorities[index] = DirectIngestState::deserialize(&crashed)
                .expect("authority restart restores its daily sketch");
        }
        authorities[index]
            .record_vote(first_vote, received_at + 100)
            .expect("duplicate retry is idempotent");
    }

    let second_vote = DirectVote::new(content_id, clients[1], day);
    for (index, authority) in authorities.iter_mut().enumerate() {
        authority
            .record_vote(
                second_vote,
                DAY_MS + 60_000 + i64::try_from(index).unwrap_or(0),
            )
            .expect("network-delayed daily vote is accepted");
        assert_eq!(authority.estimate(), 2.0, "seed={SEED}, authority={index}");
        assert!(matches!(
            authority
                .finalize(DAY_MS + 5 * 60_000)
                .expect("simulated timestamp is representable"),
            DailyPopularityStatus::Provisional { estimate: 2.0 }
        ));
        assert!(matches!(
            authority
                .finalize(DAY_MS + 6 * 60_000)
                .expect("simulated timestamp is representable"),
            DailyPopularityStatus::Finalized { estimate: 2.0 }
        ));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn virtual_time_authority_replacement_uses_signed_quorum_and_recovers_on_partition() {
    const SEED: u64 = 0xA117_0A18;
    let mut random = SeededRandom::new(SEED);
    let keys: Vec<_> = (0..5)
        .map(|_| AuthorityKeypair::from_secret_key(random_identifier(&mut random, SEED)))
        .collect();
    let known_members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            AuthorityMember::new(
                NodeId::from_bytes(random_identifier(
                    &mut random,
                    u64::try_from(index).expect("five authority indexes fit"),
                )),
                key.public_key(),
            )
            .expect("seeded Ed25519 public key is valid")
        })
        .collect();
    let routing_key = RoutingKey::from_bytes(random_identifier(&mut random, SEED + 1));
    let initial_members = select_authorities(&routing_key, &known_members)
        .expect("seeded member identities are unique");
    let previous_view = MembershipView::new(routing_key, 6, initial_members.clone())
        .expect("four closest members form a canonical view");
    let snapshot = AuthorityState::new(routing_key, Epoch::new(24), previous_view.clone(), 91);
    let conflicting = snapshot
        .clone()
        .with_components(
            populus_cluster::AuthorityMode::Direct,
            populus_cluster::AuthorityComponents {
                rate_state: vec![0xA5],
                ..populus_cluster::AuthorityComponents::default()
            },
        )
        .expect("conflicting snapshot remains valid");
    let crashed = initial_members[3].authority_id();
    let responders: Vec<_> = initial_members
        .iter()
        .copied()
        .filter(|member| member.authority_id() != crashed)
        .collect();
    let signed_responses: Vec<_> = responders
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let key = keys
                .iter()
                .find(|key| key.authority_id() == member.authority_id())
                .expect("responder key exists");
            let state = if index == 2 {
                conflicting.clone()
            } else {
                snapshot.clone()
            };
            SignedAuthorityState::sign(state, key).expect("responder signs its state")
        })
        .collect();
    let joiner = known_members
        .iter()
        .find(|member| !initial_members.contains(member))
        .copied()
        .expect("five known nodes leave one replacement candidate");
    let mut clock = VirtualTime::new();
    clock
        .schedule(0, AuthorityScenarioEvent::Crash(crashed))
        .expect("event is not in the past");
    clock
        .schedule(5, AuthorityScenarioEvent::Join(joiner.node_id()))
        .expect("event is not in the past");
    for (response, at_ms) in signed_responses.into_iter().zip([10, 20, 30]) {
        clock
            .schedule(
                at_ms,
                AuthorityScenarioEvent::StateResponse(Box::new(response)),
            )
            .expect("event is not in the past");
    }

    let mut observed_crash = false;
    let mut observed_join = false;
    let mut responses = Vec::new();
    while let Some((_at_ms, event)) = clock.next() {
        match event {
            AuthorityScenarioEvent::Crash(authority_id) => {
                observed_crash = authority_id == crashed;
            }
            AuthorityScenarioEvent::Join(node_id) => {
                observed_join = node_id == joiner.node_id();
            }
            AuthorityScenarioEvent::Partition => {}
            AuthorityScenarioEvent::StateResponse(response) => responses.push(*response),
        }
    }
    let expected_signers: Vec<_> = responders
        .iter()
        .map(AuthorityMember::authority_id)
        .collect();
    let resolution = resolve_authority_state(&previous_view, &expected_signers, &responses)
        .expect("signed scenario responses resolve");
    let StateResolution::Quorum(quorum) = resolution else {
        panic!("two matching states must form quorum; seed={SEED}");
    };
    assert_eq!(quorum.state(), &snapshot, "seed={SEED}");
    assert!(observed_crash, "seed={SEED}");
    assert!(observed_join, "seed={SEED}");

    let eligible: Vec<_> = known_members
        .iter()
        .copied()
        .filter(|member| member.authority_id() != crashed)
        .collect();
    let replacement_members =
        select_authorities(&routing_key, &eligible).expect("replacement candidates are unique");
    let replacement_view = MembershipView::new(
        routing_key,
        previous_view.generation() + 1,
        replacement_members.clone(),
    )
    .expect("membership replacement is canonical");
    let next_closest = select_authorities(
        &routing_key,
        &known_members
            .iter()
            .copied()
            .filter(|member| !initial_members.contains(member))
            .collect::<Vec<_>>(),
    )
    .expect("outside candidates are unique")[0];
    assert_eq!(
        replacement_view.generation(),
        previous_view.generation() + 1,
        "seed={SEED}"
    );
    assert!(
        replacement_view.members().contains(&next_closest),
        "seed={SEED}"
    );
    assert!(replacement_view.members().contains(&joiner), "seed={SEED}");

    let mut partition_clock = VirtualTime::new();
    partition_clock
        .schedule(0, AuthorityScenarioEvent::Crash(crashed))
        .expect("event is not in the past");
    partition_clock
        .schedule(1, AuthorityScenarioEvent::Partition)
        .expect("event is not in the past");
    for (index, response) in
        signed_responses_for_partition(&responders, &keys, &snapshot, &conflicting)
            .into_iter()
            .enumerate()
    {
        partition_clock
            .schedule(
                10 + u64::try_from(index).expect("responder index fits"),
                AuthorityScenarioEvent::StateResponse(Box::new(response)),
            )
            .expect("event is not in the past");
    }
    let mut partition_active = false;
    let mut partition_responses = Vec::new();
    while let Some((_at_ms, event)) = partition_clock.next() {
        match event {
            AuthorityScenarioEvent::Crash(_) | AuthorityScenarioEvent::Join(_) => {}
            AuthorityScenarioEvent::Partition => partition_active = true,
            AuthorityScenarioEvent::StateResponse(response) => {
                let sender = response.signer();
                let sender_node = previous_view
                    .member(sender)
                    .expect("response signer belongs to the old view")
                    .node_id();
                let same_partition = responders
                    .first()
                    .is_some_and(|first| first.node_id() == sender_node);
                if !partition_active || same_partition {
                    partition_responses.push(*response);
                }
            }
        }
    }
    let partition_resolution =
        resolve_authority_state(&previous_view, &expected_signers, &partition_responses)
            .expect("partition response set is well-formed");
    assert!(
        matches!(
            partition_resolution,
            StateResolution::RecoveryNeeded {
                best_matching: 1,
                ..
            }
        ),
        "seed={SEED}: a strict majority was guessed through the partition"
    );
}

fn signed_responses_for_partition(
    responders: &[AuthorityMember],
    keys: &[AuthorityKeypair],
    matching: &AuthorityState,
    conflicting: &AuthorityState,
) -> Vec<SignedAuthorityState> {
    responders
        .iter()
        .enumerate()
        .map(|(index, member)| {
            let key = keys
                .iter()
                .find(|key| key.authority_id() == member.authority_id())
                .expect("responder key exists");
            SignedAuthorityState::sign(
                if index == 2 {
                    conflicting.clone()
                } else {
                    matching.clone()
                },
                key,
            )
            .expect("responder signs its state")
        })
        .collect()
}

enum AuthorityScenarioEvent {
    Crash(AuthorityId),
    Join(NodeId),
    Partition,
    StateResponse(Box<SignedAuthorityState>),
}

#[test]
#[allow(clippy::too_many_lines)]
fn virtual_time_direct_ingest_retries_retargets_and_restores_exact_client_state() {
    const SEED: u64 = 0xD1EC_7009;
    let mut random = SeededRandom::new(SEED);
    let content_id = ContentId::from_digest(random_identifier(&mut random, SEED));
    let client = ClientId::from_bytes(random_identifier(&mut random, SEED + 1));
    let day = UtcDay::new(0);
    let route = routing_key(RoutingIdentifier::Content(&content_id));
    let keys: Vec<_> = (0..5)
        .map(|index| {
            AuthorityKeypair::from_secret_key(random_identifier(
                &mut random,
                SEED + 2 + u64::try_from(index).expect("key index fits"),
            ))
        })
        .collect();
    let known_members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            AuthorityMember::new(
                NodeId::from_bytes(random_identifier(
                    &mut random,
                    SEED + 10 + u64::try_from(index).expect("member index fits"),
                )),
                key.public_key(),
            )
            .expect("seeded member key is valid")
        })
        .collect();
    let initial_members =
        select_authorities(&route, &known_members).expect("seeded authority identities are unique");
    let initial_view = MembershipView::new(route, 3, initial_members.clone())
        .expect("four selected nodes form a membership view");
    let crashed_member = initial_members[3];
    let eligible: Vec<_> = known_members
        .iter()
        .copied()
        .filter(|member| member != &crashed_member)
        .collect();
    let replacement_members =
        select_authorities(&route, &eligible).expect("replacement candidates are unique");
    let replacement_view = MembershipView::new(
        route,
        initial_view.generation() + 1,
        replacement_members.clone(),
    )
    .expect("replacement is the next canonical four-node view");
    let joiner = replacement_members
        .iter()
        .copied()
        .find(|member| !initial_members.contains(member))
        .expect("replacement view contains the next closest node");
    let key_by_authority: BTreeMap<_, _> = keys
        .into_iter()
        .map(|key| (key.authority_id(), key))
        .collect();
    let policy =
        DirectIngestPolicy::new(1_000, 5 * 60_000, 60_000).expect("clock allowance is bounded");
    let mut states: BTreeMap<_, _> = initial_members
        .iter()
        .map(|member| {
            (
                member.authority_id(),
                DirectIngestState::new(content_id, day, policy),
            )
        })
        .collect();
    let mut persistent = PersistentLike::new(content_id, true);
    let vote = persistent
        .vote_when_online(client, day, &initial_view)
        .expect("initial membership matches the content")
        .expect("liked client produces a vote");
    assert_eq!(persistent.pending_authorities().len(), 4, "seed={SEED}");

    let skew_ms = [-20_000_i64, -1_000, 25_000, 45_000];
    let latency_ms = [5_u64, 15, 25, 35];
    let send_at = u64::try_from(DAY_MS - 20_000).expect("day timestamp is nonnegative");
    let mut clock = VirtualTime::new();
    for (index, member) in initial_members.iter().copied().enumerate() {
        clock
            .schedule(
                send_at + latency_ms[index],
                DirectIngestEvent::DeliverVote {
                    member,
                    membership: initial_view.clone(),
                    vote,
                    skew_ms: skew_ms[index],
                },
            )
            .expect("delivery is not in the past");
    }
    clock
        .schedule(
            send_at + 30,
            DirectIngestEvent::DeliverVote {
                member: initial_members[0],
                membership: initial_view.clone(),
                vote,
                skew_ms: skew_ms[0],
            },
        )
        .expect("duplicate retry is not in the past");
    clock
        .schedule(
            send_at + 40,
            DirectIngestEvent::Crash(crashed_member.authority_id()),
        )
        .expect("crash is not in the past");
    clock
        .schedule(
            send_at + 50,
            DirectIngestEvent::Restore(crashed_member.authority_id()),
        )
        .expect("restore is not in the past");
    clock
        .schedule(
            send_at + 55,
            DirectIngestEvent::ReplaceMembership {
                crashed: crashed_member.authority_id(),
                joiner: joiner.authority_id(),
                membership: replacement_view.clone(),
                vote,
                client,
                day,
            },
        )
        .expect("membership replacement is not in the past");

    let mut exact_clients = BTreeSet::new();
    let mut snapshots = BTreeMap::new();
    let mut crashed = BTreeSet::new();
    let mut completed = false;
    let mut duplicate_retries = 0;
    let mut snapshot_restored = false;
    let mut membership_retargeted = false;
    while let Some((at_ms, event)) = clock.next() {
        match event {
            DirectIngestEvent::DeliverVote {
                member,
                membership,
                vote,
                skew_ms,
            } => {
                if crashed.contains(&member.authority_id()) {
                    continue;
                }
                let key = key_by_authority
                    .get(&member.authority_id())
                    .expect("authority key exists");
                let received_at = i64::try_from(at_ms)
                    .expect("virtual timestamp fits signed UTC time")
                    .checked_add(skew_ms)
                    .expect("skewed timestamp fits");
                let (_, acknowledgement) = states
                    .get_mut(&member.authority_id())
                    .expect("authority state exists")
                    .record_vote_and_acknowledge(vote, received_at, &membership, key)
                    .expect("delayed daily vote is inside the configured boundary grace");
                exact_clients.insert(vote.client_id());
                if member.authority_id() == crashed_member.authority_id() {
                    continue;
                }
                let first_retry = at_ms == send_at + 30;
                if first_retry {
                    duplicate_retries += 1;
                }
                clock
                    .schedule(
                        at_ms + 3,
                        DirectIngestEvent::DeliverAck {
                            acknowledgement,
                            membership,
                        },
                    )
                    .expect("acknowledgement is not in the past");
            }
            DirectIngestEvent::DeliverAck {
                acknowledgement,
                membership,
            } => {
                if persistent
                    .acknowledge(&acknowledgement, &membership)
                    .expect("acknowledgement is signed for its membership")
                {
                    completed = true;
                }
            }
            DirectIngestEvent::Crash(authority_id) => {
                let bytes = states
                    .get(&authority_id)
                    .expect("crashed authority state exists")
                    .serialize()
                    .expect("authority state fits the canonical bound");
                snapshots.insert(authority_id, bytes);
                crashed.insert(authority_id);
            }
            DirectIngestEvent::Restore(authority_id) => {
                let bytes = snapshots
                    .get(&authority_id)
                    .expect("crash retained its canonical state");
                let restored = DirectIngestState::deserialize(bytes)
                    .expect("serialized authority state restores");
                let expected_estimate =
                    f64::from(u32::try_from(exact_clients.len()).expect("small set fits u32"));
                assert_eq!(
                    restored.estimate(),
                    expected_estimate,
                    "seed={SEED}: restart discarded the retained client vote"
                );
                states.insert(authority_id, restored);
                crashed.remove(&authority_id);
                snapshot_restored = true;
            }
            DirectIngestEvent::ReplaceMembership {
                crashed,
                joiner: replacement_joiner,
                membership,
                vote,
                client,
                day,
            } => {
                assert!(
                    membership.member(replacement_joiner).is_some(),
                    "seed={SEED}: replacement joiner is not a member"
                );
                assert_eq!(persistent.pending_authorities().len(), 1, "seed={SEED}");
                let retried = persistent
                    .vote_when_online(client, day, &membership)
                    .expect("replacement view routes to this content")
                    .expect("pending vote remains retryable");
                assert_eq!(retried, vote, "seed={SEED}: replacement changed the vote");
                assert_eq!(persistent.pending_authorities().len(), 4, "seed={SEED}");
                membership_retargeted = true;
                assert!(
                    states.contains_key(&crashed),
                    "seed={SEED}: restored original authority state is missing"
                );
                let joiner_state = states
                    .entry(replacement_joiner)
                    .or_insert_with(|| DirectIngestState::new(content_id, day, policy));
                assert_eq!(
                    joiner_state.estimate(),
                    0.0,
                    "seed={SEED}: replacement joiner inherited another authority's clients"
                );
                for (index, member) in membership.members().iter().copied().enumerate() {
                    let delay = u64::try_from(index + 1).expect("four retry indexes fit");
                    clock
                        .schedule(
                            at_ms + delay,
                            DirectIngestEvent::DeliverVote {
                                member,
                                membership: membership.clone(),
                                vote: retried,
                                skew_ms: skew_ms[index],
                            },
                        )
                        .expect("replacement retry is not in the past");
                }
            }
        }
    }

    assert_eq!(clock.now_ms(), send_at + 62, "seed={SEED}");
    assert!(snapshot_restored, "seed={SEED}");
    assert!(membership_retargeted, "seed={SEED}");
    assert_eq!(duplicate_retries, 1, "seed={SEED}");
    assert_eq!(exact_clients.len(), 1, "seed={SEED}");
    let expected_estimate =
        f64::from(u32::try_from(exact_clients.len()).expect("small set fits u32"));
    assert!(
        completed,
        "seed={SEED}: not all four valid signed acknowledgements arrived"
    );
    assert!(persistent.pending_authorities().is_empty(), "seed={SEED}");
    assert!(
        replacement_members.iter().all(|member| {
            states
                .get(&member.authority_id())
                .is_some_and(|state| (state.estimate() - expected_estimate).abs() <= f64::EPSILON)
        }),
        "seed={SEED}: HLL state diverged from the exact BTreeSet oracle"
    );
}

enum DirectIngestEvent {
    DeliverVote {
        member: AuthorityMember,
        membership: MembershipView,
        vote: DirectVote,
        skew_ms: i64,
    },
    DeliverAck {
        acknowledgement: SignedDirectVoteAck,
        membership: MembershipView,
    },
    Crash(AuthorityId),
    Restore(AuthorityId),
    ReplaceMembership {
        crashed: AuthorityId,
        joiner: AuthorityId,
        membership: MembershipView,
        vote: DirectVote,
        client: ClientId,
        day: UtcDay,
    },
}
