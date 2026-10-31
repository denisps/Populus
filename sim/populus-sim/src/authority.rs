#![allow(clippy::expect_used, clippy::panic)]

use crate::rng::{SeededRandom, random_identifier};
use populus_cluster::{
    AuthorityMember, AuthorityReplica, AuthorityState, MembershipView, SignedAuthorityState,
    StateResolution, resolve_authority_state, select_authorities,
};
use populus_crypto::AuthorityKeypair;
use populus_types::{Epoch, NodeId, RoutingKey};

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
