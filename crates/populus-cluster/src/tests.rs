#![allow(clippy::expect_used, clippy::panic)]

use super::{
    ApplyOutcome, AuthorityComponents, AuthorityError, AuthorityKeypair, AuthorityMember,
    AuthorityMode, AuthorityReplica, AuthorityState, EquivocationProof, MAX_STATE_COMPONENT_BYTES,
    MembershipView, RequestSequenceTracker, SignedAuthorityState, SignedStateRequest,
    StateResolution, resolve_authority_state, select_authorities,
};
use populus_types::{AuthorityId, Epoch, NodeId, RoutingKey};
use std::fmt::Write as _;

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String is infallible");
    }
    encoded
}

fn authority_vector_field(name: &str) -> &'static str {
    include_str!("../../../testvectors/authority-v1.txt")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}=")))
        .expect("authority vector field exists")
}

fn members(count: usize) -> (Vec<AuthorityKeypair>, Vec<AuthorityMember>) {
    let keys: Vec<_> = (0..count)
        .map(|index| AuthorityKeypair::from_secret_key([u8::try_from(index + 1).unwrap_or(0); 32]))
        .collect();
    let members = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let mut node = [0; 32];
            node[0] = u8::try_from(index).unwrap_or(0);
            node[31] = u8::try_from(index * 17).unwrap_or(0);
            AuthorityMember::new(NodeId::from_bytes(node), key.public_key())
                .expect("generated public key is valid")
        })
        .collect();
    (keys, members)
}

fn view(members: &[AuthorityMember], generation: u64) -> MembershipView {
    let routing_key = RoutingKey::from_bytes([0xA5; 32]);
    view_for(routing_key, members, generation)
}

fn view_for(
    routing_key: RoutingKey,
    members: &[AuthorityMember],
    generation: u64,
) -> MembershipView {
    let closest = select_authorities(&routing_key, members).expect("fixture members are unique");
    MembershipView::new(routing_key, generation, closest)
        .expect("fixture membership is unique and ordered")
}

fn state(membership: MembershipView, epoch: u64, sequence: u64, marker: u8) -> AuthorityState {
    AuthorityState::new(
        membership.routing_key(),
        Epoch::new(epoch),
        membership,
        sequence,
    )
    .with_components(
        AuthorityMode::Direct,
        AuthorityComponents {
            rate_state: vec![marker],
            ..AuthorityComponents::default()
        },
    )
    .expect("fixture state is valid")
}

fn sign(state: AuthorityState, key: &AuthorityKeypair) -> SignedAuthorityState {
    SignedAuthorityState::sign(state, key).expect("fixture signer belongs to membership")
}

fn quorum_state(
    membership: &MembershipView,
    keys: &[AuthorityKeypair],
    state: &AuthorityState,
    responders: &[usize],
) -> super::QuorumState {
    let responses: Vec<_> = responders
        .iter()
        .map(|index| sign(state.clone(), &keys[*index]))
        .collect();
    let expected: Vec<_> = responders
        .iter()
        .map(|index| keys[*index].authority_id())
        .collect();
    let resolution = resolve_authority_state(membership, &expected, &responses)
        .expect("fixture messages verify");
    match resolution {
        StateResolution::Quorum(quorum) => *quorum,
        StateResolution::RecoveryNeeded { .. } => panic!("fixture should reach quorum"),
    }
}

#[test]
fn authority_selection_uses_closest_xor_distance_and_stable_ties() {
    let (keys, known) = members(7);
    let routing_key = RoutingKey::from_bytes([0x21; 32]);
    let mut oracle: Vec<_> = known
        .iter()
        .copied()
        .map(|member| {
            let distance: [u8; 32] = std::array::from_fn(|index| {
                member.node_id().as_bytes()[index] ^ routing_key.as_bytes()[index]
            });
            (distance, member.node_id(), member)
        })
        .collect();
    oracle.sort_unstable_by_key(|(distance, node_id, _)| (*distance, *node_id));
    let expected: Vec<_> = oracle
        .into_iter()
        .take(4)
        .map(|(_, _, member)| member)
        .collect();

    assert_eq!(
        select_authorities(&routing_key, &known).expect("unique members"),
        expected
    );
    assert_eq!(known[0].public_key(), &keys[0].public_key());
    assert_eq!(
        select_authorities(&routing_key, &known[..3])
            .expect("partial neighborhoods are allowed")
            .len(),
        3
    );
}

#[test]
fn authority_membership_rejects_bad_keys_duplicates_and_wrong_sizes() {
    let (keys, known) = members(5);
    let invalid_public_key = (0..=u8::MAX)
        .map(|byte| [byte; 32])
        .find(|key| populus_crypto::validate_ed25519_public_key(key).is_err())
        .expect("fixture search finds a non-curve point");
    assert_eq!(
        AuthorityMember::new(NodeId::from_bytes([0; 32]), invalid_public_key),
        Err(AuthorityError::InvalidPublicKey)
    );

    let duplicate_node = AuthorityMember::new(known[0].node_id(), keys[4].public_key())
        .expect("generated public key is valid");
    assert_eq!(
        select_authorities(
            &RoutingKey::from_bytes([0xA5; 32]),
            &[known[0], duplicate_node]
        ),
        Err(AuthorityError::DuplicateMember)
    );
    assert_eq!(
        select_authorities(&RoutingKey::from_bytes([0xA5; 32]), &[known[0], known[0]]),
        Err(AuthorityError::DuplicateMember)
    );

    assert_eq!(
        MembershipView::new(RoutingKey::from_bytes([0xA5; 32]), 1, known[..3].to_vec()),
        Err(AuthorityError::InvalidMembership)
    );
    assert_eq!(
        MembershipView::new(RoutingKey::from_bytes([0xA5; 32]), 1, known.clone()),
        Err(AuthorityError::InvalidMembership)
    );
    let duplicate_authority = AuthorityMember::new(known[4].node_id(), keys[0].public_key())
        .expect("generated public key is valid");
    let mut duplicates = known[..3].to_vec();
    duplicates.push(duplicate_authority);
    assert_eq!(
        MembershipView::new(RoutingKey::from_bytes([0xA5; 32]), 1, duplicates),
        Err(AuthorityError::DuplicateMember)
    );
}

#[test]
fn state_encoding_covers_membership_epoch_sequence_and_all_components() {
    let (keys, members) = members(4);
    let membership = view(&members, 2);
    let original = AuthorityState::new(
        RoutingKey::from_bytes([0xA5; 32]),
        Epoch::new(9),
        membership.clone(),
        13,
    );
    let full = original
        .clone()
        .with_components(
            AuthorityMode::Delegated,
            AuthorityComponents {
                delegation_descriptor: vec![1, 2],
                rate_state: vec![3],
                daily_popularity_state: vec![4],
                association_summary: vec![5],
                tag_reporting_state: vec![6],
            },
        )
        .expect("delegated state needs a descriptor");
    assert_ne!(
        original.canonical_bytes().expect("valid state"),
        full.canonical_bytes().expect("valid state")
    );
    let signed = sign(full.clone(), &keys[0]);
    assert!(signed.verify().is_ok());
    assert_eq!(signed.signer(), keys[0].authority_id());
    assert_eq!(signed.state(), &full);
    assert_eq!(full.routing_key(), membership.routing_key());
    assert_eq!(full.epoch(), Epoch::new(9));
    assert_eq!(full.mode(), AuthorityMode::Delegated);
    assert_eq!(full.sequence(), 13);
    assert_eq!(
        hex(&full.canonical_bytes().expect("valid state")),
        authority_vector_field("canonical_state")
    );
    assert_eq!(hex(&signed.signature), authority_vector_field("signature"));

    let mut tampered = signed;
    tampered.signature[0] ^= 0x80;
    assert_eq!(tampered.verify(), Err(AuthorityError::InvalidSignature));
    let mut wrong_identity = sign(full.clone(), &keys[0]);
    wrong_identity.public_key[0] ^= 0x01;
    assert_eq!(
        wrong_identity.verify(),
        Err(AuthorityError::InvalidSignature)
    );
    assert_eq!(
        SignedAuthorityState::sign(full, &AuthorityKeypair::from_secret_key([0xEE; 32])),
        Err(AuthorityError::NotAMember)
    );
    assert_eq!(
        original.with_components(AuthorityMode::Delegated, AuthorityComponents::default()),
        Err(AuthorityError::InvalidModeDescriptor)
    );
}

#[test]
fn state_mode_and_component_size_boundaries_are_enforced() {
    let (_, members) = members(4);
    let membership = view(&members, 2);
    let base = AuthorityState::new(
        membership.routing_key(),
        Epoch::new(1),
        membership.clone(),
        1,
    );
    assert_eq!(
        base.clone().with_components(
            AuthorityMode::Direct,
            AuthorityComponents {
                delegation_descriptor: vec![1],
                ..AuthorityComponents::default()
            }
        ),
        Err(AuthorityError::InvalidModeDescriptor)
    );

    let exact_limit = vec![0xA7; MAX_STATE_COMPONENT_BYTES];
    let accepted = base
        .clone()
        .with_components(
            AuthorityMode::Delegated,
            AuthorityComponents {
                delegation_descriptor: vec![1],
                rate_state: exact_limit.clone(),
                ..AuthorityComponents::default()
            },
        )
        .expect("component at configured maximum is accepted");
    assert_eq!(
        accepted.components().rate_state.len(),
        MAX_STATE_COMPONENT_BYTES
    );
    assert!(accepted.canonical_bytes().is_ok());

    let oversized = base.with_components(
        AuthorityMode::Delegated,
        AuthorityComponents {
            delegation_descriptor: vec![1],
            rate_state: vec![0xA7; MAX_STATE_COMPONENT_BYTES + 1],
            ..AuthorityComponents::default()
        },
    );
    assert_eq!(oversized, Err(AuthorityError::StateComponentTooLarge));

    let mut invalid_constructed =
        AuthorityState::new(membership.routing_key(), Epoch::new(1), membership, 1);
    invalid_constructed.components = AuthorityComponents {
        rate_state: vec![0; MAX_STATE_COMPONENT_BYTES + 1],
        ..AuthorityComponents::default()
    };
    assert_eq!(
        invalid_constructed.canonical_bytes(),
        Err(AuthorityError::StateComponentTooLarge)
    );
    assert_eq!(
        AuthorityState::new(
            RoutingKey::from_bytes([0x5A; 32]),
            Epoch::new(1),
            invalid_constructed.membership_view().clone(),
            1
        )
        .canonical_bytes(),
        Err(AuthorityError::RoutingKeyMismatch)
    );
}

#[test]
fn authority_state_requests_are_signed_and_bound_to_membership_generation() {
    let (keys, members) = members(4);
    let membership = view(&members, 2);
    let request = SignedStateRequest::sign(membership.routing_key(), &membership, 19, &keys[0])
        .expect("requester is a member");
    assert!(request.verify(&membership).is_ok());
    assert_eq!(request.request_sequence(), 19);
    assert_eq!(request.routing_key(), membership.routing_key());
    assert_eq!(request.signer(), keys[0].authority_id());
    let mut tracker = RequestSequenceTracker::default();
    assert!(tracker.accept(&request, &membership).is_ok());
    assert_eq!(
        tracker.accept(&request, &membership),
        Err(AuthorityError::StaleRequest)
    );
    let lower = SignedStateRequest::sign(membership.routing_key(), &membership, 18, &keys[0])
        .expect("requester is a member");
    assert_eq!(
        tracker.accept(&lower, &membership),
        Err(AuthorityError::StaleRequest)
    );
    let newer = SignedStateRequest::sign(membership.routing_key(), &membership, 20, &keys[0])
        .expect("requester is a member");
    assert!(tracker.accept(&newer, &membership).is_ok());

    let newer_view = MembershipView::new(
        membership.routing_key(),
        membership.generation() + 1,
        membership.members().to_vec(),
    )
    .expect("same ordered members");
    assert_eq!(
        request.verify(&newer_view),
        Err(AuthorityError::InvalidSignature)
    );
    let mut tampered = request;
    tampered.request_sequence += 1;
    assert_eq!(
        tampered.verify(&membership),
        Err(AuthorityError::InvalidSignature)
    );
    assert_eq!(
        SignedStateRequest::sign(RoutingKey::from_bytes([0x5A; 32]), &membership, 1, &keys[0]),
        Err(AuthorityError::RoutingKeyMismatch)
    );
    assert_eq!(
        SignedStateRequest::sign(
            membership.routing_key(),
            &membership,
            1,
            &AuthorityKeypair::from_secret_key([0xEE; 32])
        ),
        Err(AuthorityError::NotAMember)
    );
}

#[test]
fn request_sequence_tracking_is_scoped_by_signer_routing_key_and_generation() {
    let (keys, members) = members(4);
    let first_key = RoutingKey::from_bytes([0xA5; 32]);
    let first_view = view_for(first_key, &members, 2);
    let second_key = RoutingKey::from_bytes([0x5A; 32]);
    let second_view = view_for(second_key, &members, 2);
    let next_generation = view_for(first_key, &members, 3);
    let mut tracker = RequestSequenceTracker::default();

    let first_request =
        SignedStateRequest::sign(first_key, &first_view, 10, &keys[0]).expect("member request");
    assert!(tracker.accept(&first_request, &first_view).is_ok());

    let second_routing_key =
        SignedStateRequest::sign(second_key, &second_view, 1, &keys[0]).expect("same signer");
    assert!(tracker.accept(&second_routing_key, &second_view).is_ok());

    let second_signer =
        SignedStateRequest::sign(first_key, &first_view, 1, &keys[1]).expect("second signer");
    assert!(tracker.accept(&second_signer, &first_view).is_ok());

    let next_generation_request =
        SignedStateRequest::sign(first_key, &next_generation, 0, &keys[0])
            .expect("new generation request");
    assert!(
        tracker
            .accept(&next_generation_request, &next_generation)
            .is_ok()
    );
}

#[test]
fn failover_accepts_two_matching_valid_states_and_rejects_one_conflict() {
    let (keys, members) = members(4);
    let membership = view(&members, 5);
    let matching = state(membership.clone(), 12, 44, 1);
    let conflict = state(membership.clone(), 12, 44, 2);
    let responses = vec![
        sign(matching.clone(), &keys[0]),
        sign(matching.clone(), &keys[1]),
        sign(conflict, &keys[2]),
    ];
    let expected = [0, 1, 2].map(|index| keys[index].authority_id());
    let result = resolve_authority_state(&membership, &expected, &responses)
        .expect("all responders are valid");

    let StateResolution::Quorum(quorum) = result else {
        panic!("two matching states out of three must initialize replacement");
    };
    assert_eq!(quorum.state(), &matching);
    assert_eq!(quorum.matching_signers().len(), 2);
    assert_eq!(quorum.rejected_responses(), []);
    let replacement = AuthorityReplica::from_quorum(*quorum);
    assert_eq!(replacement.state(), &matching);
}

#[test]
fn partitioned_two_vs_two_requires_recovery_not_a_tie_break() {
    let (keys, members) = members(4);
    let membership = view(&members, 1);
    let first = state(membership.clone(), 3, 10, 1);
    let second = state(membership.clone(), 3, 10, 2);
    let responses = vec![
        sign(first.clone(), &keys[0]),
        sign(first.clone(), &keys[1]),
        sign(second.clone(), &keys[2]),
        sign(second, &keys[3]),
    ];
    let expected: Vec<_> = keys.iter().map(AuthorityKeypair::authority_id).collect();
    assert_eq!(
        resolve_authority_state(&membership, &expected, &responses)
            .expect("all four signatures verify"),
        StateResolution::RecoveryNeeded {
            best_matching: 2,
            required: 3,
            rejected_responses: Vec::new(),
        }
    );

    let healed_responses = [
        responses[0].clone(),
        responses[1].clone(),
        sign(first, &keys[2]),
        responses[3].clone(),
    ];
    let recovered = resolve_authority_state(&membership, &expected, &healed_responses)
        .expect("partition healed with three responsive authorities agreeing");
    let StateResolution::Quorum(quorum) = recovered else {
        panic!("three matching authorities must restore a strict majority");
    };
    let initial = state(membership.clone(), 3, 9, 0);
    let mut replica = AuthorityReplica::new(initial).expect("initial state is canonical");
    assert_eq!(
        replica
            .apply_quorum(*quorum)
            .expect("recovered majority advances state"),
        ApplyOutcome::Applied
    );
    assert_eq!(replica.state().components().rate_state, vec![1]);
}

#[test]
fn three_different_state_views_enter_recovery() {
    let (keys, members) = members(4);
    let membership = view(&members, 2);
    let responses: Vec<_> = (0..3)
        .map(|index| {
            sign(
                state(membership.clone(), 5, 17, u8::try_from(index).unwrap_or(0)),
                &keys[index],
            )
        })
        .collect();
    let expected = [0, 1, 2].map(|index| keys[index].authority_id());
    assert_eq!(
        resolve_authority_state(&membership, &expected, &responses)
            .expect("all snapshots are authentic"),
        StateResolution::RecoveryNeeded {
            best_matching: 1,
            required: 2,
            rejected_responses: Vec::new(),
        }
    );
}

#[test]
fn equivocation_proof_requires_same_signer_and_same_version() {
    let (keys, members) = members(4);
    let membership = view(&members, 3);
    let first_state = state(membership.clone(), 7, 18, 1);
    let first = sign(first_state.clone(), &keys[0]);
    let conflicting = sign(state(membership.clone(), 7, 18, 2), &keys[0]);
    let proof = EquivocationProof::new(first.clone(), conflicting)
        .expect("same signer contradicted its statement");
    assert!(proof.verify().is_ok());
    assert_eq!(proof.authority(), keys[0].authority_id());

    let other_signer = sign(state(membership.clone(), 7, 18, 2), &keys[1]);
    assert_eq!(
        EquivocationProof::new(first, other_signer),
        Err(AuthorityError::NotEquivocation)
    );

    let same_statement = sign(first_state.clone(), &keys[0]);
    assert_eq!(
        EquivocationProof::new(sign(first_state.clone(), &keys[0]), same_statement),
        Err(AuthorityError::NotEquivocation)
    );
    assert_eq!(
        EquivocationProof::new(
            sign(first_state.clone(), &keys[0]),
            sign(state(membership.clone(), 8, 18, 2), &keys[0])
        ),
        Err(AuthorityError::NotEquivocation)
    );
    assert_eq!(
        EquivocationProof::new(
            sign(first_state.clone(), &keys[0]),
            sign(state(membership.clone(), 7, 19, 2), &keys[0])
        ),
        Err(AuthorityError::NotEquivocation)
    );

    let next_generation =
        MembershipView::new(membership.routing_key(), 4, membership.members().to_vec())
            .expect("same members at next generation");
    let membership_conflict = sign(state(next_generation, 7, 18, 1), &keys[0]);
    let membership_proof = EquivocationProof::new(sign(first_state, &keys[0]), membership_conflict)
        .expect("same-version membership statements contradict");
    assert!(membership_proof.verify().is_ok());

    let mut invalid = sign(state(membership, 7, 18, 3), &keys[0]);
    invalid.signature[0] ^= 0x01;
    assert_eq!(
        EquivocationProof::new(sign(state(view(&members, 3), 7, 18, 1), &keys[0]), invalid),
        Err(AuthorityError::InvalidSignature)
    );
}

#[test]
fn replica_rejects_stale_replay_and_sequence_rollback() {
    let (keys, members) = members(4);
    let membership = view(&members, 0);
    let initial = state(membership.clone(), 2, 20, 1);
    let mut replica = AuthorityReplica::new(initial.clone()).expect("initial state is canonical");

    let newer = state(membership.clone(), 3, 22, 2);
    assert_eq!(
        replica
            .apply_quorum(quorum_state(&membership, &keys, &newer, &[0, 1, 2]))
            .expect("strict majority"),
        ApplyOutcome::Applied
    );
    assert_eq!(
        replica
            .apply_quorum(quorum_state(&membership, &keys, &newer, &[0, 1, 2]))
            .expect("exact replay is idempotent"),
        ApplyOutcome::Duplicate
    );
    assert_eq!(
        replica.apply_quorum(quorum_state(&membership, &keys, &initial, &[0, 1, 2])),
        Err(AuthorityError::StaleState)
    );

    let lower_sequence = state(membership.clone(), 4, 21, 3);
    assert_eq!(
        replica.apply_quorum(quorum_state(
            &membership,
            &keys,
            &lower_sequence,
            &[0, 1, 2]
        )),
        Err(AuthorityError::StaleState)
    );
    let lower_epoch = state(membership.clone(), 2, 23, 4);
    assert_eq!(
        replica.apply_quorum(quorum_state(&membership, &keys, &lower_epoch, &[0, 1, 2])),
        Err(AuthorityError::StaleState)
    );
    let mut restarted =
        AuthorityReplica::new(replica.state().clone()).expect("persisted state is canonical");
    assert_eq!(
        restarted
            .apply_quorum(quorum_state(&membership, &keys, &newer, &[0, 1, 2]))
            .expect("restart replays committed state"),
        ApplyOutcome::Duplicate
    );
}

#[test]
fn replica_rejects_conflicting_same_sequence_and_membership_generation_regressions() {
    let (keys, known) = members(5);
    let routing_key = RoutingKey::from_bytes([0xA5; 32]);
    let current_members: Vec<_> = select_authorities(&routing_key, &known)
        .expect("unique members")
        .into_iter()
        .collect();
    let current = MembershipView::new(routing_key, 4, current_members.clone())
        .expect("four closest authorities");
    let responders: Vec<_> = current
        .members()
        .iter()
        .take(3)
        .map(|member| {
            known
                .iter()
                .position(|candidate| candidate.authority_id() == member.authority_id())
                .expect("current member is in the known set")
        })
        .collect();
    let initial = state(current.clone(), 7, 30, 1);
    let mut replica = AuthorityReplica::new(initial).expect("initial state is canonical");

    let conflicting = state(current.clone(), 8, 30, 2);
    assert_eq!(
        replica.apply_quorum(quorum_state(&current, &keys, &conflicting, &responders)),
        Err(AuthorityError::ConflictingVersion)
    );

    let next_members: Vec<_> = current_members
        .iter()
        .take(3)
        .copied()
        .chain(
            known
                .iter()
                .copied()
                .find(|candidate| !current_members.contains(candidate)),
        )
        .collect();
    let stale_view = MembershipView::new(routing_key, 3, next_members)
        .expect("stale generation is otherwise canonical");
    let stale_state = state(stale_view, 8, 31, 3);
    assert_eq!(
        replica.apply_quorum(quorum_state(&current, &keys, &stale_state, &responders)),
        Err(AuthorityError::StaleState)
    );

    let same_generation_members: Vec<_> = current_members
        .iter()
        .take(3)
        .copied()
        .chain(
            known
                .iter()
                .copied()
                .find(|candidate| !current_members.contains(candidate)),
        )
        .collect();
    let conflicting_view = MembershipView::new(routing_key, 4, same_generation_members)
        .expect("same generation replacement view");
    let conflicting_membership_state = state(conflicting_view, 8, 32, 4);
    assert_eq!(
        replica.apply_quorum(quorum_state(
            &current,
            &keys,
            &conflicting_membership_state,
            &responders
        )),
        Err(AuthorityError::MembershipMismatch)
    );
}

#[test]
fn replica_rejects_quorum_resolved_against_a_different_membership_basis() {
    let (keys, members) = members(4);
    let current = view(&members, 2);
    let initial = state(current.clone(), 5, 10, 0);
    let mut replica = AuthorityReplica::new(initial).expect("initial state is canonical");
    let other_basis = MembershipView::new(
        current.routing_key(),
        current.generation() + 1,
        current.members().to_vec(),
    )
    .expect("same members under another generation");
    let candidate = state(other_basis.clone(), 5, 11, 1);
    let quorum = quorum_state(&other_basis, &keys, &candidate, &[0, 1, 2]);
    assert_eq!(
        replica.apply_quorum(quorum),
        Err(AuthorityError::MembershipMismatch)
    );
}

#[test]
fn replica_rechecks_routing_key_when_applying_a_quorum() {
    let (keys, members) = members(4);
    let membership = view(&members, 2);
    let mut replica = AuthorityReplica::new(state(membership.clone(), 5, 10, 0))
        .expect("initial state is canonical");
    let candidate = state(membership.clone(), 5, 11, 1);
    let mut quorum = quorum_state(&membership, &keys, &candidate, &[0, 1, 2]);
    quorum.state.routing_key = RoutingKey::from_bytes([0x5A; 32]);
    assert_eq!(
        replica.apply_quorum(quorum),
        Err(AuthorityError::RoutingKeyMismatch)
    );
}

#[test]
fn invalid_duplicate_and_unknown_state_responses_are_reported() {
    let (keys, members) = members(4);
    let membership = view(&members, 0);
    let snapshot = state(membership.clone(), 1, 1, 0);
    let response = sign(snapshot, &keys[0]);
    let expected = [
        keys[0].authority_id(),
        keys[1].authority_id(),
        keys[2].authority_id(),
    ];
    let StateResolution::RecoveryNeeded {
        best_matching,
        required,
        rejected_responses,
    } = resolve_authority_state(&membership, &expected, &[response.clone(), response])
        .expect("duplicate response is excluded")
    else {
        panic!("one unique response cannot form quorum");
    };
    assert_eq!(best_matching, 1);
    assert_eq!(required, 2);
    assert_eq!(rejected_responses.len(), 1);
    assert_eq!(
        rejected_responses[0].reason(),
        AuthorityError::UnexpectedOrDuplicateResponse
    );

    let outsider = AuthorityId::from_bytes([0xEE; 32]);
    assert_eq!(
        resolve_authority_state(
            &membership,
            &[outsider, keys[0].authority_id(), keys[1].authority_id()],
            &[]
        ),
        Err(AuthorityError::UnknownResponder)
    );
    assert_eq!(
        resolve_authority_state(
            &membership,
            &[
                keys[0].authority_id(),
                keys[0].authority_id(),
                keys[2].authority_id()
            ],
            &[]
        ),
        Err(AuthorityError::DuplicateMember)
    );
    assert_eq!(
        resolve_authority_state(
            &membership,
            &[keys[0].authority_id(), keys[1].authority_id()],
            &[]
        ),
        Err(AuthorityError::InvalidMembership)
    );
    assert_eq!(
        resolve_authority_state(
            &membership,
            &[
                keys[0].authority_id(),
                keys[1].authority_id(),
                keys[2].authority_id(),
                outsider,
                keys[3].authority_id(),
            ],
            &[]
        ),
        Err(AuthorityError::InvalidMembership)
    );
}

#[test]
fn unexpected_and_missing_state_responses_cannot_lower_the_quorum() {
    let (keys, members) = members(4);
    let membership = view(&members, 2);
    let matching = state(membership.clone(), 5, 12, 1);
    let expected = [
        keys[0].authority_id(),
        keys[1].authority_id(),
        keys[2].authority_id(),
    ];
    let unexpected = sign(matching.clone(), &keys[3]);
    let responses = [
        sign(matching.clone(), &keys[0]),
        sign(matching.clone(), &keys[1]),
        unexpected,
    ];
    let StateResolution::Quorum(quorum) =
        resolve_authority_state(&membership, &expected, &responses)
            .expect("unexpected reply is excluded")
    else {
        panic!("two valid expected replies satisfy the three-member quorum");
    };
    assert_eq!(quorum.matching_signers().len(), 2);
    assert_eq!(quorum.rejected_responses().len(), 1);
    assert_eq!(
        quorum.rejected_responses()[0].reason(),
        AuthorityError::UnknownResponder
    );

    let two_of_four = [sign(matching.clone(), &keys[0]), sign(matching, &keys[1])];
    assert_eq!(
        resolve_authority_state(
            &membership,
            &keys
                .iter()
                .map(AuthorityKeypair::authority_id)
                .collect::<Vec<_>>(),
            &two_of_four
        )
        .expect("missing replies are not a malformed request"),
        StateResolution::RecoveryNeeded {
            best_matching: 2,
            required: 3,
            rejected_responses: Vec::new(),
        }
    );
}

#[test]
fn mismatched_routing_key_state_is_reported_and_excluded() {
    let (keys, members) = members(4);
    let routing_key = RoutingKey::from_bytes([0xA5; 32]);
    let membership = view_for(routing_key, &members, 2);
    let wrong_key = RoutingKey::from_bytes([0x5A; 32]);
    let wrong_membership = view_for(wrong_key, &members, 2);
    let matching = state(membership.clone(), 5, 12, 1);
    let wrong_state = state(wrong_membership, 5, 12, 2);
    let expected = [
        keys[0].authority_id(),
        keys[1].authority_id(),
        keys[2].authority_id(),
    ];
    let responses = [
        sign(matching.clone(), &keys[0]),
        sign(matching.clone(), &keys[1]),
        sign(wrong_state, &keys[2]),
    ];
    let StateResolution::Quorum(quorum) =
        resolve_authority_state(&membership, &expected, &responses)
            .expect("one wrong-key response cannot poison matching states")
    else {
        panic!("two matching states still satisfy quorum");
    };
    assert_eq!(quorum.state(), &matching);
    assert_eq!(quorum.rejected_responses().len(), 1);
    assert_eq!(
        quorum.rejected_responses()[0].reason(),
        AuthorityError::RoutingKeyMismatch
    );
}

#[test]
fn invalid_signature_does_not_suppress_two_matching_valid_snapshots() {
    let (keys, members) = members(4);
    let membership = view(&members, 2);
    let matching = state(membership.clone(), 2, 8, 1);
    let mut invalid = sign(state(membership.clone(), 2, 8, 2), &keys[2]);
    invalid.signature[0] ^= 0x40;
    let responses = [
        sign(matching.clone(), &keys[0]),
        sign(matching.clone(), &keys[1]),
        invalid,
    ];
    let expected = [0, 1, 2].map(|index| keys[index].authority_id());
    let StateResolution::Quorum(quorum) =
        resolve_authority_state(&membership, &expected, &responses)
            .expect("invalid response is excluded from a valid quorum")
    else {
        panic!("two matching valid states out of three must initialize");
    };
    assert_eq!(quorum.state(), &matching);
    assert_eq!(quorum.rejected_responses().len(), 1);
    assert_eq!(
        quorum.rejected_responses()[0].reason(),
        AuthorityError::InvalidSignature
    );
    assert_eq!(
        quorum.rejected_responses()[0].signer(),
        keys[2].authority_id()
    );
}

#[test]
fn replacement_membership_is_versioned_and_selects_the_next_closest() {
    let (keys, known) = members(5);
    let routing_key = RoutingKey::from_bytes([0; 32]);
    let selected = select_authorities(&routing_key, &known).expect("unique contacts");
    let previous = MembershipView::new(routing_key, 8, selected.clone()).expect("four closest");
    let replacement_members: Vec<_> = selected
        .iter()
        .take(3)
        .copied()
        .chain(
            known
                .iter()
                .copied()
                .filter(|candidate| !selected.contains(candidate))
                .take(1),
        )
        .collect();
    let replacement = MembershipView::new(routing_key, 9, replacement_members)
        .expect("replacement view has four unique members");

    assert_eq!(previous.members().len(), 4);
    assert_eq!(replacement.generation(), previous.generation() + 1);
    assert_eq!(
        replacement
            .members()
            .iter()
            .filter(|member| previous.member(member.authority_id()).is_some())
            .count(),
        3
    );

    let initial = AuthorityState::new(routing_key, Epoch::new(1), previous.clone(), 4);
    let updated = AuthorityState::new(routing_key, Epoch::new(1), replacement.clone(), 5);
    let responses: Vec<_> = previous
        .members()
        .iter()
        .take(3)
        .map(|member| {
            let key = keys
                .iter()
                .find(|key| key.authority_id() == member.authority_id())
                .expect("old authority key exists");
            sign(updated.clone(), key)
        })
        .collect();
    let expected: Vec<_> = previous
        .members()
        .iter()
        .map(AuthorityMember::authority_id)
        .collect();
    let StateResolution::Quorum(quorum) = resolve_authority_state(&previous, &expected, &responses)
        .expect("overlap authorities signed the new view")
    else {
        panic!("three of four authorities must authorize the membership transition");
    };
    let mut replica = AuthorityReplica::new(initial).expect("initial state is canonical");
    assert_eq!(
        replica
            .apply_quorum(*quorum)
            .expect("membership transition is quorum-backed"),
        ApplyOutcome::Applied
    );
    assert_eq!(replica.state().membership_view(), &replacement);
}

#[test]
fn membership_views_reject_noncanonical_order() {
    let (_, known) = members(4);
    let routing_key = RoutingKey::from_bytes([0xA5; 32]);
    let mut selected = select_authorities(&routing_key, &known).expect("unique contacts");
    selected.reverse();
    assert_eq!(
        MembershipView::new(routing_key, 1, selected),
        Err(AuthorityError::NonCanonicalMembership)
    );
}

#[test]
fn authority_errors_have_diagnostic_display_messages() {
    let errors = [
        AuthorityError::InvalidMembership,
        AuthorityError::DuplicateMember,
        AuthorityError::NonCanonicalMembership,
        AuthorityError::InvalidPublicKey,
        AuthorityError::NotAMember,
        AuthorityError::UnknownResponder,
        AuthorityError::RoutingKeyMismatch,
        AuthorityError::StaleRequest,
        AuthorityError::UnexpectedOrDuplicateResponse,
        AuthorityError::InvalidSignature,
        AuthorityError::InvalidModeDescriptor,
        AuthorityError::StateComponentTooLarge,
        AuthorityError::MembershipMismatch,
        AuthorityError::StaleState,
        AuthorityError::ConflictingVersion,
        AuthorityError::NotEquivocation,
    ];
    for error in errors {
        assert!(!error.to_string().is_empty(), "{error:?}");
    }
}
