#![allow(clippy::cast_precision_loss, clippy::expect_used, clippy::panic)]

use super::{
    DailyPopularityStatus, DirectIngestError, DirectIngestPolicy, DirectIngestState, DirectVote,
    PersistentLike, SignedDirectVoteAck,
};
use crate::{AuthorityKeypair, AuthorityMember, MembershipView, select_authorities};
use populus_types::{ClientId, ContentId, DailyVoteId, NodeId, UtcDay};
use std::collections::BTreeSet;

const DAY_MS: i64 = 86_400_000;

fn content(byte: u8) -> ContentId {
    ContentId::from_digest([byte; 32])
}

fn client(byte: u8) -> ClientId {
    ClientId::from_bytes([byte; 32])
}

fn policy(max_rate: u64, grace_ms: u64, skew_ms: u64) -> DirectIngestPolicy {
    DirectIngestPolicy::new(max_rate, grace_ms, skew_ms).expect("nonzero direct rate")
}

fn vote(content_id: ContentId, client_id: ClientId, day: UtcDay) -> DirectVote {
    DirectVote::new(content_id, client_id, day)
}

fn make_membership(
    content_id: ContentId,
    generation: u64,
    key_offset: u8,
) -> (MembershipView, Vec<AuthorityKeypair>) {
    let keys: Vec<_> = (0..4)
        .map(|index| AuthorityKeypair::from_secret_key([key_offset + index + 1; 32]))
        .collect();
    let members: Vec<_> = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            let node_byte = key_offset + u8::try_from(index).expect("four fixture members") + 1;
            AuthorityMember::new(NodeId::from_bytes([node_byte; 32]), key.public_key())
                .expect("generated public key is valid")
        })
        .collect();
    let routing_key =
        DirectIngestState::new(content_id, UtcDay::new(0), policy(1, 0, 0)).routing_key();
    let membership = MembershipView::new(
        routing_key,
        generation,
        select_authorities(&routing_key, &members).expect("fixture members are unique"),
    )
    .expect("fixture membership is canonical");
    (membership, keys)
}

fn signed_ack(
    vote: DirectVote,
    membership: &MembershipView,
    keys: &[AuthorityKeypair],
    authority_index: usize,
) -> SignedDirectVoteAck {
    let authority_id = membership.members()[authority_index].authority_id();
    let key = keys
        .iter()
        .find(|key| key.authority_id() == authority_id)
        .expect("fixture member has a signing key");
    SignedDirectVoteAck::sign(vote, membership, key).expect("member can sign its vote ack")
}

#[test]
fn duplicate_retries_are_idempotent_and_rate_target_is_advisory() {
    let content_id = content(1);
    let day = UtcDay::new(0);
    let mut state = DirectIngestState::new(content_id, day, policy(2, 1_000, 100));
    let retry = vote(content_id, client(7), day);

    let first = state
        .record_vote(retry, 1_000)
        .expect("first delivery accepted");
    let duplicate = state
        .record_vote(retry, 1_001)
        .expect("retry remains accepted");
    assert_eq!(first.provisional_estimate, 1.0);
    assert_eq!(duplicate.provisional_estimate, 1.0);
    assert_eq!(duplicate.current_minute_deliveries, 2);
    assert!(!duplicate.delegation_recommended);

    let third = state
        .record_vote(vote(content_id, client(8), day), 1_002)
        .expect("direct mode keeps accepting above its advisory target");
    assert_eq!(third.provisional_estimate, 2.0);
    assert!(third.delegation_recommended);

    let exact_oracle: BTreeSet<_> = [client(7), client(7), client(8)].into_iter().collect();
    assert_eq!(state.estimate(), exact_oracle.len() as f64);
}

#[test]
fn vote_scope_and_authority_clock_window_are_validated() {
    let content_id = content(2);
    let day = UtcDay::new(4);
    let mut state = DirectIngestState::new(content_id, day, policy(1_000, 1_000, 100));
    assert_eq!(
        state.record_vote(vote(content(3), client(1), day), 4 * DAY_MS),
        Err(DirectIngestError::WrongContent)
    );
    assert_eq!(
        state.record_vote(vote(content_id, client(1), UtcDay::new(5)), 4 * DAY_MS),
        Err(DirectIngestError::WrongDay)
    );
    assert_eq!(
        state.record_vote(
            vote(content_id, client(1), day),
            day.start_unix_millis().expect("day start") - 101
        ),
        Err(DirectIngestError::VoteOutsideAcceptanceWindow)
    );

    let mut malformed = vote(content_id, client(1), day);
    malformed.daily_vote_id = DailyVoteId::from_bytes([0xFF; 32]);
    assert_eq!(
        state.record_vote(malformed, 4 * DAY_MS),
        Err(DirectIngestError::InvalidVoteId)
    );
}

#[test]
fn late_votes_are_provisional_until_grace_and_skew_expire() {
    let content_id = content(4);
    let day = UtcDay::new(0);
    let policy = policy(1_000, 1_000, 100);
    let finalize_at = DAY_MS + 1_100;
    let mut state = DirectIngestState::new(content_id, day, policy);

    state
        .record_vote(vote(content_id, client(1), day), DAY_MS + 1_099)
        .expect("late vote inside close grace is accepted");
    assert_eq!(
        state
            .finalize(finalize_at - 1)
            .expect("time is representable"),
        DailyPopularityStatus::Provisional { estimate: 1.0 }
    );
    assert_eq!(
        state.finalize(finalize_at).expect("time is representable"),
        DailyPopularityStatus::Finalized { estimate: 1.0 }
    );
    assert_eq!(
        state.record_vote(vote(content_id, client(2), day), finalize_at - 1),
        Err(DirectIngestError::EpochFinalized)
    );
    assert_eq!(
        state.record_vote(vote(content_id, client(2), day), finalize_at),
        Err(DirectIngestError::EpochFinalized)
    );
}

#[test]
fn persistent_like_retries_until_ack_and_skips_days_offline() {
    let content_id = content(5);
    let first_day = UtcDay::new(10);
    let next_day = UtcDay::new(11);
    let (membership, keys) = make_membership(content_id, 1, 0);
    let mut like = PersistentLike::new(content_id, true);

    let first = like
        .vote_when_online(client(9), first_day, &membership)
        .expect("membership matches the content")
        .expect("online liked client emits today's vote");
    assert_eq!(like.pending_authorities().len(), 4);
    assert_eq!(
        like.vote_when_online(client(9), next_day, &membership),
        Ok(Some(first)),
        "a later UTC day does not discard an unacknowledged vote"
    );
    let first_ack = signed_ack(first, &membership, &keys, 0);
    println!(
        "vote_wire={} ack_message={} ack_wire={}",
        hex(&first.canonical_bytes()),
        hex(&first_ack.message()),
        hex(&first_ack.canonical_bytes())
    );
    assert!(
        !like
            .acknowledge(&first_ack, &membership)
            .expect("first authority is in the pinned membership")
    );
    assert!(
        !like
            .acknowledge(&first_ack, &membership)
            .expect("duplicate authority acknowledgement is harmless")
    );
    let restored = PersistentLike::deserialize(&like.serialize())
        .expect("partial acknowledgement state survives a local restart");
    assert_eq!(restored.pending_authorities().len(), 3);
    let (conflicting_view, _) = make_membership(content_id, 1, 10);
    assert_eq!(
        like.vote_when_online(client(9), first_day, &conflicting_view),
        Err(DirectIngestError::MembershipGenerationConflict)
    );
    let (stale_view, _) = make_membership(content_id, 0, 0);
    assert_eq!(
        like.vote_when_online(client(9), first_day, &stale_view),
        Err(DirectIngestError::StaleMembership)
    );
    for authority_index in 1..3 {
        let acknowledgement = signed_ack(first, &membership, &keys, authority_index);
        assert!(
            !like
                .acknowledge(&acknowledgement, &membership)
                .expect("authority is in the pinned membership")
        );
    }

    let (replacement, replacement_keys) = make_membership(content_id, 2, 10);
    assert_eq!(
        like.vote_when_online(client(9), first_day, &replacement),
        Ok(Some(first)),
        "membership replacement retries the same daily vote"
    );
    assert_eq!(like.pending_authorities().len(), 4);
    assert_eq!(
        like.acknowledge(&first_ack, &membership),
        Err(DirectIngestError::UnexpectedAcknowledgement),
        "the old membership's acknowledgement cannot complete the new view"
    );
    for authority_index in 0..4 {
        let acknowledgement = signed_ack(first, &replacement, &replacement_keys, authority_index);
        let completed = like
            .acknowledge(&acknowledgement, &replacement)
            .expect("replacement authority has a valid signed acknowledgement");
        assert_eq!(completed, authority_index == 3);
    }
    assert_eq!(like.pending_authorities(), []);

    let mut restored = PersistentLike::deserialize(&like.serialize())
        .expect("pending retry state survives a local restart");
    assert_eq!(
        restored.vote_when_online(client(9), first_day, &replacement),
        Ok(None)
    );
    assert_eq!(
        like.vote_when_online(client(9), first_day, &replacement),
        Ok(None),
        "all four authority acknowledgements complete today's vote"
    );

    let after_offline_day = like
        .vote_when_online(client(9), next_day, &replacement)
        .expect("membership matches the content")
        .expect("client returning online votes for the current day only");
    assert_eq!(after_offline_day.day(), next_day);
    like.set_liked(false);
    assert_eq!(
        like.vote_when_online(client(9), UtcDay::new(12), &replacement),
        Ok(None)
    );
    assert_eq!(
        like.acknowledge(&first_ack, &membership),
        Err(DirectIngestError::UnexpectedAcknowledgement)
    );
}

#[test]
fn direct_vote_and_signed_ack_match_the_v1_wire_vector() {
    let field = |name: &str| {
        include_str!("../../../../testvectors/direct-vote-ack-v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing direct-vote vector field {name}"))
    };
    let content_bytes = decode_hex(field("content_id"));
    let content_id =
        ContentId::try_from(content_bytes.as_slice()).expect("vector content ID is valid");
    let client_bytes = decode_hex(field("client_id"));
    let client_id = ClientId::from_bytes(
        client_bytes
            .as_slice()
            .try_into()
            .expect("vector client ID is 32 bytes"),
    );
    let day_bytes = decode_hex(field("utc_day"));
    let day = UtcDay::from_bytes(
        day_bytes
            .as_slice()
            .try_into()
            .expect("vector UTC day is eight bytes"),
    );
    let vote = DirectVote::new(content_id, client_id, day);
    assert_eq!(vote.daily_vote_id().to_string(), field("daily_vote_id"));
    assert_eq!(hex(&vote.canonical_bytes()), field("vote_wire"));
    assert_eq!(DirectVote::deserialize(&vote.canonical_bytes()), Ok(vote));

    let (membership, keys) = make_membership(content_id, 1, 0);
    assert_eq!(
        hex(&membership.generation().to_be_bytes()),
        field("membership_generation")
    );
    let acknowledgement = signed_ack(vote, &membership, &keys, 0);
    assert_eq!(hex(&acknowledgement.message()), field("ack_message"));
    assert_eq!(hex(&acknowledgement.canonical_bytes()), field("ack_wire"));
    let decoded = SignedDirectVoteAck::deserialize(&acknowledgement.canonical_bytes())
        .expect("signed acknowledgement wire bytes decode");
    assert_eq!(decoded, acknowledgement);
    decoded
        .verify(&membership)
        .expect("vector signature matches the membership key");

    let signer = keys
        .iter()
        .find(|key| key.authority_id() == acknowledgement.signer())
        .expect("ack signer exists");
    let mut state = DirectIngestState::new(content_id, day, policy(1_000, 1_000, 100));
    let (outcome, accepted_ack) = state
        .record_vote_and_acknowledge(
            vote,
            day.start_unix_millis().expect("day start") + 1,
            &membership,
            signer,
        )
        .expect("authority records and acknowledges its accepted vote");
    assert_eq!(outcome.provisional_estimate, 1.0);
    assert_eq!(accepted_ack, acknowledgement);

    let outsider = AuthorityKeypair::from_secret_key([0xFE; 32]);
    let mut untouched = DirectIngestState::new(content_id, day, policy(1_000, 1_000, 100));
    assert_eq!(
        untouched.record_vote_and_acknowledge(
            vote,
            day.start_unix_millis().expect("day start") + 1,
            &membership,
            &outsider,
        ),
        Err(DirectIngestError::UnexpectedAcknowledgement)
    );
    assert_eq!(untouched.estimate(), 0.0);
}

#[test]
fn empty_direct_state_matches_the_canonical_v1_vector() {
    let field = |name: &str| {
        include_str!("../../../../testvectors/direct-ingest-v1.txt")
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_else(|| panic!("missing direct-ingest vector field {name}"))
    };
    let content_bytes = decode_hex(field("content_id"));
    let content_id =
        ContentId::try_from(content_bytes.as_slice()).expect("vector content identifier is valid");
    let day_bytes = decode_hex(field("utc_day"));
    let day = UtcDay::from_bytes(
        day_bytes
            .as_slice()
            .try_into()
            .expect("vector UTC day uses eight bytes"),
    );
    let policy = DirectIngestPolicy::new(
        field("max_direct_votes_per_minute")
            .parse()
            .expect("rate field is numeric"),
        field("close_grace_period_ms")
            .parse()
            .expect("grace field is numeric"),
        field("max_clock_skew_ms")
            .parse()
            .expect("skew field is numeric"),
    )
    .expect("vector policy is valid");
    let state = DirectIngestState::new(content_id, day, policy);
    assert_eq!(
        hex(&state.serialize().expect("empty state fits")),
        field("empty_state")
    );
}

#[test]
fn direct_state_decoder_rejects_truncation_and_oversized_input() {
    assert_eq!(
        DirectIngestState::deserialize(b"PDIR"),
        Err(DirectIngestError::InvalidStateEncoding)
    );
    assert_eq!(
        DirectIngestState::deserialize(&vec![0; 1_048_577]),
        Err(DirectIngestError::StateTooLarge)
    );
}

#[test]
fn unrepresentable_day_bounds_are_rejected_before_serialization() {
    let state = DirectIngestState::new(content(7), UtcDay::new(i64::MAX), policy(1, 0, 0));
    assert_eq!(state.serialize(), Err(DirectIngestError::TimeOutOfRange));
}

#[test]
fn decoder_rejects_rate_state_outside_the_daily_acceptance_window() {
    let content_id = content(8);
    let day = UtcDay::new(0);
    let mut state = DirectIngestState::new(content_id, day, policy(1_000, 1_000, 100));
    state
        .record_vote(vote(content_id, client(1), day), 1_000)
        .expect("vote creates valid rate state");
    let mut encoded = state.serialize().expect("state is bounded");
    encoded[75..83].copy_from_slice(&i64::MAX.to_be_bytes());
    assert_eq!(
        DirectIngestState::deserialize(&encoded),
        Err(DirectIngestError::InvalidStateEncoding)
    );
}

#[test]
fn serialized_state_survives_authority_restart_and_preserves_retry_idempotency() {
    let content_id = content(6);
    let day = UtcDay::new(2);
    let mut state = DirectIngestState::new(content_id, day, policy(1_000, 5_000, 500));
    let retry = vote(content_id, client(12), day);
    state
        .record_vote(retry, 2 * DAY_MS + 2_000)
        .expect("vote accepted before simulated authority crash");
    let encoded = state.serialize().expect("state fits authority component");
    let mut restarted = DirectIngestState::deserialize(&encoded).expect("authority state decodes");
    assert_eq!(restarted, state);

    let duplicate = restarted
        .record_vote(retry, 2 * DAY_MS + 2_001)
        .expect("retry after restart is idempotent");
    assert_eq!(duplicate.provisional_estimate, 1.0);
    assert_eq!(restarted.estimate(), 1.0);

    let mut truncated = encoded;
    truncated.pop();
    assert_eq!(
        DirectIngestState::deserialize(&truncated),
        Err(DirectIngestError::InvalidStateEncoding)
    );
}

#[test]
fn a_zero_rate_target_is_rejected() {
    assert_eq!(
        DirectIngestPolicy::new(0, 0, 0),
        Err(DirectIngestError::InvalidPolicy)
    );
}

fn decode_hex(text: &str) -> Vec<u8> {
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    pairs
        .iter()
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).expect("hex high nibble");
            let low = char::from(pair[1]).to_digit(16).expect("hex low nibble");
            u8::try_from(high * 16 + low).expect("one byte")
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}
