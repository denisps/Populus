#![allow(
    clippy::expect_used,
    reason = "a malformed test fixture must fail the test immediately"
)]

use super::{ContentBody, ContentError, MAX_CONTENT_SIZE, MutableRevision, SignedContent};
use populus_crypto::ProducerKeypair;
use populus_types::ContentId;
use serde_json::Value;
use std::collections::BTreeMap;

fn key(seed: u8) -> ProducerKeypair {
    ProducerKeypair::from_secret_key([seed; 32])
}

fn signed_content(body: ContentBody, signers: &[&ProducerKeypair]) -> SignedContent {
    SignedContent::sign(body, signers).expect("valid signed content fixture")
}

#[test]
fn canonical_body_is_stable_across_set_and_map_insertion_order() {
    let first = ContentId::from_digest([1; 32]);
    let second = ContentId::from_digest([2; 32]);
    let mut left = ContentBody::new(1_700_000_000_000, "text/plain", b"hello".to_vec());
    left.tags = vec![second, first];
    left.associations = vec![second, first];
    left.metadata = BTreeMap::from([("z-key".to_owned(), vec![2]), ("a-key".to_owned(), vec![1])]);
    let mut right = left.clone();
    right.tags.reverse();
    right.associations.reverse();
    right.metadata = BTreeMap::from([("a-key".to_owned(), vec![1]), ("z-key".to_owned(), vec![2])]);
    assert_eq!(
        left.canonical_bytes().expect("valid body"),
        right.canonical_bytes().expect("equivalent body")
    );
    let left_object = SignedContent::new(left, Vec::new()).expect("anonymous content");
    let right_object = SignedContent::new(right, Vec::new()).expect("anonymous content");
    assert!(left_object.cid().expect("cid") == right_object.cid().expect("cid"));
}

#[test]
fn immutable_content_cid_changes_with_body_and_anonymous_content_needs_no_signature() {
    let body = ContentBody::new(7, "text/plain", b"one".to_vec());
    let object = SignedContent::new(body.clone(), Vec::new()).expect("anonymous content");
    let round_trip = SignedContent::from_bytes(&object.canonical_bytes().expect("encoded object"))
        .expect("valid round trip");
    assert!(round_trip == object);
    let changed = SignedContent::new(
        ContentBody::new(7, "text/plain", b"two".to_vec()),
        Vec::new(),
    )
    .expect("anonymous content");
    assert!(object.cid().expect("cid") != changed.cid().expect("cid"));
}

#[test]
fn content_references_use_canonical_dag_cbor_link_encoding() {
    let content_id = ContentId::from_digest([3; 32]);
    let mut body = ContentBody::new(0, "text/plain", Vec::new());
    body.tags.push(content_id);
    body.associations.push(content_id);
    let encoded = body.canonical_bytes().expect("valid linked body");
    let mut expected = vec![0x88, 0x01, 0x00, 0x6a];
    expected.extend_from_slice(b"text/plain");
    expected.extend_from_slice(&[0x40, 0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00]);
    expected.extend_from_slice(content_id.as_bytes());
    expected.extend_from_slice(&[0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00]);
    expected.extend_from_slice(content_id.as_bytes());
    expected.extend_from_slice(&[0x80, 0x80]);
    assert_eq!(encoded, expected);
    assert!(ContentBody::from_bytes(&encoded).is_ok());

    let mut invalid_link = encoded;
    let tag_offset = invalid_link
        .windows(2)
        .position(|window| window == [0xd8, 0x2a])
        .expect("encoded link tag");
    invalid_link[tag_offset] = 0xd9;
    assert!(matches!(
        ContentBody::from_bytes(&invalid_link),
        Err(ContentError::InvalidEncoding)
    ));
}

#[test]
fn producer_signatures_verify_and_modified_body_is_rejected() {
    let signer = key(3);
    let mut body = ContentBody::new(9, "text/plain", b"signed".to_vec());
    body.producers = vec![signer.producer_id()];
    let object = signed_content(body.clone(), &[&signer]);
    assert!(object.verify().is_ok());
    let encoded = object.canonical_bytes().expect("signed encoding");
    let decoded = SignedContent::from_bytes(&encoded).expect("verify decoded signature");
    assert!(decoded == object);
    let mut modified_signature = encoded;
    let last_byte = modified_signature.len() - 1;
    modified_signature[last_byte] ^= 1;
    assert!(matches!(
        SignedContent::from_bytes(&modified_signature),
        Err(ContentError::InvalidSignature)
    ));

    body.payload[0] ^= 1;
    assert!(matches!(
        SignedContent::new(body, object.signatures().to_vec()),
        Err(ContentError::InvalidSignature)
    ));
}

#[test]
fn multiple_producers_sign_the_same_canonical_body() {
    let first = key(1);
    let second = key(2);
    let mut body = ContentBody::new(11, "application/octet-stream", vec![0, 1, 2]);
    body.producers = vec![second.producer_id(), first.producer_id()];
    let object = signed_content(body, &[&second, &first]);
    assert_eq!(object.signatures().len(), 2);
    assert!(object.verify().is_ok());
    assert!(
        object.body().producers[0] < object.body().producers[1],
        "producer set is canonical"
    );
}

#[test]
fn mutable_revision_chain_is_immutable_and_monotonic() {
    let genesis = MutableRevision::genesis(
        SignedContent::new(
            ContentBody::new(1, "text/plain", b"v1".to_vec()),
            Vec::new(),
        )
        .expect("anonymous genesis"),
    )
    .expect("genesis revision");
    let next = MutableRevision::next(
        &genesis,
        SignedContent::new(
            ContentBody::new(2, "text/plain", b"v2".to_vec()),
            Vec::new(),
        )
        .expect("anonymous next body"),
    )
    .expect("next revision");
    assert!(next.validate_successor(&genesis).is_ok());
    assert_eq!(next.sequence(), 1);
    let decoded = MutableRevision::from_bytes(&next.canonical_bytes().expect("encoded revision"))
        .expect("valid revision");
    assert!(decoded == next);
    assert!(genesis.cid().expect("cid") != next.cid().expect("cid"));
    assert!(genesis.mutable_id() == next.mutable_id());

    let invalid = MutableRevision {
        sequence: 2,
        ..next.clone()
    };
    assert_eq!(
        invalid.validate_successor(&genesis),
        Err(ContentError::InvalidRevisionChain)
    );
}

#[test]
fn body_decoders_reject_malformed_oversized_and_noncanonical_bytes() {
    assert!(matches!(
        ContentBody::from_bytes(&vec![0; MAX_CONTENT_SIZE + 1]),
        Err(ContentError::ContentTooLarge)
    ));
    assert!(matches!(
        ContentBody::from_bytes(&[0x9f, 0xff]),
        Err(ContentError::InvalidEncoding)
    ));
    let noncanonical_body = [
        0x98, 0x08, 0x01, 0x00, 0x6a, b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i', b'n',
        0x40, 0x80, 0x80, 0x80, 0x80,
    ];
    assert!(matches!(
        ContentBody::from_bytes(&noncanonical_body),
        Err(ContentError::NonCanonicalEncoding)
    ));
    let mut oversized_list = vec![0x88, 0x01, 0x00, 0x6a];
    oversized_list.extend_from_slice(b"text/plain");
    oversized_list.extend_from_slice(&[0x40, 0x99, 0x01, 0x01]);
    assert!(matches!(
        ContentBody::from_bytes(&oversized_list),
        Err(ContentError::FieldTooLarge)
    ));
}

#[test]
fn producer_list_must_match_signature_identities() {
    let signer = key(7);
    let body = ContentBody::new(12, "text/plain", vec![]);
    let result = SignedContent::sign(body, &[&signer]);
    assert!(matches!(
        result,
        Err(ContentError::ProducerSignatureMismatch)
    ));

    let signers = (0..=super::MAX_SIGNATURES)
        .map(|seed| key(u8::try_from(seed).expect("signature limit fits in u8")))
        .collect::<Vec<_>>();
    let signers = signers.iter().collect::<Vec<_>>();
    assert!(matches!(
        SignedContent::sign(ContentBody::new(12, "text/plain", vec![]), &signers),
        Err(ContentError::FieldTooLarge)
    ));
}

fn content_vector() -> Value {
    serde_json::from_str(include_str!("../../../testvectors/content-v1.json"))
        .expect("valid content test vector")
}

fn required_string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .expect("required string in content test vector")
}

fn required_u64(value: &Value, key: &str) -> u64 {
    value
        .get(key)
        .and_then(Value::as_u64)
        .expect("required integer in content test vector")
}

fn decode_hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0, "test vector hex must have even length");
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty(), "test vector hex must be complete");
    pairs
        .iter()
        .map(|[high, low]| Some((hex_nibble(*high)? << 4) | hex_nibble(*low)?))
        .collect::<Option<Vec<_>>>()
        .expect("test vector uses lowercase hexadecimal")
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[test]
fn content_and_signature_match_language_independent_v1_vector() {
    let vector = content_vector();
    assert_eq!(
        vector.get("schema").and_then(Value::as_str),
        Some("populus-content-v1")
    );
    let seed: [u8; 32] = decode_hex(required_string(&vector, "secret_seed"))
        .try_into()
        .expect("32-byte seed in test vector");
    let signer = ProducerKeypair::from_secret_key(seed);
    let mut body = ContentBody::new(
        required_u64(&vector, "created_at_unix_ms"),
        required_string(&vector, "media_type"),
        required_string(&vector, "payload_utf8").as_bytes().to_vec(),
    );
    body.producers = vec![signer.producer_id()];
    let object = signed_content(body.clone(), &[&signer]);
    let revision = MutableRevision::genesis(object.clone()).expect("genesis");
    assert_eq!(
        encode_hex(&body.canonical_bytes().expect("body")),
        required_string(&vector, "body_cbor")
    );
    assert_eq!(
        encode_hex(&signer.public_key()),
        required_string(&vector, "public_key")
    );
    assert_eq!(
        signer.producer_id().to_string(),
        required_string(&vector, "producer_id")
    );
    assert_eq!(
        encode_hex(object.signatures()[0].signature()),
        required_string(&vector, "signature")
    );
    assert_eq!(
        encode_hex(&object.canonical_bytes().expect("object")),
        required_string(&vector, "signed_cbor")
    );
    assert_eq!(
        object.cid().expect("cid").to_string(),
        required_string(&vector, "content_cid")
    );
    assert_eq!(
        revision.mutable_id().to_string(),
        required_string(&vector, "mutable_content_id")
    );
    assert_eq!(
        encode_hex(&revision.canonical_bytes().expect("revision")),
        required_string(&vector, "revision_cbor")
    );
    assert_eq!(
        revision.cid().expect("revision cid").to_string(),
        required_string(&vector, "revision_cid")
    );
}
