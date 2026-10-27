//! Versioned, domain-separated identifier derivations for Populus.

use populus_types::{
    AuthorityId, ClientId, ContentId, MutableContentId, NetworkIdentity, NodeId, ProducerId,
    RoutingKey,
};
use sha2::{Digest, Sha256};
use std::fmt;

const NODE_DOMAIN: &[u8] = b"populus/node/v1";
const CLIENT_DOMAIN: &[u8] = b"populus/client/v1";
const ROUTING_DOMAIN: &[u8] = b"populus/routing/v1";
const PRODUCER_DOMAIN: &[u8] = b"populus/producer/v1";
const AUTHORITY_DOMAIN: &[u8] = b"populus/authority/v1";
const MUTABLE_DOMAIN: &[u8] = b"populus/mutable/v1";

fn encoded_length<const N: usize>(length: usize) -> [u8; N] {
    let mut encoded = [0; N];
    for (destination, source) in encoded
        .iter_mut()
        .rev()
        .zip(length.to_be_bytes().iter().rev())
    {
        *destination = *source;
    }
    encoded
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(encoded_length::<1>(domain.len()));
    hasher.update(domain);
    hasher.update(encoded_length::<4>(payload.len()));
    hasher.update(payload);
    hasher.finalize().into()
}

/// Derives a node's Populus DHT position from the canonical v1 scarcity identity.
#[must_use]
pub fn node_id(identity: &NetworkIdentity) -> NodeId {
    NodeId::from_bytes(domain_hash(NODE_DOMAIN, identity.as_bytes()))
}

/// Derives a voting identity from the same scarcity source under the separate ID-001 domain.
#[must_use]
pub fn client_id(identity: &NetworkIdentity) -> ClientId {
    ClientId::from_bytes(domain_hash(CLIENT_DOMAIN, identity.as_bytes()))
}

/// Logical routing identifier category, serialized as a one-byte v1 tag.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RoutingKind {
    /// Immutable v1 `ContentId`, tagged `0x01`.
    Content = 0x01,
    /// Stable v1 `MutableContentId`, tagged `0x02`.
    MutableContent = 0x02,
}

/// A typed logical identifier accepted as input to [`routing_key`].
///
/// The variants prevent callers from hashing untyped bytes or pairing a kind
/// tag with an identifier from a different domain.
#[derive(Clone, Copy)]
pub enum RoutingIdentifier<'a> {
    /// Route to an immutable content CID.
    Content(&'a ContentId),
    /// Route to a stable mutable-content identity.
    MutableContent(&'a MutableContentId),
}

/// Derives a fixed-width routing key from a typed logical identifier.
#[must_use]
pub fn routing_key(identifier: RoutingIdentifier<'_>) -> RoutingKey {
    let mut payload = [0; 37];
    let payload_length = match identifier {
        RoutingIdentifier::Content(content_id) => {
            payload[0] = RoutingKind::Content as u8;
            payload[1..].copy_from_slice(content_id.as_bytes());
            37
        }
        RoutingIdentifier::MutableContent(mutable_id) => {
            payload[0] = RoutingKind::MutableContent as u8;
            payload[1..33].copy_from_slice(mutable_id.as_bytes());
            33
        }
    };
    RoutingKey::from_bytes(domain_hash(ROUTING_DOMAIN, &payload[..payload_length]))
}

/// Public-key algorithm identifiers supported by v1 producer and authority IDs.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PublicKeyAlgorithm {
    /// Ed25519 public keys, exactly 32 bytes, tagged `0x01`.
    Ed25519 = 0x01,
}

/// Invalid input to a public-key identifier derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Ed25519 keys must contain exactly 32 bytes.
    InvalidPublicKeyLength {
        /// Required public-key byte length.
        expected: usize,
        /// Supplied public-key byte length.
        actual: usize,
    },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublicKeyLength { expected, actual } => {
                write!(
                    formatter,
                    "expected {expected}-byte public key, got {actual} bytes"
                )
            }
        }
    }
}

impl std::error::Error for CryptoError {}

fn key_payload(algorithm: PublicKeyAlgorithm, public_key: &[u8]) -> Result<[u8; 33], CryptoError> {
    if public_key.len() != 32 {
        return Err(CryptoError::InvalidPublicKeyLength {
            expected: 32,
            actual: public_key.len(),
        });
    }
    let mut payload = [0; 33];
    payload[0] = algorithm as u8;
    payload[1..].copy_from_slice(public_key);
    Ok(payload)
}

/// Derives an authorship identity from an algorithm tag and its public key.
///
/// This function identifies the key; it does not sign messages or validate key
/// material beyond enforcing the v1 Ed25519 public-key width.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKeyLength`] unless the public key is 32 bytes.
pub fn producer_id(
    algorithm: PublicKeyAlgorithm,
    public_key: &[u8],
) -> Result<ProducerId, CryptoError> {
    let payload = key_payload(algorithm, public_key)?;
    Ok(ProducerId::from_bytes(domain_hash(
        PRODUCER_DOMAIN,
        &payload,
    )))
}

/// Derives an authority signing-key identity under a domain distinct from `ProducerId`.
///
/// This function identifies the key; it does not sign messages or validate key
/// material beyond enforcing the v1 Ed25519 public-key width.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidPublicKeyLength`] unless the public key is 32 bytes.
pub fn authority_id(
    algorithm: PublicKeyAlgorithm,
    public_key: &[u8],
) -> Result<AuthorityId, CryptoError> {
    let payload = key_payload(algorithm, public_key)?;
    Ok(AuthorityId::from_bytes(domain_hash(
        AUTHORITY_DOMAIN,
        &payload,
    )))
}

/// Derives a stable mutable-object identity from its genesis revision CID.
#[must_use]
pub fn mutable_content_id(genesis_revision: &ContentId) -> MutableContentId {
    MutableContentId::from_bytes(domain_hash(MUTABLE_DOMAIN, genesis_revision.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{
        CryptoError, PublicKeyAlgorithm, RoutingIdentifier, authority_id, client_id,
        mutable_content_id, node_id, producer_id, routing_key,
    };
    use populus_types::{ContentId, NetworkIdentity};
    use proptest::prelude::*;
    use proptest::test_runner::{Config as ProptestConfig, RngSeed};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn vector_file() -> Value {
        let vectors = serde_json::from_str(include_str!("../../../testvectors/ids-v1.json"))
            .unwrap_or(Value::Null);
        assert_eq!(
            vectors.get("schema").and_then(Value::as_str),
            Some("populus-identifiers-v1")
        );
        vectors
    }

    fn required_value<'a>(value: &'a Value, key: &str) -> &'a Value {
        let field = value.get(key);
        assert!(field.is_some(), "missing vector field {key}");
        field.unwrap_or(value)
    }

    fn required_string<'a>(value: &'a Value, key: &str) -> &'a str {
        let field = value.get(key).and_then(Value::as_str);
        assert!(field.is_some(), "missing string vector field {key}");
        field.unwrap_or_default()
    }

    fn required_array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
        let field = value.get(key).and_then(Value::as_array);
        assert!(field.is_some(), "missing array vector field {key}");
        field.map_or(&[], Vec::as_slice)
    }

    #[test]
    fn network_vectors_check_normalization_and_both_hash_domains() {
        let vectors = vector_file();
        let entries = required_array(&vectors, "network_identities");
        assert_ne!(entries.len(), 0);

        for vector in entries {
            let input = required_string(vector, "input");
            let parsed = input.parse::<IpAddr>();
            assert!(parsed.is_ok(), "vector address must parse: {input}");
            if let Ok(address) = parsed {
                let actual = NetworkIdentity::from_ip(address);
                if let Some(expected_error) = vector.get("rejection").and_then(Value::as_str) {
                    assert!(actual.is_err(), "expected {input} to be rejected");
                    if let Err(error) = actual {
                        assert_eq!(error_code(error), expected_error, "{input}");
                    }
                } else {
                    assert!(actual.is_ok(), "expected {input} to normalize");
                    if let Ok(identity) = actual {
                        verify_network_vector(vector, input, identity);
                    }
                }
            }
        }
    }

    #[test]
    fn content_and_mutable_vectors_match_independent_sha256_oracle() {
        let vectors = vector_file();
        let content = required_value(&vectors, "content_id");
        let digest = decode_hex(required_string(content, "digest"));
        assert_eq!(digest.len(), 32);
        let digest = <[u8; 32]>::try_from(digest.as_slice());
        assert!(digest.is_ok());
        if let Ok(digest) = digest {
            let content_id = ContentId::from_digest(digest);
            let content_hex = required_string(content, "cid");
            assert_eq!(content_id.to_string(), content_hex);
            verify_mutable_vector(&vectors, content, &content_id, content_hex);
            verify_routing_vectors(&vectors, &content_id, content_hex);
        }
    }

    fn verify_mutable_vector(
        vectors: &Value,
        content: &Value,
        content_id: &ContentId,
        content_hex: &str,
    ) {
        let mutable = required_value(vectors, "mutable_content");
        let mutable_expected = required_string(mutable, "mutable_id");
        assert_eq!(
            hex(&oracle_domain_hash(
                b"populus/mutable/v1",
                content_id.as_bytes(),
            )),
            mutable_expected
        );
        let mutable_id = mutable_content_id(content_id);
        assert_eq!(mutable_id.to_string(), mutable_expected);
        assert_eq!(
            mutable.get("genesis_cid").and_then(Value::as_str),
            Some(content_hex)
        );
        assert_eq!(
            content.get("cid").and_then(Value::as_str),
            Some(content_hex)
        );
    }

    #[test]
    fn producer_and_authority_vectors_match_independent_sha256_oracle() {
        let vectors = vector_file();
        let public_key = required_value(&vectors, "public_key");
        assert_eq!(required_string(public_key, "algorithm"), "ed25519");
        assert_eq!(required_string(public_key, "tag"), "01");
        let key = decode_hex(required_string(public_key, "bytes"));
        assert_eq!(key.len(), 32);
        let mut key_payload = [0; 33];
        key_payload[0] = 0x01;
        if let Ok(key_bytes) = <[u8; 32]>::try_from(key.as_slice()) {
            key_payload[1..].copy_from_slice(&key_bytes);
        }
        let producer_expected = required_string(public_key, "producer_id");
        let authority_expected = required_string(public_key, "authority_id");
        assert_eq!(
            hex(&oracle_domain_hash(b"populus/producer/v1", &key_payload)),
            producer_expected
        );
        assert_eq!(
            hex(&oracle_domain_hash(b"populus/authority/v1", &key_payload)),
            authority_expected
        );
        assert_eq!(
            producer_id(PublicKeyAlgorithm::Ed25519, &key)
                .map(|id| id.to_string())
                .unwrap_or_default(),
            producer_expected
        );
        assert_eq!(
            authority_id(PublicKeyAlgorithm::Ed25519, &key)
                .map(|id| id.to_string())
                .unwrap_or_default(),
            authority_expected
        );
    }

    fn verify_routing_vectors(vectors: &Value, content_id: &ContentId, content_hex: &str) {
        let routing_vectors = required_array(vectors, "routing_keys");
        assert_ne!(routing_vectors.len(), 0);
        let mutable_id = mutable_content_id(content_id);
        let mutable_expected = mutable_id.to_string();
        for vector in routing_vectors {
            let kind = required_string(vector, "kind");
            let key_expected = required_string(vector, "routing_key");
            if kind == "content" {
                let mut payload = [0; 37];
                payload[0] = 0x01;
                payload[1..].copy_from_slice(content_id.as_bytes());
                assert_eq!(
                    hex(&oracle_domain_hash(b"populus/routing/v1", &payload)),
                    key_expected
                );
                assert_eq!(
                    routing_key(RoutingIdentifier::Content(content_id)).to_string(),
                    key_expected
                );
                assert_eq!(required_string(vector, "identifier"), content_hex);
            } else {
                assert_eq!(kind, "mutable_content", "unsupported routing kind");
                let mut payload = [0; 33];
                payload[0] = 0x02;
                payload[1..].copy_from_slice(mutable_id.as_bytes());
                assert_eq!(
                    hex(&oracle_domain_hash(b"populus/routing/v1", &payload)),
                    key_expected
                );
                assert_eq!(
                    routing_key(RoutingIdentifier::MutableContent(&mutable_id)).to_string(),
                    key_expected
                );
                assert_eq!(required_string(vector, "identifier"), mutable_expected);
            }
        }
    }

    fn verify_network_vector(vector: &Value, input: &str, identity: NetworkIdentity) {
        let encoding = required_string(vector, "encoding");
        let node_expected = required_string(vector, "node_id");
        let client_expected = required_string(vector, "client_id");
        assert_eq!(hex(identity.as_bytes()), encoding, "normalized {input}");
        assert_eq!(
            hex(&oracle_domain_hash(b"populus/node/v1", identity.as_bytes())),
            node_expected,
            "independent node hash for {input}"
        );
        assert_eq!(
            hex(&oracle_domain_hash(
                b"populus/client/v1",
                identity.as_bytes()
            )),
            client_expected,
            "independent client hash for {input}"
        );
        assert_eq!(node_id(&identity).to_string(), node_expected);
        assert_eq!(client_id(&identity).to_string(), client_expected);
    }

    #[test]
    fn mapped_and_six_to_four_forms_preserve_derived_identity() {
        let native = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        let mapped =
            NetworkIdentity::from_ip(IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped()));
        let six_to_four = NetworkIdentity::from_ip(IpAddr::V6(Ipv6Addr::new(
            0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1,
        )));
        assert!(native.is_ok() && native == mapped && native == six_to_four);
        if let Ok(identity) = native {
            assert_eq!(node_id(&identity).as_bytes(), node_id(&identity).as_bytes());
            assert_eq!(
                client_id(&identity).as_bytes(),
                client_id(&identity).as_bytes()
            );
            assert_ne!(
                node_id(&identity).as_bytes(),
                client_id(&identity).as_bytes()
            );
        }
    }

    #[test]
    fn public_key_length_is_checked_and_domains_are_separate() {
        assert!(matches!(
            producer_id(PublicKeyAlgorithm::Ed25519, &[0; 31]),
            Err(CryptoError::InvalidPublicKeyLength {
                expected: 32,
                actual: 31
            })
        ));
        assert!(authority_id(PublicKeyAlgorithm::Ed25519, &[0; 33]).is_err());
        let key = [0x55; 32];
        let producer = producer_id(PublicKeyAlgorithm::Ed25519, &key);
        let authority = authority_id(PublicKeyAlgorithm::Ed25519, &key);
        assert!(producer.is_ok() && authority.is_ok());
        if let (Ok(producer), Ok(authority)) = (producer, authority) {
            assert_ne!(producer.as_bytes(), authority.as_bytes());
        }
    }

    #[test]
    fn deterministic_prefix_distribution_uses_chi_square_bound() {
        let mut node_buckets = [0_u32; 256];
        let mut client_buckets = [0_u32; 256];
        for value in 0..=u16::MAX {
            let identity = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(
                8,
                0,
                value.to_be_bytes()[0],
                value.to_be_bytes()[1],
            )));
            assert!(identity.is_ok(), "8.0.0.0/16 must be eligible under v1");
            if let Ok(identity) = identity {
                node_buckets[usize::from(node_id(&identity).as_bytes()[0])] += 1;
                client_buckets[usize::from(client_id(&identity).as_bytes()[0])] += 1;
            }
        }

        let chi_square = |buckets: &[u32; 256]| {
            buckets.iter().fold(0.0, |sum, count| {
                let difference = f64::from(*count) - 256.0;
                sum + difference * difference / 256.0
            })
        };
        // For 255 degrees of freedom, 330 is a conservative high-tail cutoff
        // (approximately beyond the 99.9th percentile) for uniform first bytes.
        assert!(chi_square(&node_buckets) < 330.0);
        assert!(chi_square(&client_buckets) < 330.0);
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            rng_seed: RngSeed::Fixed(0x504f_5055_4c55_5302),
            ..ProptestConfig::default()
        })]

        #[test]
        fn same_normalized_input_has_stable_domain_outputs(bytes in any::<[u8; 4]>()) {
            let address = Ipv4Addr::new(8, bytes[0], bytes[1], bytes[2]);
            let identity = NetworkIdentity::from_ip(IpAddr::V4(address));
            prop_assert!(identity.is_ok());
            if let Ok(identity) = identity {
                let node = node_id(&identity);
                let client = client_id(&identity);
                prop_assert!(node == node_id(&identity));
                prop_assert!(client == client_id(&identity));
                prop_assert!(node.as_bytes() != client.as_bytes());
            }
        }
    }

    fn oracle_domain_hash(domain: &[u8], payload: &[u8]) -> [u8; 32] {
        let domain_prefix: &[u8] = match domain {
            b"populus/node/v1" => &[
                0x0f, b'p', b'o', b'p', b'u', b'l', b'u', b's', b'/', b'n', b'o', b'd', b'e', b'/',
                b'v', b'1',
            ],
            b"populus/client/v1" => &[
                0x11, b'p', b'o', b'p', b'u', b'l', b'u', b's', b'/', b'c', b'l', b'i', b'e', b'n',
                b't', b'/', b'v', b'1',
            ],
            b"populus/routing/v1" => &[
                0x12, b'p', b'o', b'p', b'u', b'l', b'u', b's', b'/', b'r', b'o', b'u', b't', b'i',
                b'n', b'g', b'/', b'v', b'1',
            ],
            b"populus/producer/v1" => &[
                0x13, b'p', b'o', b'p', b'u', b'l', b'u', b's', b'/', b'p', b'r', b'o', b'd', b'u',
                b'c', b'e', b'r', b'/', b'v', b'1',
            ],
            b"populus/authority/v1" => &[
                0x14, b'p', b'o', b'p', b'u', b'l', b'u', b's', b'/', b'a', b'u', b't', b'h', b'o',
                b'r', b'i', b't', b'y', b'/', b'v', b'1',
            ],
            b"populus/mutable/v1" => &[
                0x12, b'p', b'o', b'p', b'u', b'l', b'u', b's', b'/', b'm', b'u', b't', b'a', b'b',
                b'l', b'e', b'/', b'v', b'1',
            ],
            _ => &[0x00],
        };
        let mut preimage = domain_prefix.to_vec();
        preimage.extend_from_slice(
            &u32::try_from(payload.len())
                .unwrap_or_default()
                .to_be_bytes(),
        );
        preimage.extend_from_slice(payload);
        Sha256::digest(preimage).into()
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len().saturating_mul(2));
        for byte in bytes {
            let _ = write!(output, "{byte:02x}");
        }
        output
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        pairs
            .iter()
            .filter_map(|pair| {
                let high = char::from(*pair.first()?).to_digit(16)?;
                let low = char::from(*pair.get(1)?).to_digit(16)?;
                u8::try_from(high * 16 + low).ok()
            })
            .collect()
    }

    fn error_code(error: populus_types::NetworkIdentityError) -> &'static str {
        use populus_types::NetworkIdentityError as Error;
        match error {
            Error::Ipv4Private => "ipv4_private",
            Error::Ipv4Loopback => "ipv4_loopback",
            Error::Ipv4LinkLocal => "ipv4_link_local",
            Error::Ipv4CarrierGradeNat => "ipv4_carrier_grade_nat",
            Error::Ipv4Multicast => "ipv4_multicast",
            Error::Ipv4Reserved => "ipv4_reserved",
            Error::Ipv4Unspecified => "ipv4_unspecified",
            Error::Ipv4Documentation => "ipv4_documentation",
            Error::Ipv6Unspecified => "ipv6_unspecified",
            Error::Ipv6Loopback => "ipv6_loopback",
            Error::Ipv6LinkLocal => "ipv6_link_local",
            Error::Ipv6Multicast => "ipv6_multicast",
            Error::Ipv6UniqueLocal => "ipv6_unique_local",
            Error::Ipv6Documentation => "ipv6_documentation",
            Error::Ipv6SiteLocal => "ipv6_site_local",
            Error::Ipv6Discard => "ipv6_discard",
            Error::Ipv6Teredo => "ipv6_teredo",
            Error::Ipv6Nat64 => "ipv6_nat64",
            Error::Ipv4Compatible => "ipv4_compatible",
            Error::Ipv6NotGlobalUnicast => "ipv6_not_global_unicast",
        }
    }
}
