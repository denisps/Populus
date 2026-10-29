use super::{
    AuthorityId, ClientId, ContentId, ContentIdParseError, Epoch, IdParseError, MutableContentId,
    NetworkIdentity, NetworkIdentityError, NetworkIdentityParseError, NodeId, ProducerId,
    RoutingKey, XorDistance,
};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, RngSeed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[test]
fn id_hex_and_byte_round_trips() {
    let bytes = [0xabu8; 32];
    let ids = [
        NodeId::from_bytes(bytes).to_string(),
        ClientId::from_bytes(bytes).to_string(),
        ProducerId::from_bytes(bytes).to_string(),
        AuthorityId::from_bytes(bytes).to_string(),
        MutableContentId::from_bytes(bytes).to_string(),
        RoutingKey::from_bytes(bytes).to_string(),
    ];
    assert!(ids.iter().all(|text| text == &"ab".repeat(32)));
    assert!(NodeId::from_str(&ids[0]).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(ClientId::from_str(&ids[1]).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(ProducerId::from_str(&ids[2]).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(AuthorityId::from_str(&ids[3]).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(MutableContentId::from_str(&ids[4]).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(RoutingKey::from_str(&ids[5]).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(ClientId::try_from(bytes.as_slice()).is_ok_and(|id| id.as_bytes() == &bytes));
    assert!(ClientId::try_from(&bytes[..31]).is_err());
    assert!(ProducerId::try_from(&bytes[..31]).is_err());
    assert!(AuthorityId::try_from(&bytes[..31]).is_err());
    assert!(MutableContentId::try_from(&bytes[..31]).is_err());
    assert!(RoutingKey::try_from(&bytes[..31]).is_err());
    assert!(NodeId::from_str(&"A".repeat(64)).is_err());
    assert!(NodeId::from_str("00").is_err());
    assert!(matches!(
        NodeId::try_from(&bytes[..31]),
        Err(IdParseError::WrongLength {
            expected: 32,
            actual: 31
        })
    ));
}

#[test]
fn content_id_profile_is_strict() {
    let cid = ContentId::from_digest([0x42; 32]);
    assert!(ContentId::try_from(cid.as_bytes().as_slice()).is_ok_and(|parsed| parsed == cid));
    assert!(ContentId::from_str(&cid.to_string()).is_ok_and(|parsed| parsed == cid));
    assert!(matches!(
        ContentId::try_from(&cid.as_bytes()[..35]),
        Err(ContentIdParseError::WrongLength { .. })
    ));

    for index in 0..4 {
        let mut unsupported = *cid.as_bytes();
        unsupported[index] ^= 1;
        assert!(matches!(
            ContentId::from_bytes(unsupported),
            Err(ContentIdParseError::InvalidProfile)
        ));
    }
    let mut trailing = cid.as_bytes().to_vec();
    trailing.push(0);
    assert!(ContentId::try_from(trailing.as_slice()).is_err());
    assert!(ContentId::from_str(&"A".repeat(72)).is_err());
}

#[test]
fn epoch_is_big_endian_and_opaque() {
    let epoch = Epoch::new(0x0102_0304_0506_0708);
    assert_eq!(epoch.to_bytes(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(Epoch::try_from(epoch.to_bytes().as_slice()).is_ok_and(|decoded| decoded == epoch));
    assert!(Epoch::try_from(&[0; 7][..]).is_err());
    assert!(Epoch::new(2) < Epoch::new(3));
}

#[test]
fn network_identity_encodings_round_trip() {
    let ipv4 = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(ipv4.is_ok());
    if let Ok(identity) = ipv4 {
        assert_eq!(identity.as_bytes(), [0x04, 8, 8, 8, 8]);
        assert!(
            NetworkIdentity::from_bytes(identity.as_bytes())
                .is_ok_and(|decoded| decoded == identity)
        );
    }

    let ipv6 = NetworkIdentity::from_ip(IpAddr::V6(
        Ipv6Addr::from_str("2001:4860:1234:abcd::1").unwrap_or(Ipv6Addr::UNSPECIFIED),
    ));
    assert!(ipv6.is_ok());
    if let Ok(identity) = ipv6 {
        assert_eq!(
            identity.as_bytes(),
            [0x06, 0x20, 0x01, 0x48, 0x60, 0x12, 0x34]
        );
        assert!(
            NetworkIdentity::from_bytes(identity.as_bytes())
                .is_ok_and(|decoded| decoded == identity)
        );
    }
    assert!(matches!(
        NetworkIdentity::from_bytes(&[0x06, 0x10, 0, 0, 0, 0, 0]),
        Err(NetworkIdentityParseError::Ineligible(
            NetworkIdentityError::Ipv6NotGlobalUnicast
        ))
    ));
    assert!(matches!(
        NetworkIdentity::from_bytes(&[0x05, 0, 0, 0, 0]),
        Err(NetworkIdentityParseError::InvalidFamilyTag)
    ));
}

#[test]
fn ipv4_and_mapped_ipv4_apply_the_same_eligibility_policy_id_002() {
    let rejected = [
        ("10.0.0.1", NetworkIdentityError::Ipv4Private),
        ("172.16.0.1", NetworkIdentityError::Ipv4Private),
        ("192.168.0.1", NetworkIdentityError::Ipv4Private),
        ("127.0.0.1", NetworkIdentityError::Ipv4Loopback),
        ("169.254.1.1", NetworkIdentityError::Ipv4LinkLocal),
        ("100.64.0.1", NetworkIdentityError::Ipv4CarrierGradeNat),
        ("224.0.0.1", NetworkIdentityError::Ipv4Multicast),
        ("240.0.0.1", NetworkIdentityError::Ipv4Reserved),
        ("255.255.255.255", NetworkIdentityError::Ipv4Reserved),
        ("0.1.2.3", NetworkIdentityError::Ipv4Unspecified),
        ("192.0.2.1", NetworkIdentityError::Ipv4Documentation),
        ("198.51.100.1", NetworkIdentityError::Ipv4Documentation),
        ("203.0.113.1", NetworkIdentityError::Ipv4Documentation),
    ];
    for (address, expected) in rejected {
        let parsed = Ipv4Addr::from_str(address);
        assert!(parsed.is_ok());
        if let Ok(ipv4) = parsed {
            assert!(NetworkIdentity::from_ip(IpAddr::V4(ipv4)) == Err(expected));
            let mapped = ipv4.to_ipv6_mapped();
            assert!(NetworkIdentity::from_ip(IpAddr::V6(mapped)) == Err(expected));
        }
    }

    let loopback = Ipv4Addr::LOCALHOST.to_ipv6_mapped();
    assert!(
        NetworkIdentity::from_ip(IpAddr::V6(loopback)) == Err(NetworkIdentityError::Ipv4Loopback)
    );
    let documentation = Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped();
    assert!(
        NetworkIdentity::from_ip(IpAddr::V6(documentation))
            == Err(NetworkIdentityError::Ipv4Documentation)
    );

    let native = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let mapped = NetworkIdentity::from_ip(IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped()));
    assert!(native.is_ok() && native == mapped);
}

#[test]
fn six_to_four_applies_ipv4_eligibility_before_ipv6_policy_id_002() {
    let public = Ipv6Addr::new(0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 1);
    let native = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    assert!(native.is_ok());
    assert!(NetworkIdentity::from_ip(IpAddr::V6(public)) == native);

    let private = Ipv6Addr::new(0x2002, 0x0a00, 0x0001, 0, 0, 0, 0, 1);
    assert!(
        NetworkIdentity::from_ip(IpAddr::V6(private)) == Err(NetworkIdentityError::Ipv4Private)
    );
    let documentation = Ipv6Addr::new(0x2002, 0xc000, 0x0201, 0, 0, 0, 0, 1);
    assert!(
        NetworkIdentity::from_ip(IpAddr::V6(documentation))
            == Err(NetworkIdentityError::Ipv4Documentation)
    );
}

#[test]
fn ipv6_exclusion_classes_are_rejected_after_transition_classification_id_002() {
    let rejected = [
        ("::", NetworkIdentityError::Ipv6Unspecified),
        ("::1", NetworkIdentityError::Ipv6Loopback),
        ("fe80::1", NetworkIdentityError::Ipv6LinkLocal),
        ("ff02::1", NetworkIdentityError::Ipv6Multicast),
        ("fc00::1", NetworkIdentityError::Ipv6UniqueLocal),
        ("2001:db8::1", NetworkIdentityError::Ipv6Documentation),
        ("fec0::1", NetworkIdentityError::Ipv6SiteLocal),
        ("100::1", NetworkIdentityError::Ipv6Discard),
        ("2001::1", NetworkIdentityError::Ipv6Teredo),
        ("64:ff9b::808:808", NetworkIdentityError::Ipv6Nat64),
        ("64:ff9b:1::1", NetworkIdentityError::Ipv6Nat64),
        ("::8.8.8.8", NetworkIdentityError::Ipv4Compatible),
        ("1000::1", NetworkIdentityError::Ipv6NotGlobalUnicast),
    ];
    for (address, expected) in rejected {
        let parsed = Ipv6Addr::from_str(address);
        assert!(parsed.is_ok());
        if let Ok(ipv6) = parsed {
            assert!(NetworkIdentity::from_ip(IpAddr::V6(ipv6)) == Err(expected));
        }
    }
}

#[test]
fn ipv6_prefix_normalization_and_family_separation_id_002() {
    let first = NetworkIdentity::from_ip(IpAddr::V6(
        Ipv6Addr::from_str("2001:4860:1234:abcd::1").unwrap_or(Ipv6Addr::UNSPECIFIED),
    ));
    let same_prefix = NetworkIdentity::from_ip(IpAddr::V6(
        Ipv6Addr::from_str("2001:4860:1234:ffff::1234").unwrap_or(Ipv6Addr::UNSPECIFIED),
    ));
    let adjacent = NetworkIdentity::from_ip(IpAddr::V6(
        Ipv6Addr::from_str("2001:4860:1235::1").unwrap_or(Ipv6Addr::UNSPECIFIED),
    ));
    assert!(first.is_ok() && first == same_prefix);
    assert!(first.is_ok() && first != adjacent);

    let ipv4 = NetworkIdentity::from_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let ipv6 = NetworkIdentity::from_ip(IpAddr::V6(
        Ipv6Addr::from_str("2001:4860::1").unwrap_or(Ipv6Addr::UNSPECIFIED),
    ));
    assert!(ipv4.is_ok() && ipv6.is_ok() && ipv4 != ipv6);
    assert!(
        NetworkIdentity::from_ip(IpAddr::V6(
            Ipv6Addr::from_str("2001:4860::1").unwrap_or(Ipv6Addr::UNSPECIFIED)
        ))
        .is_ok()
    );
}

#[test]
fn xor_distance_has_big_endian_order_and_prefix_count() {
    let zero = NodeId::from_bytes([0; 32]);
    let same = XorDistance::between_nodes(&zero, &zero);
    assert_eq!(same.as_bytes(), &[0; 32]);
    assert_eq!(same.leading_zero_bits(), 256);

    let mut far_bytes = [0; 32];
    far_bytes[0] = 0x80;
    let mut near_bytes = [0; 32];
    near_bytes[0] = 0x7f;
    let far = XorDistance::between_nodes(&zero, &NodeId::from_bytes(far_bytes));
    let near = XorDistance::between_nodes(&zero, &NodeId::from_bytes(near_bytes));
    assert!(near < far);
    assert_eq!(near.leading_zero_bits(), 1);
    let key = RoutingKey::from_bytes(near_bytes);
    assert_eq!(
        XorDistance::between_node_and_key(&zero, &key).as_bytes(),
        near.as_bytes()
    );
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        rng_seed: RngSeed::Fixed(0x504f_5055_4c55_5301),
        ..ProptestConfig::default()
    })]

    #[test]
    fn xor_identity_symmetry_and_order_match_big_endian(
        left in any::<[u8; 32]>(),
        right in any::<[u8; 32]>(),
        target in any::<[u8; 32]>(),
    ) {
        let a = NodeId::from_bytes(left);
        let b = NodeId::from_bytes(right);
        let key = RoutingKey::from_bytes(target);
        let zero = XorDistance::between_nodes(&a, &a);
        prop_assert!(zero.as_bytes() == &[0; 32]);
        let ab = XorDistance::between_nodes(&a, &b);
        let ba = XorDistance::between_nodes(&b, &a);
        prop_assert!(ab == ba);
        let to_key = XorDistance::between_node_and_key(&a, &key);
        let manual: [u8; 32] = std::array::from_fn(|index| left[index] ^ target[index]);
        prop_assert!(to_key.as_bytes() == &manual);
        prop_assert_eq!(to_key.cmp(&ab), manual.cmp(ab.as_bytes()));
    }

    #[test]
    fn arbitrary_id_bytes_round_trip(bytes in any::<[u8; 32]>()) {
        let id = NodeId::from_bytes(bytes);
        prop_assert!(NodeId::try_from(id.as_bytes().as_slice()).is_ok_and(|parsed| parsed == id));
        let client = ClientId::from_bytes(bytes);
        prop_assert!(ClientId::try_from(client.as_bytes().as_slice()).is_ok_and(|parsed| parsed == client));
        let producer = ProducerId::from_bytes(bytes);
        prop_assert!(ProducerId::try_from(producer.as_bytes().as_slice()).is_ok_and(|parsed| parsed == producer));
        let authority = AuthorityId::from_bytes(bytes);
        prop_assert!(AuthorityId::try_from(authority.as_bytes().as_slice()).is_ok_and(|parsed| parsed == authority));
        let mutable = MutableContentId::from_bytes(bytes);
        prop_assert!(MutableContentId::try_from(mutable.as_bytes().as_slice()).is_ok_and(|parsed| parsed == mutable));
        let routing = RoutingKey::from_bytes(bytes);
        prop_assert!(RoutingKey::try_from(routing.as_bytes().as_slice()).is_ok_and(|parsed| parsed == routing));
    }

    #[test]
    fn arbitrary_content_digest_and_epoch_round_trip(
        digest in any::<[u8; 32]>(),
        value in any::<u64>(),
    ) {
        let cid = ContentId::from_digest(digest);
        prop_assert!(ContentId::try_from(cid.as_bytes().as_slice()).is_ok_and(|parsed| parsed == cid));
        prop_assert!(ContentId::from_str(&cid.to_string()).is_ok_and(|parsed| parsed == cid));
        let epoch = Epoch::new(value);
        prop_assert!(Epoch::try_from(epoch.to_bytes().as_slice()).is_ok_and(|parsed| parsed == epoch));
    }

    #[test]
    fn arbitrary_parser_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=80)) {
        let _ = NodeId::try_from(bytes.as_slice());
        let _ = ClientId::try_from(bytes.as_slice());
        let _ = ProducerId::try_from(bytes.as_slice());
        let _ = AuthorityId::try_from(bytes.as_slice());
        let _ = MutableContentId::try_from(bytes.as_slice());
        let _ = RoutingKey::try_from(bytes.as_slice());
        let _ = ContentId::try_from(bytes.as_slice());
        let _ = NetworkIdentity::try_from(bytes.as_slice());
        let _ = Epoch::try_from(bytes.as_slice());
        let text = String::from_utf8_lossy(&bytes);
        let _ = NodeId::from_str(&text);
        let _ = ClientId::from_str(&text);
        let _ = ProducerId::from_str(&text);
        let _ = AuthorityId::from_str(&text);
        let _ = MutableContentId::from_str(&text);
        let _ = RoutingKey::from_str(&text);
        let _ = ContentId::from_str(&text);
    }
}
