#![no_main]

use libfuzzer_sys::fuzz_target;
use populus_types::{
    AuthorityId, ClientId, ContentId, Epoch, MutableContentId, NetworkIdentity, NodeId, ProducerId,
    RoutingKey,
};
use std::net::IpAddr;
use std::str::FromStr;

fuzz_target!(|input: &[u8]| {
    let _ = NodeId::try_from(input);
    let _ = ClientId::try_from(input);
    let _ = ProducerId::try_from(input);
    let _ = AuthorityId::try_from(input);
    let _ = MutableContentId::try_from(input);
    let _ = RoutingKey::try_from(input);
    let _ = ContentId::try_from(input);
    let _ = NetworkIdentity::try_from(input);
    let _ = Epoch::try_from(input);

    let text = String::from_utf8_lossy(input);
    let _ = NodeId::from_str(&text);
    let _ = ClientId::from_str(&text);
    let _ = ProducerId::from_str(&text);
    let _ = AuthorityId::from_str(&text);
    let _ = MutableContentId::from_str(&text);
    let _ = RoutingKey::from_str(&text);
    let _ = ContentId::from_str(&text);
    if let Ok(address) = text.parse::<IpAddr>() {
        let _ = NetworkIdentity::from_ip(address);
    }

    if let Some(decoded) = decode_lower_hex(&text) {
        let _ = NetworkIdentity::try_from(decoded.as_slice());
        let _ = ContentId::try_from(decoded.as_slice());
        let _ = Epoch::try_from(decoded.as_slice());
        let _ = NodeId::try_from(decoded.as_slice());
    }
});

fn decode_lower_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let (pairs, _) = text.as_bytes().as_chunks::<2>();
    let mut decoded = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let high = lower_hex_nibble(pair[0])?;
        let low = lower_hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn lower_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
