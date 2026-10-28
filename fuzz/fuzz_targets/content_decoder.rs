#![no_main]

use libfuzzer_sys::fuzz_target;
use populus_content::{ContentBody, MAX_CONTENT_SIZE, MutableRevision, SignedContent};

fuzz_target!(|input: &[u8]| {
    exercise_decoders(input);
    if let Some(decoded) = decode_hex(input) {
        exercise_decoders(&decoded);
    }
});

fn exercise_decoders(input: &[u8]) {
    let _ = ContentBody::from_bytes(input);
    let _ = SignedContent::from_bytes(input);
    let _ = MutableRevision::from_bytes(input);
}

fn decode_hex(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() > MAX_CONTENT_SIZE.saturating_mul(2) {
        return None;
    }
    let (pairs, remainder) = input.as_chunks::<2>();
    if !remainder.is_empty() {
        return None;
    }
    let mut decoded = Vec::with_capacity(pairs.len());
    for [high, low] in pairs {
        decoded.push((hex_nibble(*high)? << 4) | hex_nibble(*low)?);
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
