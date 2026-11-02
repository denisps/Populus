#![no_main]

use libfuzzer_sys::fuzz_target;
use populus_cluster::{DirectIngestState, DirectVote, PersistentLike, SignedDirectVoteAck};

fuzz_target!(|input: &[u8]| {
    let _ = DirectIngestState::deserialize(input);
    let _ = DirectVote::deserialize(input);
    let _ = SignedDirectVoteAck::deserialize(input);
    let _ = PersistentLike::deserialize(input);
    if let Some(decoded) = decode_hex_seed(input) {
        let _ = DirectIngestState::deserialize(&decoded);
        let _ = DirectVote::deserialize(&decoded);
        let _ = SignedDirectVoteAck::deserialize(&decoded);
        let _ = PersistentLike::deserialize(&decoded);
    }
});

fn decode_hex_seed(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() > 2 * 1_048_576 || input.len() % 2 != 0 {
        return None;
    }
    input
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
