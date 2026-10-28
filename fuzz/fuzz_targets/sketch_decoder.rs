#![no_main]

use libfuzzer_sys::fuzz_target;
use populus_sketch::ClientSketch;

fuzz_target!(|input: &[u8]| {
    let _ = ClientSketch::deserialize(input);
});
