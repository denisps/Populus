use crate::config::{ClockSkewDistribution, LatencyDistribution, SimulationError};

pub(crate) struct SeededRandom {
    state: u64,
}

impl SeededRandom {
    pub(crate) fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub(crate) fn index(&mut self, length: usize) -> Result<usize, SimulationError> {
        let length =
            u64::try_from(length).map_err(|_| SimulationError::CountLimitExceeded("node count"))?;
        if length == 0 {
            return Err(SimulationError::NoNodes);
        }
        usize::try_from(self.sample_below(length))
            .map_err(|_| SimulationError::CountLimitExceeded("node count"))
    }

    pub(crate) fn sample_below(&mut self, bound: u64) -> u64 {
        let rejection_threshold = bound.wrapping_neg() % bound;
        loop {
            let value = self.next_u64();
            if value >= rejection_threshold {
                return value % bound;
            }
        }
    }
}

impl LatencyDistribution {
    pub(super) fn sample(self, random: &mut SeededRandom) -> u64 {
        match self {
            Self::Fixed(value) => value,
            Self::Uniform { min_ms, max_ms } => {
                if min_ms == 0 && max_ms == u64::MAX {
                    return random.next_u64();
                }
                min_ms + random.sample_below(max_ms - min_ms + 1)
            }
        }
    }
}

impl ClockSkewDistribution {
    pub(super) fn sample(self, random: &mut SeededRandom) -> i64 {
        match self {
            Self::Fixed(value) => value,
            Self::Uniform { min_ms, max_ms } => {
                let min_ordered = ordered_i64(min_ms);
                let max_ordered = ordered_i64(max_ms);
                if min_ordered == 0 && max_ordered == u64::MAX {
                    return from_ordered_i64(random.next_u64());
                }
                let width = max_ordered - min_ordered + 1;
                from_ordered_i64(min_ordered + random.sample_below(width))
            }
        }
    }
}

pub(crate) fn random_identifier(random: &mut SeededRandom, index: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    for chunk in bytes[..24].as_chunks_mut::<8>().0 {
        chunk.copy_from_slice(&random.next_u64().to_be_bytes());
    }
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    bytes
}

fn ordered_i64(value: i64) -> u64 {
    let mut bytes = value.to_be_bytes();
    bytes[0] ^= 0x80;
    u64::from_be_bytes(bytes)
}

fn from_ordered_i64(value: u64) -> i64 {
    let mut bytes = value.to_be_bytes();
    bytes[0] ^= 0x80;
    i64::from_be_bytes(bytes)
}
