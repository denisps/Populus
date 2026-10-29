use crate::{NodeId, RoutingKey};

/// Big-endian 256-bit XOR distance between routing identifiers.
///
/// Distances may be computed between a `NodeId` and either a `RoutingKey` or
/// another `NodeId`; these are the two protocol-defined routing comparisons.
/// Ordering is unsigned big-endian numeric ordering and leading-zero counts use bits.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct XorDistance([u8; 32]);

impl XorDistance {
    /// Computes the distance from a node position to a logical routing key.
    #[must_use]
    pub fn between_node_and_key(node: &NodeId, key: &RoutingKey) -> Self {
        let mut distance = [0; 32];
        for (output, (left, right)) in distance
            .iter_mut()
            .zip(node.as_bytes().iter().zip(key.as_bytes()))
        {
            *output = left ^ right;
        }
        Self(distance)
    }

    /// Computes the distance between two node positions.
    #[must_use]
    pub fn between_nodes(left: &NodeId, right: &NodeId) -> Self {
        let mut distance = [0; 32];
        for (output, (left, right)) in distance
            .iter_mut()
            .zip(left.as_bytes().iter().zip(right.as_bytes()))
        {
            *output = left ^ right;
        }
        Self(distance)
    }

    /// Returns the distance bytes in big-endian comparison order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the number of zero bits preceding the first set bit, from 0 to 256.
    #[must_use]
    pub fn leading_zero_bits(&self) -> u16 {
        let mut count = 0_u16;
        for byte in self.0 {
            if byte == 0 {
                count += 8;
            } else {
                let mut mask = 0x80;
                while byte & mask == 0 {
                    count += 1;
                    mask >>= 1;
                }
                break;
            }
        }
        count
    }
}
