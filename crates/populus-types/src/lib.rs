//! Foundational, non-cryptographic protocol types for Populus.

mod content_id;
mod distance;
mod epoch;
mod id;
mod network_identity;

pub use content_id::{ContentId, ContentIdParseError};
pub use distance::XorDistance;
pub use epoch::Epoch;
pub use id::{
    AuthorityId, ClientId, IdParseError, MutableContentId, NodeId, ProducerId, RoutingKey,
};
pub use network_identity::{NetworkIdentity, NetworkIdentityError, NetworkIdentityParseError};

#[cfg(test)]
mod tests;
