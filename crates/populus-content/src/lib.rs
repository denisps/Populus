//! Canonical immutable and mutable content models for Populus.

mod body;
mod codec;
mod error;
mod mutable;
mod signed;

pub use body::{
    CONTENT_SCHEMA_VERSION, ContentBody, MAX_CONTENT_ITEMS, MAX_CONTENT_SIZE, MAX_METADATA_ENTRIES,
    MAX_METADATA_KEY_SIZE, MAX_METADATA_VALUE_SIZE, MAX_PAYLOAD_SIZE,
};
pub use error::ContentError;
pub use mutable::MutableRevision;
pub use signed::{ContentSignature, MAX_SIGNATURES, SignedContent};

#[cfg(test)]
mod tests;
