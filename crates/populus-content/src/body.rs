use crate::codec::{
    Decoder, Encoder, check_encoded_size, decode_body, encode_body, finish_decoder,
};
use crate::error::ContentError;
use crate::signed::MAX_SIGNATURES;
use populus_types::{ContentId, ProducerId};
use std::collections::BTreeMap;

/// Content schema version supported by this crate.
pub const CONTENT_SCHEMA_VERSION: u8 = 1;
/// Maximum size of an encoded body, signed object, or revision.
pub const MAX_CONTENT_SIZE: usize = 20 * 1024 * 1024;
/// Maximum payload size in bytes.
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
/// Maximum number of values in tags, associations, or producers.
pub const MAX_CONTENT_ITEMS: usize = 256;
/// Maximum number of metadata entries.
pub const MAX_METADATA_ENTRIES: usize = 64;
/// Maximum UTF-8 bytes in a metadata key.
pub const MAX_METADATA_KEY_SIZE: usize = 128;
/// Maximum bytes in one metadata value.
pub const MAX_METADATA_VALUE_SIZE: usize = 64 * 1024;
/// A versioned content body; collection fields are set-valued and encoded in sorted order.
#[derive(Clone, PartialEq, Eq)]
pub struct ContentBody {
    /// Schema version; v1 is the only supported value.
    pub schema_version: u8,
    /// Creation time as Unix milliseconds.
    pub created_at: u64,
    /// Media type, such as `text/plain` or `application/octet-stream`.
    pub media_type: String,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
    /// Content tags represented by immutable content identifiers.
    pub tags: Vec<ContentId>,
    /// Associations to other immutable content identifiers.
    pub associations: Vec<ContentId>,
    /// Producer identities expected to sign this body; empty for anonymous content.
    pub producers: Vec<ProducerId>,
    /// Extensible metadata with UTF-8 keys and opaque byte values.
    pub metadata: BTreeMap<String, Vec<u8>>,
}

impl ContentBody {
    /// Creates a v1 body with no tags, associations, producers, or metadata.
    #[must_use]
    pub fn new(created_at: u64, media_type: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            schema_version: CONTENT_SCHEMA_VERSION,
            created_at,
            media_type: media_type.into(),
            payload,
            tags: Vec::new(),
            associations: Vec::new(),
            producers: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    /// Encodes the body as canonical DAG-CBOR using a fixed positional schema.
    ///
    /// Set-valued fields are sorted by their protocol bytes, so their input
    /// insertion order cannot alter the body digest or signature preimage.
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds a v1 bound or contains duplicate set entries.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContentError> {
        validate_body(self)?;
        let tags = sorted_values(&self.tags)?;
        let associations = sorted_values(&self.associations)?;
        let producers = sorted_values(&self.producers)?;
        let mut encoder = Encoder::new(Vec::new());
        encode_body(&mut encoder, self, &tags, &associations, &producers);
        let output = encoder.into_writer();
        check_encoded_size(&output)?;
        Ok(output)
    }

    /// Decodes a canonical v1 body, rejecting malformed, noncanonical, or oversized input.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, malformed CBOR, invalid fields,
    /// duplicate set entries, trailing bytes, or input exceeding [`MAX_CONTENT_SIZE`].
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ContentError> {
        check_encoded_size(encoded)?;
        let mut decoder = Decoder::new(encoded);
        let body = decode_body(&mut decoder)?;
        finish_decoder(&decoder, encoded)?;
        if body.canonical_bytes()? != encoded {
            return Err(ContentError::NonCanonicalEncoding);
        }
        Ok(body)
    }

    pub(super) fn canonicalized(mut self) -> Result<Self, ContentError> {
        validate_body(&self)?;
        self.tags.sort_unstable();
        self.associations.sort_unstable();
        self.producers.sort_unstable();
        ensure_unique(&self.tags)?;
        ensure_unique(&self.associations)?;
        ensure_unique(&self.producers)?;
        Ok(self)
    }
}

pub(super) fn validate_body(body: &ContentBody) -> Result<(), ContentError> {
    if body.schema_version != CONTENT_SCHEMA_VERSION {
        return Err(ContentError::UnsupportedVersion);
    }
    if body.media_type.is_empty()
        || body.media_type.len() > 255
        || !body.media_type.is_ascii()
        || !body.media_type.contains('/')
        || body.media_type.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(ContentError::InvalidField);
    }
    if body.payload.len() > MAX_PAYLOAD_SIZE
        || body.tags.len() > MAX_CONTENT_ITEMS
        || body.associations.len() > MAX_CONTENT_ITEMS
        || body.producers.len() > MAX_SIGNATURES
        || body.metadata.len() > MAX_METADATA_ENTRIES
    {
        return Err(ContentError::FieldTooLarge);
    }
    for (key, value) in &body.metadata {
        if key.is_empty()
            || key.len() > MAX_METADATA_KEY_SIZE
            || value.len() > MAX_METADATA_VALUE_SIZE
            || key.chars().any(char::is_control)
        {
            return Err(ContentError::FieldTooLarge);
        }
    }
    Ok(())
}

fn ensure_unique<T: Ord>(values: &[T]) -> Result<(), ContentError> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(ContentError::DuplicateItems);
    }
    Ok(())
}

fn sorted_values<T: Copy + Ord>(values: &[T]) -> Result<Vec<T>, ContentError> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    ensure_unique(&sorted)?;
    Ok(sorted)
}

pub(super) fn is_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
