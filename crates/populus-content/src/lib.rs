//! Canonical immutable and mutable content models for Populus.

use populus_crypto::{
    CryptoError, ProducerKeypair, PublicKeyAlgorithm, mutable_content_id, producer_id,
    verify_ed25519,
};
use populus_types::{ContentId, MutableContentId, ProducerId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

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
/// Maximum number of producer signatures on an object.
pub const MAX_SIGNATURES: usize = 32;

const SIGNED_CONTENT_VERSION: u8 = 1;
const MUTABLE_REVISION_VERSION: u8 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"populus/content-signature/v1\0";

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

    fn canonicalized(mut self) -> Result<Self, ContentError> {
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

/// One Ed25519 signature over a canonical [`ContentBody`].
#[derive(Clone, PartialEq, Eq)]
pub struct ContentSignature {
    producer_id: ProducerId,
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl ContentSignature {
    /// Returns the producer identity derived from the signing public key.
    #[must_use]
    pub const fn producer_id(&self) -> ProducerId {
        self.producer_id
    }

    /// Returns the Ed25519 public key used to verify this signature.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns the 64-byte Ed25519 signature.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
}

/// Immutable body plus zero or more producer signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct SignedContent {
    body: ContentBody,
    signatures: Vec<ContentSignature>,
}

impl SignedContent {
    /// Creates an anonymous object or validates signatures supplied by producers.
    ///
    /// The body's producer set must exactly match the unique signing identities.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature set does not match the body or any
    /// signature fails verification.
    pub fn new(
        body: ContentBody,
        mut signatures: Vec<ContentSignature>,
    ) -> Result<Self, ContentError> {
        let body = body.canonicalized()?;
        signatures.sort_unstable_by_key(ContentSignature::producer_id);
        if signatures.len() > MAX_SIGNATURES {
            return Err(ContentError::FieldTooLarge);
        }
        ensure_unique_by(&signatures, ContentSignature::producer_id)?;
        let expected = &body.producers;
        if signatures.len() != expected.len()
            || signatures
                .iter()
                .zip(expected)
                .any(|(signature, producer)| signature.producer_id != *producer)
        {
            return Err(ContentError::ProducerSignatureMismatch);
        }

        let unsigned = Self { body, signatures };
        unsigned.verify()?;
        Ok(unsigned)
    }

    /// Signs a body with each supplied producer key.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied keys do not exactly match the body's
    /// producer set, or if body validation fails.
    pub fn sign(body: ContentBody, signers: &[&ProducerKeypair]) -> Result<Self, ContentError> {
        if signers.len() > MAX_SIGNATURES {
            return Err(ContentError::FieldTooLarge);
        }
        let canonical_body = body.canonicalized()?;
        let body_bytes = canonical_body.canonical_bytes()?;
        let preimage = signature_preimage(&body_bytes);
        let mut signatures = Vec::with_capacity(signers.len());
        for signer in signers {
            let public_key = signer.public_key();
            let id = producer_id(PublicKeyAlgorithm::Ed25519, &public_key)
                .map_err(ContentError::from)?;
            signatures.push(ContentSignature {
                producer_id: id,
                public_key,
                signature: signer.sign(&preimage),
            });
        }
        Self::new(canonical_body, signatures)
    }

    /// Returns the immutable body.
    #[must_use]
    pub const fn body(&self) -> &ContentBody {
        &self.body
    }

    /// Returns signatures in canonical producer-ID order.
    #[must_use]
    pub fn signatures(&self) -> &[ContentSignature] {
        &self.signatures
    }

    /// Verifies the body's canonical encoding and every producer signature.
    ///
    /// # Errors
    ///
    /// Returns an error when the signature identities differ from the body or
    /// any Ed25519 signature is invalid.
    pub fn verify(&self) -> Result<(), ContentError> {
        validate_body(&self.body)?;
        if !is_sorted(&self.body.tags)
            || !is_sorted(&self.body.associations)
            || !is_sorted(&self.body.producers)
            || self.signatures.len() != self.body.producers.len()
        {
            return Err(ContentError::ProducerSignatureMismatch);
        }
        let body_bytes = self.body.canonical_bytes()?;
        let preimage = signature_preimage(&body_bytes);
        for (signature, expected_id) in self.signatures.iter().zip(&self.body.producers) {
            let derived_id = producer_id(PublicKeyAlgorithm::Ed25519, &signature.public_key)
                .map_err(ContentError::from)?;
            if derived_id != signature.producer_id || signature.producer_id != *expected_id {
                return Err(ContentError::ProducerSignatureMismatch);
            }
            verify_ed25519(&signature.public_key, &preimage, &signature.signature)
                .map_err(ContentError::from)?;
        }
        Ok(())
    }

    /// Encodes the complete immutable object as canonical DAG-CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if signatures or encoded size are invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContentError> {
        self.verify()?;
        let body = self.body.canonical_bytes()?;
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(3);
        encoder.u8(SIGNED_CONTENT_VERSION);
        let mut writer = encoder.into_writer();
        writer.extend_from_slice(&body);
        let mut encoder = Encoder::new(writer);
        encoder.array(self.signatures.len() as u64);
        for signature in &self.signatures {
            encoder.array(4);
            encoder.u8(PublicKeyAlgorithm::Ed25519 as u8);
            encoder.bytes(signature.producer_id.as_bytes());
            encoder.bytes(&signature.public_key);
            encoder.bytes(&signature.signature);
        }
        let output = encoder.into_writer();
        check_encoded_size(&output)?;
        Ok(output)
    }

    /// Returns the content-addressed CID of the complete signed object.
    ///
    /// # Errors
    ///
    /// Returns an error if the object is invalid or exceeds the v1 size limit.
    pub fn cid(&self) -> Result<ContentId, ContentError> {
        Ok(content_id(&self.canonical_bytes()?))
    }

    /// Decodes and verifies a canonical signed object.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, unsupported, oversized, or
    /// cryptographically invalid objects.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ContentError> {
        check_encoded_size(encoded)?;
        let mut decoder = Decoder::new(encoded);
        let object = decode_signed_content(&mut decoder)?;
        finish_decoder(&decoder, encoded)?;
        if object.canonical_bytes()? != encoded {
            return Err(ContentError::NonCanonicalEncoding);
        }
        Ok(object)
    }
}

/// An immutable revision in a mutable-content chain.
#[derive(Clone, PartialEq, Eq)]
pub struct MutableRevision {
    mutable_id: MutableContentId,
    sequence: u64,
    previous_revision: Option<ContentId>,
    content: SignedContent,
}

impl MutableRevision {
    /// Creates a genesis revision. Its stable mutable ID derives from the signed
    /// content CID, avoiding a circular dependency on the revision's own CID.
    ///
    /// # Errors
    ///
    /// Returns an error if the signed content is invalid or oversized.
    pub fn genesis(content: SignedContent) -> Result<Self, ContentError> {
        let anchor = content.cid()?;
        Ok(Self {
            mutable_id: mutable_content_id(&anchor),
            sequence: 0,
            previous_revision: None,
            content,
        })
    }

    /// Creates the next revision after `previous`.
    ///
    /// # Errors
    ///
    /// Returns an error if the previous sequence is exhausted.
    pub fn next(previous: &Self, content: SignedContent) -> Result<Self, ContentError> {
        let sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(ContentError::SequenceOverflow)?;
        let revision = Self {
            mutable_id: previous.mutable_id,
            sequence,
            previous_revision: Some(previous.cid()?),
            content,
        };
        revision.validate()?;
        Ok(revision)
    }

    /// Returns this chain's stable identity.
    #[must_use]
    pub const fn mutable_id(&self) -> MutableContentId {
        self.mutable_id
    }

    /// Returns the monotonic revision sequence, starting at zero.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the preceding immutable revision CID, if this is not genesis.
    #[must_use]
    pub const fn previous_revision(&self) -> Option<ContentId> {
        self.previous_revision
    }

    /// Returns the immutable content held by this revision.
    #[must_use]
    pub const fn content(&self) -> &SignedContent {
        &self.content
    }

    /// Encodes this revision as canonical DAG-CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if its sequence, predecessor, or genesis anchor is invalid.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContentError> {
        self.validate()?;
        let content = self.content.canonical_bytes()?;
        let mut encoder = Encoder::new(Vec::new());
        encoder.array(5);
        encoder.u8(MUTABLE_REVISION_VERSION);
        encoder.bytes(self.mutable_id.as_bytes());
        encoder.u64(self.sequence);
        match self.previous_revision {
            Some(previous) => {
                encode_cid_link(&mut encoder, &previous);
            }
            None => {
                encoder.null();
            }
        }
        let mut writer = encoder.into_writer();
        writer.extend_from_slice(&content);
        let output = writer;
        check_encoded_size(&output)?;
        Ok(output)
    }

    /// Returns the content-addressed CID of this immutable revision.
    ///
    /// # Errors
    ///
    /// Returns an error if the revision is invalid or oversized.
    pub fn cid(&self) -> Result<ContentId, ContentError> {
        Ok(content_id(&self.canonical_bytes()?))
    }

    /// Verifies that this revision directly follows `previous`.
    ///
    /// # Errors
    ///
    /// Returns an error for a different mutable ID, a skipped or rolled-back
    /// sequence, or a predecessor CID mismatch.
    pub fn validate_successor(&self, previous: &Self) -> Result<(), ContentError> {
        let expected_sequence = previous
            .sequence
            .checked_add(1)
            .ok_or(ContentError::SequenceOverflow)?;
        if self.mutable_id != previous.mutable_id
            || self.sequence != expected_sequence
            || self.previous_revision != Some(previous.cid()?)
        {
            return Err(ContentError::InvalidRevisionChain);
        }
        self.validate()
    }

    /// Decodes a canonical immutable revision and validates its local invariants.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, noncanonical, unsupported, or oversized input.
    pub fn from_bytes(encoded: &[u8]) -> Result<Self, ContentError> {
        check_encoded_size(encoded)?;
        let mut decoder = Decoder::new(encoded);
        expect_array(&mut decoder, 5)?;
        if read_u8(&mut decoder)? != MUTABLE_REVISION_VERSION {
            return Err(ContentError::UnsupportedVersion);
        }
        let mutable_id = read_mutable_id(&mut decoder)?;
        let sequence = read_u64(&mut decoder)?;
        let previous_revision = if decoder.datatype()? == Type::Null {
            decoder.null()?;
            None
        } else {
            Some(read_cid_link(&mut decoder)?)
        };
        let content = decode_signed_content(&mut decoder)?;
        finish_decoder(&decoder, encoded)?;
        let revision = Self {
            mutable_id,
            sequence,
            previous_revision,
            content,
        };
        revision.validate()?;
        if revision.canonical_bytes()? != encoded {
            return Err(ContentError::NonCanonicalEncoding);
        }
        Ok(revision)
    }

    fn validate(&self) -> Result<(), ContentError> {
        self.content.verify()?;
        match (self.sequence, self.previous_revision) {
            (0, None) => {
                let anchor = self.content.cid()?;
                if self.mutable_id != mutable_content_id(&anchor) {
                    return Err(ContentError::InvalidRevisionChain);
                }
            }
            (0, Some(_)) | (_, None) => return Err(ContentError::InvalidRevisionChain),
            (_, Some(_)) => {}
        }
        Ok(())
    }
}

/// Errors while constructing, encoding, decoding, or verifying v1 content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentError {
    /// A schema or container version is not supported.
    UnsupportedVersion,
    /// The signature algorithm is not supported.
    UnsupportedAlgorithm,
    /// The encoded or generated object exceeds its bounded size.
    ContentTooLarge,
    /// A payload, list, map, key, value, or signature count exceeds its bound.
    FieldTooLarge,
    /// A required field is invalid for the v1 schema.
    InvalidField,
    /// A set-valued field contains duplicates.
    DuplicateItems,
    /// The body producer list and signatures do not match exactly.
    ProducerSignatureMismatch,
    /// The CBOR bytes are malformed or do not match the expected schema.
    InvalidEncoding,
    /// The input is valid CBOR but not the canonical v1 representation.
    NonCanonicalEncoding,
    /// A signature does not verify or its public key does not identify its producer.
    InvalidSignature,
    /// A mutable revision does not follow its declared predecessor.
    InvalidRevisionChain,
    /// The mutable revision sequence cannot be incremented.
    SequenceOverflow,
}

impl fmt::Display for ContentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsupportedVersion => "unsupported content version",
            Self::UnsupportedAlgorithm => "unsupported content signature algorithm",
            Self::ContentTooLarge => "content exceeds the maximum encoded size",
            Self::FieldTooLarge => "content field exceeds its v1 bound",
            Self::InvalidField => "invalid content field",
            Self::DuplicateItems => "duplicate value in set-valued content field",
            Self::ProducerSignatureMismatch => "producer identities do not match signatures",
            Self::InvalidEncoding => "invalid content encoding",
            Self::NonCanonicalEncoding => "noncanonical content encoding",
            Self::InvalidSignature => "invalid content signature",
            Self::InvalidRevisionChain => "invalid mutable revision chain",
            Self::SequenceOverflow => "mutable revision sequence overflow",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ContentError {}

impl From<CryptoError> for ContentError {
    fn from(error: CryptoError) -> Self {
        match error {
            CryptoError::InvalidPublicKeyLength { .. } => Self::InvalidField,
            CryptoError::InvalidPublicKey | CryptoError::InvalidSignature => Self::InvalidSignature,
        }
    }
}

fn validate_body(body: &ContentBody) -> Result<(), ContentError> {
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

fn encode_body(
    encoder: &mut Encoder,
    body: &ContentBody,
    tags: &[ContentId],
    associations: &[ContentId],
    producers: &[ProducerId],
) {
    encoder.array(8);
    encoder.u8(body.schema_version);
    encoder.u64(body.created_at);
    encoder.str(&body.media_type);
    encoder.bytes(&body.payload);

    encoder.array(tags.len() as u64);
    for tag in tags {
        encode_cid_link(encoder, tag);
    }
    encoder.array(associations.len() as u64);
    for association in associations {
        encode_cid_link(encoder, association);
    }
    encoder.array(producers.len() as u64);
    for producer in producers {
        encoder.bytes(producer.as_bytes());
    }
    encoder.array(body.metadata.len() as u64);
    for (key, value) in &body.metadata {
        encoder.array(2);
        encoder.str(key);
        encoder.bytes(value);
    }
}

fn decode_body(decoder: &mut Decoder<'_>) -> Result<ContentBody, ContentError> {
    expect_array(decoder, 8)?;
    let schema_version = read_u8(decoder)?;
    if schema_version != CONTENT_SCHEMA_VERSION {
        return Err(ContentError::UnsupportedVersion);
    }
    let created_at = read_u64(decoder)?;
    let media_type = read_str(decoder, 255)?.to_owned();
    let payload = read_bytes(decoder, MAX_PAYLOAD_SIZE)?.to_vec();
    let tags = read_content_ids(decoder)?;
    let associations = read_content_ids(decoder)?;
    let producers = read_producer_ids(decoder)?;
    let metadata_count = read_array_len(decoder, MAX_METADATA_ENTRIES)?;
    let mut metadata = BTreeMap::new();
    for _ in 0..metadata_count {
        expect_array(decoder, 2)?;
        let key = read_str(decoder, MAX_METADATA_KEY_SIZE)?.to_owned();
        let value = read_bytes(decoder, MAX_METADATA_VALUE_SIZE)?.to_vec();
        if metadata.insert(key, value).is_some() {
            return Err(ContentError::DuplicateItems);
        }
    }
    let body = ContentBody {
        schema_version,
        created_at,
        media_type,
        payload,
        tags,
        associations,
        producers,
        metadata,
    };
    body.canonicalized()
}

fn read_content_ids(decoder: &mut Decoder<'_>) -> Result<Vec<ContentId>, ContentError> {
    let count = read_array_len(decoder, MAX_CONTENT_ITEMS)?;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(read_cid_link(decoder)?);
    }
    Ok(ids)
}

fn read_producer_ids(decoder: &mut Decoder<'_>) -> Result<Vec<ProducerId>, ContentError> {
    let count = read_array_len(decoder, MAX_SIGNATURES)?;
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        ids.push(read_producer_id(decoder)?);
    }
    Ok(ids)
}

fn read_producer_id(decoder: &mut Decoder<'_>) -> Result<ProducerId, ContentError> {
    Ok(ProducerId::from_bytes(read_fixed_bytes::<32>(decoder)?))
}

fn read_mutable_id(decoder: &mut Decoder<'_>) -> Result<MutableContentId, ContentError> {
    Ok(MutableContentId::from_bytes(read_fixed_bytes::<32>(
        decoder,
    )?))
}

fn encode_cid_link(encoder: &mut Encoder, content_id: &ContentId) {
    let mut link_bytes = [0; 37];
    link_bytes[1..].copy_from_slice(content_id.as_bytes());
    encoder.tag(42);
    encoder.bytes(&link_bytes);
}

fn read_cid_link(decoder: &mut Decoder<'_>) -> Result<ContentId, ContentError> {
    if decoder.tag()? != 42 {
        return Err(ContentError::InvalidEncoding);
    }
    let link_bytes = read_fixed_bytes::<37>(decoder)?;
    if link_bytes[0] != 0 {
        return Err(ContentError::InvalidEncoding);
    }
    ContentId::try_from(&link_bytes[1..]).map_err(|_| ContentError::InvalidEncoding)
}

fn read_fixed_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], ContentError> {
    let bytes = read_bytes(decoder, N)?;
    bytes.try_into().map_err(|_| ContentError::InvalidEncoding)
}

fn read_bytes<'a>(decoder: &mut Decoder<'a>, maximum: usize) -> Result<&'a [u8], ContentError> {
    let bytes = decoder.bytes()?;
    if bytes.len() > maximum {
        return Err(ContentError::FieldTooLarge);
    }
    Ok(bytes)
}

fn read_str<'a>(decoder: &mut Decoder<'a>, maximum: usize) -> Result<&'a str, ContentError> {
    let value = decoder.str()?;
    if value.len() > maximum {
        return Err(ContentError::FieldTooLarge);
    }
    Ok(value)
}

fn read_u8(decoder: &mut Decoder<'_>) -> Result<u8, ContentError> {
    decoder.u8()
}

fn read_u64(decoder: &mut Decoder<'_>) -> Result<u64, ContentError> {
    decoder.u64()
}

fn decode_signed_content(decoder: &mut Decoder<'_>) -> Result<SignedContent, ContentError> {
    let start = decoder.position();
    expect_array(decoder, 3)?;
    if read_u8(decoder)? != SIGNED_CONTENT_VERSION {
        return Err(ContentError::UnsupportedVersion);
    }
    let body_start = decoder.position();
    let body = decode_body(decoder)?;
    let body_end = decoder.position();
    let input = decoder.input();
    let body_bytes = input
        .get(body_start..body_end)
        .ok_or(ContentError::InvalidEncoding)?;
    if body.canonical_bytes()? != body_bytes {
        return Err(ContentError::NonCanonicalEncoding);
    }
    let count = read_array_len(decoder, MAX_SIGNATURES)?;
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        expect_array(decoder, 4)?;
        if read_u8(decoder)? != PublicKeyAlgorithm::Ed25519 as u8 {
            return Err(ContentError::UnsupportedAlgorithm);
        }
        let producer_id = read_producer_id(decoder)?;
        let public_key = read_fixed_bytes::<32>(decoder)?;
        let signature = read_fixed_bytes::<64>(decoder)?;
        signatures.push(ContentSignature {
            producer_id,
            public_key,
            signature,
        });
    }
    let end = decoder.position();
    let signed_bytes = input.get(start..end).ok_or(ContentError::InvalidEncoding)?;
    let object = SignedContent::new(body, signatures)?;
    if object.canonical_bytes()? != signed_bytes {
        return Err(ContentError::NonCanonicalEncoding);
    }
    Ok(object)
}

fn read_array_len(decoder: &mut Decoder<'_>, maximum: usize) -> Result<usize, ContentError> {
    let Some(length) = decoder.array()? else {
        return Err(ContentError::InvalidEncoding);
    };
    let length = usize::try_from(length).map_err(|_| ContentError::FieldTooLarge)?;
    if length > maximum {
        return Err(ContentError::FieldTooLarge);
    }
    Ok(length)
}

fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), ContentError> {
    if decoder.array()? != Some(expected) {
        return Err(ContentError::InvalidEncoding);
    }
    Ok(())
}

fn finish_decoder(decoder: &Decoder<'_>, encoded: &[u8]) -> Result<(), ContentError> {
    if decoder.position() != encoded.len() {
        return Err(ContentError::InvalidEncoding);
    }
    Ok(())
}

fn check_encoded_size(encoded: &[u8]) -> Result<(), ContentError> {
    if encoded.len() > MAX_CONTENT_SIZE {
        return Err(ContentError::ContentTooLarge);
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

fn is_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn ensure_unique_by<T, K: Ord>(values: &[T], key: impl Fn(&T) -> K) -> Result<(), ContentError> {
    if values.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
        return Err(ContentError::DuplicateItems);
    }
    Ok(())
}

fn signature_preimage(body: &[u8]) -> Vec<u8> {
    let mut preimage = Vec::with_capacity(SIGNATURE_DOMAIN.len() + body.len());
    preimage.extend_from_slice(SIGNATURE_DOMAIN);
    preimage.extend_from_slice(body);
    preimage
}

fn content_id(encoded: &[u8]) -> ContentId {
    ContentId::from_digest(Sha256::digest(encoded).into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Type {
    Null,
    Other,
}

struct Encoder {
    writer: Vec<u8>,
}

impl Encoder {
    fn new(writer: Vec<u8>) -> Self {
        Self { writer }
    }

    fn array(&mut self, length: u64) -> &mut Self {
        self.write_head(4, length);
        self
    }

    fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.write_head(2, bytes.len() as u64);
        self.writer.extend_from_slice(bytes);
        self
    }

    fn str(&mut self, value: &str) -> &mut Self {
        self.write_head(3, value.len() as u64);
        self.writer.extend_from_slice(value.as_bytes());
        self
    }

    fn u8(&mut self, value: u8) -> &mut Self {
        self.write_head(0, u64::from(value));
        self
    }

    fn u64(&mut self, value: u64) -> &mut Self {
        self.write_head(0, value);
        self
    }

    fn tag(&mut self, value: u64) -> &mut Self {
        self.write_head(6, value);
        self
    }

    fn null(&mut self) -> &mut Self {
        self.writer.push(0xf6);
        self
    }

    fn into_writer(self) -> Vec<u8> {
        self.writer
    }

    fn write_head(&mut self, major: u8, value: u64) {
        let major = major << 5;
        match value {
            0..=23 => self.writer.push(major | value.to_le_bytes()[0]),
            24..=255 => {
                self.writer
                    .extend_from_slice(&[major | 0x18, value.to_le_bytes()[0]]);
            }
            256..=65_535 => {
                self.writer.push(major | 0x19);
                self.writer.extend_from_slice(&value.to_be_bytes()[6..]);
            }
            65_536..=4_294_967_295 => {
                self.writer.push(major | 0x1a);
                self.writer.extend_from_slice(&value.to_be_bytes()[4..]);
            }
            _ => {
                self.writer.push(major | 0x1b);
                self.writer.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn array(&mut self) -> Result<Option<u64>, ContentError> {
        self.read_head(4).map(Some)
    }

    fn bytes(&mut self) -> Result<&'a [u8], ContentError> {
        self.read_slice(2)
    }

    fn str(&mut self) -> Result<&'a str, ContentError> {
        std::str::from_utf8(self.read_slice(3)?).map_err(|_| ContentError::InvalidEncoding)
    }

    fn u8(&mut self) -> Result<u8, ContentError> {
        u8::try_from(self.read_head(0)?).map_err(|_| ContentError::InvalidEncoding)
    }

    fn u64(&mut self) -> Result<u64, ContentError> {
        self.read_head(0)
    }

    fn tag(&mut self) -> Result<u64, ContentError> {
        self.read_head(6)
    }

    fn datatype(&self) -> Result<Type, ContentError> {
        self.input
            .get(self.position)
            .map(|byte| {
                if *byte == 0xf6 {
                    Type::Null
                } else {
                    Type::Other
                }
            })
            .ok_or(ContentError::InvalidEncoding)
    }

    fn null(&mut self) -> Result<(), ContentError> {
        if self.input.get(self.position) != Some(&0xf6) {
            return Err(ContentError::InvalidEncoding);
        }
        self.position += 1;
        Ok(())
    }

    fn position(&self) -> usize {
        self.position
    }

    fn input(&self) -> &'a [u8] {
        self.input
    }

    fn read_slice(&mut self, major: u8) -> Result<&'a [u8], ContentError> {
        let length =
            usize::try_from(self.read_head(major)?).map_err(|_| ContentError::InvalidEncoding)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(ContentError::InvalidEncoding)?;
        let value = self
            .input
            .get(self.position..end)
            .ok_or(ContentError::InvalidEncoding)?;
        self.position = end;
        Ok(value)
    }

    fn read_head(&mut self, expected_major: u8) -> Result<u64, ContentError> {
        let initial = *self
            .input
            .get(self.position)
            .ok_or(ContentError::InvalidEncoding)?;
        self.position += 1;
        if initial >> 5 != expected_major {
            return Err(ContentError::InvalidEncoding);
        }
        let additional = initial & 0x1f;
        match additional {
            0..=23 => Ok(u64::from(additional)),
            24 => {
                let value = u64::from(self.read_array::<1>()?[0]);
                if value < 24 {
                    return Err(ContentError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            25 => {
                let value = u64::from(u16::from_be_bytes(self.read_array::<2>()?));
                if u8::try_from(value).is_ok() {
                    return Err(ContentError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            26 => {
                let value = u64::from(u32::from_be_bytes(self.read_array::<4>()?));
                if u16::try_from(value).is_ok() {
                    return Err(ContentError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            27 => {
                let value = u64::from_be_bytes(self.read_array::<8>()?);
                if u32::try_from(value).is_ok() {
                    return Err(ContentError::NonCanonicalEncoding);
                }
                Ok(value)
            }
            _ => Err(ContentError::InvalidEncoding),
        }
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ContentError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(ContentError::InvalidEncoding)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(ContentError::InvalidEncoding)?;
        self.position = end;
        bytes.try_into().map_err(|_| ContentError::InvalidEncoding)
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "a malformed test fixture must fail the test immediately"
    )]

    use super::{ContentBody, ContentError, MAX_CONTENT_SIZE, MutableRevision, SignedContent};
    use populus_crypto::ProducerKeypair;
    use populus_types::ContentId;
    use serde_json::Value;
    use std::collections::BTreeMap;

    fn key(seed: u8) -> ProducerKeypair {
        ProducerKeypair::from_secret_key([seed; 32])
    }

    fn signed_content(body: ContentBody, signers: &[&ProducerKeypair]) -> SignedContent {
        SignedContent::sign(body, signers).expect("valid signed content fixture")
    }

    #[test]
    fn canonical_body_is_stable_across_set_and_map_insertion_order() {
        let first = ContentId::from_digest([1; 32]);
        let second = ContentId::from_digest([2; 32]);
        let mut left = ContentBody::new(1_700_000_000_000, "text/plain", b"hello".to_vec());
        left.tags = vec![second, first];
        left.associations = vec![second, first];
        left.metadata =
            BTreeMap::from([("z-key".to_owned(), vec![2]), ("a-key".to_owned(), vec![1])]);
        let mut right = left.clone();
        right.tags.reverse();
        right.associations.reverse();
        right.metadata =
            BTreeMap::from([("a-key".to_owned(), vec![1]), ("z-key".to_owned(), vec![2])]);
        assert_eq!(
            left.canonical_bytes().expect("valid body"),
            right.canonical_bytes().expect("equivalent body")
        );
        let left_object = SignedContent::new(left, Vec::new()).expect("anonymous content");
        let right_object = SignedContent::new(right, Vec::new()).expect("anonymous content");
        assert!(left_object.cid().expect("cid") == right_object.cid().expect("cid"));
    }

    #[test]
    fn immutable_content_cid_changes_with_body_and_anonymous_content_needs_no_signature() {
        let body = ContentBody::new(7, "text/plain", b"one".to_vec());
        let object = SignedContent::new(body.clone(), Vec::new()).expect("anonymous content");
        let round_trip =
            SignedContent::from_bytes(&object.canonical_bytes().expect("encoded object"))
                .expect("valid round trip");
        assert!(round_trip == object);
        let changed = SignedContent::new(
            ContentBody::new(7, "text/plain", b"two".to_vec()),
            Vec::new(),
        )
        .expect("anonymous content");
        assert!(object.cid().expect("cid") != changed.cid().expect("cid"));
    }

    #[test]
    fn content_references_use_canonical_dag_cbor_link_encoding() {
        let content_id = ContentId::from_digest([3; 32]);
        let mut body = ContentBody::new(0, "text/plain", Vec::new());
        body.tags.push(content_id);
        body.associations.push(content_id);
        let encoded = body.canonical_bytes().expect("valid linked body");
        let mut expected = vec![0x88, 0x01, 0x00, 0x6a];
        expected.extend_from_slice(b"text/plain");
        expected.extend_from_slice(&[0x40, 0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00]);
        expected.extend_from_slice(content_id.as_bytes());
        expected.extend_from_slice(&[0x81, 0xd8, 0x2a, 0x58, 0x25, 0x00]);
        expected.extend_from_slice(content_id.as_bytes());
        expected.extend_from_slice(&[0x80, 0x80]);
        assert_eq!(encoded, expected);
        assert!(ContentBody::from_bytes(&encoded).is_ok());

        let mut invalid_link = encoded;
        let tag_offset = invalid_link
            .windows(2)
            .position(|window| window == [0xd8, 0x2a])
            .expect("encoded link tag");
        invalid_link[tag_offset] = 0xd9;
        assert!(matches!(
            ContentBody::from_bytes(&invalid_link),
            Err(ContentError::InvalidEncoding)
        ));
    }

    #[test]
    fn producer_signatures_verify_and_modified_body_is_rejected() {
        let signer = key(3);
        let mut body = ContentBody::new(9, "text/plain", b"signed".to_vec());
        body.producers = vec![signer.producer_id()];
        let object = signed_content(body.clone(), &[&signer]);
        assert!(object.verify().is_ok());
        let encoded = object.canonical_bytes().expect("signed encoding");
        let decoded = SignedContent::from_bytes(&encoded).expect("verify decoded signature");
        assert!(decoded == object);
        let mut modified_signature = encoded;
        let last_byte = modified_signature.len() - 1;
        modified_signature[last_byte] ^= 1;
        assert!(matches!(
            SignedContent::from_bytes(&modified_signature),
            Err(ContentError::InvalidSignature)
        ));

        body.payload[0] ^= 1;
        assert!(matches!(
            SignedContent::new(body, object.signatures().to_vec()),
            Err(ContentError::InvalidSignature)
        ));
    }

    #[test]
    fn multiple_producers_sign_the_same_canonical_body() {
        let first = key(1);
        let second = key(2);
        let mut body = ContentBody::new(11, "application/octet-stream", vec![0, 1, 2]);
        body.producers = vec![second.producer_id(), first.producer_id()];
        let object = signed_content(body, &[&second, &first]);
        assert_eq!(object.signatures().len(), 2);
        assert!(object.verify().is_ok());
        assert!(
            object.body().producers[0] < object.body().producers[1],
            "producer set is canonical"
        );
    }

    #[test]
    fn mutable_revision_chain_is_immutable_and_monotonic() {
        let genesis = MutableRevision::genesis(
            SignedContent::new(
                ContentBody::new(1, "text/plain", b"v1".to_vec()),
                Vec::new(),
            )
            .expect("anonymous genesis"),
        )
        .expect("genesis revision");
        let next = MutableRevision::next(
            &genesis,
            SignedContent::new(
                ContentBody::new(2, "text/plain", b"v2".to_vec()),
                Vec::new(),
            )
            .expect("anonymous next body"),
        )
        .expect("next revision");
        assert!(next.validate_successor(&genesis).is_ok());
        assert_eq!(next.sequence(), 1);
        let decoded =
            MutableRevision::from_bytes(&next.canonical_bytes().expect("encoded revision"))
                .expect("valid revision");
        assert!(decoded == next);
        assert!(genesis.cid().expect("cid") != next.cid().expect("cid"));
        assert!(genesis.mutable_id() == next.mutable_id());

        let invalid = MutableRevision {
            sequence: 2,
            ..next.clone()
        };
        assert_eq!(
            invalid.validate_successor(&genesis),
            Err(ContentError::InvalidRevisionChain)
        );
    }

    #[test]
    fn body_decoders_reject_malformed_oversized_and_noncanonical_bytes() {
        assert!(matches!(
            ContentBody::from_bytes(&vec![0; MAX_CONTENT_SIZE + 1]),
            Err(ContentError::ContentTooLarge)
        ));
        assert!(matches!(
            ContentBody::from_bytes(&[0x9f, 0xff]),
            Err(ContentError::InvalidEncoding)
        ));
        let noncanonical_body = [
            0x98, 0x08, 0x01, 0x00, 0x6a, b't', b'e', b'x', b't', b'/', b'p', b'l', b'a', b'i',
            b'n', 0x40, 0x80, 0x80, 0x80, 0x80,
        ];
        assert!(matches!(
            ContentBody::from_bytes(&noncanonical_body),
            Err(ContentError::NonCanonicalEncoding)
        ));
        let mut oversized_list = vec![0x88, 0x01, 0x00, 0x6a];
        oversized_list.extend_from_slice(b"text/plain");
        oversized_list.extend_from_slice(&[0x40, 0x99, 0x01, 0x01]);
        assert!(matches!(
            ContentBody::from_bytes(&oversized_list),
            Err(ContentError::FieldTooLarge)
        ));
    }

    #[test]
    fn producer_list_must_match_signature_identities() {
        let signer = key(7);
        let body = ContentBody::new(12, "text/plain", vec![]);
        let result = SignedContent::sign(body, &[&signer]);
        assert!(matches!(
            result,
            Err(ContentError::ProducerSignatureMismatch)
        ));

        let signers = (0..=super::MAX_SIGNATURES)
            .map(|seed| key(u8::try_from(seed).expect("signature limit fits in u8")))
            .collect::<Vec<_>>();
        let signers = signers.iter().collect::<Vec<_>>();
        assert!(matches!(
            SignedContent::sign(ContentBody::new(12, "text/plain", vec![]), &signers),
            Err(ContentError::FieldTooLarge)
        ));
    }

    fn content_vector() -> Value {
        serde_json::from_str(include_str!("../../../testvectors/content-v1.json"))
            .expect("valid content test vector")
    }

    fn required_string<'a>(value: &'a Value, key: &str) -> &'a str {
        value
            .get(key)
            .and_then(Value::as_str)
            .expect("required string in content test vector")
    }

    fn required_u64(value: &Value, key: &str) -> u64 {
        value
            .get(key)
            .and_then(Value::as_u64)
            .expect("required integer in content test vector")
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "test vector hex must have even length");
        let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty(), "test vector hex must be complete");
        pairs
            .iter()
            .map(|[high, low]| Some((hex_nibble(*high)? << 4) | hex_nibble(*low)?))
            .collect::<Option<Vec<_>>>()
            .expect("test vector uses lowercase hexadecimal")
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }

    fn hex_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }

    #[test]
    fn content_and_signature_match_language_independent_v1_vector() {
        let vector = content_vector();
        assert_eq!(
            vector.get("schema").and_then(Value::as_str),
            Some("populus-content-v1")
        );
        let seed: [u8; 32] = decode_hex(required_string(&vector, "secret_seed"))
            .try_into()
            .expect("32-byte seed in test vector");
        let signer = ProducerKeypair::from_secret_key(seed);
        let mut body = ContentBody::new(
            required_u64(&vector, "created_at_unix_ms"),
            required_string(&vector, "media_type"),
            required_string(&vector, "payload_utf8").as_bytes().to_vec(),
        );
        body.producers = vec![signer.producer_id()];
        let object = signed_content(body.clone(), &[&signer]);
        let revision = MutableRevision::genesis(object.clone()).expect("genesis");
        assert_eq!(
            encode_hex(&body.canonical_bytes().expect("body")),
            required_string(&vector, "body_cbor")
        );
        assert_eq!(
            encode_hex(&signer.public_key()),
            required_string(&vector, "public_key")
        );
        assert_eq!(
            signer.producer_id().to_string(),
            required_string(&vector, "producer_id")
        );
        assert_eq!(
            encode_hex(object.signatures()[0].signature()),
            required_string(&vector, "signature")
        );
        assert_eq!(
            encode_hex(&object.canonical_bytes().expect("object")),
            required_string(&vector, "signed_cbor")
        );
        assert_eq!(
            object.cid().expect("cid").to_string(),
            required_string(&vector, "content_cid")
        );
        assert_eq!(
            revision.mutable_id().to_string(),
            required_string(&vector, "mutable_content_id")
        );
        assert_eq!(
            encode_hex(&revision.canonical_bytes().expect("revision")),
            required_string(&vector, "revision_cbor")
        );
        assert_eq!(
            revision.cid().expect("revision cid").to_string(),
            required_string(&vector, "revision_cid")
        );
    }
}
