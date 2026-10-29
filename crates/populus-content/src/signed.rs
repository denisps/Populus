use crate::body::{ContentBody, is_sorted, validate_body};
use crate::codec::{
    Decoder, Encoder, SIGNED_CONTENT_VERSION, check_encoded_size, content_id,
    decode_signed_content, finish_decoder,
};
use crate::error::ContentError;
use populus_crypto::{ProducerKeypair, PublicKeyAlgorithm, producer_id, verify_ed25519};
use populus_types::{ContentId, ProducerId};

/// Maximum number of producer signatures on an object.
pub const MAX_SIGNATURES: usize = 32;

const SIGNATURE_DOMAIN: &[u8] = b"populus/content-signature/v1\0";

/// One Ed25519 signature over a canonical [`ContentBody`].
#[derive(Clone, PartialEq, Eq)]
pub struct ContentSignature {
    producer_id: ProducerId,
    public_key: [u8; 32],
    signature: [u8; 64],
}

impl ContentSignature {
    pub(super) fn from_decoded(
        producer_id: ProducerId,
        public_key: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            producer_id,
            public_key,
            signature,
        }
    }

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
