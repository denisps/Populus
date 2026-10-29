use populus_crypto::CryptoError;
use std::fmt;

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
