use crate::codec::{
    Decoder, Encoder, Type, check_encoded_size, content_id, decode_signed_content, encode_cid_link,
    expect_array, finish_decoder, read_cid_link, read_mutable_id, read_u8, read_u64,
};
use crate::error::ContentError;
use crate::signed::SignedContent;
use populus_crypto::mutable_content_id;
use populus_types::{ContentId, MutableContentId};

const MUTABLE_REVISION_VERSION: u8 = 1;

/// An immutable revision in a mutable-content chain.
#[derive(Clone, PartialEq, Eq)]
pub struct MutableRevision {
    #[cfg(test)]
    pub(crate) mutable_id: MutableContentId,
    #[cfg(not(test))]
    mutable_id: MutableContentId,
    #[cfg(test)]
    pub(crate) sequence: u64,
    #[cfg(not(test))]
    sequence: u64,
    #[cfg(test)]
    pub(crate) previous_revision: Option<ContentId>,
    #[cfg(not(test))]
    previous_revision: Option<ContentId>,
    #[cfg(test)]
    pub(crate) content: SignedContent,
    #[cfg(not(test))]
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
        let content = self.content.canonical_bytes()?;
        self.validate_chain(&content)?;
        self.encode_unchecked(&content)
    }

    /// Encodes the revision around already-encoded, already-verified content.
    fn encode_unchecked(&self, content: &[u8]) -> Result<Vec<u8>, ContentError> {
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
        writer.extend_from_slice(content);
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
        // The content was verified once while decoding.
        let content_bytes = revision.content.encode_unchecked()?;
        revision.validate_chain(&content_bytes)?;
        if revision.encode_unchecked(&content_bytes)? != encoded {
            return Err(ContentError::NonCanonicalEncoding);
        }
        Ok(revision)
    }

    /// Verifies the content and the revision-chain invariants.
    fn validate(&self) -> Result<(), ContentError> {
        self.content.verify()?;
        let content_bytes = self.content.encode_unchecked()?;
        self.validate_chain(&content_bytes)
    }

    /// Checks sequence, predecessor, and genesis anchor given the encoded,
    /// already-verified content.
    fn validate_chain(&self, content_bytes: &[u8]) -> Result<(), ContentError> {
        match (self.sequence, self.previous_revision) {
            (0, None) => {
                let anchor = content_id(content_bytes);
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
