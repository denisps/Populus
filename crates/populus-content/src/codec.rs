use crate::body::{
    CONTENT_SCHEMA_VERSION, ContentBody, MAX_CONTENT_ITEMS, MAX_CONTENT_SIZE, MAX_METADATA_ENTRIES,
    MAX_METADATA_KEY_SIZE, MAX_METADATA_VALUE_SIZE, MAX_PAYLOAD_SIZE,
};
use crate::error::ContentError;
use crate::signed::{ContentSignature, MAX_SIGNATURES, SignedContent};
use populus_crypto::PublicKeyAlgorithm;
use populus_types::{ContentId, MutableContentId, ProducerId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) const SIGNED_CONTENT_VERSION: u8 = 1;

pub(super) fn encode_body(
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

pub(super) fn decode_body(decoder: &mut Decoder<'_>) -> Result<ContentBody, ContentError> {
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

pub(super) fn read_mutable_id(decoder: &mut Decoder<'_>) -> Result<MutableContentId, ContentError> {
    Ok(MutableContentId::from_bytes(read_fixed_bytes::<32>(
        decoder,
    )?))
}

pub(super) fn encode_cid_link(encoder: &mut Encoder, content_id: &ContentId) {
    let mut link_bytes = [0; 37];
    link_bytes[1..].copy_from_slice(content_id.as_bytes());
    encoder.tag(42);
    encoder.bytes(&link_bytes);
}

pub(super) fn read_cid_link(decoder: &mut Decoder<'_>) -> Result<ContentId, ContentError> {
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

pub(super) fn read_u8(decoder: &mut Decoder<'_>) -> Result<u8, ContentError> {
    decoder.u8()
}

pub(super) fn read_u64(decoder: &mut Decoder<'_>) -> Result<u64, ContentError> {
    decoder.u64()
}

pub(super) fn decode_signed_content(
    decoder: &mut Decoder<'_>,
) -> Result<SignedContent, ContentError> {
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
        signatures.push(ContentSignature::from_decoded(
            producer_id,
            public_key,
            signature,
        ));
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

pub(super) fn expect_array(decoder: &mut Decoder<'_>, expected: u64) -> Result<(), ContentError> {
    if decoder.array()? != Some(expected) {
        return Err(ContentError::InvalidEncoding);
    }
    Ok(())
}

pub(super) fn finish_decoder(decoder: &Decoder<'_>, encoded: &[u8]) -> Result<(), ContentError> {
    if decoder.position() != encoded.len() {
        return Err(ContentError::InvalidEncoding);
    }
    Ok(())
}

pub(super) fn check_encoded_size(encoded: &[u8]) -> Result<(), ContentError> {
    if encoded.len() > MAX_CONTENT_SIZE {
        return Err(ContentError::ContentTooLarge);
    }
    Ok(())
}

pub(super) fn content_id(encoded: &[u8]) -> ContentId {
    ContentId::from_digest(Sha256::digest(encoded).into())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Type {
    Null,
    Other,
}

pub(super) struct Encoder {
    writer: Vec<u8>,
}

impl Encoder {
    pub(super) fn new(writer: Vec<u8>) -> Self {
        Self { writer }
    }

    pub(super) fn array(&mut self, length: u64) -> &mut Self {
        self.write_head(4, length);
        self
    }

    pub(super) fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.write_head(2, bytes.len() as u64);
        self.writer.extend_from_slice(bytes);
        self
    }

    fn str(&mut self, value: &str) -> &mut Self {
        self.write_head(3, value.len() as u64);
        self.writer.extend_from_slice(value.as_bytes());
        self
    }

    pub(super) fn u8(&mut self, value: u8) -> &mut Self {
        self.write_head(0, u64::from(value));
        self
    }

    pub(super) fn u64(&mut self, value: u64) -> &mut Self {
        self.write_head(0, value);
        self
    }

    fn tag(&mut self, value: u64) -> &mut Self {
        self.write_head(6, value);
        self
    }

    pub(super) fn null(&mut self) -> &mut Self {
        self.writer.push(0xf6);
        self
    }

    pub(super) fn into_writer(self) -> Vec<u8> {
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

pub(super) struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(super) fn new(input: &'a [u8]) -> Self {
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

    pub(super) fn datatype(&self) -> Result<Type, ContentError> {
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

    pub(super) fn null(&mut self) -> Result<(), ContentError> {
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
