//! Explicit, signed membership manifests for bootstrapping a new Populus network.

use std::collections::BTreeSet;

use populus_crypto::{
    AuthorityKeypair, PublicKeyAlgorithm, authority_id, node_id, validate_ed25519_public_key,
    verify_ed25519,
};
use populus_types::{AuthorityId, NetworkIdentity, NodeId};

const HEADER: &[u8; 4] = b"PIGM";
const VERSION: u8 = 1;
const MEMBER_COUNT: usize = 4;
const MAX_PEER_ID_BYTES: usize = 128;
const MAX_MEMBER_ADDRESSES: usize = 8;
const MAX_ADDRESS_BYTES: usize = 256;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
const SIGNATURE_DOMAIN: &[u8] = b"populus/genesis-manifest-signature/v1";

/// One operator-provisioned initial member of a network's genesis committee.
#[derive(Clone, PartialEq, Eq)]
pub struct GenesisMember {
    network_identity: NetworkIdentity,
    node_id: NodeId,
    peer_id: Vec<u8>,
    public_key: [u8; 32],
    addresses: Vec<String>,
}

impl std::fmt::Debug for GenesisMember {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenesisMember")
            .field("network_identity", &self.network_identity.as_bytes())
            .field("node_id", &self.node_id)
            .field("peer_id", &self.peer_id)
            .field("public_key", &self.public_key)
            .field("addresses", &self.addresses)
            .finish()
    }
}

impl GenesisMember {
    /// Creates one canonical initial member record.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisManifestError`] for an empty/oversized transport
    /// identity, invalid public key, or invalid address list.
    pub fn new(
        network_identity: NetworkIdentity,
        peer_id: Vec<u8>,
        public_key: [u8; 32],
        mut addresses: Vec<String>,
    ) -> Result<Self, GenesisManifestError> {
        if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID_BYTES {
            return Err(GenesisManifestError::InvalidPeerId);
        }
        validate_ed25519_public_key(&public_key)
            .map_err(|_| GenesisManifestError::InvalidPublicKey)?;
        addresses.sort_unstable();
        addresses.dedup();
        if addresses.is_empty() || addresses.len() > MAX_MEMBER_ADDRESSES {
            return Err(GenesisManifestError::InvalidAddressList);
        }
        for address in &addresses {
            if address.is_empty()
                || address.len() > MAX_ADDRESS_BYTES
                || !address.is_ascii()
                || !address.starts_with('/')
            {
                return Err(GenesisManifestError::InvalidAddressList);
            }
        }
        Ok(Self {
            network_identity,
            node_id: node_id(&network_identity),
            peer_id,
            public_key,
            addresses,
        })
    }

    /// Returns the normalized scarce network identity.
    #[must_use]
    pub const fn network_identity(&self) -> NetworkIdentity {
        self.network_identity
    }

    /// Returns the derived Populus node identity.
    #[must_use]
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the exact expected transport identity bytes.
    #[must_use]
    pub fn peer_id(&self) -> &[u8] {
        &self.peer_id
    }

    /// Returns the expected raw Ed25519 transport public key.
    #[must_use]
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    /// Returns bounded direct dial addresses in canonical order.
    #[must_use]
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }
}

/// An out-of-band trusted signature over an exact four-member genesis set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisManifest {
    network_id: [u8; 32],
    signer: AuthorityId,
    members: Vec<GenesisMember>,
    signature: [u8; 64],
}

impl GenesisManifest {
    /// Creates and signs a canonical manifest with the provisioned trust key.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisManifestError::InvalidMemberCount`] unless exactly
    /// four distinct `NodeId`s, network identities, `PeerId`s, and signing keys
    /// are present.
    pub fn sign(
        network_id: [u8; 32],
        mut members: Vec<GenesisMember>,
        trust_key: &AuthorityKeypair,
    ) -> Result<Self, GenesisManifestError> {
        validate_members(&members)?;
        members.sort_unstable_by_key(GenesisMember::node_id);
        let mut manifest = Self {
            network_id,
            signer: trust_key.authority_id(),
            members,
            signature: [0; 64],
        };
        manifest.signature = trust_key.sign(&manifest.signing_message()?);
        Ok(manifest)
    }

    /// Verifies the manifest against an independently provisioned trust key.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisManifestError::UntrustedSigner`] when the supplied
    /// trust key does not match the signer or signature.
    pub fn verify(&self, trusted_public_key: &[u8; 32]) -> Result<(), GenesisManifestError> {
        validate_members(&self.members)?;
        validate_ed25519_public_key(trusted_public_key)
            .map_err(|_| GenesisManifestError::UntrustedSigner)?;
        let expected = authority_id(PublicKeyAlgorithm::Ed25519, trusted_public_key)
            .map_err(|_| GenesisManifestError::UntrustedSigner)?;
        if expected != self.signer
            || verify_ed25519(
                trusted_public_key,
                &self.signing_message()?,
                &self.signature,
            )
            .is_err()
        {
            return Err(GenesisManifestError::UntrustedSigner);
        }
        Ok(())
    }

    /// Returns the network identifier committed by this manifest.
    #[must_use]
    pub const fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    /// Returns the trust-anchor signing identity.
    #[must_use]
    pub const fn signer(&self) -> AuthorityId {
        self.signer
    }

    /// Returns the initial members in canonical `NodeId` order.
    #[must_use]
    pub fn members(&self) -> &[GenesisMember] {
        &self.members
    }

    /// Encodes the signed manifest in bounded canonical v1 form.
    ///
    /// # Errors
    ///
    /// Returns [`GenesisManifestError::ManifestTooLarge`] if the encoded
    /// manifest exceeds its bound.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, GenesisManifestError> {
        let mut bytes = self.unsigned_bytes()?;
        bytes.extend_from_slice(&self.signature);
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(GenesisManifestError::ManifestTooLarge);
        }
        Ok(bytes)
    }

    /// Decodes a bounded canonical v1 manifest. Signature verification remains explicit.
    ///
    /// # Errors
    ///
    /// Returns a typed error for malformed fields, duplicate members, or
    /// oversized input.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, GenesisManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(GenesisManifestError::ManifestTooLarge);
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take::<4>()? != *HEADER || cursor.byte()? != VERSION {
            return Err(GenesisManifestError::InvalidEncoding);
        }
        let network_id = cursor.take::<32>()?;
        let signer = AuthorityId::from_bytes(cursor.take::<32>()?);
        let count = usize::from(cursor.byte()?);
        if count != MEMBER_COUNT {
            return Err(GenesisManifestError::InvalidMemberCount);
        }
        let mut members = Vec::with_capacity(MEMBER_COUNT);
        for _ in 0..MEMBER_COUNT {
            let identity_len = usize::from(cursor.byte()?);
            let network_identity = NetworkIdentity::from_bytes(cursor.take_slice(identity_len)?)
                .map_err(|_| GenesisManifestError::InvalidNetworkIdentity)?;
            let expected_node_id = NodeId::from_bytes(cursor.take::<32>()?);
            if node_id(&network_identity) != expected_node_id {
                return Err(GenesisManifestError::InvalidNodeId);
            }
            let peer_id_len = usize::from(cursor.byte()?);
            let peer_id = cursor.take_slice(peer_id_len)?.to_vec();
            let public_key = cursor.take::<32>()?;
            let address_count = usize::from(cursor.byte()?);
            if address_count == 0 || address_count > MAX_MEMBER_ADDRESSES {
                return Err(GenesisManifestError::InvalidAddressList);
            }
            let mut addresses = Vec::with_capacity(address_count);
            for _ in 0..address_count {
                let address_len = usize::from(cursor.u16()?);
                let address = std::str::from_utf8(cursor.take_slice(address_len)?)
                    .map_err(|_| GenesisManifestError::InvalidAddressList)?;
                addresses.push(address.to_owned());
            }
            members.push(GenesisMember::new(
                network_identity,
                peer_id,
                public_key,
                addresses,
            )?);
        }
        let signature = cursor.take::<64>()?;
        cursor.finish()?;
        validate_members(&members)?;
        if members
            .windows(2)
            .any(|pair| pair[0].node_id >= pair[1].node_id)
        {
            return Err(GenesisManifestError::InvalidEncoding);
        }
        Ok(Self {
            network_id,
            signer,
            members,
            signature,
        })
    }

    fn unsigned_bytes(&self) -> Result<Vec<u8>, GenesisManifestError> {
        validate_members(&self.members)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(HEADER);
        bytes.push(VERSION);
        bytes.extend_from_slice(&self.network_id);
        bytes.extend_from_slice(self.signer.as_bytes());
        bytes.push(
            u8::try_from(self.members.len())
                .map_err(|_| GenesisManifestError::InvalidMemberCount)?,
        );
        for member in &self.members {
            let identity = member.network_identity.as_bytes();
            bytes.push(
                u8::try_from(identity.len())
                    .map_err(|_| GenesisManifestError::InvalidNetworkIdentity)?,
            );
            bytes.extend_from_slice(identity);
            bytes.extend_from_slice(member.node_id.as_bytes());
            bytes.push(
                u8::try_from(member.peer_id.len())
                    .map_err(|_| GenesisManifestError::InvalidPeerId)?,
            );
            bytes.extend_from_slice(&member.peer_id);
            bytes.extend_from_slice(&member.public_key);
            bytes.push(
                u8::try_from(member.addresses.len())
                    .map_err(|_| GenesisManifestError::InvalidAddressList)?,
            );
            for address in &member.addresses {
                let length = u16::try_from(address.len())
                    .map_err(|_| GenesisManifestError::InvalidAddressList)?;
                bytes.extend_from_slice(&length.to_be_bytes());
                bytes.extend_from_slice(address.as_bytes());
            }
        }
        if bytes.len().saturating_add(64) > MAX_MANIFEST_BYTES {
            return Err(GenesisManifestError::ManifestTooLarge);
        }
        Ok(bytes)
    }

    fn signing_message(&self) -> Result<Vec<u8>, GenesisManifestError> {
        let bytes = self.unsigned_bytes()?;
        let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + bytes.len());
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&bytes);
        Ok(message)
    }
}

fn validate_members(members: &[GenesisMember]) -> Result<(), GenesisManifestError> {
    if members.len() != MEMBER_COUNT {
        return Err(GenesisManifestError::InvalidMemberCount);
    }
    let mut node_ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut peer_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    for member in members {
        if !node_ids.insert(member.node_id)
            || !identities.insert(member.network_identity.as_bytes().to_vec())
            || !peer_ids.insert(member.peer_id.clone())
            || !public_keys.insert(member.public_key)
        {
            return Err(GenesisManifestError::DuplicateMember);
        }
        if member.node_id != node_id(&member.network_identity)
            || member.peer_id.is_empty()
            || member.peer_id.len() > MAX_PEER_ID_BYTES
            || member.addresses.is_empty()
            || member.addresses.len() > MAX_MEMBER_ADDRESSES
        {
            return Err(GenesisManifestError::InvalidMember);
        }
        validate_ed25519_public_key(&member.public_key)
            .map_err(|_| GenesisManifestError::InvalidPublicKey)?;
        if member.addresses.iter().any(|address| {
            address.is_empty()
                || address.len() > MAX_ADDRESS_BYTES
                || !address.is_ascii()
                || !address.starts_with('/')
        }) {
            return Err(GenesisManifestError::InvalidAddressList);
        }
    }
    Ok(())
}

/// Typed errors from genesis manifest construction, decoding, or verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisManifestError {
    /// Exactly four initial members are required.
    InvalidMemberCount,
    /// Two initial records reuse a network, node, transport, or signing identity.
    DuplicateMember,
    /// A member's normalized network identity or derived `NodeId` is invalid.
    InvalidNetworkIdentity,
    /// A member's `NodeId` does not derive from its network identity.
    InvalidNodeId,
    /// A transport `PeerId` is empty or exceeds its protocol bound.
    InvalidPeerId,
    /// A member public key is not a valid Ed25519 key.
    InvalidPublicKey,
    /// A direct address list is empty, oversized, or contains malformed strings.
    InvalidAddressList,
    /// A manifest member violates a structural invariant.
    InvalidMember,
    /// Manifest bytes exceed the fixed maximum size.
    ManifestTooLarge,
    /// The signature or signer does not match the out-of-band trust key.
    UntrustedSigner,
    /// The byte encoding is malformed or noncanonical.
    InvalidEncoding,
    /// The encoded input ended before a required field.
    Truncated,
}

impl std::fmt::Display for GenesisManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidMemberCount => "genesis manifest must contain exactly four members",
            Self::DuplicateMember => "genesis manifest contains duplicate members",
            Self::InvalidNetworkIdentity => "genesis network identity is invalid",
            Self::InvalidNodeId => "genesis NodeId does not match network identity",
            Self::InvalidPeerId => "genesis PeerId is invalid",
            Self::InvalidPublicKey => "genesis public key is invalid",
            Self::InvalidAddressList => "genesis direct address list is invalid",
            Self::InvalidMember => "genesis member record is invalid",
            Self::ManifestTooLarge => "genesis manifest exceeds its size bound",
            Self::UntrustedSigner => "genesis manifest signature is not trusted",
            Self::InvalidEncoding => "genesis manifest encoding is invalid",
            Self::Truncated => "genesis manifest is truncated",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for GenesisManifestError {}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn byte(&mut self) -> Result<u8, GenesisManifestError> {
        Ok(self.take::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, GenesisManifestError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], GenesisManifestError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(GenesisManifestError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(GenesisManifestError::Truncated)?;
        self.position = end;
        value
            .try_into()
            .map_err(|_| GenesisManifestError::Truncated)
    }

    fn take_slice(&mut self, length: usize) -> Result<&'a [u8], GenesisManifestError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(GenesisManifestError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(GenesisManifestError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn finish(self) -> Result<(), GenesisManifestError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(GenesisManifestError::InvalidEncoding)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::{GenesisManifest, GenesisManifestError, GenesisMember};
    use populus_crypto::AuthorityKeypair;
    use populus_types::NetworkIdentity;

    fn members() -> Vec<GenesisMember> {
        ["8.8.8.8", "1.1.1.1", "4.4.4.4", "9.9.9.9"]
            .into_iter()
            .enumerate()
            .map(|(index, ip)| {
                let identity = NetworkIdentity::from_ip(ip.parse().expect("public IP"))
                    .expect("eligible identity");
                let key = AuthorityKeypair::from_secret_key(
                    [u8::try_from(index + 1).expect("key index"); 32],
                );
                GenesisMember::new(
                    identity,
                    vec![u8::try_from(index + 1).expect("peer ID"); 16],
                    key.public_key(),
                    vec![format!("/ip4/{ip}/tcp/4001")],
                )
                .expect("valid genesis member")
            })
            .collect()
    }

    #[test]
    fn signed_genesis_manifest_round_trips_and_requires_out_of_band_trust() {
        let trust = AuthorityKeypair::from_secret_key([91; 32]);
        let manifest = GenesisManifest::sign([7; 32], members(), &trust).expect("sign manifest");
        let bytes = manifest.canonical_bytes().expect("encode manifest");
        let decoded = GenesisManifest::deserialize(&bytes).expect("decode manifest");
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.network_id(), &[7; 32]);
        decoded
            .verify(&trust.public_key())
            .expect("trusted signature verifies");
        assert_eq!(
            decoded.verify(&[92; 32]),
            Err(GenesisManifestError::UntrustedSigner)
        );
    }

    #[test]
    fn genesis_manifest_rejects_duplicate_members_and_trailing_bytes() {
        let trust = AuthorityKeypair::from_secret_key([93; 32]);
        let mut duplicate_members = members();
        let duplicate = duplicate_members[0].clone();
        duplicate_members[3] = duplicate;
        assert_eq!(
            GenesisManifest::sign([7; 32], duplicate_members, &trust),
            Err(GenesisManifestError::DuplicateMember)
        );
        let manifest = GenesisManifest::sign([7; 32], members(), &trust).expect("sign manifest");
        let mut bytes = manifest.canonical_bytes().expect("encode manifest");
        bytes.push(0);
        assert_eq!(
            GenesisManifest::deserialize(&bytes),
            Err(GenesisManifestError::InvalidEncoding)
        );
    }
}
