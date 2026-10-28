# Identifier vectors v1

`ids-v1.json` is a language-independent JSON fixture for the Phase 1 identifier
protocol. It contains eligible and rejected IPv4/IPv6 input addresses, their
expected canonical scarcity encodings or typed rejection classes, and the
resulting NodeId and ClientId values. The remaining entries cover the v1
ContentId, MutableContentId, both supported RoutingKey kinds, and matching
ProducerId/AuthorityId derivations for one Ed25519 public key.

## Schema

- `schema` identifies the fixture format.
- `network_identities` contains an `input` IP literal. Eligible addresses have
  `encoding`, `node_id`, and `client_id`; ineligible addresses have `rejection`.
  Mapped and 6to4 literals are included to show that they are classified as
  embedded IPv4 before ordinary IPv6 eligibility.
- `content_id` contains a 32-byte digest and the complete 36-byte CID.
- `mutable_content` contains the genesis CID and its stable mutable identifier.
- `routing_keys` contains `kind`, typed identifier bytes, and derived 32-byte key.
- `public_key` contains the algorithm name and tag, exact public key bytes, and
  both domain-separated public-key identifiers.

All byte strings and identifier values are lowercase hexadecimal with no `0x`
prefix. Network identity encodings are `0x04 || IPv4[4]` or
`0x06 || IPv6-prefix[6]`.

## Exact preimage construction

Every derivation uses SHA-256 over this exact byte sequence:

```text
u8(domain_ascii_byte_length)
|| domain_ascii_bytes
|| u32_be(payload_byte_length)
|| payload_bytes
```

The domains are `populus/node/v1`, `populus/client/v1`,
`populus/routing/v1`, `populus/producer/v1`, `populus/authority/v1`, and
`populus/mutable/v1`. The domain length is one byte; the payload length is four
bytes in big-endian order.

Payload definitions:

| Identifier | Payload |
| --- | --- |
| NodeId | Canonical NetworkIdentity encoding |
| ClientId | The same canonical NetworkIdentity encoding, under its distinct domain |
| RoutingKey for Content | `0x01 || complete 36-byte ContentId` |
| RoutingKey for MutableContent | `0x02 || 32-byte MutableContentId` |
| ProducerId | `0x01 || 32-byte Ed25519 public key` |
| AuthorityId | `0x01 || 32-byte Ed25519 public key`, under the authority domain |
| MutableContentId | Complete 36-byte genesis ContentId |

`ContentId` itself is the fixed profile `0x01 || 0x71 || 0x12 || 0x20 ||
digest[32]`: CIDv1, dag-cbor codec, and sha2-256 multihash. Its digest in this
fixture is a literal test input, not a content-encoding implementation.

To independently reproduce a vector, normalize the address according to
ARCHITECTURE.md §2.2, assemble the payload and length fields above, and hash the
resulting bytes with SHA-256. Expected digests are literal values and are never
generated at test runtime by the production derivation functions.

## Content vectors v1

`content-v1.json` is the language-independent Phase 3 vector for canonical
content-body bytes, a complete signed object and CID, and its mutable genesis
revision. It includes a fixed Ed25519 producer and signature so other
implementations can verify the signature preimage and complete encoding
independently.
