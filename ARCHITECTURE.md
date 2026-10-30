# ARCHITECTURE.md

# Populus Architecture

## Status

This document describes the current strongest design candidate.

Some mechanisms, especially delegated-client assignment, threshold tuning, and Byzantine outlier thresholds, remain intentionally experimental until simulation provides evidence.

IPv6 scarcity normalization is specified as v1 policy in section 2.2. It remains subject to validation by the Phase 16 NAT/IPv6/Sybil scenarios.

The architecture should preserve the ability to replace these policies without rewriting the transport or content model.

---

# 1. Design principles

Populus separates:

```text
network transport
routing identity
voting identity
producer identity
content identity
popularity measurement
authority
ingest capacity
associations/tags
```

These concerns must not collapse into one identity or one global consensus mechanism.

Core principles:

```text
1. Keep authority clusters small.
2. Scale ingest separately from authority.
3. Keep authoritative state reconstructable.
4. Use approximate structures for massive cardinalities.
5. Replicate summaries rather than raw client populations.
6. Use deterministic placement.
7. Treat all remote input as malicious.
8. Prefer eventual convergence over unnecessary consensus.
9. Keep content semantics independent from network identity.
10. Preserve independent paths for verification.
```

---

# 2. Identity model

## 2.1 libp2p PeerId

`PeerId` identifies a cryptographic libp2p peer and is used for:

```text
transport authentication
Noise
connection identity
libp2p protocol operation
```

It is not Populus's DHT position.

## 2.2 Network scarcity identity

Populus uses a normalized public network allocation as its scarce identity primitive.

Conceptually:

```text
IPv4 -> public /32
IPv6 -> normalized assigned prefix (v1 policy below)
```

### Design priority

Sybil resistance is more important than inclusiveness. Over-merging many real users into one identity is acceptable; letting one actor mint many identities is not.

### Eligibility (v1)

An address that is not eligible is rejected with a typed error. It never produces a NetworkIdentity. Rejection must not panic.

The following IPv6 rejected classes apply to ordinary IPv6 addresses after the
IPv4-mapped and 6to4 forms have been classified below:

```text
unspecified (::)
loopback (::1)
link-local (fe80::/10)
multicast (ff00::/8)
unique-local (fc00::/7)
documentation (2001:db8::/32)
site-local / deprecated (fec0::/10)
discard (100::/64)
Teredo (2001::/32; deprecated, not the host's real prefix)
NAT64 (64:ff9b::/96 and 64:ff9b:1::/48)
IPv4-compatible (::/96; deprecated)
anything outside global unicast 2000::/3
```

IPv4 rejected classes:

```text
private (10/8, 172.16/12, 192.168/16)
loopback (127/8)
link-local (169.254/16)
CGNAT (100.64/10)
multicast (224/4)
reserved and broadcast (240/4, 255.255.255.255)
unspecified (0/8)
documentation (192.0.2/24, 198.51.100/24, 203.0.113/24)
```

### Classification, eligibility, and normalization (v1)

Address processing is performed by one pure normalization function. Eligibility
is evaluated against the effective scarcity resource, which may differ from
the syntactic IP family supplied by the caller.

Processing order:

```text
1. Native IPv4:
   Apply IPv4 eligibility rules. If eligible, use the address as an IPv4 /32 identity.
2. IPv4-mapped IPv6 (::ffff:0:0/96):
   Treat this as an IPv4 representation, not an IPv6 scarcity resource. Extract the
   embedded IPv4 address, apply IPv4 eligibility rules, and if eligible produce the
   same IPv4 /32 identity as the native IPv4 representation.
3. 6to4 IPv6 (2002::/16):
   Extract the embedded IPv4 address, apply IPv4 eligibility rules, and if eligible
   use that IPv4 /32 identity.
   The scarce resource is that IPv4 address. This prevents 6to4 from giving an
   attacker a free /48 per IPv4 address, and prevents one IPv4 address from
   yielding both an IPv4 and a 6to4 identity.
4. All other IPv6:
   Apply IPv6 eligibility rules. The address must be eligible global unicast under
   the v1 policy, including membership in 2000::/3 and exclusion of the specifically
   rejected ranges. If eligible, truncate it to its /48 (low 80 bits zeroed).
```

The embedded IPv4 address in either transition form must pass the same IPv4
eligibility checks as a native IPv4 address. For example, `::ffff:8.8.8.8` and
`8.8.8.8` identify the same scarcity resource, while `::ffff:10.0.0.1` is rejected.
Ordinary IPv6 addresses outside `2000::/3` are rejected; mapped and 6to4 addresses
are classified before that IPv6-only eligibility check.

Rationale for /48: it is the standard maximum end-site allocation, and it is freely available to attackers through tunnel brokers and cheap hosting (65,536 /64s each). Anything finer than /48 would let a single actor mint many identities, so /64 and /56 are rejected for that reason.

Accepted cost: users who share a /48 (large mobile or ISP pools, campuses) collapse into one identity.

### Canonical encoding of NetworkIdentity

Length-delimited and family-tagged:

```text
IPv4: 0x04 || 4 octets
IPv6: 0x06 || 6 octets   (the /48 prefix)
```

The normalized value is what is hashed under the domains in sections 2.3 and 2.4. An IPv4 identity (5 bytes) and an IPv6 identity (7 bytes) cannot collide, because of the family tag and the different lengths.

### Versioning and compatibility

The policy version is bound to the hash domains (`populus/node/v1`, `populus/client/v1`). Any change to the prefix length or to eligibility is a protocol change. It requires a new domain version (`.../v2`), an ARCHITECTURE.md update, new test vectors, and a mixed-version consideration, because NodeIds and ClientIds from different versions are unrelated.

### Implementation requirements

The policy must be implemented as one pure function with typed errors in `populus-types` (Phase 1). It must not be duplicated elsewhere.

Required Phase 1 tests and vectors (invariant ID-002):

```text
one rejection test per eligibility class (IPv4 and IPv6)
IPv4-mapped collapses to the embedded IPv4 identity
6to4 collapses to the embedded IPv4 identity
two addresses in the same /48 -> same identity
adjacent /48s -> different identities
IPv4 and IPv6 identities never equal
golden hash vectors for NodeId and ClientId
```

### Known residual weaknesses

```text
attackers holding multiple /48s or many IPv4 addresses (cloud providers and
tunnel brokers can provide several /48s per account)
mobile carrier pools and other shared prefixes (over-merging)
privacy: a /48 or IPv4 hash is enumerable (see the section 2.4 caveat)
```

### Future work

Adaptive aggregation, for example treating an announced BGP prefix or a provider /32 as a rate-limited bucket, is out of scope for v1. It should be evaluated with the Phase 16 Sybil and eclipse simulations.

This identity is imperfect.

Known limitations include:

```text
NAT
CGNAT
VPNs
cloud IP ownership
large address holders
mobile IP churn
IPv6 delegation differences
```

It is intended to make mass identity creation costly, not to prove one-human-one-ID.

## 2.3 NodeId

```text
NodeId =
    domain_hash("populus/node/v1", canonical NetworkIdentity encoding)
```

NodeIds determine position in the Populus XOR DHT.

Because NetworkIdentity is hashed, neighboring IP addresses do not produce neighboring NodeIds.

## 2.4 ClientId

```text
ClientId =
    domain_hash("populus/client/v1", canonical NetworkIdentity encoding)
```

ClientId is used for popularity voting/deduplication.

It is completely separate from producer identity.

Important privacy limitation:

A simple public hash of IPv4 is not anonymization. The IPv4 space is small enough to enumerate.

Populus must not claim that hashed ClientIds hide the originating IPv4 address.

The exposure/privacy model requires separate review before protocol stabilization.

## 2.5 ProducerId

A producer is identified cryptographically.

Conceptually:

```text
ProducerId =
    domain_hash("populus/producer/v1", u8(algorithm) || public_key)
```

Producer identity represents authorship and subscriptions.

One person/network identity may possess many producer keys.

That does not grant additional ClientIds for popularity voting.

## 2.6 ContentId

Immutable content is content-addressed.

The Phase 1 `ContentId` parser accepts this restricted profile only:

```text
CIDv1
dag-cbor codec (0x71)
sha2-256 multihash (0x12, 32-byte digest)
exactly 36 bytes, with no trailing data
```

The complete object may be anonymous or signed. Phase 3 may widen the profile
if another deterministic canonical codec or hash is required.

## 2.7 MutableContentId

Mutable objects have:

```text
stable MutableContentId
+
immutable RevisionCID for each revision
```

Each revision links to its predecessor where appropriate.

For v1, `MutableContentId` is the domain-separated hash of the genesis anchor
`ContentId` bytes under `populus/mutable/v1`. The anchor is the complete signed
immutable content object used to create sequence zero; it is not the CID of the
revision wrapper, avoiding a circular identifier dependency. The mutable ID is
stable for the lifetime of the object; later revision CIDs do not change it.

## 2.8 RoutingKey

XOR routing operates on a fixed-width uniformly distributed key.

Logical identifiers are converted through domain-separated hashing:

```text
RoutingKey =
    domain_hash("populus/routing/v1", u8(kind) || logical_identifier)
```

This avoids treating an encoded CID or other variable-format identifier directly as a uniformly random XOR key.

## 2.9 Versioned hash and identifier encodings

The exact v1 construction is:

```text
domain_hash(domain, payload) =
    SHA-256(u8(len(domain)) || domain_ascii ||
            u32_be(len(payload)) || payload)
```

The one-byte domain length and four-byte big-endian payload length make the
preimage unambiguous. Domain strings are ASCII and versioned. This construction
refines the conceptual `H("populus/.../v1" || ...)` notation above; that notation
does not mean raw concatenation without the length fields.

The v1 domains are `populus/node/v1`, `populus/client/v1`,
`populus/routing/v1`, `populus/producer/v1`, `populus/authority/v1`, and
`populus/mutable/v1`. `NodeId` and `ClientId` hash the same canonical
`NetworkIdentity` encoding under separate domains (ID-001). `RoutingKey` accepts
typed logical identifiers only: kind `0x01` followed by the 36-byte v1 `ContentId`,
or kind `0x02` followed by the 32-byte `MutableContentId`.

The v1 `ContentId` profile is exactly 36 bytes:
`0x01 || 0x71 || 0x12 || 0x20 || digest[32]` (CIDv1, dag-cbor codec, sha2-256
multihash). Other versions, codecs, hash codes, digest lengths, and trailing bytes
are invalid. This restricted profile is intentionally implemented without CID
helper crates; Phase 3 may widen it if the content model requires additional
profiles.

`ProducerId` and `AuthorityId` use algorithm tag `0x01` for Ed25519 and require a
32-byte public key. An `AuthorityId` uses the separate `populus/authority/v1`
domain, so the same key never has the same derived identifier as its `ProducerId`.
This authority-key identity choice is a design decision requiring maintainer review.

`MutableContentId` uses the genesis `ContentId` as its payload. This stable
self-certifying identifier choice is also a design decision requiring maintainer
review.

`Epoch` is an opaque unsigned 64-bit protocol value. Its wire representation is
exactly eight bytes in big-endian order; it has no wall-clock interpretation.

---

# 3. Content model

V1 immutable content uses bounded DAG-CBOR positional arrays. Positional fields
avoid map-key ordering ambiguities; collection fields are set-valued, sorted by
their encoded identifier bytes, and reject duplicates. Metadata is represented
as a lexically sorted array of `[UTF-8 key, byte-string value]` pairs. The body
array is:

```text
[schema_version, created_at_unix_ms, media_type, payload_bytes,
 tags[], associations[], producer_ids[], metadata_pairs[]]
```

The schema version is 1. Payloads are limited to 16 MiB, encoded bodies and
objects to 20 MiB, tags and associations to 256 each, producers to 32, metadata
to 64 entries, keys to 128 UTF-8 bytes, and values to 64 KiB. Unknown versions
and over-limit input are rejected before collection allocation.

Signed content is a canonical three-element array:

```text
[object_version, ContentBody, signatures[]]
```

Each signature entry is `[algorithm, producer_id, public_key, signature]`.
Algorithm `0x01` is Ed25519. The public key must derive the stated ProducerId,
the body producer set must exactly match the unique signature identities, and
each signature verifies over:

```text
"populus/content-signature/v1\0" || canonical_body_bytes
```

Anonymous content has empty producer and signature arrays. The complete signed
object, including signatures, is encoded as DAG-CBOR and receives its CID under
the existing CIDv1 dag-cbor/sha2-256 profile.
V1 assigns a CID to the complete signed object, not to the nested body alone.

A multi-producer object can contain several independent signatures over the
same canonical body. All arrays and map-like metadata have deterministic order.
Tags, associations, and predecessor revisions are encoded as DAG-CBOR links
(tag 42 over `0x00 || complete_ContentId_bytes`), not as untyped byte strings.

Anonymous content contains no producer signature.

---

# 4. Mutable content

A mutable logical object points to immutable revisions:

```text
MutableContentId
    |
    +-> Revision CID 1
          |
          +-> Revision CID 2
                 |
                 +-> Revision CID 3
```

A revision contains:

```text
mutable_content_id
sequence/version
previous_revision_cid
body
signature(s)
```

Sequence zero derives its stable MutableContentId from the signed immutable
content CID (the genesis anchor) before the revision wrapper is encoded. Later
revisions must preserve that mutable ID, increment the sequence by one, and
name the preceding revision CID. Every revision wrapper is independently
immutable and content-addressed. V1 defines chain integrity, not authorization
or key continuity; those policies remain future work.

Authorities index the current accepted head rather than mutating previously content-addressed objects.

---

# 5. libp2p role

Reuse libp2p for transport and peer connectivity:

```text
PeerId
Multiaddr
TCP
QUIC
Noise
Yamux
DNS
Identify
Ping
RequestResponse
connection management
```

Do not force the Populus routing model into libp2p's existing PeerId-based Kademlia behavior.

Populus implements its own routing state and protocol while transporting messages over libp2p connections.

`populus-network` owns the production transport adapter and keeps Swarm details
out of routing and protocol state machines. It enables TCP and QUIC with Noise,
Yamux, and DNS, and includes identify and ping behaviours. Application streams
use `/populus/transport/1` request-response messages framed as a four-byte
big-endian length and payload. The adapter rejects frames larger than 1 MiB
before allocating payload storage and rejects oversized requests and responses
before queueing or sending them. It limits buffered outbound work to 64 active
and 64 additional requests queued or awaiting failure events, and applies a
30-second request timeout. When the combined bound is full, the caller receives
an explicit queue-full result and can retry after progress; work is never
silently discarded or buffered without a limit.
Transport peer identity remains `PeerId`; routing contacts remain
scarce-network-derived `NodeId`.

---

# 6. Populus XOR DHT

Node position:

```text
NodeId = hash(NetworkIdentity)
```

Distance:

```text
XorDist(A, B) = A XOR B
```

Routing tables are Kademlia-like.

The implementation may reuse algorithmic ideas or code patterns from rust-libp2p Kademlia, but routing-table keys and protocol semantics are Populus-specific.

Correctness oracle:

```text
sort all known nodes by XOR distance
```

Optimized routing must agree with that oracle for equivalent knowledge.

The pure routing table stores up to 20 contacts in each of 256 buckets,
classified by the most-significant differing bit from its local `NodeId`.
Contacts exceeding a bucket's capacity are rejected until an existing contact
is removed; no contact is evicted without transport liveness information.
Nearest-node lookup is exact over the table's retained contacts, not over nodes
the table has never learned. Routing state contains `NodeId` values only and
does not substitute libp2p `PeerId` for Populus identity.

---

# 7. Content authority cluster

For every Populus `RoutingKey`, the normal authority set is:

```text
the four closest NodeIds
```

Conceptually:

```text
ContentID
    |
    v
RoutingKey
    |
    v
A B C D
```

These four nodes are the authoritative replicated set.

They should remain small and stable enough that they can closely cross-check one another.

Authorities do not scale to hundreds or thousands simply because content becomes viral.

Traffic scaling is delegated separately.

---

# 8. Authority communication

All authority-to-authority messages are signed by the sender's transport/authority key.

Signed messages provide:

```text
authentication
equivocation evidence
replay detection when combined with epochs/sequences
proof of contradictory statements
```

Clients do not automatically trust a message merely because an authority signature verifies.

A client does not begin with an external PKI telling it which four authority keys are legitimate.

Instead, the client discovers the DHT neighborhood and queries multiple independently reached in-cluster nodes.

Consistent cluster information from the expected neighborhood is the client-side trust mechanism.

Authority signatures are primarily valuable inside the cluster for proving misbehavior.

---

# 9. Authority failure and replacement

Suppose:

```text
A B C D
```

are authoritative.

If D disappears and E becomes the next closest eligible authority:

```text
A B C E
```

E requests replicated state from A, B, and C.

If:

```text
A -> state X
B -> state X
C -> state Y
```

E may initialize from X.

Rule:

```text
2 matching valid states out of the remaining 3
```

is sufficient under the current one-Byzantine-authority assumption.

If all three disagree:

```text
do not guess
enter recovery
reconstruct from retained input/checkpoints
```

Authority membership transitions themselves need explicit versioning and testing.

---

# 10. Direct ingest

Low-traffic content is handled directly by the four authorities.

Conceptually:

```text
client
  | | | |
  v v v v
  A B C D
```

Each authority independently updates its local popularity sketch.

The exact direct-mode message redundancy may be optimized later, but all four authorities must be able to verify the resulting state.

Initial maximum direct ingest target:

```text
1000 votes/minute
```

This is a tunable engineering parameter, not a protocol constant until benchmarks justify it.

---

# 11. Daily popularity epochs

Persistent likes are represented through daily votes.

Conceptually:

```text
DailyVoteContentId =
    H(
        "populus/vote/v1"
        || ActualContentId
        || UTC-date
    )
```

A client with a persistent local like submits one vote during a day when it is online.

An unlike stops subsequent daily votes.

Consequences:

```text
daily population naturally expires
no deletion from HLL is needed
offline clients can still vote when they appear
final daily count is known only after the epoch closes
```

Realtime counts are provisional.

Authorities may track intra-day trends.

---

# 12. HyperLogLog

HLL estimates distinct ClientIds using fixed memory.

The v1 `populus-sketch` implementation uses an exact sparse representation for
up to 256 distinct ClientIds, promoting to dense HLL on the next new ID.
ClientIds are already domain-separated SHA-256 outputs; v1 uses the first 64
bits, interpreted big-endian, directly for register selection and rank.

Dense configuration:

```text
precision p = 14
registers = 16,384
6 bits/register
~12 KiB dense register storage
~0.81% nominal relative standard error
```

The register array is bit-packed. V1 serialization consists of `PHLL`, a
version byte (`1`), a representation byte (`0` sparse, `1` dense), followed by
either strictly increasing 32-byte ClientIds or the fixed-length packed
register array. Decoders reject unsupported versions, noncanonical sparse
input, invalid register values, and inputs larger than the largest valid
encoding. Any incompatible encoding or hash/register change requires a new
format version and compatibility consideration.

HLL properties important to Populus:

```text
duplicate inserts are naturally idempotent
sketches can be merged
memory is independent of client population
independent partitions can be recombined
```

HLL cannot answer:

```text
"Has ClientId X previously appeared?"
```

It estimates cardinality.

Membership filters are separate implementation details if ever needed.

---

# 13. Audience-set statistics

Because HLLs represent client sets, approximate statistics are possible.

Example:

```text
ArgumentativeReplies
    ~= |A union B| - |A|
```

which estimates clients in B not observed in A, depending on the semantic definition of A and B.

Intersection:

```text
|A intersection B|
    ~= |A| + |B| - |A union B|
```

Errors compound.

These statistics are useful for analytics and ranking experiments but must not be used directly for security decisions without explicit error analysis.

Alternative sketches such as KMV/Theta may be introduced if intersection quality becomes important.

---

# 14. Delegated ingest

When direct ingest approaches its maximum rate, authorities enter delegated mode.

Authorities:

```text
1. Observe sustained ingest load.
2. Select nearby non-authoritative nodes.
3. Publish delegation parameters.
4. Discourage direct authority discovery/connection for ordinary ingest.
5. Receive aggregate HLL reports instead of every client vote.
```

The four authorities remain authoritative.

Delegated nodes provide capacity, not authority.

---

# 15. Three shuffled ingest views

Delegated nodes are logically divided into three independent assignment views.

Each client sends to one ingest destination in each view:

```text
ClientId
   |
   +-> view 0 -> ingest node X
   +-> view 1 -> ingest node Y
   +-> view 2 -> ingest node Z
```

X, Y, and Z should be distinct whenever sufficient nodes exist.

The three views contain the same logical client population but partition it differently.

This provides:

```text
load distribution
independent measurement
outlier detection
failure redundancy
```

---

# 16. Client-to-ingest assignment

The exact v1 assignment algorithm remains under simulation.

Candidates include:

```text
MatchBits(NodeId, H(ClientId || view), selected_bits)

MatchBits(NodeId, different disjoint ClientId ranges)

XOR-nearest selection from delegated candidates

rendezvous-style selection
```

Desired properties:

```text
deterministic
balanced
three independent views
exactly one destination/view
cheap to calculate
works with sparse random NodeIds
stable for a fixed descriptor
resistant to one malicious node capturing multiple views
```

The algorithm and version are part of the delegation descriptor.

Therefore it can be experimentally replaced before protocol v1 freezes.

---

# 17. Match-bit sizing

If a bit-based scheme is selected, authorities choose match width from:

```text
actual nearby candidate population
measured offered load
desired maximum per-ingest-node rate
```

Never infer cluster size as:

```text
cluster_size = 2^bits
```

NodeIds are pseudorandom and sparse.

Authorities are expected to have good DHT knowledge of the nearby ContentID cluster and can calculate the observed distribution directly.

---

# 18. Delegation control loop

Initial target:

```text
keep ingest nodes below approximately 1000 votes/minute
```

The controller should use:

```text
hysteresis
smoothing
minimum dwell times
quantized selector changes
fast scale-up
slower scale-down
```

This avoids:

```text
b -> b+1 -> b -> b+1
```

oscillation from noisy measurements.

Delegation state is allowed to vary as load changes.

Authority membership is not resized with popularity.

---

# 19. Ingest report windows

Initial report window:

```text
1 minute
```

Each ingest node has at least:

```text
active HLL
pending HLL
```

At rollover:

```text
pending = active
active = new empty HLL
send pending to A, B, C, D
```

The node immediately continues receiving the next window.

The pending HLL is retained until all four authorities confirm delivery.

A missing ACK causes retry, not data deletion.

---

# 20. Clock drift and latency

Ingest nodes do not share an exact report boundary.

Example:

```text
node X believes minute ended
node Y is 20 seconds behind
node Z is still receiving packets delayed by the network
```

Therefore:

```text
view 0 minute N
view 1 minute N
view 2 minute N
```

need not contain exactly the same ClientIds.

Authorities must not treat small per-minute disagreement as proof of malice.

Minute reports are best suited for:

```text
load
rate
trend
delegation control
```

As adjacent windows accumulate into a daily sketch, boundary skew should largely disappear.

Outlier detection should therefore use:

```text
wider rolling windows
daily cumulative state
known HLL error
known timing tolerance
```

---

# 21. Authority aggregation of delegated reports

For each view:

```text
merge all ingest sketches belonging to that view
```

Authorities can maintain:

```text
view0 daily HLL
view1 daily HLL
view2 daily HLL
```

All three should eventually represent approximately the same client population.

If:

```text
view0 ~= view1
view2 is an extreme outlier
```

view2 may be rejected or quarantined according to protocol rules.

The precise statistical threshold must be derived from simulation.

---

# 22. Byzantine scope

The current architecture targets practical Byzantine resistance, not universal Byzantine consensus.

Assumptions:

```text
four authorities
at most one malicious authority for normal quorum behavior

three independently shuffled ingest views
at most one materially corrupted view for majority/outlier behavior
```

A captured local DHT neighborhood may violate these assumptions.

Routing/eclipse resistance must therefore be tested separately.

---

# 23. Authority misbehavior

Cryptographically provable examples:

```text
same authority signs two conflicting descriptors for same epoch/sequence
same authority signs incompatible finalized states
invalid state transition signed by authority
```

Other behavior may be suspicious but not objectively provable.

One authority must not unilaterally disqualify another.

Liveness removal should depend on independently observable timeout rules.

Unprovable behavioral disputes require quorum handling rather than accusation.

---

# 24. Delegation discovery

A viral ContentID must avoid forcing every client connection onto its four authorities.

Delegation information should be cacheable by nearby DHT nodes.

A client lookup may receive:

```text
delegated-mode descriptor
assignment version
assignment parameters
current epoch/window
candidate information needed for assignment
```

before reaching the four authority nodes directly.

Clients should query more than one independently reached in-cluster node and compare descriptors.

The exact cache/discovery mechanism remains to be designed and simulated.

---

# 25. Associations as tags

Populus uses one recursive association abstraction.

A reply, hashtag, topic, language, producer category, or other relationship may be represented through associated ContentIDs.

Example:

```text
Tweet A

Reply B
    associated/tagged with A

Politics Tag
    associated with Root

English Tag
    associated with Root
```

A tag can itself:

```text
contain a description
be immutable or mutable content
have producers
have tags
be popular
have associations
```

This reduces the number of special-purpose indexing systems.

---

# 26. Reporting popularity to tags

Nodes responsible for a ContentID report popularity summaries to authorities responsible for associated ContentIDs/tags.

Do not report every individual client upstream.

Use geometric popularity thresholds.

Candidate progression:

```text
approximately 1.25^k
```

This provides finer granularity than powers of ten while keeping lifetime report count approximately logarithmic.

Example conceptual sequence:

```text
100
125
156
195
244
305
...
```

Exact integer rounding and thresholds must be deterministic.

---

# 27. Large tags

A huge tag may be associated with millions or billions of child ContentIDs.

Its four authorities must not retain unbounded per-child hot state.

They may delegate:

```text
low-volume child tracking
candidate ranking
association ingest
```

to nearby non-authoritative nodes using mechanisms similar to content ingest delegation.

The authority cluster retains:

```text
top results
verified summaries
control state
```

rather than every raw observation.

---

# 28. Producer subscriptions

A ProducerId represents a public-key identity.

Content may declare one or more producers.

Clients may subscribe to ProducerIds independently from popularity voting.

Conceptually:

```text
ProducerId
   |
   +-> Content A
   +-> Content B
   +-> Content C
```

Producer subscription/discovery may reuse generic ContentID/tag indexing concepts, but producer identity remains cryptographic rather than IP-derived.

---

# 29. State minimization

Authority nodes should avoid storing:

```text
all ClientIds
all individual likes
all individual subscribers
all child associations indefinitely
raw duplicated ingest traffic
```

Prefer:

```text
HLLs
bounded top-K structures
small replicated descriptors
geometric summaries
reconstructable caches
```

Persistent state must have a documented reason to exist.

---

# 30. Security concerns still requiring design work

## IP-derived identity privacy

Hashing IPv4 does not hide it from enumeration.

## IPv6 normalization

Specified as v1 policy in section 2.2 (/48 truncation, 6to4 and IPv4-mapped collapse, strict eligibility). Remaining work is validation in the Phase 16 NAT/IPv6/Sybil scenarios.

## NAT fairness

Many humans behind one public IPv4 may become one ClientId.

This is security-favorable but popularity-unfair.

## VPN and cloud resources

IP addresses have unequal economic cost.

## DHT eclipse attack

An attacker with many scarce identities may attempt to surround a target RoutingKey.

## Authority-set convergence

Different routing-table knowledge may temporarily produce different beliefs about the four closest nodes.

## Delegation descriptor discovery

Clients must avoid authority overload without accepting arbitrary forged delegation state.

## Malicious suppression

A malicious ingest node can omit legitimate clients more easily than it can invent scarce ClientIds.

The three-view structure is intended to make this detectable.

These are first-class protocol questions and should remain visible rather than hidden behind implementation.

---

# 31. Non-goals for the first implementation

Do not initially build:

```text
GUI
recommendation ML
federated identity provider
blockchain
global consensus
proof-of-work
complex database layer
full-text search
media transcoding
moderation system
production NAT traversal policy
```

The first implementation proves:

```text
identity
routing
content
popularity sketches
authority replication
direct ingest
delegated ingest
tag aggregation
failure behavior
```

Everything else can build on that foundation.

---

# 32. Architectural success criteria

The design succeeds if simulation and implementation show that:

```text
1. Four authorities remain low-overhead even for viral content.
2. Ingest capacity can expand without changing authority count.
3. 1K -> 100M daily popularity does not require migrating raw client state.
4. One failed delegated node does not destroy the daily estimate.
5. One malicious ingest view cannot dominate two honest views.
6. One malicious authority cannot unilaterally rewrite cluster state.
7. HLL memory remains bounded with growing client count.
8. Association/tag traffic grows sublinearly through aggregation.
9. Clients can discover delegated ingest without overloading authorities.
10. Runtime state, dependencies, binary size, and hot-path costs remain measurable for every commit.
```

Until those properties are demonstrated through deterministic simulation and tests, the architecture remains a hypothesis rather than a proven protocol.