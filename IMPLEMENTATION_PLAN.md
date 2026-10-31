# IMPLEMENTATION_PLAN.md

# Populus Implementation Plan

## 1. Objective

Populus is a Rust implementation of a decentralized social/content network built on libp2p transports with a custom XOR-distance DHT, IP-derived scarce network identities, content-addressed objects, producer identities, approximate distributed popularity counting, recursive tag/association aggregation, and dynamically delegated ingest.

The implementation must optimize for:

1. Correct distributed behavior before optimization.
2. Deterministic and reproducible protocol behavior.
3. Small authoritative state.
4. Bounded memory and connection load.
5. Resistance to individual malicious or faulty nodes.
6. Efficient handling of viral ContentIDs.
7. Minimal runtime dependencies and binary bloat.
8. Testability through pure models and deterministic simulation.
9. AI-agent-friendly development with small, independently verifiable commits.

No networking optimization is accepted unless there is first a behavioral test or reference model proving the intended behavior.

---

# 2. Repository layout

Initial workspace:

```text
populus/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
├── clippy.toml
├── deny.toml
├── AGENTS.md
├── ARCHITECTURE.md
├── CONTRIBUTING.md
├── IMPLEMENTATION_PLAN.md
├── TESTING.md
├── crates/
│   ├── populus-types/
│   ├── populus-crypto/
│   ├── populus-content/
│   ├── populus-sketch/
│   ├── populus-routing/
│   ├── populus-protocol/
│   ├── populus-cluster/
│   ├── populus-network/
│   ├── populus-store/
│   └── populus-node/
├── sim/
│   └── populus-sim/
├── xtask/
├── fuzz/
├── benches/
└── metrics/
    └── budgets.toml
```

Crates should remain small enough that their purpose can be described in one sentence.

Do not create a new crate merely to move code. Add a crate only when it establishes a useful dependency boundary.

Runtime crate dependency direction:

```text
types
  ↑
crypto
  ↑
content     sketch     routing
     \        |        /
        protocol
           ↑
        cluster
           ↑
        network
           ↑
          node
```

`populus-sim` may depend on all pure protocol crates but production crates must never depend on the simulator.

---

# 3. Phase 0: repository and quality infrastructure

This phase is mandatory before implementing protocol behavior.

The repository is not considered initialized until all checks run successfully on an almost-empty workspace.

## 3.1 Rust configuration

Use Rust Edition 2024.

`rust-toolchain.toml`:

```toml
[toolchain]
channel = "stable"
profile = "minimal"
components = ["rustfmt", "clippy", "llvm-tools-preview"]
```

Root `Cargo.toml` should begin approximately as:

```toml
[workspace]
resolver = "3"
members = [
    "crates/*",
    "sim/populus-sim",
    "xtask",
]
exclude = ["fuzz"]

[workspace.package]
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/<owner>/populus"

[workspace.dependencies]
bytes = "1"
cid = "0.11"
futures = "0.3"
libp2p = { version = "0.56", default-features = false }
multihash-codetable = { version = "0.1", default-features = false, features = ["sha2"] }
serde = { version = "1", features = ["derive"] }
serde_ipld_dagcbor = "0.7"
sha2 = "0.10"
thiserror = "2"
tokio = { version = "1", default-features = false }

[workspace.lints.rust]
unsafe_code = "forbid"
unused_must_use = "deny"
unused_qualifications = "warn"
missing_docs = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
dbg_macro = "deny"
todo = "deny"
unimplemented = "deny"
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
large_futures = "warn"
large_stack_arrays = "warn"
needless_pass_by_value = "warn"

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
panic = "abort"
strip = "symbols"

[profile.profiling]
inherits = "release"
debug = true
strip = "none"
```

Dependency versions above are starting points, not protocol requirements. Pin versions in `Cargo.lock`.

Do not enable broad libp2p default features.

Start with only features actually needed, expected to include:

```text
tokio
tcp
quic
dns
noise
yamux
identify
ping
request-response
```

Do not enable `libp2p::kad` in the production dependency graph merely because Populus uses Kademlia-like routing. Populus requires its own NodeID and routing logic.

## 3.2 clippy.toml

Create:

```toml
cognitive-complexity-threshold = 20
too-many-arguments-threshold = 7
too-many-lines-threshold = 120
type-complexity-threshold = 250
```

These are guidance limits, not incentives to create meaningless abstractions.

A localized `#[allow(...)]` is preferable to distorting code solely to satisfy a lint. Every non-obvious allow must include a short reason.

## 3.3 rustfmt.toml

```toml
edition = "2024"
max_width = 100
newline_style = "Unix"
use_field_init_shorthand = true
use_try_shorthand = true
```

## 3.4 Dependency policy

Install and configure:

```text
cargo-deny
cargo-machete
cargo-bloat
cargo-nextest
cargo-llvm-cov
cargo-mutants
cargo-semver-checks
cargo-fuzz
iai-callgrind-runner
```

Use `cargo install --locked` unless a prebuilt pinned tool is used in CI.

`deny.toml` starts with:

```toml
[advisories]
unmaintained = "all"
unsound = "all"

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"

[licenses]
confidence-threshold = 0.93
allow = [
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "Unicode-3.0",
    "Zlib",
]
```

Any additional license requires explicit review.

Every new runtime dependency must answer:

```text
Why is this needed?
Can std or an existing dependency do it?
How many transitive dependencies does it add?
Which features are enabled?
Does it affect binary size?
Does it introduce native code?
Does it introduce unsafe code?
Is it maintained?
```

## 3.5 Test dependencies

Add only where needed:

```toml
[dev-dependencies]
proptest = "1"
rand = "0.9"
rand_chacha = "0.9"
tempfile = "3"
divan = "0.1"
```

Use `iai-callgrind` for deterministic CI performance measurements of hot pure functions.

Add `loom` only if custom lock-free or synchronization-sensitive code is introduced.

Use `hyperloglogplus` only as a dev-only statistical/reference implementation if useful. Populus likely needs its own HLL representation because register access, deterministic serialization, sparse/dense control, and reconciliation are protocol-relevant.

## 3.6 xtask

`cargo xtask` becomes the stable developer interface.

Initial commands:

```text
cargo xtask fmt
cargo xtask lint
cargo xtask test
cargo xtask test-all
cargo xtask coverage
cargo xtask deps
cargo xtask metrics
cargo xtask gate commit
cargo xtask gate pr
```

`gate commit` must be reasonably fast.

It runs:

```text
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo machete
cargo deny check
cargo xtask metrics --quick
```

`gate pr` additionally runs:

```text
cargo test --workspace --doc
cargo xtask coverage
selected cargo mutants checks
deterministic simulator scenarios
iai-callgrind regression checks
release binary-size checks
cargo tree -d
```

Fuzzing, long simulations, Miri, large mutation runs, and soak tests run on scheduled CI or before releases.

---

# 4. Metrics tracked for every commit

Every CI run produces a machine-readable artifact:

```text
metrics/<git-sha>.json
```

It does not need to be committed to Git.

Track at minimum:

```text
release binary bytes
.text section bytes
runtime direct dependency count
runtime transitive dependency count
duplicate dependency versions
clean build duration
incremental build duration
HLL insert cost
HLL merge cost
HLL memory bytes
routing nearest-node lookup cost
client assignment cost
canonical encode/decode cost
simulated ingest messages/sec
simulated authority messages/sec
peak simulator memory
```

Use deterministic instruction-count benchmarks for hard CI regression gates where possible.

Wall-clock benchmark results are informational unless executed on controlled hardware.

Initial policy:

```text
all metrics: record from first implementation
binary size increase > 2%: annotate
binary size increase > 5%: requires explicit justification
new runtime dependency: annotate dependency-tree delta
hot-path instruction increase > 5%: investigate
hot-path instruction increase > 10%: fail unless approved
```

Budgets become stricter after stable baselines exist.

Never optimize code solely to satisfy a noisy benchmark.

---

# 5. Testing architecture established in Phase 0

Before implementing protocol code, create these test layers:

```text
unit/
property/
reference/
simulation/
network/
adversarial/
fuzz/
bench/
```

The simulator must support:

```text
seeded deterministic randomness
virtual monotonic clock
per-node wall-clock offset
packet latency
packet jitter
packet loss
reordering
duplication
partitions
node crash
node restart
node join
node leave
Byzantine scripted behavior
bounded bandwidth
bounded connection count
```

No integration test should need `sleep()` to model protocol time.

---

# 6. Phase 1: fundamental IDs, hashing, encoding, and crypto

Implement:

```text
NodeId
ClientId
ProducerId
ContentId
MutableContentId
RoutingKey
Epoch
AuthorityId
```

Requirements:

```text
NodeId = domain-separated hash of normalized scarce network identity
ClientId = separately domain-separated hash of the same scarcity source
ProducerId = cryptographic producer identity
RoutingKey = fixed-width hash used for XOR distance
ContentId = immutable content identity
MutableContentId = stable identity for mutable content
PeerId remains libp2p transport identity
NetworkIdentity normalization follows ARCHITECTURE.md section 2.2 (ID-002):
  one pure function with typed errors in populus-types, IPv6 -> /48, ineligible addresses rejected
```

Do not allow implicit conversion between these ID types.

Implement domain-separated hashes such as:

```text
H("populus/node/v1" || encoded_network_identity)
H("populus/client/v1" || encoded_network_identity)
H("populus/routing/v1" || logical_identifier)
```

Use length-delimited or otherwise unambiguous encoding.

### Tests

Unit:

```text
same input -> same ID
different domain -> different ID
IPv4 normalization
IPv6 prefix normalization
XOR distance
ordering
serialization round trips
```

Property:

```text
xor(a,a) == 0
xor distance symmetric
hash-derived IDs statistically distribute over tested prefixes
serialization round trip for arbitrary valid IDs
```

Golden vectors are appropriate here because external protocol bytes must remain stable.

Completion condition:

A language-independent test-vector file can reproduce all identifier derivations.

---

# 7. Phase 2: HyperLogLog and distinct-client sketches

Implement the Populus distinct counter behind an interface.

Initial representation:

```text
sparse representation for small populations
dense HLL for larger populations
```

Target initial dense precision:

```text
p = 14
registers = 16,384
6 bits/register
raw dense register storage ~= 12 KiB
nominal HLL error ~= 0.81%
```

Required operations:

```text
insert(ClientId)
estimate()
merge()
serialize()
deserialize()
iterate/read registers
reset()
memory_usage()
```

Do not expose implementation details to higher protocol layers unless needed for reconciliation.

### Reference oracle

Tests maintain an exact `HashSet<ClientId>` for manageable populations.

### Required properties

```text
inserting same ClientId repeatedly does not materially change estimate
merge(A,A) == A
merge(A,B) == merge(B,A)
merge(merge(A,B),C) == merge(A,merge(B,C))
partition then merge approximates direct insertion
serialization preserves sketch
sparse -> dense promotion preserves estimate
```

Test cardinalities across:

```text
0
1
10
100
1K
10K
1M
```

Large cardinalities may use generated hashes without retaining full production-sized state.

Validate statistical error over many deterministic seeds, not against one lucky data set.

Test audience relationships such as:

```text
|A union B|
|B \ A| ~= |A union B| - |A|
|A intersection B| ~= |A| + |B| - |A union B|
```

These derived statistics are informational only and must not become security decisions without independent error analysis.

The v1 implementation uses exact sorted ClientIds through 256 entries and
promotes to a 14-bit-precision HLL with six-bit packed registers. Serialization
is versioned and canonical; see ARCHITECTURE.md section 12. Its decoder is
covered by a fuzz target.

Phase 2 completion requires the interface, merge/serialization properties,
deterministic statistical tests through one million IDs, exact small-set
comparisons, and bounded decoder behavior to pass.

---

# 8. Phase 3: immutable and mutable content model

Implement immutable content first.

Conceptual object:

```text
ContentBody {
    schema_version
    created_at
    media_type
    payload
    tags[]
    associations[]
    producers[]
    metadata
}
```

Optional signatures:

```text
Signature {
    producer_id
    algorithm
    signature
}
```

Anonymous content has no producers or signatures.

Multi-producer content may contain multiple valid signatures over the same canonical body.

Use deterministic canonical encoding before hashing or signing.

Prefer DAG-CBOR plus CID/multihash unless testing reveals a compelling reason not to.

Immutable object:

```text
body bytes
-> body digest
-> signatures
-> complete object
-> CID
```

Mutable content:

```text
MutableContentId
Revision {
    mutable_id
    sequence
    previous_revision_cid
    body
    signatures
}
```

Every revision is immutable and content-addressed.

### Tests

```text
same semantic object -> same canonical bytes
field/map insertion order does not affect CID where schema permits
single-byte semantic change -> different CID
signature verifies correct body
signature fails modified body
multiple producers independently verify
anonymous object needs no signature
revision chain validates
sequence rollback rejected where applicable
```

Fuzz all parsers.

---

# 9. Phase 4: pure XOR-DHT routing core

Implement routing separately from libp2p networking.

Do not optimize first.

Start with a brute-force reference implementation:

```text
closest(target, peers, n):
    sort all peers by xor_distance(target, NodeId)
    take n
```

Then implement Kademlia-style buckets using Populus `NodeId`.

### Tests

Every optimized nearest-node lookup must be differential-tested against brute force.

Property tests:

```text
closest node ordering equals brute-force ordering
insert order does not change logical nearest set
remove/reinsert behaves correctly
duplicate peer rejected
bucket bounds maintained
random churn preserves lookup correctness
```

Simulation:

```text
100 nodes
1K nodes
10K virtual nodes
joins
leaves
churn
partitions
recovery
```

The seeded `populus-sim` routing lifecycle scenario runs each operation at all
three sizes, checks each table against the brute-force nearest-node oracle, and
verifies that partitions remove cross-component contacts and recovery restores
reachable contacts. This is a virtual routing-table model, not a transport or
iterative-network simulation.

No libp2p transport is needed yet.

---

# 10. Phase 5: deterministic distributed simulator

Before live networking, provide a deterministic virtual-time event engine and run
the implemented routing, content, and client-sketch APIs through it. The simulator
is a first-class test oracle, not a demo. It must support seeded identities,
latency and clock skew, scheduled node failures, and scripted malicious message
behavior without sockets or wall-clock time.

The authority-cluster and ingest-buffer state machines are defined in later
phases (7-10). Do not duplicate or prematurely specify those protocols in the
simulator; wire their pure implementations into this engine as those phases land.
Until then, simulator vote placement is only a workload generator and does not
select the protocol's client-to-ingest assignment algorithm.

Each simulation must accept:

```text
seed
node count
client count
content count
latency distribution
clock-skew distribution
failure schedule
malicious-node strategy
```

A failed randomized simulation must print a seed that reproduces it exactly.

Add small reference scenarios as permanent regression tests.

Phase 5 is the simulator foundation, not an implementation of protocol phases
that have not been built. Its coverage is incremental: every later phase that
adds protocol behavior owns integrating that behavior into `populus-sim` and
adding deterministic scenarios for its externally observable invariants. Do not
duplicate or implement future protocol behavior in the simulator ahead of its
owning phase. This applies to transport and routing integration in Phase 6,
authority behavior in Phase 7, direct ingest in Phase 8, delegated assignment
in Phase 9, delegated ingest in Phase 10, and each subsequent protocol phase.

The foundation is complete when fixed-seed workloads are reproducible, failures
report their seed, virtual time and configured faults are observable, and the
implemented routing, content, and client-sketch APIs are exercised with
independent checks. Phase 4's specified routing scales and lifecycle scenarios
are a prerequisite and must be covered before closing Phase 5. Cluster and
ingest behavior becomes a simulator requirement in the phase that implements
each state machine.

---

# 11. Phase 6: libp2p transport integration

Reuse libp2p for:

```text
PeerId
Noise
TCP
QUIC
Yamux
DNS
Multiaddr
connection management
request-response streams
identify
ping
```

Do not use libp2p PeerId as Populus NodeId.

Do not use stock libp2p Kademlia as the authoritative routing implementation.

Implement a transport adapter so routing and protocol state machines do not depend directly on `Swarm`.

### Tests

```text
two-node local connection
QUIC path
TCP path
request-response framing
message-size limits
malformed frame rejection
connection cancellation
peer disconnect
backpressure
```

Use loopback networking only for these tests.

Most behavior remains tested without sockets.

---

# 12. Phase 7: four-node authority cluster

For each routing key:

```text
authorities = four closest known NodeIds by XOR distance
```

Authorities maintain minimal replicated authoritative state.

All authority-to-authority protocol messages are signed.

Initial authority state includes:

```text
content/routing key
epoch
membership view
mode: direct | delegated
delegation descriptor
rate state
daily popularity state
association summary
tag reporting state
sequence/generation
```

### Failover

When one authority disappears:

```text
next closest eligible node joins
new node queries remaining three
two matching valid state views are sufficient to initialize
```

If no two match:

```text
do not guess
enter recovery/rebuild state
request retained reports/checkpoints
```

### Tests

```text
one authority crash
authority restart
replacement joins
2 matching + 1 conflicting state
signed equivocation proof
stale state replay
sequence rollback
2-vs-2 disagreement
network partition
```

A node may be automatically disqualified only for objectively provable protocol violations or liveness rules defined by the protocol.

---

# 13. Phase 8: direct ingest

Small ContentIDs are handled directly by all four authorities.

Each authority maintains HLL state.

Initial delegation trigger:

```text
maximum desired direct rate = 1000 votes/minute
```

This number is configurable until benchmarked.

Votes use daily epochs.

Conceptually:

```text
VoteId = H(
    "populus/vote/v1"
    || ActualContentId
    || UTC-date
)
```

A persistent local like causes the client to submit a fresh vote once per day when online.

Unlike means the client stops producing future daily votes.

### Tests

```text
duplicate delivery
retry
late daily vote
UTC boundary
client offline for part of day
authority clock skew
network latency
authority crash during ingest
```

Daily totals are authoritative only after an appropriate close/grace period.

Realtime counts are provisional.

---

# 14. Phase 9: delegated ingest assignment experiment

Do not freeze the assignment algorithm before simulation.

Define an interface:

```text
IngestAssignment {
    assign(client_id, view, descriptor) -> IngestNode
}
```

Test at least:

```text
A. salted client hashes:
   H(ClientId || view)

B. disjoint ClientId bit ranges

C. XOR/rendezvous selection among delegated nodes

D. MatchBits-based assignment within the ContentID neighborhood
```

Selection goals:

```text
three independent views
one destination per view
three different nodes when cluster size permits
near-uniform load
deterministic
cheap
stable under a fixed delegation descriptor
difficult for one malicious ingest node to influence multiple views
```

Authorities know the actual nearby node population.

Never assume:

```text
2^bits == number of available nodes
```

NodeIDs are sparse random points.

The selected bit width must be based on the observed candidate population and measured ingest rate.

Benchmark and simulate before choosing protocol v1.

---

# 15. Phase 10: delegated ingest protocol

When direct rate exceeds the configured threshold:

```text
authorities
    -> select closest suitable non-authority ingest nodes
    -> publish delegation descriptor
    -> direct clients away from authorities
```

Clients report to one node in each of three independently shuffled views.

Each ingest node maintains:

```text
current HLL
previous/reporting HLL
report sequence
ACK state for four authorities
```

At window rollover:

```text
current -> pending report
new current starts immediately
pending report sent to all four authorities
pending report retained until all four acknowledge
```

Never stop collection while transmitting the previous report.

Default initial reporting interval:

```text
1 minute
```

It may increase for extremely large clusters if testing shows this is useful.

### Timing behavior

Per-minute sketches are not expected to be identical across views because of:

```text
latency
clock drift
reordering
different report boundaries
```

Authorities therefore use minute reports primarily for:

```text
rate
trend
capacity control
statistics
```

Daily cumulative sketches are a stronger cross-view consistency signal.

### Tests

Simulate:

```text
+/- 30 second wall-clock skew
0-10 second latency
heavy jitter
report reorder
lost ACK
lost report
duplicate report
ingest crash before ACK
ingest crash after ACK
authority crash during ACK
malicious inflated sketch
malicious suppressed sketch
one corrupted view
```

---

# 16. Phase 11: delegation control loop

Implement a pure deterministic controller.

Inputs:

```text
observed rate
estimated per-node rate
current candidate population
current selector/bit width
current reporting interval
recent history
```

Outputs:

```text
direct/delegated mode
candidate count
assignment parameters
reporting interval
```

Use:

```text
hysteresis
minimum dwell time
quantized changes
rate smoothing
hard overload trigger
```

Never allow minute-to-minute noise to create uncontrolled oscillation.

### Tests

```text
steady load
slow ramp
viral 1K -> 100M
sudden collapse
alternating near-threshold rate
delayed reports
missing view
malicious high report
malicious low report
```

Property:

```text
for stable offered load, configuration eventually stabilizes
```

---

# 17. Phase 12: outlier and Byzantine-report handling

Do not initially compare raw minute HLL registers as if windows were perfectly aligned.

Reconcile over windows large enough to absorb normal timing skew.

Compare:

```text
view cardinality
rolling cardinality
daily cumulative HLL
rate distribution
per-node assignment expectations
```

The protocol should tolerate one bad independent view when two healthy views agree within statistically justified bounds.

Thresholds must be derived from simulation and HLL error, not arbitrary constants.

Never silently discard a view without recording why.

### Tests

```text
honest timing disagreement
HLL statistical error
one extreme inflated view
one suppressed view
selective suppression
slow dishonest drift
two conflicting malicious views
```

Security expectation:

```text
three shuffled ingest views tolerate one bad view
four authorities target tolerance of one bad authority
```

This is not a claim of general Byzantine consensus.

---

# 18. Phase 13: tags, associations, and recursive aggregation

Treat associations as ContentIDs.

A tag may:

```text
have content/description
be tagged itself
be associated with other tags
report upward to a root tag
```

Replies can be represented through associations rather than requiring a separate popularity architecture.

The authority nodes for a child ContentID report popularity changes to authority nodes responsible for associated tag ContentIDs.

Use geometric update thresholds rather than every count change.

Initial candidate:

```text
threshold(k) ~= 1.25^k
```

Exact progression remains configurable.

Large tag clusters may delegate tracking of many low-volume associated children to non-authoritative nodes.

### Tests

```text
content -> tag
reply -> parent content
tag -> tag
language tag -> root
large fan-out
cycles
duplicate associations
malicious association report
geometric threshold transitions
```

Cycles must never cause recursive report storms.

---

# 19. Phase 14: producer identities and subscriptions

Producer identity is entirely separate from ClientId and NodeId.

Support:

```text
anonymous content
single producer
multiple producers
producer feed
producer subscription
```

A producer public key identifies authorship.

A subscription to a producer is not a popularity vote unless explicitly represented as one.

Tests must prove that:

```text
changing network identity does not alter ProducerId
changing ProducerId does not alter ClientId
multiple producer keys can sign one content object
anonymous content remains valid
```

---

# 20. Phase 15: persistence and recovery

Do not choose a database before state requirements are known.

Start with traits and an in-memory implementation.

Persist only state proven necessary for:

```text
restart recovery
authority continuity
pending ingest reports
content cache
routing table bootstrap
```

Evaluate storage engines only after workloads are measurable.

Adding RocksDB, SQLite, redb, sled, or another database requires a dependency, binary-size, memory, and write-amplification comparison.

---

# 21. Phase 16: hardening

Before protocol stabilization:

```text
fuzz every network decoder
mutation-test core state machines
run long deterministic simulations
run randomized churn simulations
run eclipse/Sybil scenarios
run NAT/IPv6 scenarios
run multi-process localhost tests
run memory profiling
run dependency audit
run binary bloat report
run performance baselines
```

Protocol v1 is not frozen until deterministic encoding vectors and cross-version compatibility tests exist.

---

# 22. Definition of done for every implementation commit

A commit implementing behavior is complete only when:

```text
1. Behavior is documented or already specified.
2. Tests fail without the implementation.
3. Tests exercise observable behavior or invariants.
4. Reference/model tests exist where practical.
5. Property tests cover algorithmic code where practical.
6. No existing test was weakened without explanation.
7. cargo xtask gate commit passes.
8. Runtime dependency delta is reviewed.
9. Binary/performance metrics are recorded.
10. No unexplained regression is introduced.
11. ARCHITECTURE.md is updated if protocol behavior changed.
12. AGENTS.md remains accurate if workflow changed.
```

The preferred commit shape is:

```text
spec/test -> implementation -> cleanup
```

When practical, the test and implementation may be in one commit, but the test must remain independently meaningful.
