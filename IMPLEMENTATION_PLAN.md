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
cargo xtask setup
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

`setup` checks the four pinned Cargo tools and installs only missing or mismatched
versions in one locked, unoptimized dev-profile invocation, without debug
information or incremental compilation, sharing build artifacts in the ignored
`.cache/populus-tools/` directory. It also checks `rustfmt`, `clippy`, and
`llvm-tools-preview` for the active toolchain and installs only missing components
in one `rustup component add` invocation. No installer runs if everything is ready.
Gates preflight all four pinned versions and all three Rust components and direct
users to `cargo xtask setup` if any are unavailable; checks never invoke installers.

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

Small `ContentId`s are handled directly by all four authorities.

Each authority maintains HLL state.

Initial delegation trigger:

```text
maximum desired direct rate = 1000 votes/minute
```

This number is configurable until benchmarked.

Votes use daily epochs.

Conceptually:

```text
DailyVoteId = SHA-256(
    "populus/vote/v1"
    || ActualContentId
    || signed UTC-day offset since 1970-01-01
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

The direct-ingest state is a pure model bound to one `ContentId` and `UtcDay`.
All four authorities consume the same client-selected daily epoch, insert
validated `ClientId`s idempotently into their own `ClientSketch`, and replicate
the versioned bounded snapshot through Phase 7 state. Clients retry a pending
vote until all four authorities in the pinned membership view return valid
signed acknowledgements or the vote expires; a membership replacement
re-targets the same vote. Clients retry through the following UTC day, then
discard a still-pending vote when returning two or more days later and vote
only for the current day. The combined configurable close-grace and clock-skew
allowance is bounded to one day so this expiry cannot discard a vote that
authorities could still accept.
Configurable close grace and clock-skew allowances keep boundary-delayed votes
provisional before finalization. Exceeding the configurable direct-rate target
recommends delegation but does not discard votes; assignment and delegated-
ingest transitions remain owned by Phases 9-10.

The canonical daily-bucket hash and authority snapshot bytes are fixed by
`testvectors/daily-vote-v1.txt` and `testvectors/direct-ingest-v1.txt`.
Direct-vote and signed-ack wire bytes are fixed by
`testvectors/direct-vote-ack-v1.txt`.

---

# 14. Phase 9: delegated ingest assignment experiment

Do not freeze the assignment algorithm before simulation. Phase 9 supplies the
experimental harness and candidate implementations, but does not choose a
protocol-v1 algorithm or wire encoding.

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

`populus-cluster` implements these candidates behind the `IngestAssignment`
trait. `DelegationDescriptor` canonicalizes a unique candidate set and records
the assignment version, candidate strategy, and MatchBits width. Per-content
simulator descriptors use the closest known nodes in that content's
`RoutingKey` neighborhood. The three-view helper resolves collisions
deterministically and uses distinct destinations whenever the candidate pool
permits.

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

The selected bit width must be based on the observed candidate population and
measured ingest rate.

The MatchBits width helper uses the observed candidate count, offered rate, and
per-ingest-node rate target. Match bits are applied to NodeId bits immediately
after the candidate set's shared prefix and compared with the client's hash
prefix. A missing sparse prefix falls back to the closest candidate rather than
reporting a missing destination.

`populus-sim` can run each candidate through the same seeded workload and
reports per-view node loads, the observed candidate count, the selected
MatchBits width, and an experimental descriptor-size estimate. Run the
assignment microbenchmark with:

```bash
cargo run --release -p populus-cluster --example ingest_assignment_benchmark
```

Each raw benchmark sample records its index, execution order, algorithm,
nanosecond duration, and checksum. Execution order rotates between samples.
These machine-specific measurements leave protocol-v1 selection and canonical
wire encoding open for a later decision.

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

The seeded simulator exercises the actual delegated report/ACK state with
independent view accumulators, +/-30-second ingest clock offsets, 0-10-second
network delay, lost report and ACK retries, duplicate delivery, sender and
receiver snapshot restoration, and a delayed stale report. It also measures
how inflated or suppressed sketches affect only their own view; statistical
quarantine remains Phase 12 work.

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

The pure cluster controller consumes explicit virtual timestamps and up to
three view-rate reports, smooths a bounded five-sample history, preserves the
selected assignment algorithm, and quantizes candidate and reporting-interval
changes. Direct mode estimates capacity from offered rate without a delegated
three-view multiplier. Contraction and direct-mode return use separate counters
that advance only on fresh valid observations; hard overload cannot scale down.
Its seeded simulator scenarios cover the required ramp/jump, collapse, threshold
oscillation, missing/delayed reports, and single-view malicious outliers. The
initial thresholds and interval buckets are engineering defaults; they remain
tunable pending broader simulation evidence.

---

# Phase 11.5: Permissionless Network Formation and Runtime Identity

Phase 11.5 connects the existing transport, Populus DHT, identity lifecycle,
authority, and ingest state machines. It must preserve the permissionless
network model defined in [ARCHITECTURE.md](./ARCHITECTURE.md#5101-agreed-phase-115-protocol-decisions).

A process may start and participate provisionally without a trusted manifest,
founding committee, or privileged signer. The public network has a fixed
protocol-defined network identifier independent of keys. Each process uses one
configured network identifier; messages, signed evidence, candidate records,
and persisted state must be bound to it. Disconnected groups using the same
identifier are one network, and their DHT neighborhoods should merge through
ordinary discovery, authenticated identity checks, and state reconciliation.

Verification and ownership are local, evidence-based views. Select verifier
preferences from the nearest currently eligible verified `NodeId`s in the local
DHT neighborhood. Do not construct globally finalized eligibility snapshots
or a certificate chain. Distinct verified `NodeId`s count as protocol
identities only; they do not prove distinct physical operators. Provisional
identities may help discovery but must not be presented as independently
verified or used as verified authority members.

Ownership uses renewable bounded leases and current direct-reachability
evidence. Keep a valid, healthy incumbent. Candidate ranking changes standby
preference, not ownership of a healthy incumbent. Contradictory current claims
must retain a valid incumbent only when that remains consistent with the
evidence; otherwise mark the `NodeId` disputed and exclude it from authority
eligibility until reconciliation. Do not claim global uniqueness or globally
consistent membership during arbitrary partitions. Treat convergence as
best-effort and test it under partitions, reordered evidence, churn, and
recovery.

Candidate storage remains bounded and deterministically sharded. Resource
limits are local policy, not a network-wide candidate limit. Keep the existing
4,096-record cap as a provisional local bound; defer dynamic scaling until
simulator workloads justify it. Restart recovery preserves the process
identity and necessary local state, then revalidates reachability and
ownership against current observations. It does not replay a certificate
chain from genesis.

## 11.5.1 Persistent process identity and local recovery

Persist the libp2p process identity atomically and durably. Preserve bounded
local candidate sequence history and any state needed to avoid replay or
contradictory local ownership after restart. On restart, treat saved contacts
and ownership as hints: revalidate network ID, PeerId, current direct
reachability, lease expiry, and conflicts before restoring verified status.
Do not treat stale local state as authority over newly observed evidence.

**Current status: Partially implemented.** The transport key is written through
a create-once temporary file and non-replacing hard link. The file and every
directory entry along its existing or newly created path are synced before
success; loading an existing key also syncs that path before returning it.
Candidate sequence history, ownership state, and restart revalidation are not
persisted.

## 11.5.2 Permissionless startup and peer discovery

Allow a process to start with the fixed public network ID and no bootstrap
addresses. Configured peers are discovery entry points, not trusted
authorities. Bootstrap failure must neither terminate ordinary participation
nor trigger special initialization. Maintain separate provisional and verified
routing views where necessary. Retry alternate advertised addresses after a
dial failure, and reconcile peer routing and Populus state separately when
previously disconnected groups meet.

**Current status: Partially implemented.** The process uses the configured
network ID and can start without bootstrap addresses. Discovery retries the
remaining advertised addresses after a dial failure. Provisional DHT views and
ownership or authority-state reconciliation are not implemented.

## 11.5.3 Continuous public identity discovery

Continue observing direct connection endpoints and locally discovered public
addresses throughout process lifetime. Normalize every address through the
production `NetworkIdentity` validator. Support multiple IPv4 and IPv6
identities per process, deduplicate equivalent normalized identities, and
revalidate after address or connection changes. Inject public-address
observations and reachability outcomes in tests without weakening production
validation. Rotate periodic observer selection so peers beyond a fixed prefix
are not starved.

**Current status: Partially implemented.** The process periodically refreshes
observations, rotates the selected connected peers, and attributes requests to
their exact connection endpoints. The runtime still does not discover and
activate every local address change automatically. Multiple identity lifecycle
and revalidation cases need broader integration coverage.

## 11.5.4 Provisional participation and identity verification

A new identity may exchange discovery information provisionally. A provisional
claim is not a verified active `NodeId`; only current authenticated evidence
may promote it. Count distinct verified active `NodeId`s rather than `PeerId`s
when a policy requires independent protocol identities. Retain the current
production address eligibility validator. Bind signed observation and
reachability evidence to the network ID, exact candidate registration, fresh
challenge, verifier identity, and validity interval. Preserve valid incumbent
state during refresh and do not consume a challenge on an invalid response.

**Current status: Partially implemented.** Local observation, nonce, identity,
and direct-verification lifecycle APIs exist. Provisional DHT participation,
network-bound signed evidence, and end-to-end verifier exchange are not
implemented. The lifecycle must also preserve capacity while verification is
refreshed and while retirement cleanup is pending.

## 11.5.5 Bounded candidate registry

Keep signed, expiring candidate registrations bound to the configured network,
normalized identity, derived `NodeId`, transport public key, and exact
`PeerId`. Preserve deterministic sharding and bounded pages. Retain sequence
high-water marks after a registration expires so an older still-valid record
cannot reappear. The per-process cap is a resource limit; it does not cap the
network's candidate population. Registration messages must report only
records actually admitted to the registry.

**Current status: Partially implemented.** Signed registrations, sharding,
bounded pages, and request/acknowledgement messages exist. The local registry
retains a sequence high-water mark until the latest expiry among accepted
versions, then reclaims that replay metadata and its bounded slot. Runtime
publication is caller-driven, sequence history is not durably restored, and
publication reports request IDs admitted before a fan-out failure without
providing retry or recovery automation.

## 11.5.6 Candidate persistence, leases, and standby ranking

Persist the local identity and sequence state needed for safe renewal. Use
renewable bounded leases and current independently verified reachability.
Prefer standbys with verified successful renewal history, then apply a stable
`PeerId` tie-break. Do not rotate a healthy incumbent because another
candidate ranks higher. Lease duration, renewal interval, and tolerated clock
skew are provisional until simulation measures their behavior under delay,
partitions, stale messages, and restart.

**Current status: Deferred.** Candidate renewals, distributed registry
persistence, verified renewal history, and standby ranking are not connected to
a runtime ownership view. Existing lease constants are provisional.

## 11.5.7 Conflict-aware local ownership view

Represent candidate observations and ownership claims as network-scoped,
independently verifiable evidence. Reject replayed, expired, wrong-network, or
wrong-candidate evidence. When two claims conflict, retain a still-valid
incumbent only if current evidence supports it; otherwise mark the `NodeId`
disputed and exclude it from authority eligibility. Do not select a winner
because one group started earlier, because it contains bootstrap peers, or
because its routing table merged first. Convergence is expected after peers
exchange current evidence, but is not a global partition-time guarantee.

**Current status: Deferred.** Genesis-rooted committee and binding-certificate
machinery has been removed. The process does not yet exchange distributed
ownership evidence or reconcile conflicting assertions. Keep disputed
identities out of authority eligibility until a safe reconciliation mechanism
is implemented and simulated.

## 11.5.8 Identity activation and retirement

Allow multiple normalized IPv4/IPv6 identities per process while enforcing
local resource bounds. Do not release an active slot during verification
refresh or before retirement cleanup completes. Beginning retirement stops
advertising the identity and accepting new direct or delegated ingest work for
its authority state. Keep the retirement marker until routing and authority
cleanup finishes. Do not reactivate an identity already retiring.

**Current status: Partially implemented.** The process keeps lifecycle state
per normalized identity, excludes retiring identities from newly advertised
contacts, and binds authority work and cleanup to its owning logical `NodeId`.
Complete multi-identity handoff remains incomplete.

## 11.5.9 Existing authority and ingest integration

Use the existing direct and delegated ingest state machines without simplified
substitutes. Resolve `ClientId` from the exact authenticated inbound
connection endpoint. A direct-vote success event or acknowledgement may be
reported only after the authority state machine accepts and records the vote.
Reject direct and delegated ingest from retiring or disputed authorities.
Preserve duplicate handling, acknowledgements, retry buffers, and replicated
state invariants. Network membership discovery and authority-state conflict
reconciliation are separate responsibilities.

**Current status: Partially implemented.** Request/response adapters invoke
the existing ingest state machines and return signed acknowledgements only
after acceptance. The process uses the exact inbound connection endpoint for
client identity checks. Membership remains caller-installed, and automated
authority membership, fan-out, retry, and recovery are incomplete.

## 11.5.10 CLI, configuration, and observability

Provide one network ID per process, defaulting to the fixed public network ID.
Remove trusted-genesis options and configuration keys. Reject a `--config`
option without a filename, malformed network IDs, unsupported address forms,
and unknown keys. Log provisional, verified, disputed, and retiring state
without implying global ownership guarantees.

**Current status: Partially implemented.** The CLI accepts one configured
network ID, defaults to the fixed public ID, rejects unknown keys, and no
longer exposes genesis authorization options. Structured lifecycle
observability and broader configuration validation remain.

## 11.5.11 Tests, simulations, and acceptance criteria

Use focused unit tests for canonical encoding, network mismatch, replay,
challenge retention, candidate sequence rollback, persistence durability,
identity transitions, and exact connection attribution. Use localhost tests for
actual authenticated transport behavior and multi-identity processes. Keep the
Linux namespace laboratory in Phase 17. Deterministic simulation must cover
partition and merge, candidate conflicts, incumbent renewal, delayed and
reordered evidence, stale state after restart, multiple PeerIds per NodeId,
and authority/ingest refusal while disputed or retiring.

Run workspace tests, deterministic simulation, strict Clippy, and the commit
and PR gates after protocol and runtime work is complete. Do not claim a
quality gate that was not run.

### Phase 11.5 completion criteria

| Criterion | Status | Evidence / remaining work |
| --- | --- | --- |
| 1. Stable process identity and durable restart recovery | Partially implemented | Transport identity creation is atomic and durable; candidate state, leases, and restart revalidation are not persisted. |
| 2. Permissionless startup without genesis authorization | Fully implemented | Genesis manifests, signing keys, CLI options, and committee-chain runtime APIs have been removed. A node can start without bootstrap peers. |
| 3. Network ID is fixed/configured and binds messages and state | Partially implemented | The CLI configures one network ID, defaults to the fixed public ID, and the application envelope rejects mismatches. Candidate registrations carry the network ID; durable network-scoped state is not implemented. |
| 4. Bootstrap discovery, retries, and neighborhood merging | Partially implemented | Discovery retries alternate advertised addresses. Provisional routing and authority-state reconciliation after a merge remain. |
| 5. Continuous multi-address identity discovery | Partially implemented | Periodic observations, endpoint attribution, and peer rotation exist; automatic local identity change handling remains incomplete. |
| 6. Provisional participation without false verification claims | Partially implemented | Candidate contacts can support discovery, but a separate provisional routing view and full promotion workflow are absent. |
| 7. Distinct verified NodeId evidence and direct reachability | Partially implemented | Local evidence counts distinct NodeIds and uses direct endpoint observations; distributed signed verifier exchange is not implemented. |
| 8. Bounded sharded candidate registry without a global cap | Partially implemented | Signed registrations, deterministic shards, bounded pages, and local limits exist; sequence recovery and distributed persistence are incomplete. |
| 9. Renewable leases and incumbent/standby behavior | Deferred | The runtime has no renewable ownership leases or standby history to preserve an incumbent. |
| 10. Conflict detection and eventual state reconciliation | Deferred | Candidate-registration conflicts can be rejected locally, but distributed ownership evidence and authority-state reconciliation are absent. |
| 11. Safe identity retirement and authority cleanup | Partially implemented | Retirement prevents new advertisements and authority work for its specific owner, and cleanup preserves sibling-owned state; complete handoff and persisted authority recovery remain. |
| 12. Actual authority and ingest state-machine integration | Partially implemented | Direct and delegated adapters use existing state machines, exact endpoint attribution, and acceptance-based acknowledgements; membership and recovery remain caller-managed. |
| 13. Regression coverage and full quality gates | Partially implemented | Focused tests cover local protocol and lifecycle behavior; permissionless simulations and final workspace gates remain. |

Phase 11.5 is incomplete. The previous trusted-genesis committee model is not a
valid compatibility layer for the permissionless protocol and must be removed.
No claim of global ownership uniqueness, global membership consistency, or
partition-time availability is part of the acceptance criteria.

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


# 20. Phase 15: persistence and recovery

## Objective

Provide durable, bounded, and recoverable storage for Populus state
that must survive process restarts, crashes, and network interruptions.

Phase 11.5 introduces the minimum persistence needed for a runnable
node, particularly its cryptographic PeerId and bootstrap contacts.

Phase 15 formalizes storage durability, recovery semantics, integrity,
migration, and resource management across all implemented subsystems.

Do not choose a database before state requirements and workloads
are known.

Start with explicit storage interfaces and an in-memory reference
implementation. Evaluate persistent storage engines using measured
workloads.

---

## 15.1 State classification

Classify state into four categories:

### A. Persistent local identity

- Process cryptographic private key and stable PeerId
- Local node configuration
- Explicit bootstrap configuration

These must survive restart.

Private key material must be protected using appropriate filesystem
permissions and must never be written to logs or metrics.

Phase 11.5 must already implement minimal safe persistence of
the process identity. Phase 15 may improve its storage abstraction
and recovery guarantees without changing the PeerId.

### B. Recoverable network state

- Bootstrap peer cache
- DHT routing contacts
- Public address observations
- NodeID verification evidence
- Active NodeID bindings
- Candidate registration metadata
- Verified candidate persistence history
- Standby candidate rankings

This state may be cached locally to accelerate recovery.

However, locally persisted evidence is not automatically current
or authoritative after restart.

Verification signatures, membership generations, expiration,
and leases must be revalidated before cached data is trusted.

Candidate ranking history must be based on independently
verified evidence rather than self-reported uptime.

### C. Durable protocol state

- Authority membership views and generations
- Accepted authority state/checkpoints
- Unacknowledged delegated-ingest HLL reports
- Report sequences and acknowledgement progress
- Daily sketches needed for recovery
- Pending replicated transitions
- Finalized epoch metadata
- Replay-protection information where required

Losing this state must not silently acknowledge work that
can no longer be recovered.

A pending ingest report must not be discarded until all four
required authorities have acknowledged it, consistent with
the existing delegated-ingest protocol.

Persisting a report locally does not replace delivery and
acknowledgement requirements.

### D. Reconstructable caches

- Cached content
- Cached association summaries
- Derived popularity statistics
- Rebuildable routing indexes
- Expired candidate registrations
- Temporary discovery results

These may be discarded and reconstructed.

Use explicit capacity limits, expiration rules, and eviction
policies.

Do not retain unbounded per-client or per-candidate state.

---

## 15.2 Storage interfaces

Define narrowly scoped storage interfaces for:

```text
ProcessIdentityStore
BootstrapPeerStore
IdentityEvidenceStore
NodeBindingStore
AuthorityCheckpointStore
IngestReportStore
ContentCache
```

These names are conceptual. The implementation may combine them
where appropriate.

Protocol state machines should not directly depend on a specific
database implementation.

Avoid introducing a generic database abstraction more complex
than the actual required operations.

Each persistent record must specify:

- Record version
- Logical identity/key
- Epoch or generation, where applicable
- Sequence or monotonic revision, where applicable
- Expiration semantics
- Maximum encoded size
- Integrity validation requirements

A stored NodeID binding is a cached signed network assertion,
not proof that the local process currently owns the NodeID.

---

## 15.3 Durability and crash consistency

Define when writes must be durable and when best-effort
persistence is sufficient.

Use atomic replacement or a transactional mechanism for state
whose partial writes would violate protocol invariants.

Test crashes at every important state transition:

```text
Before writing
During writing
After writing but before acknowledgement
After acknowledgement
During checkpoint replacement
During membership generation transition
During identity retirement
```

Recovery must reject incomplete or corrupted records.

A node must never roll back to older protocol state silently.

If persisted state cannot be validated, enter an explicit
recovery state and request fresh evidence from other peers.

Do not allow a local cache to override a newer authenticated
network state.

---

## 15.4 Identity and candidate recovery

After restarting:

1. Restore the stable process PeerId.
2. Load bootstrap contacts.
3. Load cached public identity observations.
4. Load signed, unexpired verification evidence.
5. Revalidate current local and externally observed addresses.
6. Reconfirm active NodeID bindings before assuming authority.
7. Restore or rebuild eligible logical DHT nodes.
8. Resume periodic identity discovery and renewal.

A cached active binding is not permission to skip current
ownership and reachability checks.

If the process changed its public IP while offline, it must
discover and verify the new identity rather than continue
advertising an invalid old NodeID.

Candidate history should survive ordinary restarts when useful,
but expiration and verification rules still apply.

Never trust a locally stored persistence score merely because
it appears in a valid storage record.

---

## 15.5 Authority and ingest recovery

On restart, recover:

- Latest validated membership generation
- Latest accepted state/checkpoint
- Current epoch
- Pending state transitions
- Unacknowledged ingest reports
- Per-authority acknowledgement progress
- Relevant sequence numbers

Retained reports must be retransmitted idempotently when needed.

Recovery must not invent acknowledgements.

A restored node must reconcile its state with current authorities
before resuming responsibilities that require current membership.

If a node was replaced while offline, it must not resume its
former authority position merely because its local checkpoint
says it was previously authoritative.

---

## 15.6 Storage engine evaluation

Compare candidate storage engines only after collecting realistic
workload measurements.

Candidates may include:

```text
simple atomic files
redb
SQLite
RocksDB
other justified alternatives
```

Evaluate:

- Runtime dependency count
- Binary-size impact
- Resident memory
- Write amplification
- Recovery time
- Transaction guarantees
- Concurrent access requirements
- Storage growth over time
- Native dependencies
- Build and cross-platform complexity

A simpler solution is preferable when it meets the requirements.

Do not introduce RocksDB, SQLite, or another database merely
because the application is distributed.

---

## 15.7 Tests

Required scenarios:

```text
Persistent PeerId survives restart
Malformed identity file rejected
Missing/corrupt private key handled explicitly
Cached bootstrap peers restored
Expired identity evidence rejected
Public IP changes while node is offline
Candidate history restored without trusting stale ownership
Old active binding rejected after replacement
Authority checkpoint recovered
Membership-generation rollback rejected
Crash during checkpoint write
Crash before ingest-report ACK
Crash after partial ACK progress
Duplicate report retransmission
Pending reports retained until all four ACKs
Corrupt storage record
Unknown storage schema version
Large candidate registry with bounded storage
Cache eviction and expiry
```

Use deterministic fault injection and explicit crash points.

The storage implementation must be tested against an independent
in-memory reference model where practical.

---

## Phase 15 completion criteria

Phase 15 is complete when:

1. Necessary local and protocol state survives restart.
2. Persisted cryptographic identity is stable and protected.
3. Cached network assertions are revalidated before use.
4. Stale or expired NodeID bindings cannot silently resume authority.
5. Ingest reports survive crashes without false acknowledgements.
6. Authority state recovery rejects rollback and invalid transitions.
7. Corruption and partial writes are handled explicitly.
8. Recoverable caches are bounded and may be rebuilt.
9. Storage engine selection is supported by measured tradeoffs.
10. Dependency, binary-size, memory, and performance gates pass.
11. Recovery scenarios run in populus-sim and relevant localhost tests.
12. ARCHITECTURE.md and TESTING.md describe the resulting durability and recovery contracts.


# 21. Phase 16: protocol security, correctness, and hardening

## Objective

Harden the Populus protocol and implementation against malformed
input, malicious participants, resource exhaustion, concurrency
failures, identity attacks, and unexpected distributed behavior.

Phase 16 focuses on deterministic simulation, property testing,
fuzzing, mutation testing, and ordinary localhost integration.

Phase 17 separately validates the resulting implementation using
Linux network namespaces, actual IP routing, NAT, multihoming,
kernel-level packet faults, and independent processes.

Phase 16 completion does not imply protocol v1 is ready to freeze.
Protocol stabilization also requires the applicable Phase 17 tests.

---

## 16.1 Identity and bootstrap security

Audit the Phase 11.5 identity lifecycle:

```text
Unknown
Discovered
Verifying
Active
Suspect
Retiring
Removed
```

Verify:

- NodeId always derives from an eligible normalized NetworkIdentity.
- ClientId and NodeId remain separate hash domains.
- PeerId is not substituted for NodeId in routing decisions.
- Three agreeing observed-address reports only initiate verification.
- One observer cannot manufacture multiple independent observations.
- Stale and replayed observations are rejected.
- Verification requires fresh authenticated reachability evidence.
- A cached verification cannot bypass expiration or current checks.
- Bootstrap peers are discovery entry points, not trust anchors.
- Unverified peers cannot advertise themselves as active authorities.

Test false address observations, malicious bootstrap peers,
eclipse attempts, and conflicting routing contacts.

A public address observation is not proof of exclusive ownership
of the corresponding IPv4 address or IPv6 prefix.

Document remaining limitations of the IP-based scarcity model.

---

## 16.2 Shared-IP candidate and ownership attacks

Test many PeerIds competing for one NodeId.

Attack scenarios:

```text
Mass candidate registration
Many ports advertised by one peer
Repeated registration renewal
Forged persistence history
Fake uptime claims
Stale verification evidence
Competing active-owner claims
Conflicting binding generations
False incumbent failure reports
Concurrent standby promotions
Network partition during arbitration
```

Properties:

- One normalized NetworkIdentity occupies at most one position
  in a converged DHT membership view.
- Multiple PeerIds do not create multiple authority positions.
- A healthy incumbent is not displaced by registration alone.
- Candidate ranking uses independently verified evidence.
- A failed candidate does not receive priority through repetition.
- Candidate registration and verification work remain bounded.
- Conflicting active bindings are detected.
- An unresolved ownership conflict does not silently select
  an arbitrary winner.

Simulate hundreds or thousands of competing candidates without
creating an equivalent number of operating-system processes.

---

## 16.3 DHT and authority security

Test:

```text
NodeID neighborhood manipulation
Malicious routing contacts
Incomplete routing tables
Eclipse attempts
One malicious authority
One unavailable authority
Authority equivocation
Membership generation rollback
Stale state replay
Conflicting authority snapshots
Concurrent membership transitions
2-vs-2 partitions
```

Verify that authority selection counts distinct eligible NodeIds.

Do not assume different NodeIds necessarily represent independent
operators or administrative domains.

A process with multiple verified NodeIds may control multiple DHT
positions, subject to the global scarcity and Byzantine assumptions.

Document what is guaranteed by cryptographic signatures, by quorum
intersection, and only by operational assumptions.

Do not describe the system as Byzantine-safe without stating the
number and placement of compromised participants it tolerates.

---

## 16.4 Ingest and popularity security

Test:

```text
Forged ClientId
Duplicate votes
Replayed daily votes
Late daily votes
Invalid vote epochs
Malicious inflated HLL
Suppressed HLL
Selective client suppression
Missing ingest view
Malicious report sequence
Malformed report
Lost acknowledgement
Stale delegation descriptor
Contradictory delegation descriptors
```

Verify the boundary between an authenticated network connection
and a scarcity-derived ClientId.

A client-provided ClientId alone must not be treated as proof
of entitlement to cast a vote for that identity.

Verify that:

- Duplicate observations do not increase distinct cardinality.
- Missing or delayed reports do not silently finalize incomplete state.
- One malicious view cannot dominate two healthy independent views
  within the stated timing/statistical assumptions.
- Report reconciliation accounts for HLL error and clock skew.
- Delegation control remains stable under noisy or malicious input.

---

## 16.5 Robustness and fuzzing

Fuzz all untrusted network decoders and protocol entry points.

Include:

```text
Transport framing
Routing contacts
Observed-address responses
Verification evidence
Candidate registrations
Active NodeID bindings
Authority messages
Delegation descriptors
Ingest reports
Content objects
Mutable revisions
Persistent record decoders
```

Requirements:

- No panic from malformed remote input.
- No unbounded allocation.
- No unbounded recursion.
- No unexpected integer overflow.
- No uncontrolled task or connection creation.
- No infinite retry or message amplification loop.

Use bounded input sizes and explicit resource limits.

---

## 16.6 Mutation, property, and reference testing

Run mutation testing against critical pure state machines.

Prioritize:

```text
Identity normalization
Candidate ranking
Active binding arbitration
Routing selection
Authority membership
HLL reconciliation
Ingest report acknowledgement
Delegation control
Persistence recovery
```

Preserve independent reference implementations.

Do not change tests merely to match implementation behavior.

Every significant surviving mutation must be investigated.

Test suites must assert observable properties and invariants,
not merely source strings, debug messages, or private data layout.

---

## 16.7 Long-running deterministic simulations

Extend populus-sim scenarios to include:

```text
High node churn
High candidate churn
Long-lived shared-IP contention
Changing public identities
Repeated authority replacement
Temporary and prolonged partitions
Viral traffic bursts
Delegation resizing
Large tag association graphs
Delayed report recovery
Clock skew and latency
Malicious peer combinations
```

Every randomized failure must include a reproducible seed,
configuration, and failure schedule.

The simulator should remain independent of Linux network namespaces.

---

## 16.8 Performance and resource hardening

Run:

```text
Memory profiling
Binary bloat analysis
Dependency audit
Instruction-count benchmarks
CPU throughput benchmarks
Connection-count stress tests
Queue/backpressure tests
Storage growth tests
```

Track:

- Per-logical-node state
- Per-candidate registry state
- Number of live verification requests
- Number of active connections
- Pending ingest-report memory
- Authority communication overhead
- Bootstrap convergence work
- Time to recover after faults

Prevent unbounded resource growth under malicious or accidental load.

Review dependency and performance deltas using the existing
cargo xtask gates.

---

## 16.9 Compatibility and protocol versioning

Verify deterministic vectors for:

```text
NetworkIdentity
NodeId
ClientId
ProducerId
RoutingKey
ContentId
MutableContentId
Authority messages
Observed-address and verification messages
Candidate registrations
Active NodeID bindings
Delegation descriptors
Ingest reports
Persistent record formats
```

Protocol changes require explicit versioning.

Test old/new version interaction where mixed-version operation
is supported.

Unsupported versions must fail explicitly rather than being
silently interpreted as a compatible representation.

---

## Phase 16 completion criteria

Phase 16 is complete when:

1. Critical protocol state machines have adversarial tests.
2. Identity and ownership security assumptions are documented.
3. Bootstrap and verification resist tested forgery/replay cases.
4. Candidate registration and arbitration remain bounded.
5. Authority replacement and conflicts follow documented rules.
6. Ingest and popularity fraud cases are tested.
7. Network decoders and critical parsers have fuzz coverage.
8. Mutation testing has been performed on key state machines.
9. Long-running deterministic simulations pass.
10. Persistence and recovery fault tests pass.
11. Multi-process localhost integration tests pass.
12. Dependency, binary-size, memory, and performance gates pass.
13. Protocol encoding and versioning vectors are complete.
14. Remaining security limitations are documented explicitly.

Phase 17 remains responsible for validating real IP/network behavior
through Linux namespaces and kernel-level network fault injection.

Protocol v1 must not be frozen until the relevant Phase 17 scenarios
also pass.

---

# Phase 17: Linux Public Network Laboratory

## Objective

Build a reusable Linux networking laboratory that runs real
populus-node processes in isolated network namespaces.

The laboratory validates the actual Linux networking stack,
libp2p transports, bootstrap, public identity discovery,
identity verification, NodeID arbitration, authority failover,
and delegated ingest.

It complements, but does not replace, populus-sim.

The simulator provides deterministic protocol execution.
The Linux laboratory validates behavior under real kernel
networking, sockets, routing, scheduling, and packet delivery.

The test environment must not require publicly allocated
IP addresses or external infrastructure.

---

## 17.1 Namespace topology

Create an isolated Linux network environment.

Preferred topology:

```text
Outer isolated user/network/mount namespaces
    |
    +-- Linux bridge: br-populus
          |
          +-- veth pair 1
          |     |
          |     +-- node namespace 1
          |             |
          |             +-- populus-node
          |
          +-- veth pair 2
          |     |
          |     +-- node namespace 2
          |             |
          |             +-- populus-node
          |
          +-- veth pair 3
          |     |
          |     +-- node namespace 3
          |             |
          |             +-- populus-node
          |
          +-- veth pair 4
          |     |
          |     +-- node namespace 4
          |             |
          |             +-- populus-node
          |
          +-- veth pair 5
                |
                +-- node namespace 5
                        |
                        +-- populus-node
```

Each node namespace must have:

- its own virtual network interface
- its own IP addresses
- its own routing table
- independent sockets and ports
- a separate populus-node process
- separate process data/configuration directories

The topology must be configurable to support additional nodes.

Keep the entire laboratory isolated from the host's external
network interfaces.

Do not modify the host's default routing table or firewall.

Use automatic cleanup for processes, network devices, and namespaces.

---

## 17.2 Rootless operation

Prefer unprivileged Linux user namespaces.

Conceptual approach:

```text
unshare user namespace
    |
    v
obtain namespace-local capabilities
    |
    v
create isolated network namespace
    |
    v
create bridge and veth interfaces
    |
    v
create node network namespaces
```

The test harness may require CAP_NET_ADMIN inside the isolated
user namespace.

Do not assume all Linux distributions permit unprivileged
user namespaces or nested namespace operations.

Detect support before starting the laboratory.

Some systems may require a privileged test runner.

Do not silently escalate privileges.

Where traditional `ip netns add` requires unavailable mount
permissions, use namespace-holder processes and enter their
network namespaces through supported mechanisms.

Document required kernel features and userspace dependencies,
including iproute2 and tc.

The laboratory must fail with a clear diagnostic when the
required namespace functionality is unavailable.

---

## 17.3 Test-only public address eligibility

Use the IPv4 benchmarking range:

```text
198.18.0.0/15
```

Example node addresses:

```text
198.18.0.11
198.18.0.12
198.18.0.13
198.18.0.14
198.18.0.15
```

This range is reserved for benchmarking and is not globally
routable on the public Internet.

Populus's normal production identity validator must continue
rejecting addresses that are ineligible under ARCHITECTURE.md.

Provide a narrowly scoped test-only eligibility policy that
allows the laboratory's explicitly configured address ranges.

Requirements:

- Keep normalization and hashing identical to production.
- Change only address eligibility for the test environment.
- Do not duplicate the normalization algorithm.
- Do not change the production NodeId or ClientId hash domains.
- Do not permit arbitrary addresses merely because tests are running.
- Keep the test policy inaccessible in normal production operation.
- Require explicit lab configuration/build support.
- Never advertise laboratory identities to a real Populus network.

Prefer injecting an eligibility-policy abstraction into the
existing normalization flow.

Do not implement the exception as a global environment variable
that can silently disable production eligibility rules.

Add tests proving:

```text
production policy rejects benchmark addresses
netlab policy accepts explicitly allowed benchmark addresses
same normalized input produces deterministic identity
normal IPv4/IPv6 validation behavior remains unchanged
```

For IPv6 laboratory testing, use an explicitly isolated test
range and apply the same narrow eligibility-policy mechanism.

---

## 17.4 Test harness

Integrate the laboratory with cargo xtask.

Proposed interface:

```text
cargo xtask netlab check
cargo xtask netlab up --nodes 5
cargo xtask netlab status
cargo xtask netlab test
cargo xtask netlab down
```

Additional controls:

```text
cargo xtask netlab stop-node 3
cargo xtask netlab start-node 3
cargo xtask netlab disconnect-node 3
cargo xtask netlab reconnect-node 3
```

Fault injection:

```text
cargo xtask netlab fault \
    --node 3 \
    --latency 100ms \
    --loss 5%
```

Use Linux `tc netem` for network conditions such as:

```text
latency
jitter
loss
reordering
duplication
corruption
rate limiting
```

Use namespace routing/firewall controls for:

```text
network partitions
one-way communication failures
isolated nodes
reconnections
```

Where supported, provide commands for changing a running
node's IP addresses and routes.

The harness must collect:

```text
node logs
exit status
identity state
routing state
active authority sets
network interfaces
IP addresses
connections
test assertions
```

Tests must return meaningful nonzero exit codes on failure.

Never use log-string matching as the sole evidence of protocol
correctness.

---

## 17.5 Basic five-node network

Start five separate populus-node processes.

Initial acceptance scenario:

```text
Node 1 starts
    |
    v
Node 2 bootstraps through Node 1
    |
    v
Node 3 joins
    |
    v
Node 4 joins
    |
    v
Node 5 joins
    |
    v
All nodes discover the network
```

Each node must discover its public-facing identity through
the Populus protocol rather than a manually supplied NodeId.

The laboratory can provide deterministic bootstrap addresses,
but must not inject the derived identities into the processes.

Verify:

- Each node has its own PeerId.
- Each unique test NetworkIdentity produces the expected NodeId.
- The nodes can establish libp2p connections.
- The DHT discovers all five nodes.
- Nearest-node lookups return correct results.
- The four closest eligible nodes form the expected authority set.

The test must validate the real node executable, not a
separate simplified test implementation.

---

## 17.6 Authority failover

Select a ContentID whose RoutingKey has a known authority ordering.

Start the five-node network.

Submit client votes through the actual network protocol.

Verify that the correct four authority nodes receive and
record the necessary state.

Terminate one authoritative process.

Expected sequence:

```text
authority becomes unreachable
    |
    v
remaining nodes detect failure
    |
    v
next eligible NodeId considered
    |
    v
replacement joins authority cluster
    |
    v
state recovered from surviving authorities
    |
    v
vote processing resumes
```

Verify:

- no duplicate authority membership
- correct binding generations
- preserved accepted state
- proper handling of in-flight messages
- recovery after node restart
- no false recovery from the failed node's private memory

Compare observable behavior with deterministic simulator scenarios.

---

## 17.7 Multi-identity and multihoming tests

Configure a namespace with multiple addresses.

Scenarios:

```text
two public-like IPv4 identities
one IPv4 plus one IPv6 identity
multiple IPv6 addresses inside one /48
multiple independently normalized IPv6 prefixes
```

Verify:

- The process discovers all eligible identities.
- Each distinct normalized scarcity identity creates one NodeId.
- Addresses sharing an IPv6 /48 collapse to one NodeId.
- One PeerId manages multiple logical NodeIDs.
- Each logical node maintains independent routing state.
- The configured logical-node limit is respected.
- Actual outbound connections use the intended source identity
  when identity-specific verification requires it.

Change addresses while the processes run.

Verify dynamic activation, revalidation, and retirement.

---

## 17.8 Shared-IP and NodeID competition

A single bridged network with unique IPs is insufficient to
test multiple PeerIDs competing for one public NetworkIdentity.

Add router/NAT namespace topologies where multiple internal
nodes appear externally under the same public IPv4 address.

For example:

```text
Client A --\
Client B ---- NAT router -- shared public IP
Client C --/
```

Each client maintains its own PeerId.

All derive the same candidate NodeId from the observed
external scarcity identity.

Test:

- Multiple candidates register under one NodeId.
- Only the selected active PeerId occupies the DHT position.
- A healthy incumbent retains its position.
- Candidate persistence ordering is respected.
- A new candidate does not cause immediate displacement.
- Loss of the incumbent triggers standby promotion.
- Competing promotions and stale bindings are detected.
- Multiple open ports do not create additional NodeIDs.

Support at least several competing peers in the real laboratory.

Test thousands of candidates through populus-sim rather than
requiring thousands of Linux namespaces.

The registry must remain bounded and functional under large
synthetic candidate populations.

---

## 17.9 NAT and public identity discovery

Extend the topology with router namespaces and NAT.

Test:

```text
direct public-like address
outbound NAT
static port forwarding
multiple hosts behind one NAT
changed external NAT address
expired port mapping
IPv4/IPv6 dual stack
```

Verify that observed addresses reflect actual network behavior.

Test external observation through at least three independent peers.

Verify that a node behind NAT does not automatically become an
eligible active DHT node if it lacks required inbound reachability.

A shared NAT address is not proof of exclusive scarcity identity
ownership.

Verify that a changed public address causes the expected new
identity discovery and old-identity retirement.

---

## 17.10 Delegated ingest network tests

Start enough processes to exercise:

```text
4 authority nodes
3 or more ingest nodes
additional fallback nodes
```

Use at least eight nodes for the initial delegated-ingest scenario.

Generate a controlled client workload through actual networking.

Verify:

- direct ingest starts correctly
- the delegation threshold triggers delegated mode
- clients discover the delegation descriptor
- three shuffled ingest views receive their assignments
- ingest nodes build HLL reports
- reports reach all four authorities
- pending reports survive missing acknowledgements
- the authority control loop changes assignment parameters
- a failed ingest node does not silently erase its prior report
- authority statistics converge within specified error bounds

Inject latency, reordering, and packet loss.

Do not expect minute HLLs to be identical across differently
timed ingest nodes.

Test cumulative daily population convergence separately from
per-minute traffic statistics.

---

## 17.11 Security and adversarial scenarios

Use controlled malicious test processes or protocol fault adapters.

Scenarios:

```text
forged identity advertisement
fake observed-address response
stale verification replay
invalid NodeId/PeerId binding
competing active-owner claims
malicious ingest reports
suppressed ingest reports
false authority membership
stale authority generations
network partition during promotion
```

Verify that the implementation preserves the documented
security assumptions and detects contradictory evidence.

Do not label tests Byzantine-safe merely because one malicious
node was rejected.

Explicitly document:

```text
number of malicious participants
network assumptions
verification quorum assumptions
resulting guarantees
remaining failure modes
```

---

## 17.12 Performance and resource tracking

Track:

```text
startup duration
bootstrap duration
identity discovery duration
verification duration
time to active NodeID
DHT convergence duration
authority failover duration
number of active connections
connection churn
CPU usage
resident memory
network bytes
direct-ingest throughput
delegated-ingest throughput
```

Run scenarios with increasing node counts and network impairment.

Separate protocol-performance regressions from noisy host scheduling
and kernel timing effects.

Use controlled environments for hard performance gates.

---

## 17.13 CI integration

The Linux laboratory is a separate CI test layer.

Do not require kernel namespace capabilities for ordinary
Rust unit tests or the deterministic simulator.

Recommended CI organization:

```text
commit gate:
    existing Rust tests, linting, and deterministic simulation

PR gate:
    supported lightweight Linux netlab smoke tests

scheduled / pre-release:
    extended namespace tests
    NAT and IPv6 scenarios
    network partitions
    multi-identity scenarios
    adversarial tests
    long-running churn and recovery
```

A runner that does not support the necessary namespace features
must report an explicit unsupported-environment result.

Required netlab jobs must run on a runner where their capabilities
are available; unsupported environments must not produce a false pass.

Keep the laboratory entirely separate from production networking.

---

## Phase 17 completion criteria

Phase 17 is complete when:

1. An isolated Linux network with five or more namespaces can
   be created and destroyed reliably.
2. Real populus-node processes run inside those namespaces.
3. Nodes bootstrap and discover each other.
4. Runtime public identity discovery works using actual socket
   observations.
5. Verification succeeds or fails according to real reachability.
6. Multiple NodeIDs per process work under multihoming.
7. IP changes are detected and logical nodes transition correctly.
8. Multiple PeerIDs behind one public IPv4 can compete for one NodeId.
9. A healthy incumbent is not displaced by a newcomer.
10. Standby promotion works when the active owner fails.
11. The four-authority cluster operates across separate processes.
12. Direct votes and popularity queries work end-to-end.
13. Delegated ingest operates across separate processes.
14. Real packet loss, latency, reordering, and partitions can
    be injected.
15. Failure and recovery behavior is verified against the
    deterministic simulator's corresponding expectations.
16. The test harness cleans up all processes and network resources.
17. Production identity eligibility remains unchanged.
18. No external network connection is required.
19. CI supports the tests through explicitly configured Linux runners.
20. Performance and resource metrics are recorded.

Do not freeze protocol v1 until the relevant Phase 17 identity,
routing, authority, NAT, and failure tests have passed.

Document any remaining unsupported network configurations or
security assumptions before considering the protocol stable.

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
