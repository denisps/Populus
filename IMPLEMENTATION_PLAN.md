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

# Phase 11.5: Runnable Populus Network, Bootstrap, and Dynamic Identity Management

## Objective

Integrate the existing transport, DHT routing, authority-cluster,
direct-ingest, and delegated-ingest components into a functional
Populus node executable.

Implement automatic network bootstrap, public identity discovery,
verification, multi-identity operation, and NodeID ownership arbitration.

A Populus process represents a physical or virtual host, not a single
NodeID. It may operate multiple logical DHT nodes derived from distinct,
verified public network identities.

The node must start and participate in bootstrap without requiring
a manually configured public IP address.

Identity discovery and verification are continuous runtime processes,
not operations performed only during startup.

The resulting executable must be usable on a real network without
depending on the deterministic simulator.

## Architectural principles

1. One persistent libp2p PeerId identifies the process.
2. One process may operate multiple logical NodeIDs.
3. Every NodeID derives exclusively from a normalized NetworkIdentity.
4. Multiple PeerIDs may compete to operate the same NodeID.
5. Only one active PeerID should represent a given NodeID in a
   converged DHT membership view.
6. New candidates must not displace healthy incumbents.
7. Persistence and demonstrated availability determine candidate
   preference, not the number of open ports or created keypairs.
8. Identity observations are evidence, not proof of ownership.
9. The Populus DHT itself provides candidate discovery and arbitration.
10. No separate libp2p Kademlia overlay is introduced.
11. Nodes without verified public identities may still participate
    as outbound-only peers or clients.
12. All candidate, verification, and arbitration state must be bounded
    per node and subject to expiration.

Keep the existing separation between PeerId, NodeId, ClientId,
ProducerId, ContentId, and RoutingKey.

---

## 11.5.1 Persistent process identity and lifecycle

Refactor the current single-NodeId executable into a process managing
multiple logical DHT nodes.

Conceptual structure:

```rust
struct PopulusProcess {
    transport: TransportManager,
    identity_manager: IdentityManager,
    logical_nodes: HashMap<NodeId, LogicalNode>,
    config: NodeConfig,
}
```

Each logical node maintains its own:

- NodeId and NetworkIdentity binding
- DHT routing state
- authority responsibilities
- delegated-ingest responsibilities
- lifecycle state
- relevant protocol timers and metrics

Share libp2p transport, connection management, and cryptographic PeerId
across logical nodes where practical.

Use asynchronous tasks/state machines rather than a dedicated OS thread
per NodeID.

Limit the maximum number of simultaneously active logical nodes.
Start with a configurable default of four.

The limit is a local resource-management policy, not a network-wide
identity restriction.

Persist the process's cryptographic identity so restarting does not
generate a new PeerId.

Prefer a small, explicit persistence interface rather than introducing
a heavyweight database prematurely.

Tests:

- Restart preserves PeerId.
- A single process can manage multiple logical nodes.
- Logical nodes have independent routing state.
- Multiple IPv6 addresses within one normalized /48 create one NodeID.
- Duplicate NetworkIdentity discoveries do not create duplicate nodes.
- The configured identity limit is enforced.
- One logical node stopping does not stop unrelated logical nodes.
- Transport shutdown cleanly stops all logical nodes.

---

## 11.5.2 Bootstrap and peer discovery

Implement a configurable bootstrap mechanism.

Initial peers may be obtained from:

- explicitly configured libp2p Multiaddrs
- DNS-based bootstrap entries
- previously persisted peer contacts
- optional local-network discovery

Bootstrap peers are discovery entry points, not trusted authorities.

The bootstrap procedure must work before the process has an active
public NodeID.

Conceptual startup:

```text
Start process
    |
    v
Load persistent PeerId
    |
    v
Start libp2p listeners
    |
    v
Connect to bootstrap peers
    |
    v
Discover additional Populus peers
    |
    v
Obtain external address observations
    |
    v
Verify network identities
    |
    v
Activate logical NodeIDs
    |
    v
Join Populus XOR DHT
```

Use the existing Populus routing implementation for iterative peer
discovery.

Implement the missing network protocol messages required to exchange
routing contacts and execute iterative XOR-distance lookups.

A routing contact must bind the NodeId to the corresponding PeerId
and reachable transport addresses.

Verify contact validity before treating it as an eligible DHT node.

Bootstrap must not depend on a single permanently available server.

After joining, nodes should discover peers through the decentralized
DHT rather than relying on bootstrap infrastructure.

If all known peers become unavailable, retry discovery with bounded
exponential backoff.

An isolated process with no known peers cannot discover an existing
network. Support an explicitly configured genesis/test-network mode,
but do not silently assume that an isolated process constitutes the
global Populus network.

Tests:

- Bootstrap through one known peer.
- Bootstrap through multiple peers.
- Discover peers not present in the initial bootstrap list.
- Bootstrap when the process has no NodeID.
- Bootstrap peer disappears after discovery.
- Previously persisted contacts enable reconnection.
- All bootstrap peers temporarily unavailable.
- Malformed, stale, duplicate, and contradictory peer records.
- Routing lookup agrees with the brute-force reference model when
  equivalent peer knowledge is available.
- Bootstrap cannot insert an unverified NodeID into the eligible
  authority set.

---

## 11.5.3 Continuous public identity discovery

Public identity discovery is part of the Populus protocol.

A process may have multiple public network identities because of:

- multiple public IPv4 addresses
- multiple public IPv6 prefixes
- IPv4 and IPv6 operating simultaneously
- multiple network interfaces
- multihoming
- changes to externally visible NAT addresses

Use local interface enumeration together with externally observed
addresses reported by connected peers.

Implement a small optional flag on suitable Populus protocol requests:

```text
REQUEST_OBSERVED_ADDRESS
```

When set, the responding peer includes its observation of the
requester's remote connection endpoint.

Conceptual response:

```rust
struct ObservedAddress {
    observed_endpoint: SocketAddr,
    request_nonce: Nonce,
}
```

The observation is associated with the authenticated responding PeerId
through the underlying libp2p connection.

Do not assume a network-level observation contains a globally trusted
claim about the requester's identity.

Correlate responses with their requests, authenticated connections,
and nonces. Reject unsolicited or stale observations.

Discovery policy:

- Require at least three distinct authenticated observers reporting
  the same normalized public network identity.
- Prefer observers representing distinct verified NodeIDs and network
  identities.
- Do not count multiple responses from one observer as independent.
- For IPv6, normalize observations according to the existing /48 policy.
- Deduplicate multiple addresses mapping to one NetworkIdentity.
- Keep discovery state bounded and time-limited.
- Use hysteresis to avoid identity churn from conflicting observations.

Three agreeing observations promote an identity to verification,
not directly to Active.

Do not wait for all three observations when an already verified identity
is merely being renewed and existing evidence remains valid.

Discovery is continuous. It must also react to local interface changes,
connection changes, and conflicting external observations.

Tests:

- Three independent agreeing observers.
- Two agreeing observers are insufficient for initial promotion.
- One observer sending repeated identical observations.
- Three observers with conflicting observations.
- IPv4 and IPv6 observations on different connections.
- Multiple IPv6 addresses mapping to one /48.
- A public IPv4 change during operation.
- Stale and replayed observations.
- Different externally observed addresses on different interfaces.
- A malicious observer reporting an arbitrary address.
- No observers available.
- Discovery state expiration and resource bounds.

---

## 11.5.4 Public identity verification

An observed NetworkIdentity is not yet an active DHT identity.

Each candidate follows this lifecycle:

```text
Unknown
    |
    v
Discovered
    |
    v
Verifying
    |
    v
Active
    |
    +--> Suspect
    |       |
    |       +--> Active
    |       |
    |       +--> Retiring
    |
    +--> Retiring
            |
            v
          Removed
```

When entering Verifying:

1. Normalize the observed network identity using the Phase 1 rules.
2. Derive the candidate NodeId.
3. Discover the nearest already-active eligible DHT neighbors.
4. Request independent verification from the appropriate verifier set.
5. Establish fresh direct inbound reachability challenges.
6. Confirm that the contacted endpoint authenticates as the expected
   PeerId.
7. Confirm that the claimed network identity is consistent with the
   verified connection and the applicable identity policy.
8. Record signed, time-limited verification evidence.
9. Enter Active only after the required confirmations and ownership
   arbitration have succeeded.

Use three successful independent confirmations as the initial target,
subject to the verifier-selection and quorum rules established below.

Verification must distinguish:

```text
externally observed source address
direct inbound reachability
cryptographic PeerId authentication
NodeID ownership arbitration
```

These are separate properties.

A peer may have a known public IP but lack an inbound-reachable endpoint.

For IPv6 /48 identities, reachability of one address in the prefix
does not prove exclusive control of the entire allocation.

Likewise, an inbound connection to a NAT-forwarded port does not prove
exclusive ownership of the public IPv4 address.

Verification therefore establishes eligible operational control of
a network endpoint and a scarcity-identity claim, not legal or exclusive
ownership of the IP resource.

Use direct dial-back challenges where feasible. A successful relayed
connection alone is insufficient to establish direct public reachability.

Reuse libp2p Identify and available AutoNAT functionality where suitable.
Do not duplicate an existing mechanism without justification.

The verifier set should be derived deterministically from the Populus
DHT neighborhood of the candidate NodeId, excluding the claimant itself
and counting distinct verified network identities.

Avoid a circular dependency where a candidate must already be Active
to discover its own verifiers.

Provide an explicit initial-network/genesis policy when an adequate
verified neighborhood does not yet exist.

All verification records must contain:

- protocol version
- claimed NodeId
- claiming PeerId
- verifier identity
- fresh challenge/nonce binding
- expiration or epoch
- signature

Verification evidence expires and must be renewed.

Tests:

- Valid identity and successful direct dial-back.
- Observed IP with no inbound reachability.
- Correct IP but incorrect PeerId.
- Correct PeerId but incorrect claimed identity.
- Replay of an old verification.
- Verifier disappearance.
- Conflicting verifier responses.
- One malicious verifier.
- IPv4 behind port-forwarding NAT.
- IPv6 prefix with multiple reachable addresses.
- Candidate loses reachability during verification.
- Insufficient verified neighbors during initial bootstrap.
- Verification must not activate a NodeID merely because
  three arbitrary peers claimed that it was valid.

---

## 11.5.5 NodeID candidate registry

A normalized NetworkIdentity yields exactly one NodeId, but multiple
PeerIds may compete to operate that NodeId.

Example:

```text
NodeId X
    |
    +-- PeerId A: Active
    +-- PeerId B: Verified standby
    +-- PeerId C: Verified standby
    +-- PeerId D: Candidate
    +-- PeerId E: Candidate
    ...
```

A shared public IPv4 address may represent thousands of physical peers.

Every candidate must be discoverable without forcing the four closest
nodes to store an unbounded list or maintain connections to all candidates.

Use the Populus DHT itself for candidate registration and discovery.

Do not introduce a second libp2p Kademlia network.

Conceptual registry key:

```text
CandidateRegistryKey =
    H("populus/node-candidates/v1" || NodeId)
```

Each candidate advertises a signed, expiring registration containing:

```text
NodeId
PeerId
reachable Multiaddrs
registration sequence
registration expiration
verification references
```

Registrations are not active ownership certificates.

For large candidate populations, distribute registry storage through
deterministically derived registry shards.

For example:

```text
CandidateShard =
    prefix(H(PeerId), shard_bits)

ShardKey =
    H("populus/node-candidates/shard/v1" ||
      NodeId || CandidateShard)
```

The base NodeId registry maintains only bounded indexing information,
the current active binding, and selected standby summaries.

Sharded registration storage handles the long tail of candidates.

Candidate discovery must support bounded pagination or equivalent
incremental enumeration.

Prevent unbounded registration memory, query responses, and verification
traffic.

Registration renewal and expiration should naturally remove
inactive candidates.

All registered candidates remain conceptually eligible to compete.
Do not automatically treat a newly discovered PeerId as malicious.

A candidate's existence does not entitle it to replace an incumbent.

Tests:

- One candidate.
- Multiple PeerIds sharing one NodeId.
- Thousands of candidate registrations in simulation.
- Deterministic registry sharding.
- Registration expiration.
- Duplicate registration.
- Malformed or forged registration.
- Bounded registry memory and response size.
- Candidate discovery across multiple registry shards.
- Loss and recovery of a registry-storage node.
- Registry queries do not overload the four nearest NodeIds.

---

## 11.5.6 Candidate persistence and ranking

Prefer candidates with demonstrated availability and persistence.

Persistence must be based on independently observed successful
verification/renewal history, not self-reported timestamps.

Ranking rules:

1. A healthy active incumbent retains its NodeID.
2. Verified standby candidates are preferred over unverified candidates.
3. More persistent/reliably reachable candidates are generally preferred.
4. Invalid, expired, or repeatedly unreachable candidates lose priority.
5. Equal-ranked candidates use deterministic PeerId tie-breaking.

Persistence is a reliability measure, not proof of honesty.

A candidate with a long history must still satisfy current reachability
and protocol-verification requirements.

Do not give additional priority for:

- opening many ports
- creating additional PeerIds
- repeatedly registering the same identity
- submitting more verification requests

The active candidate should not rotate daily merely because a different
candidate has accumulated slightly better ranking statistics.

Instead:

```text
Healthy incumbent -> remains Active
Standby rankings   -> periodically recalculated
Incumbent fails    -> best eligible standby considered
```

Use periodic verification epochs, initially daily, for persistence
accounting and standby ranking.

Use shorter reachability checks where required for operational failover.

The exact persistence score and expiration policy must be deterministic
for equivalent verified evidence, documented, and simulation-tested.

Tests:

- Healthy incumbent remains active when a new candidate joins.
- Older verified standby outranks an otherwise equivalent newcomer.
- Candidate cannot forge persistence through local timestamps.
- Multiple ports do not improve ranking.
- Candidate expiration reduces eligibility.
- Equal-ranked candidates converge on the same order.
- Long-lived but unreachable candidate is not promoted.
- Thousands of competing PeerIds do not cause unbounded work.

---

## 11.5.7 Active NodeID arbitration and failover

The DHT neighborhood of a NodeId maintains the active binding and
coordinates candidate promotion.

Conceptual binding:

```rust
struct ActiveNodeBinding {
    node_id: NodeId,
    peer_id: PeerId,
    generation: u64,
    valid_until: Timestamp,
    verification_epoch: Epoch,
}
```

The binding must be supported by an appropriate signed quorum record,
not merely by a candidate's own announcement.

Use the existing four-node authority and membership mechanisms where
possible, without assuming that their current state-recovery rules
already implement safe ownership elections.

A proposed active binding must specify:

```text
NodeId
selected PeerId
previous binding/generation
new generation
lease/epoch
verification evidence
approving verifier identities
```

An incumbent may be replaced when:

- it voluntarily resigns,
- its binding expires without successful renewal,
- it fails the defined independent reachability checks, or
- a documented protocol violation produces sufficient evidence.

A newly registered candidate must never displace a healthy incumbent
merely by announcing a claim to the same NodeId.

Arbitration must explicitly handle:

```text
concurrent promotion proposals
stale signed bindings
conflicting generations
network partitions
temporarily unreachable incumbents
competing verifier neighborhoods
```

A locally incremented generation counter is not enough to resolve
conflicting promotions.

The protocol must distinguish state-recovery evidence from a quorum
decision authorizing a new active binding.

If a single active binding cannot safely be determined, retain an
explicit conflicting/unresolved state instead of arbitrarily choosing.

Do not claim global uniqueness during arbitrary network partitions
without demonstrating the required quorum intersection and membership
assumptions.

Prefer safety over availability when conflicting ownership would allow
two independently operating DHT nodes to claim the same position.

When a standby is promoted:

1. Verify its current reachability.
2. Authorize a new binding generation.
3. Publish the binding to the relevant DHT neighborhood.
4. Activate the promoted logical node.
5. Recover routing and authority state from independent peers.
6. Resume eligible authority/ingest responsibilities.

The replacement does not inherit the previous PeerId's cryptographic
identity or private state.

Tests:

- Incumbent fails and standby is promoted.
- Incumbent temporarily times out and recovers.
- Concurrent promotion requests.
- Conflicting active bindings.
- Stale generation replay.
- One malicious verifier.
- Two partitioned verifier groups.
- Promotion during authority state recovery.
- Incumbent voluntarily resigns.
- Replacement reconstructs state instead of copying the failed
  peer's private memory.
- One NodeId is counted once in authority selection regardless
  of how many PeerIds claim it.

---

## 11.5.8 Dynamic identity activation and retirement

Identity discovery continues for the lifetime of the process.

When a new public identity is discovered:

```text
Discovered -> Verifying -> Active
```

When an existing identity changes or becomes unreachable:

```text
Active -> Suspect -> Active
                 -> Retiring -> Removed
```

Examples:

```text
ISP changes public IPv4
IPv6 prefix delegation changes
second WAN connection appears
network interface disappears
NAT port mapping expires
```

The process must handle those changes without restarting its
persistent transport identity.

Requirements:

- Avoid immediate retirement from one failed reachability check.
- Use configurable hysteresis and expiration.
- Stop advertising identities no longer verified.
- Do not allow an old NodeID to remain authoritative indefinitely.
- Allow best-effort graceful responsibility handoff.
- Preserve unrelated active identities.
- Rejoin under a new NodeID after verification succeeds.

On multihomed systems, ensure verification is associated with the
correct source interface/address.

A successful generic outgoing connection does not prove that the
process can originate traffic from every claimed interface.

If the transport cannot support required source-address selection,
that identity must remain unverified for the affected capability.

Tests:

- Public IPv4 changes while the process remains running.
- IPv6 prefix changes.
- One of several identities disappears.
- New identity discovered while at configured capacity.
- NAT mapping changes.
- Temporary network outage.
- Concurrent activation and retirement.
- Graceful shutdown of a logical node.
- No stale authority claims after retirement.

---

## 11.5.9 Integrate existing protocols into populus-node

Connect the previously implemented protocol components to the real
network executable.

Do not reimplement them in the executable.

The node must support:

- Populus DHT peer discovery
- nearest-node lookup
- authority-cluster membership
- signed authority communication
- direct-ingest request handling
- actual client vote counting
- signed ACK responses
- popularity queries
- delegated-ingest descriptor discovery
- delegated-ingest operation using the Phase 9-11 components

Retain the modular separation:

```text
populus-node
    |
    +-- process lifecycle
    +-- identity manager
    +-- logical DHT nodes
    +-- protocol state machines
    |
    v
populus-network
    |
    v
libp2p Swarm
```

Do not introduce libp2p Swarm dependencies into pure routing or
authority state-machine code.

Keep existing deterministic state-machine tests as independent oracles.

A full public deployment, NAT traversal solution, or graphical client
is not required in this phase.

The node must nevertheless be able to form a functional network
between mutually reachable instances.

---

## 11.5.10 CLI and operational visibility

Replace the existing manually supplied identity requirement with
automatic discovery.

Illustrative CLI:

```text
populus-node run \
    --listen /ip4/0.0.0.0/tcp/4001 \
    --bootstrap <multiaddr> \
    --max-node-ids 4
```

Support configuration-file equivalents.

Provide observability for:

```text
PeerId
listening Multiaddrs
connected peers
bootstrap state
observed public addresses
candidate identities
verified identities
active NodeIDs
identity verification status
candidate/standby ranking
DHT routing-table health
authority assignments
ingest status
```

Provide a simple status interface or CLI command.

Support graceful shutdown and persistent PeerId reuse.

Use structured tracing.

Do not expose private keys or unbounded peer lists in logs.

---

## 11.5.11 Testing and simulation

Extend populus-sim with actual identity-management and
bootstrap state machines.

The deterministic simulator must exercise the same pure logic used
by the executable.

Include:

```text
bootstrap with no NodeID
public-address observations
identity verification
multiple identities per process
candidate registration
shared-IP competition
incumbent retention
standby promotion
address changes
verification expiration
network partitions
malicious and stale identity claims
```

Add multi-process localhost tests using real libp2p connections.

These tests should not depend on Linux network namespaces yet.

Inject address observations and reachability results through explicit
test interfaces where necessary.

Use exact independent state/reference models for candidate ordering,
binding generations, and election outcomes.

For protocol transitions, test the actual resulting state rather
than searching logs for expected strings.

Run all existing quality gates.

Record dependency, binary-size, and performance changes.

---

## Phase 11.5 completion criteria

Phase 11.5 is complete when:

1. populus-node starts without a manually configured public identity.
2. It bootstraps through known peers and discovers additional DHT peers.
3. It discovers its public network identities at runtime.
4. Three independent agreeing observations can initiate verification.
5. Verification checks direct reachability and authenticated PeerId.
6. A verified identity can activate as a logical NodeID.
7. One process can manage several NodeIDs with independent DHT state.
8. Several PeerIDs can register as candidates for one NodeID.
9. A healthy incumbent is not displaced by a new candidate.
10. Candidate ranking and standby promotion are deterministic for
    equivalent verified evidence.
11. Conflicting active bindings are detected and safely handled.
12. Public identity changes do not require process restart.
13. The executable performs actual DHT routing and authority discovery.
14. Five reachable Populus processes can establish a functioning
    DHT neighborhood.
15. A client can submit a direct vote and query its popularity.
16. An authority failure can trigger replacement and state recovery.
17. Existing delegated-ingest components can operate through the
    real network adapter.
18. Real-network tests and deterministic simulator tests pass.
19. The implementation remains bounded in memory and connection use.
20. ARCHITECTURE.md, TESTING.md, and AGENTS.md document the
    implemented identity lifecycle and verification assumptions.

Current acceptance status:

- **Fully implemented:** 1 (default startup without a manually supplied public
  identity), 7 (multiple logical NodeIDs have separate local routing state),
  18 (the current localhost integration and deterministic simulation tests pass;
  this does not establish the deferred distributed scenarios).
- **Partially implemented:** 2 (bounded DHT contact discovery exists, but
  authority discovery and durable bootstrap are absent); 3 (runtime observation
  refresh exists, but identity lifecycle changes do not automatically complete
  verification and activation); 4 (NodeID-deduplicated observation threshold
  exists, without a network-wide signed verifier protocol); 5 (the state
  machine requires authenticated direct reachability evidence from its caller,
  but automatic challenge/dial-back is absent); 6 (local activation is
  available through an explicit signed genesis manifest or local
  verification, but not certified ownership arbitration); 12 (observations are
  refreshed without restart, but verified binding replacement/retirement is
  not automatic); 13 (custom DHT routing exists, authority membership
  discovery does not); 15 (a localhost direct-vote and signed-popularity
  adapter uses the existing direct-ingest state machine when authority
  membership is explicitly installed); 17 (a localhost report/ACK path uses
  the existing delegated sender/receiver state machines, but requires caller-
  installed membership and contacts and lacks automatic fanout/recovery); 19 (identity/contact limits exist, but
  network-wide and connection limits are not established); 20 (the architecture
  records the decisions and limitations, while full lifecycle/test/operations
  guidance remains incomplete).
- **Deferred:** 8 (signed multi-candidate registration), 9 (distributed
  incumbent/standby arbitration), 10 (candidate ranking and promotion), 11
  (committee-bound conflict detection and safe resolution), 14 (five-process
  DHT scenario), and 16 (authority replacement and state recovery).

Phase 11.5 is not complete. In particular, committee-chain certificates,
durable anti-equivocation, candidate registry/sharding, automatic verifier
selection and renewal, authority membership/state replication, automated
delegated-ingest fanout/retry and recovery, and five-process failure/recovery
simulation are not implemented. A trusted signed genesis manifest is loaded
and gates local genesis activation, but its network identifier is not compared
against a separately configured runtime network identifier, and it does not
provide safe post-genesis membership transitions. Delegated-ingest networking
exists only as an explicitly installed request/response path; its membership
discovery, automatic four-authority fanout/retry, and durable recovery remain
unresolved. Passing local tests is not evidence that missing mechanisms are
present or secure.

The identity-verification and arbitration assumptions must be stated
explicitly. Passing a local test does not establish that the protocol
is secure against arbitrary collusion, eclipse attacks, or partitions.

Phase 17 will validate these mechanisms using real Linux network
namespaces, source addresses, NAT, and kernel-level faults.

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
