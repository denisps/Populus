# TESTING.md

# Populus Testing Strategy

## 1. Testing objective

The goal is not merely to prove that the current implementation behaves like itself.

The goal is to provide evidence that Populus satisfies externally meaningful properties under:

```text
normal operation
large populations
latency
clock drift
message duplication
message loss
reordering
node churn
partial failure
malicious behavior
future refactoring
```

Coverage is diagnostic information, not proof of correctness.

A test suite that reaches 100% line coverage but cannot detect an intentionally introduced logic error is inadequate.

Mutation testing and independent reference models are used specifically to detect this failure mode.

---

# 2. Test hierarchy

## Level 1: unit tests

Small deterministic behavior.

Examples:

```text
ID parsing
XOR distance
HLL register update
canonical encoding
signature verification
rate-controller transition
```

## Level 2: property tests

Automatically generated inputs exercise mathematical and structural invariants.

Use `proptest`.

Examples:

```text
commutativity
associativity
idempotence
round trips
ordering invariance
partition/merge invariance
```

## Level 3: reference-model tests

Compare optimized code to an intentionally simple independent implementation.

Examples:

```text
routing table vs sort-all-peers
HLL vs HashSet cardinality
assignment index vs scan-all-candidates
async authority state vs pure state-machine model
```

## Level 4: deterministic simulation

Run many logical nodes and clients without sockets.

Simulate:

```text
time
network
churn
faults
malice
load
```

## Level 5: localhost network tests

Exercise actual libp2p transports and framing.

Do not use these for behaviors that can be tested more deterministically at lower levels.

## Level 6: fuzzing

Fuzz all untrusted decoders and protocol state-machine entry points.

## Level 7: mutation testing

Use `cargo-mutants` on core pure crates.

A surviving mutant is evidence that tests may not constrain meaningful behavior.

## Level 8: performance and scale tests

Bench hot paths and execute large virtual simulations.

---

# 3. Requirement and invariant IDs

Important architecture invariants receive stable IDs.

Example:

```text
ID-001  NodeId and ClientId use separate hash domains.
ROUTE-001  Authorities are selected by XOR distance to RoutingKey.
AUTH-001  Normal authority count is four.
INGEST-001  Pending report survives until all four authority ACKs.
INGEST-002  A client is assigned to three independent delegated views.
HLL-001  Duplicate ClientId insertion is idempotent.
HLL-002  HLL merge is commutative and associative.
TIME-001  Minute boundary skew must not permanently lose a daily vote.
TAG-001  Cyclic associations must not create recursive report storms.
```

Tests should reference the relevant invariant in their name or documentation.

Do not couple test names to private function names unnecessarily.

---

# 4. HLL tests

Use an exact `HashSet<ClientId>` oracle.

## Essential properties

For sketch `S`:

```text
insert(x)
insert(x)
```

must produce the same logical cardinality as a single insertion within deterministic sketch semantics.

For merge:

```text
merge(A, A) == A

merge(A, B) == merge(B, A)

merge(merge(A, B), C)
    ==
merge(A, merge(B, C))
```

Where exact register equality is appropriate.

## Partition property

Generate population `P`.

Randomly split into:

```text
P0
P1
...
Pn
```

Build one HLL per partition.

Then:

```text
merge(HLL(P0), ..., HLL(Pn))
```

must equal or closely correspond to:

```text
HLL(P)
```

This directly models delegated ingest.

## Accuracy tests

For each cardinality and many deterministic seeds:

```text
100
1K
10K
100K
1M
```

measure relative error.

Validate distribution and confidence bounds rather than demanding that every run stay below the nominal mean error.

Do not write:

```rust
assert_eq!(hll.estimate(), 1000);
```

Write a statistically justified bound.

## Serialization

Test:

```text
build -> encode -> decode -> merge
```

against:

```text
build -> merge
```

Serialization must not change the estimate or registers.

---

# 5. Routing tests

Maintain the simplest possible oracle:

```rust
fn reference_closest(
    target: RoutingKey,
    peers: &[Peer],
    n: usize,
) -> Vec<NodeId> {
    // Sort every peer by XOR distance.
}
```

Every optimized implementation is tested against it.

Generate:

```text
random NodeIds
duplicate attempts
sparse ID spaces
dense local prefixes
random insertion order
random removal order
```

Assertions concern the returned nearest set and ordering, not internal K-bucket layout unless K-bucket layout itself is being tested.

---

# 6. Content and cryptography tests

Golden vectors are mandatory for:

```text
NodeId derivation
ClientId derivation
ProducerId derivation
RoutingKey derivation
canonical content encoding
CID
signature preimage
signature output for fixed test keys
```

Private test keys must never be production keys.

Content tests must include:

```text
anonymous
one producer
multiple producers
empty tags
many tags
unknown optional fields where version rules permit
large payload rejection
invalid signature
duplicate producer
revision fork
revision rollback
```

Canonical encoding must be checked independently from the high-level content API.

---

# 7. Authority-cluster model tests

Implement a pure state model that does not use sockets or Tokio tasks.

Commands:

```text
JoinAuthority
LeaveAuthority
ReceiveState
ReceiveSignedMessage
EnterDirectMode
EnterDelegatedMode
UpdateDescriptor
ReceiveIngestReport
AckReport
FinalizeWindow
FinalizeEpoch
```

Events:

```text
StateChanged
DelegationChanged
ReportAccepted
ReportRejected
PeerQuarantined
RecoveryNeeded
```

The async/network implementation should be driven with command sequences and compared to this model where practical.

Required scenarios:

```text
four honest authorities
one crash
one replacement
one stale authority
one equivocating authority
2 matching states + 1 mismatch
three different states
2-vs-2 partition
recovery after partition
```

---

# 8. Ingest timing tests

This is a critical area.

Minute HLLs are not expected to match exactly because ingest nodes may have:

```text
different wall-clock offsets
different packet latency
different report latency
different rollover points
```

Simulation must include cases such as:

```text
Node A clock: -20 s
Node B clock: +0 s
Node C clock: +25 s

client sends at true time 12:00:58
```

The vote may appear in different nominal minute reports.

The test must verify:

```text
the daily or sufficiently wide cumulative result converges
```

not:

```text
all minute reports are byte-identical
```

---

# 9. Double-buffer tests

For every ingest node:

```text
active buffer
pending report buffer
```

Properties:

```text
rollover never blocks new inserts
pending report is immutable
lost ACK does not erase pending report
duplicate ACK is harmless
duplicate report transmission is harmless
all four ACKs permit reclamation
```

Fault injection must kill the node at every state-machine boundary.

---

# 10. Delegated assignment tests

The assignment algorithm must remain behind a trait until selected through simulation.

For each candidate algorithm measure:

```text
load variance
maximum node load
fraction of clients with missing destination
fraction with duplicate destinations
assignment stability
CPU cost
bytes required in descriptor
behavior as candidate set changes
effect of malicious candidate placement
```

For three views, test:

```text
view destinations are distinct when enough nodes exist
view assignments are statistically independent
every client has exactly one selected destination per view
same descriptor + same client -> same assignment
```

If MatchBits is used, explicitly test sparse NodeID populations.

Never assume all bit-prefix buckets contain nodes.

---

# 11. Byzantine and adversarial tests

Script malicious nodes.

Strategies include:

```text
inflate HLL
suppress HLL
selectively suppress certain clients
replay old report
change sequence
equivocate to different authorities
send inconsistent delegation descriptor
delay messages strategically
ACK data not retained
pretend another membership view
```

Expected tolerance targets:

```text
one malicious ingest view should not dominate two honest views
one malicious authority should not unilaterally alter replicated state
```

These are protocol goals, not mathematical guarantees until formally demonstrated.

Every security test must state its assumptions.

---

# 12. Control-loop tests

Model load as a function of virtual time.

Required inputs:

```text
constant
linear ramp
exponential ramp
viral jump
step down
oscillation around threshold
bursty traffic
missing reports
```

Required properties:

```text
does not exceed hard target indefinitely when capacity exists
does not resize continuously under stable load
does not flap near threshold
responds quickly enough to overload
shrinks substantially more slowly than it grows
```

Use deterministic virtual time.

---

# 13. Tag and association tests

Model tags as ordinary ContentIDs.

Test:

```text
A tagged B
B tagged Root
reply C associated with A
tag associated with another tag
cycles
large fan-out
many tiny children
```

Properties:

```text
no recursive infinite propagation
duplicate reports are idempotent
geometric thresholds bound report count
a child's popularity can be reconstructed independently
```

For popularity `N`, number of geometric updates should grow approximately:

```text
O(log N)
```

---

# 14. Fuzzing

At minimum create fuzz targets for:

```text
wire decoder
canonical content decoder
CID/content parser
signed authority message decoder
delegation descriptor decoder
HLL decoder
routing message decoder
mutable revision decoder
```

Fuzz target rule:

```text
arbitrary bytes must never panic, hang, allocate unbounded memory, or violate declared size limits
```

Seed corpora include valid protocol examples so fuzzing explores semantically deep states.

---

# 15. Mutation testing

Run `cargo-mutants` regularly on:

```text
populus-types
populus-sketch
populus-routing
populus-cluster pure state logic
populus-content
```

High-value surviving mutants must be addressed by:

```text
better test
documented equivalent behavior
explicit exclusion with reason
```

Do not add meaningless assertions merely to kill a mutant.

---

# 16. Coverage

Use:

```bash
cargo llvm-cov nextest --workspace
```

Coverage is reported per crate and per changed file.

Avoid a single project-wide percentage target as the primary quality measure.

Instead enforce:

```text
new protocol branches need tests
uncovered security-sensitive branches require explanation
coverage must not materially collapse
```

Reference tests, mutation score, and invariant coverage matter more than raw line percentage.

---

# 17. Performance testing

Use two classes.

## Deterministic CI microbenchmarks

Use `iai-callgrind` for:

```text
HLL insert
HLL merge
XOR distance
nearest-node lookup
assignment
canonical encoding
signature verification
```

Track instruction counts and selected cache metrics.

## Wall-clock throughput benchmarks

Use Divan or custom harnesses for:

```text
votes/sec
reports/sec
routing lookups/sec
content encode/decode/sec
```

Wall-clock results are not hard CI gates on uncontrolled runners.

---

# 18. Scale simulation

Run increasingly large synthetic simulations without allocating one OS task per simulated entity.

Target progression:

```text
1K clients
100K clients
1M clients
100M logical clients using aggregated generation
1B logical clients using statistical workload generation
```

At large scales, generate equivalent distributions rather than creating one Rust object per human.

Track:

```text
messages
CPU work
authority state
ingest state
bytes transmitted
peak memory
control-loop configuration
```

---

# 19. Test anti-patterns

Reject tests that:

```text
only search source/output for expected strings
duplicate the implementation line for line
depend on debug formatting
sleep and hope
use unseeded randomness
assert irrelevant internal ordering
mock so much that no real behavior remains
only test the happy path
silently retry flaky failures
weaken bounds after a regression without analysis
```

A flaky test is a bug.

Do not add automatic retries to make a flaky test appear green.