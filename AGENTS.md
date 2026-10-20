# AGENTS.md

# AGENTS.md

This repository is expected to be developed heavily by AI coding agents.

The purpose of this file is to prevent locally reasonable changes from damaging protocol correctness, test quality, performance, or architectural simplicity.

## Read first

Before changing code, read in this order:

```text
1. AGENTS.md
2. ARCHITECTURE.md
3. IMPLEMENTATION_PLAN.md
4. TESTING.md
5. CONTRIBUTING.md
6. README.md
7. the README or module docs for the crate being changed
```

If these files conflict, stop and surface the conflict rather than silently choosing one.

---

# 1. Core rules

## Keep changes narrow

One task should normally touch one subsystem.

Do not perform opportunistic refactors unrelated to the requested behavior.

Do not rename broad APIs while implementing an unrelated feature.

## Preserve independent test oracles

Never rewrite a reference implementation to use the optimized implementation it is supposed to check.

Examples:

```text
routing oracle must remain brute-force
HLL oracle must remain exact where feasible
cluster oracle must remain pure and simpler than async implementation
```

## Tests must fail for the bug

Before finalizing a fix, verify that the relevant new test would fail on the broken implementation.

Do not merely add tests that execute the changed lines.

## Never weaken tests to make code pass

Do not:

```text
increase tolerance without analysis
delete assertions
replace exact protocol checks with string checks
add retries to flaky tests
skip tests
mark tests ignored
lower mutation expectations
```

unless the behavior requirement itself changed and documentation is updated.

---

# 2. Architectural boundaries

These identities are distinct:

```text
PeerId      = libp2p transport identity
NodeId      = scarce-network-derived DHT position
ClientId    = scarce-network-derived voting identity
ProducerId  = public-key authorship identity
ContentId   = content/object identity
RoutingKey  = fixed-width XOR-routing key
```

Never substitute one for another because their byte lengths happen to match.

Especially prohibited:

```text
NodeId = PeerId
ClientId = ProducerId
ProducerId = ClientId
```

Production Populus routing must not silently fall back to libp2p Kademlia's PeerId-based routing.

---

# 3. Dependency rule

Before adding a crate, search the workspace for an existing solution.

A new runtime dependency needs justification.

Prefer:

```text
std
existing workspace dependency
small focused crate
```

over a large framework.

Do not enable dependency default features without inspecting them.

After changing dependencies run:

```bash
cargo tree -e features
cargo tree -d
cargo machete
cargo deny check
cargo xtask metrics
```

---

# 4. Protocol changes

If a change affects:

```text
hashing
ID derivation
encoding
CID
signatures
routing
authority selection
delegation
ingest assignment
vote epochs
tag propagation
wire formats
```

then it is a protocol change.

A protocol change requires:

```text
ARCHITECTURE.md update
tests
compatibility consideration
test vectors when byte-level behavior changes
```

Do not make protocol behavior implicit in a helper function with no documentation.

---

# 5. Working procedure

For every task:

```text
A. Identify desired externally visible behavior.
B. Identify relevant invariant IDs.
C. Locate or create an independent oracle.
D. Add focused tests.
E. Implement the smallest change.
F. Run focused tests.
G. Run cargo xtask gate commit.
H. Review git diff.
I. Run cargo xtask metrics if hot path, dependency, or binary changed.
J. Update architecture/docs where required.
```

Before declaring completion, inspect:

```bash
git diff --check
git diff
```

Look specifically for:

```text
accidental generated files
debug prints
TODOs
weakened tests
new unwraps
broad dependency feature activation
large unrelated formatting changes
```

---

# 6. Testing rules for agents

Prefer assertions about:

```text
outputs
state transitions
invariants
messages
security decisions
resource bounds
```

Avoid assertions about:

```text
private helper invocation counts
debug strings
private field layout
incidental Vec ordering
implementation-specific function names
```

Use property tests for algorithms.

Use deterministic seeds.

If a random test fails, preserve the seed as a regression case.

If implementing an optimization:

```text
first prove equivalence against the reference implementation
then benchmark
```

---

# 7. Simulator rules

Do not use real time inside protocol state machines.

Inject time.

Do not use `thread::sleep` or `tokio::time::sleep` in deterministic simulation tests unless the clock is paused/virtualized.

The simulator must remain reproducible.

Every randomized scenario has:

```text
seed
configuration
failure schedule
```

A failure report must print enough information to rerun it.

---

# 8. Network parser rules

All remote input is hostile.

Before allocating from a declared remote length:

```text
validate maximum
```

All decoders must:

```text
reject malformed input
reject unsupported versions
reject oversized messages
never panic
never recurse without a bound
never allocate based on unchecked remote values
```

Add fuzz coverage for new decoders.

---

# 9. Distributed-state rules

Always ask:

```text
What if this message is duplicated?
What if it is delayed?
What if it arrives after a newer message?
What if the sender crashes?
What if the receiver crashes?
What if the sender lies?
What if the same message comes from two paths?
```

Every persistent or replicated state transition should have:

```text
epoch
sequence/version
identity
```

where appropriate.

Do not rely solely on wall-clock ordering.

---

# 10. Authority behavior

Normal authority count is four.

A single authority must not be able to:

```text
change authoritative cluster state alone
disqualify another authority on an unsupported accusation
rewrite finalized state
select arbitrary delegates outside protocol rules
```

Authority-to-authority messages are signed.

Signatures are evidence of what an authority said.

They are not automatically a trust root for ordinary clients.

Client confidence comes from independently discovering multiple expected in-cluster nodes and observing consistent state.

---

# 11. HLL rules

Do not treat HLL as an exact counter.

Do not test HLL accuracy with one sample.

Do not use HLL-derived set subtraction for security-critical decisions without documented statistical analysis.

HLL merge must remain deterministic.

If changing HLL representation:

```text
test old/new decoding if compatibility matters
test sparse/dense transition
test merge equivalence
benchmark memory
benchmark insertion
benchmark merge
```

---

# 12. Delegated ingest rules

Ingest reports are double-buffered.

Never erase a pending report until all four authorities have acknowledged it.

A new collection window begins immediately when the previous one closes.

Minute HLLs from different shuffled views are not expected to be identical.

Clock skew and latency may move clients across adjacent report windows.

Judge convergence over wider windows and daily state.

---

# 13. Performance rules

Do not claim a speedup without measurement.

When changing hot code, report:

```text
benchmark
before
after
binary-size delta
dependency delta
```

Prefer algorithmic improvements over micro-optimizations.

Do not introduce unsafe code for speed without explicit approval and measurements proving the need.

---

# 14. Binary-size rules

Before adding large dependencies or broad features run:

```bash
cargo bloat --release --crates
cargo tree -e features
```

Runtime bloat matters even if functionality is correct.

Dev dependencies do not directly enlarge the release binary, but they still affect repository complexity and CI.

---

# 15. Logging and debugging

Use `tracing`.

Temporary diagnostic output must not remain in commits.

Do not test protocol correctness through log strings.

Logs must not become an undocumented inter-process interface.

---

# 16. Error handling

Remote failures are expected.

Prefer typed `Result`.

Do not panic on:

```text
disconnect
timeout
invalid packet
unknown version
bad signature
stale message
missing peer
full queue
```

A panic may be appropriate only for an internal invariant that cannot result from remote input.

---

# 17. Completion report

When an agent finishes a meaningful code task, its summary should contain:

```text
What changed
What behavior/invariant it implements
Tests added or changed
Commands run
Performance/binary/dependency impact
Known unresolved issues
```

Do not claim a test passed unless it was actually run.

Do not claim a performance improvement without a measured result.