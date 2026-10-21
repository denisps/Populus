# CONTRIBUTING.md

# Contributing to Populus

Populus is a distributed-systems project where a locally plausible change can produce globally incorrect behavior. Contributions must therefore be judged by externally observable behavior, protocol invariants, resource use, and adversarial conditions rather than by code coverage alone.

## Development setup

Install stable Rust through rustup.

Required components:

```bash
rustup component add rustfmt clippy llvm-tools-preview
```

Recommended Cargo tools:

```bash
cargo install --locked cargo-nextest
cargo install --locked cargo-deny
cargo install --locked cargo-machete
cargo install --locked cargo-bloat
cargo install --locked cargo-llvm-cov
cargo install --locked cargo-mutants
cargo install --locked cargo-semver-checks
cargo install --locked iai-callgrind-runner
```

`cargo-fuzz` requires a compatible nightly toolchain and is used by fuzzing jobs rather than the normal fast development path.

## Normal workflow

Before editing:

```text
1. Read AGENTS.md.
2. Read the relevant ARCHITECTURE.md section.
3. Identify the invariant or behavior being changed.
4. Find the corresponding tests and reference model.
```

During implementation:

```text
1. Keep the change narrow.
2. Add or change tests first when practical.
3. Do not change unrelated behavior.
4. Do not add dependencies for convenience.
5. Run focused tests continuously.
```

Before committing:

```bash
cargo xtask gate commit
```

Before requesting review:

```bash
cargo xtask gate pr
```

## Commit policy

Prefer small commits with one reason to exist.

Good:

```text
routing: add brute-force nearest-node oracle
routing: implement bucket nearest lookup
routing: differential-test bucket lookup against oracle
```

Bad:

```text
refactor networking and add HLL and fix tests
```

Do not mix mass formatting with behavioral changes.

Do not hide generated code, vendored libraries, binary blobs, or large fixtures in ordinary commits.

## Tests must verify behavior

Tests should answer questions such as:

```text
Does the optimized routing algorithm select the same nearest nodes as the reference model?

Does partitioning a population across ingest nodes and merging their HLLs preserve the population estimate?

Does a crashed ingest node retain its pending report until all authorities ACK?

Does the control loop stabilize under constant load?

Can one malicious shuffled view distort the result when two honest views agree?
```

Tests should generally not answer:

```text
Does this private field equal 7?

Does this debug string contain "delegated"?

Was helper function X called exactly twice?

Does an internal Vec have exactly this ordering when ordering is not part of the protocol?
```

Tests may inspect implementation details only when those details themselves are protocol or safety requirements.

## Reference implementations

For complex optimized algorithms, first maintain a simple slow oracle.

Examples:

```text
HashSet<ClientId>       -> HLL oracle
full peer sort          -> routing oracle
simple assignment scan  -> optimized assignment oracle
pure state machine      -> async cluster implementation oracle
```

The oracle should favor clarity over performance.

Do not "optimize" the reference implementation into the same algorithm as the production implementation.

## Property and metamorphic testing

Prefer invariant tests that survive internal refactoring.

Examples:

```text
merge(A,B) == merge(B,A)

routing result independent of insertion order

encoding -> decoding -> encoding produces identical canonical bytes

partition population -> merge partitions approximates unpartitioned sketch

adding network latency changes timing but not eventual finalized daily population

duplicating a message does not duplicate a client
```

Use deterministic random seeds.

Every randomized failure must print its seed.

## Snapshot and golden tests

Golden data is appropriate for:

```text
wire encoding
CID derivation
signature vectors
hash derivation
protocol compatibility vectors
```

Avoid snapshots for:

```text
debug output
logs
internal structs
large arbitrary JSON
incidental ordering
```

A snapshot should protect a compatibility contract, not freeze an implementation.

## Time-dependent tests

Never rely on real sleeps for protocol timing.

Use:

```text
virtual clocks
Tokio paused time where applicable
simulator time
explicit clock injection
```

Tests involving latency, clock drift, minute rollover, retry, expiry, and daily epochs must use controllable time.

## Dependencies

A new runtime dependency requires a short justification in the commit or PR.

Include:

```text
purpose
direct alternatives considered
enabled features
transitive dependency delta
binary-size delta
license (see [Licensing](#licensing))
maintenance status
```

Run:

```bash
cargo tree -e features
cargo tree -d
cargo machete
cargo deny check
```

Prefer:

```toml
default-features = false
```

when broad defaults are unnecessary.

Dev-only tools are less sensitive to runtime bloat but still affect build complexity and supply-chain surface.

## Licensing

Populus is licensed under the MIT license (see `LICENSE`).

Contributions are accepted under the same license (inbound = outbound).

Every workspace crate must inherit the license:

```toml
license.workspace = true
```

Only permissively licensed dependencies are allowed, as listed in the `deny.toml` allow-list. Copyleft (GPL, AGPL, LGPL, MPL, SSPL, etc.) and unlicensed dependencies are not allowed.

Adding any license to the allow-list requires explicit maintainer review.

`cargo deny check licenses` enforces this and is part of `cargo xtask gate commit`.

Copied or vendored code must preserve its original copyright notice and license text, and must be recorded (for example in `THIRD_PARTY_NOTICES.md` or in the PR description). Large copied code needs justification.

Do not paste code from incompatible sources, or AI output that reproduces licensed code verbatim.

## Unsafe Rust

Workspace policy is:

```text
unsafe_code = forbid
```

If unsafe code becomes necessary:

1. It requires a design decision first.
2. Place it in a narrowly scoped crate.
3. Change the workspace policy only deliberately.
4. Document every invariant.
5. Add Miri tests where applicable.
6. Fuzz the boundary.
7. Prefer a well-audited dependency over custom unsafe code when reasonable.

## Error handling

Libraries return typed errors.

Do not use `panic!`, `unwrap()`, or `expect()` for recoverable network input.

Tests may use `unwrap()` where failure would simply mean the test cannot continue.

Network decoders must reject malformed or oversized inputs without panicking.

## Logging

Use structured `tracing`.

Logs are diagnostics, not protocol state.

Never write tests whose correctness depends on log text unless testing the logging interface itself.

Never log:

```text
private signing material
full sensitive network identifiers unnecessarily
unbounded remote content
```

## Performance

Every commit is measured.

A performance optimization must include:

```text
the workload
the old result
the new result
the correctness tests proving equivalent behavior
```

Do not replace a clear algorithm with a complex optimization for a negligible benchmark win.

Hot-path regressions require explanation.

## Binary size

The node is expected to run broadly, including on inexpensive hardware.

Monitor:

```text
stripped release size
.text size
crate-level contribution
feature expansion
duplicate dependency versions
```

Use:

```bash
cargo bloat --release --crates
cargo tree -d
```

A large new dependency for a small convenience function is normally rejected.

## Protocol changes

Any change affecting these areas is a protocol change:

```text
ID derivation
canonical encoding
CID generation
signature preimage
DHT routing
authority selection
ingest assignment
delegation descriptors
daily vote epochs
tag reports
wire message semantics
```

Protocol changes require:

```text
ARCHITECTURE.md update
compatibility/version decision
tests
new or updated vectors where applicable
simulation of mixed old/new behavior if versions may coexist
```

## Documentation

Comments explain why, invariants, and non-obvious distributed behavior.

Do not comment obvious syntax.

Public protocol types should explain:

```text
meaning
units
valid range
security assumptions
lifetime
versioning
```

## Review checklist

A reviewer should ask:

```text
Can this be tested against an independent oracle?
What happens when messages arrive twice?
What happens when messages arrive late?
What happens when one node lies?
What happens when one node disappears?
What happens at 1000x the expected load?
Does state grow with users, content, associations, or time?
Can state be reconstructed?
Did dependency or binary size increase?
Did the change accidentally make an implementation detail part of the protocol?
```