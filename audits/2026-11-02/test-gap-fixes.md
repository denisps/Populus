# Test-gap implementation report

The implementation sub-agent reported sketch, content, `replace_authority`, and `gate pr` changes, and said `cargo nextest run -p populus-sim` failed because the simulator was being edited concurrently. That claim was rechecked.

## Resolution

The reported test and replacement changes are present in `10fb3b5` and were not weakened:

- HLL promotion uses an independent register oracle. 100k and multi-seed 1M bounds are asserted.
- Mutable rollback is rejected. Competing sequence-1 forks stay distinguishable.
- Duplicate producer IDs are rejected.
- `replace_authority` is generation-checked and covered by cluster tests.
- `gate pr` runs the simulator suite. Mutants and `iai-callgrind` remain skipped because those harnesses are not installed.

The simulator compile failure was from the concurrent fault-model edit, not from this change. The simulator later compiled and its tests passed.


## Original report

Implemented the sketch, content, cluster replacement API, and `gate_pr` changes. No protocol formats, vectors, signatures, dependencies, or Phase 9+ behavior were changed.

**Files:** `crates/populus-sketch/src/tests.rs`, `crates/populus-content/src/tests.rs`, `crates/populus-cluster/src/lib.rs`, `crates/populus-cluster/src/tests.rs`, `xtask/src/main.rs`. Cargo also refreshed `Cargo.lock` during dependency restoration.

**Passed:** focused offline tests, focused clippy with `-D warnings`, and `cargo test -p xtask --offline`.

**Blocked:** `cargo nextest run -p populus-sim` fails to compile `sim/populus-sim/src/engine.rs` (`ScheduledAction: Copy` and missing `SimNode` fields). I left simulator code untouched as requested. No unresolved protocol gap. No commit created.