# Phase 0 audit

Reviewed again on 2026-11-02 against `audit/pre-phase-9` after the implementation commits. The original sub-agent report is preserved below.

## Resolution

| Finding | Status | Why |
|---|---|---|
| Empty `populus-node` | Fixed | `a7176a5`. `Node` owns `Transport`, keeps caller-supplied `NodeId` distinct from `PeerId`, and exchanges direct votes on loopback TCP and QUIC. |
| Empty `populus-protocol` | Not implemented | Versioned envelopes are intentionally undefined. The crate documents that node and transport must not invent one. Recorded in `IDEAS.md`. |
| Empty `populus-store` | Not this phase | Persistence is Phase 15. |
| `deny.toml` NCSA allowlist | Not changed | Already committed. License allowlist changes need maintainer review (`CONTRIBUTING.md`). |
| Unused planned test crates | Not added | Dependencies are added only where used. `rand_chacha`, `tempfile`, `divan`, and `iai-callgrind` have no harness. |
| `iai-callgrind` and mutants | Not implemented | No harness is installed. `gate pr` prints an explicit skip. Enforcement waits for a recorded baseline (`IDEAS.md`). |
| PR gate skipped simulator scenarios | Fixed | `gate pr` runs `cargo nextest run -p populus-sim` after the commit gate, doctests, and coverage. |
| Binary-size fail gate | Not enforced | Metrics record release size. The plan tightens budgets only after a stable baseline. |
| Metrics budgets unread | Not enforced | Same baseline rule. `metrics/budgets.toml` remains documentary. |
| CI runs `gate commit` only | Not changed | `CONTRIBUTING.md` assigns `gate commit` to the fast path and `gate pr` to review. The inactive long-running workflow is reserved for fuzz, mutation, and soak jobs that do not exist yet. |
| Simulator fault model | Fixed | See `phases4-5-audit.md`. Disabled faults do not consume extra RNG. |
| Top-level `unit/` `property/` directories | Not restructured | Tests live in crate modules, `fuzz/`, and `populus-sim`. Moving files would not add behavior. |
| CI still runs `cargo xtask setup` | Not a gap | Gates do not install tools. CI setup is the documented installer. |


## Original report

## 1. Phase 0 checklist

### Repository layout

- **PASS — Workspace members/exclusion.** Root workspace includes `crates/*`, `sim/populus-sim`, and `xtask`, and excludes `fuzz` (`Cargo.toml:2-8`).
- **PASS — Required crate directories exist.** All ten listed crates are present.
- **PARTIAL — Dependency direction.** Most pure-crate dependencies follow the intended direction, but `populus-protocol` is effectively empty (`crates/populus-protocol/src/lib.rs:1`), while `populus-node` and `populus-store` contain no implementation. The intended runtime chain is therefore not meaningfully established.
- **PASS — Simulator isolation.** The simulator depends on pure protocol crates (`sim/populus-sim/Cargo.toml:7-15`); production crates do not reference it.
- **PASS — No obvious extra code-moving crate.**

### Rust configuration

- **PASS — Edition/toolchain.** Edition 2024 and required stable components are configured (`Cargo.toml:11`, `rust-toolchain.toml:1-4`).
- **PASS — Workspace lints.** Unsafe code is forbidden, unused must-use is denied, and requested Clippy policies are present (`Cargo.toml:32-49`).
- **PASS — Release profiles.** Required release and profiling settings exist (`Cargo.toml:51-62`).
- **PASS — libp2p feature minimization.** Default features are disabled and requested transport/behaviour features are enabled (`Cargo.toml:17-27`).
- **PASS — No production `libp2p::kad` dependency found.**
- **PASS — `clippy.toml` and `rustfmt.toml`.** Values match the plan (`clippy.toml:1-4`, `rustfmt.toml:1-6`).
- **PARTIAL — `deny.toml`.** Required bans/sources/advisories are present, but the license allowlist adds `NCSA`, which is not in the specified starting policy (`deny.toml:13-27`). The file also contains a narrowly justified advisory ignore (`deny.toml:4-7`), which requires ongoing review.

### Dependency policy and test dependencies

- **PARTIAL — Dependency justification.** Runtime dependencies are small, but there is no per-dependency justification mechanism or audit documentation. Several planned test dependencies (`rand_chacha`, `tempfile`, `divan`, `iai-callgrind`) are absent from manifests.
- **PARTIAL — Property testing.** `proptest` exists in types, crypto, and routing (`crates/populus-types/Cargo.toml:8-9`, `crates/populus-crypto/Cargo.toml:13-14`, `crates/populus-routing/Cargo.toml:11-12`), but the broader required test architecture is incomplete.
- **FAIL — Deterministic performance testing.** No `iai-callgrind` harness or dependency was found.
- **PASS — No production `hyperloglogplus` dependency found.**

### xtask commands and gates

- **PASS — Commands exist.** `setup`, `fmt`, `lint`, `test`, `test-all`, `coverage`, `deps`, `metrics`, and both gate variants are dispatched (`xtask/src/main.rs:41-68`).
- **PASS — Commit gate mostly matches.** It runs fmt check, Clippy with `-D warnings`, nextest, machete, deny, and quick metrics (`xtask/src/main.rs:450-458`).
- **FAIL — PR gate does not perform required checks.** Mutation testing, deterministic simulator scenarios, and iai-callgrind are explicitly skipped (`xtask/src/main.rs:460-469`). Release binary-size is only informational, not a gate.
- **PARTIAL — Setup.** Tools are version-pinned and installed with `--locked` (`xtask/src/main.rs:14-18`, `xtask/src/main.rs:126-150`), but CI invokes `cargo xtask setup`, so CI still performs installation rather than using preinstalled/pinned tools.

### Metrics

- **PARTIAL — Metrics artifact.** `metrics/<sha>.json` is generated with many required fields (`xtask/src/main.rs:571-612`), but most protocol/performance fields are always `null`, and budgets are never read or enforced.
- **PARTIAL — Budgets.** `metrics/budgets.toml` exists (`metrics/budgets.toml:1-8`), but no code references or validates it.

### Testing architecture and simulator

- **PARTIAL — Seeded deterministic simulation.** Seed, virtual timestamps, latency, clock skew, crashes/recovery, replay, duplication, and scripted malicious strategies exist (`sim/populus-sim/src/config.rs:17-126`).
- **FAIL — Required simulator capabilities incomplete.** No explicit support was found for jitter, random loss, reordering controls, network partitions, bounded bandwidth, bounded connection count, or Byzantine scripted behavior beyond message drop/duplicate/delay/replay.
- **PASS — No protocol `sleep()` usage found in simulator.**
- **PARTIAL — Simulation tests.** Scenario tests cover reproducibility, duplicates, crashes/recovery, clock skew, and routing lifecycle (`sim/populus-sim/src/tests.rs:25-250`, `sim/populus-sim/src/routing/tests.rs:10-57`), but do not cover the full required fault model.
- **FAIL — Required test layers are not implemented.** Reference, network, adversarial, fuzz, and deterministic benchmark coverage are missing or incomplete. The inactive workflow confirms fuzz/mutation/soak checks are not configured (`.github/workflows/long-running.yml:1-18`).
- **FAIL — CI does not match PR gates.** CI only runs `gate commit` on pull requests (`.github/workflows/ci.yml:14-25`); it never runs `gate pr`.

## 2. Fixes before Phase 9, ranked

### Critical

1. **Implement and enforce the PR gate.** Replace the explicit skips in `xtask/src/main.rs:460-469` with actual mutation, simulator, iai-callgrind, binary-size, and duplicate-dependency checks.
2. **Make CI run the PR gate.** `.github/workflows/ci.yml:22` currently runs only `gate commit`.
3. **Complete simulator fault modeling.** Add jitter, loss, reordering, partitions, bandwidth/connection bounds, and Byzantine scripted actions.
4. **Implement missing protocol/runtime crates.** `populus-protocol`, `populus-store`, and `populus-node` are effectively stubs; the declared dependency architecture is not operational (`crates/populus-protocol/src/lib.rs:1`).

### High

5. **Add required test layers and harnesses**, especially reference-model tests, network tests, adversarial tests, fuzz targets, and iai-callgrind benchmarks.
6. **Enforce metrics budgets.** `budgets.toml` is currently dead configuration; metrics contain mostly null measurements and no threshold enforcement.
7. **Add actual release binary-size gating.** Current code only reports the size (`xtask/src/main.rs:468`, `571-612`).
8. **Review and justify license deviations**, particularly `NCSA` in `deny.toml:23`.

### Medium

9. Add missing planned test dependencies only where used: `rand_chacha`, `tempfile`, `divan`, and `iai-callgrind`.
10. Add tests validating dependency direction and preventing accidental libp2p Kademlia/default-feature activation.

## 3. Intentionally deferred items

The plan’s later protocol phases can reasonably defer protocol behavior, routing functionality, storage semantics, node orchestration, and production networking behavior. Those should not be treated as Phase 0 failures by themselves.

However, Phase 0 explicitly requires the quality infrastructure and gate structure to exist. The current explicit deferrals of mutation testing, simulator scenarios, and iai-callgrind are still Phase 0/definition-of-done gaps, not merely later protocol work.

## 4. Protocol/design deficiencies

- The simulator’s “Byzantine” model is currently limited to transport/message manipulation; it does not model equivocation, invalid signatures, conflicting state, forged membership, or inconsistent responses.
- Failure handling is node availability toggling rather than a general network model; it cannot distinguish node crashes from partition-induced reachability loss.
- Metrics report schema exists, but null performance fields make it impossible to detect regressions in the stated hot paths.
- The declared runtime dependency graph is aspirational because core protocol, storage, and node crates are empty; this risks later collapsing boundaries or introducing shortcuts.