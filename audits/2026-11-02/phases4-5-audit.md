# Phases 4-5 audit

Reviewed again on 2026-11-02, including the simulator diff that was still uncommitted at compaction. The original sub-agent report is preserved below.

## Resolution

| Finding | Status | Why |
|---|---|---|
| Jitter, probabilistic loss, reorder | Fixed | Optional config fields. Disabled values do not sample RNG. Tests require a changed outcome and an inverted delivery order. |
| Engine partitions | Fixed | `PartitionAction::Split` drops cross-group votes and counts `partition_drops`. Heal restores delivery. |
| Join, leave, restart | Fixed | Restart clears sketch state and is counted separately from crash/recover, which keeps state. Leave does not clear retained state. |
| Bounded connections | Fixed | Excess new peer pairs are rejected and counted. Existing pairs stay up until crash, leave, or restart. |
| Bounded bandwidth | Fixed in this follow-up | The first implementation added a constant per-message delay, then serialized in whole milliseconds, then rounded every transmission to microseconds. The simulator now accumulates exact rate-scaled egress ticks and rounds only at event delivery. The regression sends 3,000 messages from one source at both 1 MB/s and 1 GB/s, requiring 384 ms and 1 ms respectively. |
| Conflicting-state script with fewer than four nodes | Fixed | `validate_config` rejects `SendConflictingAuthorityStates` unless there are at least four nodes. Tests cover node counts 1, 2, and 3, so invalid scripts fail before authority construction. |
| Byzantine scripts | Fixed for the required behaviors | One-shot drop, duplicate, delay, and signed conflicting authority states. Equivocation builds a proof and requires `resolve_authority_state` to keep the supported state. A general multi-step adversary language is not required before Phase 9. |
| Routing oracle used `known_nodes()` | Partially fixed | `modest_routing_lifecycle_uses_virtual_time_and_brute_force_oracle` compares retained contacts with an expected alive/partition set, then brute-force closest. The 10k test still brute-forces the retained set: bucket capacity makes membership depend on insertion order, and a second bucket implementation would not be independent. |
| Routing not inside `run_simulation` | Not moved | Plan section 10 says vote placement is a workload generator, not the routing protocol. Routing lifecycle remains a deterministic `populus-sim` scenario. |
| Full-bucket rejection / no eviction | Not changed | Correct until transport liveness exists. Recorded in `IDEAS.md`. |


## Original report

## 1. Checklist

| Requirement | Status | Evidence |
|---|---|---|
| Routing independent of libp2p; uses Populus `NodeId` | **PASS** | `crates/populus-routing/src/lib.rs:1-3, 43-48`; no libp2p dependency/API found |
| Brute-force XOR oracle | **PASS** | `crates/populus-routing/src/lib.rs:168-190` |
| 256 MSB-differing-bit buckets, capacity 20 | **PASS** | `crates/populus-routing/src/lib.rs:7-12, 144-147`; bucket calculation at `:155-158` |
| Reject full buckets; no eviction | **PASS** | `crates/populus-routing/src/lib.rs:68-79` |
| Exact nearest lookup over retained contacts | **PASS** | `crates/populus-routing/src/lib.rs:119-152` |
| Differential lookup tests | **PASS** | `crates/populus-routing/src/tests.rs:25-42, 122-145`; lifecycle checks at `sim/populus-sim/src/routing/tests.rs:237-251` |
| Required routing property tests | **PARTIAL** | Duplicate/full bucket, remove/reinsert, ordering, bucket bounds, and lookup properties exist at `crates/populus-routing/src/tests.rs:45-173`. Random churn is only a fixed loop, not a randomized property; insertion-order test does not independently verify different retained sets (`:99-119`). |
| 100/1K/10K routing lifecycle | **PASS** | `sim/populus-sim/src/routing/tests.rs:10-58` |
| Joins, leaves, churn, partitions, recovery | **PASS** | `sim/populus-sim/src/routing/tests.rs:16-58` |
| Independent routing oracle in lifecycle | **PARTIAL** | Uses brute force at `sim/populus-sim/src/routing/tests.rs:243-247`, but oracle input is `table.known_nodes()` (`:239`), so it verifies ordering over the implementation’s retained set, not correct membership/retention against an independent expected table. |
| Deterministic seeded randomness | **PASS** | `sim/populus-sim/src/rng.rs:1-16`; reproducibility test `sim/populus-sim/src/tests.rs:25-48` |
| Virtual monotonic time | **PASS** | Event timestamps/queue in `sim/populus-sim/src/engine.rs:312-363`; no `sleep()` or wall-clock API found |
| Per-node clock offset | **PASS** | `sim/populus-sim/src/config.rs:117-120`; applied at `sim/populus-sim/src/engine.rs:298-305` |
| Latency | **PARTIAL** | Configured and sampled in `sim/populus-sim/src/workload.rs:110-125`, but only vote scheduling; no packet/network abstraction |
| Jitter | **FAIL** | No jitter distribution/configuration found |
| Loss | **PARTIAL** | Crash/drop and malicious drop exist (`sim/populus-sim/src/engine.rs:210-218`), but no probabilistic packet loss |
| Reordering | **PARTIAL** | Priority queue can order by timestamp, but no explicit reordering fault/model |
| Duplication/replay | **PASS** | `sim/populus-sim/src/config.rs:90-103`; handling `sim/populus-sim/src/engine.rs:235-275` |
| Partitions in simulator engine | **FAIL** | Partitions exist only in the routing unit-test model (`sim/populus-sim/src/routing/tests.rs:126-170`), not `SimulationConfig`/engine |
| Crash/restart | **PARTIAL** | Crash/recover schedule exists (`sim/populus-sim/src/config.rs:64-77`); no explicit node restart state/reset semantics |
| Join/leave in simulator | **FAIL** | No simulator configuration or engine support; only routing test helpers |
| Byzantine scripted behavior | **PARTIAL** | Four fixed strategies only (`sim/populus-sim/src/config.rs:82-103`); no scripts/stateful arbitrary behavior |
| Bounded bandwidth | **FAIL** | No bandwidth model/configuration found |
| Bounded connection count | **FAIL** | No connection model/configuration found |
| Required simulation inputs | **PARTIAL** | Seed/counts/content/latency/skew/failures/malicious strategy at `sim/populus-sim/src/config.rs:108-128`; missing jitter, loss, partitions, bandwidth, connections, join/leave/restart controls |
| Failure reports reproduction seed | **PASS** | `sim/populus-sim/src/config.rs:173-176, 205-208`; tests `sim/populus-sim/src/tests.rs:214-254` |
| Small permanent regression scenarios | **PASS** | `sim/populus-sim/src/tests.rs:25-254` |
| Routing/content/client-sketch APIs exercised | **PARTIAL** | Content/sketch are exercised in `sim/populus-sim/src/engine.rs:75-98`; routing is exercised by separate routing tests, not the main event engine |
| Production crates independent of simulator | **PASS** | Simulator is a separate workspace member; routing crate has no simulator dependency |

Architecture comparison: **routing conforms** to `ARCHITECTURE.md:475-495`. Testing guidance is only partially met: Level 4 requires simulated network/churn/faults/malice/load (`TESTING.md:80-96`), while the engine lacks partitions, joins/leaves, bandwidth, and connection limits. Routing guidance requires generated removal/insertion/churn (`TESTING.md:246-275`), but coverage is mostly fixed examples.

## 2. Missing capabilities/tests before Phase 9

- Add packet/network abstractions with explicit jitter, probabilistic loss, reordering, duplication, and bounded bandwidth.
- Add partition state and node join/leave/restart events to `SimulationConfig` and the event engine.
- Add connection-count limits and observable connection admission/rejection.
- Add scripted/stateful Byzantine behaviors rather than only fixed enum strategies.
- Integrate routing tables into the event engine; currently routing lifecycle is a separate test-only model (`sim/populus-sim/src/routing.rs:1-3`).
- Add randomized property tests for insert/remove/reinsert churn and independent expected membership.
- Add simulator scenarios that run routing lifecycle operations through virtual time, not only direct table mutation.

## 3. Tests asserting implementation against itself

The main issue is lifecycle validation: it derives the “oracle” contacts from `table.known_nodes()` (`sim/populus-sim/src/routing/tests.rs:239-247`). Thus lookup ordering is independently brute-force sorted, but retained-contact correctness is not independently established.

`crates/populus-routing/src/tests.rs:99-119` compares two tables created by the same implementation and does not prove insertion order preserves the logical nearest set against a separately computed expected set.

## 4. Design/protocol deficiencies worth IDEAS.md

- Routing buckets have no contact liveness metadata or eviction/replacement policy; full buckets permanently reject contacts until explicit removal (`crates/populus-routing/src/lib.rs:68-79`).
- Simulator “network” currently models vote delivery directly to nodes, not packets, links, queues, or connections.
- Partition behavior exists only in a bespoke two-table test model, so it does not validate production routing lifecycle semantics.
- Failure/recovery is a boolean availability toggle, not restart/reinitialization behavior.
- Malicious behavior is destination-based and globally selected, rather than per-node scripted protocol behavior.

## 5. 10K simulation test

**Exists and is not ignored/skipped.** The test explicitly iterates `10_000` at `sim/populus-sim/src/routing/tests.rs:10-12`; there are no `#[ignore]` or `cfg` gates around it. It should run as a normal test, though it is only a routing-table lifecycle test—not a 10K-node deterministic event-engine simulation.