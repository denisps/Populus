# Phases 7-8 audit

Reviewed again on 2026-11-02. The original sub-agent report is preserved below.

## Resolution

| Finding | Status | Why |
|---|---|---|
| No generation-checked replacement | Fixed | `replace_authority` keeps the other three members, selects the next-closest outsider, increments generation, and errors on a non-member, missing joiner, or overflow. |
| `select_authorities` may return fewer than four | Not changed | `MembershipView::new` still rejects a short cluster. A separate partial type is an `IDEAS.md` item, not a behavior change. |
| Phase 8 simulator was a manual loop | Fixed | Virtual-time scenarios deliver votes, duplicate a retry, crash and restore canonical state, retarget the same vote after replacement, and require four signed acknowledgements. The exact client set is a `BTreeSet` oracle. |
| Joiner inherited the crashed snapshot | Fixed in this follow-up | Restore no longer copies the crashed authority's clients onto the joiner. The joiner starts empty and must record the retargeted vote. |
| Authority partition not in the vote engine | Not moved | State responses are not vote-workload packets. The scenario still drops cross-partition responses and requires `RecoveryNeeded { best_matching: 1 }`. A resolver that guesses from one reply fails the test. |
| No live four-node Swarm cluster | Not this phase | Phase 6 integrates transport. Authority messages cannot share that stream until an envelope exists. Pure cluster APIs and simulator scenarios cover the Phase 7/8 invariants. |
| Liveness, concurrent replacement, cluster finalization, distinct-client rate trigger | Not implemented | Protocol rules, recorded in `IDEAS.md`. Absence is not treated as disqualification. The rate trigger still counts deliveries; changing it would be a protocol change. |
| Phase 9+ | Not present | Delegation remains advisory. No assignment or delegated ingest was added. |


## Original report

## 1. Checklist

### Phase 7 — four-node authority cluster

| Requirement | Result | Evidence |
|---|---|---|
| Four closest XOR authorities, NodeId tie-break | **PARTIAL** | `select_authorities` sorts distance then member (`crates/populus-cluster/src/lib.rs:145-186`). It explicitly permits fewer than four (`:128-143`); only `MembershipView` rejects incomplete clusters (`:99-104`). |
| Exactly four unique members, canonical order | **PASS** | `crates/populus-cluster/src/lib.rs:99-118` |
| Generation/membership replacement | **PARTIAL** | Generation is represented and tested (`:73-76`, `crates/populus-cluster/src/tests.rs:955-978`), but no transition enforces that replacement generations increment exactly once. |
| Signed authority messages and key binding | **PASS** | Signed state/request verification binds signer identity and public key (`lib.rs:335-399`, `:420-499`). |
| Canonical state/request bytes | **PASS** | State encoding (`lib.rs:335-399`) and request encoding (`:480-497`) are vector-tested (`tests.rs:250-303`). |
| Complete initial state and 1 MiB component limits | **PASS** | Components/mode are present and validated (`lib.rs:188-318`, `:245-318`). |
| Strict quorum; invalid replies cannot suppress quorum | **PASS** | Three-of-four and two-of-three semantics are documented/implemented (`lib.rs:691-792`). |
| 2-vs-2 disagreement requires recovery | **PASS** | `crates/populus-cluster/src/tests.rs:488-555` |
| Rollback and exact replay handling | **PASS** | `crates/populus-cluster/src/lib.rs:828-865` |
| Equivocation proof | **PASS** | `crates/populus-cluster/src/lib.rs:877-926`; tested at `tests.rs:557-620`. |
| Required failure tests | **PARTIAL** | Pure-model tests cover quorum, rollback, replay, equivocation, replacement and partition. No real network/authority lifecycle implementation is present. |
| Seeded simulator replacement scenario | **PASS** | `sim/populus-sim/src/authority.rs:15-111` |
| `authority-v1.txt` vector | **PASS** | `crates/populus-cluster/src/tests.rs:250-303`; vector `testvectors/authority-v1.txt` |

### Phase 8 — direct ingest

| Requirement | Result | Evidence |
|---|---|---|
| Four-authority direct ingest, idempotent sketches | **PASS** | `DirectIngestState` and duplicate handling (`direct_ingest.rs:636-749`); tests `direct_ingest/tests.rs:72-112`. |
| Advisory 1000/minute trigger, no vote loss | **PASS** | `crates/populus-cluster/src/direct_ingest.rs:16-18`, `:676-730`; test `:72-112`. |
| Exact DailyVoteId encoding/vector | **PASS** | Raw concatenation, 36-byte ContentId and signed 8-byte big-endian day (`crates/populus-crypto/src/lib.rs:95-103`); vector test `crates/populus-crypto/src/tests.rs:123-126`. |
| Persistent like/unlike behavior | **PASS** | `crates/populus-cluster/src/direct_ingest.rs:330-447`; tests `direct_ingest/tests.rs:180-220`. |
| Pending retry, replacement retargeting, two-day expiry | **PASS** | `direct_ingest.rs:363-421`; membership/retry tests `direct_ingest/tests.rs:180-220`. |
| Signed four-authority acknowledgements | **PASS** | `direct_ingest.rs:211-329`, `:443-470`. |
| Grace/skew bounded to one day | **PASS** | `direct_ingest.rs:14-67`; tests `direct_ingest/tests.rs:115-177`. |
| Exact BTreeSet oracle | **PASS** | `crates/populus-cluster/src/direct_ingest/tests.rs:72-112` |
| Required direct-ingest vectors | **PASS** | References/tests exist for daily, snapshot, and ack vectors (`direct_ingest/tests.rs`, `testvectors/`). |
| Simulator integration for Phase 8 timing | **FAIL** | Simulator timing tests cover the older workload/sketch engine (`sim/populus-sim/src/engine.rs:41-319`), while Phase 8 behavior is only a unit test in `sim/populus-sim/src/authority.rs:113-178`; it does not exercise simulator event delivery, membership replacement, signed ACK retries, or authority crash during ingest. |

## 2. Important defects and omissions

**High**
1. **No actual four-authority cluster/network integration.** The implementation is pure state APIs and tests; no authority-to-authority transport, crash/restart lifecycle, network partition, or liveness protocol is wired into the simulator. This is especially contrary to TESTING’s “async/network implementation” requirement (`TESTING.md:346-367`).
2. **Phase 8 simulator scenario is not integrated.** The “direct ingest” simulator test directly instantiates four `DirectIngestState`s and manually supplies timestamps; it does not use simulator latency/events or signed ACK retry behavior (`sim/populus-sim/src/authority.rs:113-178`).
3. **Replacement generation is caller-controlled.** `MembershipView::new` accepts any generation (`lib.rs:73-118`); no replacement operation proves generation advancement or validates the retained-three/next-closest transition.

**Medium**
4. `select_authorities` returns 1–3 members and documents partial neighborhoods as valid (`lib.rs:128-143`; test `tests.rs:170-176`). This is safe only if every caller uses `MembershipView`; the selector itself can be misused as an initialized cluster.
5. Tests do not clearly cover every required independent scenario: explicit authority crash during ingest, client offline then current-day voting, all four signed ACKs through a retry event path, or simulator membership replacement while pending.
6. State application checks epoch, sequence, and generation independently, but does not define/validate their cross-field monotonic transition semantics (`lib.rs:846-862`).

## 3. Protocol deficiencies / IDEAS.md candidates

- **Liveness/disqualification rules remain unspecified.** The code has no objectively defined liveness threshold or disqualification evidence model, despite the plan restriction.
- **Replacement protocol is underspecified.** It should define who increments generation, how the next closest candidate is selected from a complete neighborhood, and how concurrent replacements are resolved.
- **DailyVoteId encoding is now fixed in code/vector**, but the original plan’s “signed UTC-day offset” was ambiguous. Document explicitly: raw concatenation, no length prefixes, signed `i64` big-endian.
- **Finalization time semantics need a precise authority-clock rule.** Current implementation uses local `now_ms`; cross-authority acceptance/finalization consistency is not modeled in a cluster protocol.
- **Sketch snapshot version/sequence replication is only embedded as opaque state.** No integrated protocol demonstrates snapshot convergence or conflict resolution after ingest.

## 4. Premature Phase 9+ behavior

No clear premature delegated assignment or delegated-ingest protocol was found. Rate overflow only produces an advisory recommendation (`direct_ingest.rs:676-730`); no assignment, delegation transition, or delegated ingest implementation is present.

## 5. Oracle independence

**Mixed, but generally adequate for pure logic.**

- Authority selection has an independent distance/order calculation (`tests.rs:137-169`).
- Direct ingest uses an exact independent `BTreeSet<ClientId>` oracle (`direct_ingest/tests.rs:72-112`).
- Canonical bytes and DailyVoteId use external testvector files.
- However, simulator authority tests mostly construct and validate the same high-level implementation APIs, and there is no independent event/network oracle for Phase 7/8 integration.