# Phases 1-3 audit

Reviewed again on 2026-11-02. The original sub-agent report is preserved below.

## Resolution

| Finding | Status | Why |
|---|---|---|
| Missing 100k cardinality and single 1M seed | Fixed | `dense_estimates_stay_within_statistical_bounds_for_seeded_populations` covers 1k/10k/100k for seeds 0-7 and 1M for seeds 22-24, with relative error under 0.04. |
| Weak sparse-to-dense promotion test | Fixed | `register_values_match_independent_reference_calculation` compares registers with an independent reference, not only a loose estimate bound. |
| Missing rollback and fork tests | Fixed | Rollback to sequence 0 is rejected. Two distinct sequence-1 successors of the same predecessor are both locally valid and have different CIDs. |
| Duplicate producers untested | Fixed | `duplicate_producer_ids_in_a_body_are_rejected`. |
| XOR property coverage | Already present | `xor_distance_has_big_endian_order_and_prefix_count` and `xor_identity_symmetry_and_order_match_big_endian` cover identity, symmetry, and byte-wise order. No change was required. |
| Extra malformed canonical vectors | Not added | `testvectors/content-v1.json` remains the language-independent oracle. Decoder tests already reject truncation, noncanonical collections, and bad signatures. New vectors would not change the encoding. |
| IPv6 `/48`, HLL analytics, mutable authorization | Not implemented | Protocol design, recorded in `IDEAS.md`. Not a missing Phase 1-3 function. |


## Original report

## 1. Checklist

### Phase 1

| Requirement | Result | Evidence |
|---|---|---|
| Distinct ID types; no implicit conversion | **PASS** | Separate opaque types and compile-fail conversion test: `crates/populus-types/src/id.rs:52-91` |
| PeerId remains distinct | **PASS** | No `PeerId` substitution found; transport identity is not represented by these IDs |
| Epoch opaque u64 / big-endian | **PASS** | `crates/populus-types/src/epoch.rs:1-45`; tests `crates/populus-types/src/tests.rs:71-82` |
| NetworkIdentity pure typed-error normalization | **PASS** | `network_identity.rs:118-229` |
| IPv4 /32, IPv6 /48 canonical encodings | **PASS** | `network_identity.rs:87-91, 214-229`; tests `src/tests.rs:106-137` |
| Eligibility rejection classes | **PASS** | Typed classes `network_identity.rs:6-43`; tests `src/tests.rs:144-217` |
| IPv4-mapped and 6to4 collapse | **PASS** | `network_identity.rs:169-179`; tests `src/tests.rs:144-183` |
| Exact domain-hash construction and required domains | **PASS** | `populus-crypto/src/lib.rs:17-39, 42-49, 76-90, 284-312` |
| RoutingKey typed 0x01/0x02 encoding | **PASS** | `populus-crypto/src/lib.rs:52-90` |
| Restricted 36-byte CID profile | **PASS** | `populus-types/src/content_id.rs:5-18, 60-80` |
| Producer/Authority Ed25519 identities and separate domains | **PASS** | `populus-crypto/src/lib.rs:169-218, 268-307`; vectors/tests `src/tests.rs:151-185` |
| ID-001 separate NodeId/ClientId domains | **PASS** | `populus-crypto/src/lib.rs:42-49`; vector oracle tests `src/tests.rs:232-252` |
| XOR distance, ordering, serialization, properties | **PARTIAL** | Distance implementation `populus-types/src/distance.rs:1-31`; property tests exist, but required XOR-focused tests are not clearly comprehensive |
| Language-independent golden vectors | **PASS** | `testvectors/ids-v1.json`; independent oracle tests `populus-crypto/src/tests.rs:139-252` |

### Phase 2

| Requirement | Result | Evidence |
|---|---|---|
| Required sketch interface | **PASS** | `populus-sketch/src/lib.rs:53-257` |
| Exact sorted 256 then p=14, 6-bit HLL | **PASS** | `src/lib.rs:5-18, 66-77, 347-392` |
| Versioned canonical serialization and decoder bounds | **PASS** | `src/lib.rs:133-214`; malformed tests `src/tests.rs:169-214` |
| Decoder fuzz target | **PASS** | `fuzz/fuzz_targets/sketch_decoder.rs` |
| Duplicate, merge algebra, partition properties | **PASS** | `populus-sketch/src/tests.rs:29-158` |
| Exact HashSet oracle | **PASS** | `src/tests.rs:216-236` |
| Sparse-to-dense preservation | **PARTIAL** | Promotion test only checks estimate within a loose fixed bound: `src/tests.rs:39-58` |
| Required cardinalities | **PARTIAL** | Tests include 0/1/10/100/256, 1K/10K/1M; missing required 100K: `src/tests.rs:216-236, 238-267` |
| Many deterministic statistical seeds | **PASS** | Eight seeds for 1K/10K and one 1M seed: `src/tests.rs:238-267` |
| Audience statistics informational only | **PASS** | Only test-level calculation; no security use found: `src/tests.rs:270-285` |
| Implementation details hidden from higher layers | **PASS** | Representation is private: `src/lib.rs:25-34` |

### Phase 3

| Requirement | Result | Evidence |
|---|---|---|
| ContentBody fields and bounds | **PASS** | `populus-content/src/body.rs:8-48, 108-134` |
| Positional DAG-CBOR and deterministic ordering | **PASS** | `codec.rs:15-48`; canonicalization `body.rs:54-105` |
| Duplicate rejection | **PASS** | `body.rs:136-155`; decoder canonicalization `codec.rs:49-78` |
| Ed25519 signature preimage and verification | **PASS** | `signed.rs:12-16, 105-143, 254-259` |
| Anonymous and multi-producer content | **PASS** | `signed.rs:45-94`; tests `content/src/tests.rs:41-143` |
| Public key derives ProducerId; producer set matches signatures | **PASS** | `signed.rs:62-81, 127-143` |
| CID covers complete signed object | **PASS** | `signed.rs:187-204`; `codec.rs:240-242` |
| DAG-CBOR tag-42 links | **PASS** | `codec.rs:110-125`; tests `content/src/tests.rs:67-95` |
| Mutable ID from genesis CID | **PASS** | `mutable.rs:36-47`; `populus-crypto/src/lib.rs:311-312` |
| Revision sequence, predecessor, rollback/fork integrity | **PARTIAL** | Validation exists `mutable.rs:82-125, 194-216`; tests cover skipped sequence but not a true rollback or fork |
| Content parser fuzzing | **PASS** | `fuzz/fuzz_targets/content_decoder.rs` exercises body, signed, and revision parsers |
| Required golden encoding/CID/signature vectors | **PASS** | `testvectors/content-v1.json`; independent checks `content/src/tests.rs:278-371` |

## 2. Fixes before completion

### High

1. **Phase 2 statistical coverage is incomplete.**  
   Required 100K cardinality is absent, and the 1M result uses only one deterministic seed (`populus-sketch/src/tests.rs:238-267`). A biased implementation could pass this test. The oracle is independent for small populations, but the large-population oracle is only the known inserted count—not an independent set oracle.

2. **Sparse→dense promotion test is weak.**  
   It accepts an absolute error under 20 for 257 items (`src/tests.rs:39-58`), which does not establish preservation of registers or estimate semantics. A materially broken promotion could pass.

3. **Mutable rollback/fork tests are missing.**  
   `content/src/tests.rs:145-173` tests sequence `2` instead of a rollback and does not construct competing successors. The implementation likely rejects them, but the required oracle is not independently demonstrated.

### Medium

4. **Phase 1 XOR property coverage is not evident.**  
   The repository has distance implementation and routing tests, but the requested explicit `xor(a,a)==0`, symmetry, distribution, and serialization properties should be confirmed in `populus-types/src/tests.rs` rather than inferred from routing tests.

5. **Content negative coverage is incomplete.**  
   The plan/TESTING requirements call for invalid signatures, duplicate producers, large payloads, revision forks, rollback, and unknown optional fields. Some are covered, but duplicate producers and true fork/rollback cases are not directly tested.

6. **Independent canonical-encoding oracle is limited.**  
   Content vectors are checked against expected bytes (`content/src/tests.rs:278-371`), but most canonicality tests compare implementation output against itself. Add externally generated vectors for malformed/noncanonical collection ordering and links.

## 3. Protocol/design issues for `IDEAS.md`

- IPv6 `/48` aggregation intentionally merges all addresses in a prefix; the architecture itself records this residual Sybil/fairness weakness (`ARCHITECTURE.md:189-200`).
- HLL-derived set differences/intersections have compounded error and must remain analytics-only; this is correctly documented but should be enforced at API boundaries (`ARCHITECTURE.md:823-872`).
- Mutable revision validation provides chain integrity but no authorization or key continuity; a holder of signing authority can create competing valid successors (`ARCHITECTURE.md:425-435`, `mutable.rs:82-125`).
- The content schema has no extensible/unknown-field mechanism despite the testing requirement mentioning unknown optional fields; any schema extension requires a version change.

## 4. TODO/unimplemented/allow findings

No phase-specific `TODO` or `unimplemented!` was found in the reviewed Phase 1–3 implementation.

Relevant lint allowances are justified but should not obscure testing gaps:

- HLL floating-point conversion allowance: `populus-sketch/src/lib.rs:87-91`
- HLL register conversion allowance: `src/lib.rs:370-381`
- Test-only `expect` allowances: `populus-sketch/src/tests.rs:145-151`; `populus-content/src/tests.rs:1-4`