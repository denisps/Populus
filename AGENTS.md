# AGENTS.md

This repository is developed heavily by AI coding agents. These are the
repository-wide guardrails; detailed protocol, testing, and contributor
guidance belongs in the documents linked below.

## Read relevant documentation

Read this file first. Then read only the relevant sections, in this order:

1. `ARCHITECTURE.md` for current behavior and protocol invariants.
2. `IMPLEMENTATION_PLAN.md` for the relevant phase and planned work.
3. `TESTING.md` for the applicable oracle, tests, and validation rules.
4. `CONTRIBUTING.md` for development commands, dependencies, and review policy.
5. `README.md` and the affected crate's README or module docs as needed.

Do not load entire documents by default. Follow cross-references when the task
touches another subsystem. If documents conflict, stop and surface the conflict
instead of choosing silently.

## Repository guardrails

- Keep changes narrow; do not refactor unrelated APIs or behavior.
- Preserve independent test oracles. Tests must detect the bug, and must not be
  weakened to make an implementation pass. See `TESTING.md`.
- `PeerId`, `NodeId`, `ClientId`, `ProducerId`, `ContentId`, and `RoutingKey`
  are distinct protocol identities. Never substitute one for another;
  production Populus routing must not fall back to PeerId-based libp2p
  Kademlia. See `ARCHITECTURE.md` sections 2, 5, and 6.
- Treat changes to hashing, identifiers, encoding, signatures, routing,
  authority selection, delegation, ingest, epochs, tags, or wire behavior as
  protocol changes. Update architecture, compatibility notes, and tests;
  include vectors when bytes change. Do not leave protocol behavior implicit in
  an undocumented helper. See `IMPLEMENTATION_PLAN.md` and `CONTRIBUTING.md`.
- Remote input is hostile. Follow the decoder and fuzzing requirements in
  `TESTING.md` section 14 and typed error guidance in `CONTRIBUTING.md`.
- Distributed transitions must account for duplicate, delayed, reordered, and
  stale messages, including failures and malicious peers. Include identity and
  epoch/sequence information in replicated state where appropriate; see
  `ARCHITECTURE.md` section 1.
- Do not let one authority unilaterally alter authoritative state, disqualify
  another authority, or rewrite finalized state. See `ARCHITECTURE.md`
  sections 7-10, 16-17, and 22-23.
- Keep HLLs approximate, merges deterministic, and the exact oracle independent.
  Preserve delegated-ingest buffering and acknowledgement behavior. See
  `ARCHITECTURE.md` sections 12-21 and `TESTING.md` sections 4 and 8-11.
- Search the workspace before adding a crate or dependency. Runtime dependencies
  require justification; follow the dependency and feature rules in
  `IMPLEMENTATION_PLAN.md` section 3.4 and `CONTRIBUTING.md`.
- Respect the workspace's `unsafe_code = "forbid"` policy. Use structured
  `tracing`; return typed errors for expected failures. See `CONTRIBUTING.md`.

## Implementation workflow

1. Identify the externally visible behavior and relevant invariant.
2. Locate the corresponding tests and an independent oracle where applicable.
3. Add or update focused tests, then make the smallest implementation change.
4. Run focused validation. Before committing, run `cargo xtask gate commit`.
5. Inspect `git diff --check` and `git diff`; review generated files, weakened
   tests, debug output, new panics/unwraps, broad dependency features, and
   unrelated edits.
6. Run `cargo xtask metrics` for hot-path, dependency, or binary changes, as
   required by `CONTRIBUTING.md`.

## Completion report

For meaningful code changes, report what changed, the behavior or invariant,
tests and commands actually run, performance/dependency impact, and unresolved
issues. Do not claim unrun tests or unmeasured performance improvements.

## Out-of-scope ideas

When implementation work reveals a concrete useful idea outside the task, check
root `IDEAS.md` for an equivalent and add a concise actionable note there.
Remove or update an idea when it is implemented or no longer relevant.
