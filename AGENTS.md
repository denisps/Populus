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

Before broader workspace exploration, start `cargo xtask setup` in the
background. Continue reading the relevant documentation while it runs, and
confirm setup completed successfully before running tests, coverage, or gates.

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

## Workflow efficiency

Don't call 'cargo fmt --all' or other automatic formating tools too often. This tool is important before commiting your code, but if you are still making changes and fixing thing, it changes the code under you and it is not longer how you remember it, and it makes it hard for you to do prescise edits, and causing your edit toolcalls to fail.

## Human-Oriented Technical Documentation

Technical documentation must be optimized for human comprehension, not maximum information density or minimum token count. Preserve technical precision while minimizing the cognitive effort required to understand the system.

### Writing principles

- Prefer clear, natural sentences over compressed technical language.
- Limit the number of distinct concepts introduced in a single sentence or paragraph.
- Prefer active voice. Explicitly identify the actor, its action, the affected entity, and the conditions under which the action occurs.
- Avoid excessive nominalization, stacked technical modifiers, and unnecessarily abstract phrasing.
- Use established technical terminology consistently. Do not invent new terminology merely to shorten an explanation.
- Define unfamiliar terms before relying on them.
- Do not assume that the reader has the entire architecture in their working memory.
- Use additional sentences when they improve comprehension, but avoid redundant explanations and unnecessary filler.

### Explaining complex systems

When introducing a nontrivial mechanism, explain the following in a natural order:

1. **Purpose:** What problem does it solve?
2. **Context:** Under what circumstances does the problem arise?
3. **Mechanism:** Who does what, when, and how?
4. **Rationale:** Why does this approach solve or mitigate the problem?
5. **Limitations:** What assumptions, trade-offs, and failure conditions remain?

Use concrete examples, sequential descriptions, and diagrams where they materially improve understanding.

Introduce concepts incrementally. Explain normal operation before discussing exceptional conditions, security considerations, and optimizations.

### Precision and readability

Do not simplify documentation by removing important technical details, weakening requirements, or concealing unresolved problems.

Separate explanatory prose from normative protocol requirements where appropriate. Explanatory prose should establish an intuitive understanding of the mechanism, while normative requirements should specify its exact behavior.

Use mathematical notation, tables, pseudocode, and formal definitions when they communicate the intended meaning more clearly than prose.

### Documentation review

Before finalizing documentation, review newly written or substantially modified sections from the perspective of a technically competent human who is familiar with the project but has not participated in the current implementation.

Check whether the reader can understand:

- What the mechanism does.
- Why it exists.
- How its components interact.
- What assumptions it depends on.
- What happens when those assumptions fail.

Rewrite passages that require repeated reading or mentally unpacking several interconnected abstractions.

Apply these principles to architecture documents, implementation plans, design proposals, audit reports, decision records, and pull request descriptions.

## Completion report

For meaningful code changes, report what changed, the behavior or invariant,
tests and commands actually run, performance/dependency impact, and unresolved
issues. Do not claim unrun tests or unmeasured performance improvements.

## Out-of-scope ideas

When implementation work reveals a concrete useful idea outside the task, check
root `IDEAS.md` for an equivalent and add a concise actionable note there.
Remove or update an idea when it is implemented or no longer relevant.
