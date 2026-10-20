# Test layers

The layer directories reserve the Phase 0 structure; behavior-specific tests belong beside
their implementation and must be added with the relevant protocol phase.

- `unit`: deterministic local behavior.
- `property`: generated invariant checks with deterministic seeds.
- `reference`: comparisons against simpler independent oracles.
- `simulation`: virtual-time, seeded distributed scenarios; never use real sleeps.
- `network`: localhost transport and framing checks.
- `adversarial`: scripted faults and malicious inputs.
- `fuzz`: cargo-fuzz harnesses for untrusted parsers.
- `bench`: reproducible performance harnesses.

No protocol behavior or test scenarios exist yet.
