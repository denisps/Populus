# Test layers

The layer directories reserve the test structure; behavior-specific tests belong beside
their implementation and must be added with the relevant protocol phase. Deterministic
distributed scenarios live in `sim/populus-sim` so they can exercise several workspace
crates without moving protocol tests out of their owning crates.

- `unit`: deterministic local behavior.
- `property`: generated invariant checks with deterministic seeds.
- `reference`: comparisons against simpler independent oracles.
- `simulation`: virtual-time, seeded distributed scenarios; never use real sleeps.
- `network`: localhost transport and framing checks.
- `adversarial`: scripted faults and malicious inputs.
- `fuzz`: cargo-fuzz harnesses for untrusted parsers.
- `bench`: reproducible performance harnesses.

The `populus-sim` crate currently covers seeded routing/content/sketch workloads,
routing lifecycle scenarios at 100, 1K, and 10K nodes (joins, leaves, churn,
partitions, and recovery), virtual latency and clock skew, node availability
transitions, and scripted vote message faults. Authority-cluster and ingest-buffer
scenarios will be added by their owning protocol phases when those pure state
machines are implemented.
