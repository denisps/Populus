# Populus
Populus is a Rust implementation of a decentralized social/content network built on libp2p transports with a custom XOR-distance DHT, IP-derived scarce network identities, content-addressed objects, producer identities, approximate distributed popularity counting, recursive tag/association aggregation, and dynamically delegated ingest.

Before submitting changes, run the repository quality gate with `cargo xtask gate commit`.

License: MIT (see [LICENSE](LICENSE)).

## Running a node

`populus-node` starts without a manually supplied public identity and persists
its libp2p PeerId at `.populus/peer.key` by default:

```bash
cargo run -p populus-node -- run \
  --listen /ip4/0.0.0.0/tcp/4001 \
  --bootstrap /ip4/203.0.113.8/tcp/4001/p2p/<peer-id>
```

Use `--identity-key PATH`, repeat `--listen` or `--bootstrap`, and configure
`--max-node-ids N` (default 4) as needed. A simple key/value config file is
also accepted with `--config FILE`; supported keys are `listen`, `bootstrap`,
`identity_key`, `max_node_ids`, and `genesis_identity` (repeat `listen` and
`bootstrap` for multiple values). The explicit `--genesis-identity PUBLIC-IP`
option bypasses observation and verification and is for isolated test
networks only.

The current runtime supports transport bootstrap, bounded contact discovery,
nonce-correlated address observations, and local identity lifecycle hooks.
It does not yet implement quorum-backed NodeID ownership arbitration or the
authority/delegated-ingest network protocol. In particular, receiving a direct
vote without an active authority is refused, not reported as counted.
