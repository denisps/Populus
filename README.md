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
`--max-node-ids N` (default 4) as needed. `--network-id HEX` selects the one
network this process joins; by default it uses the public Populus network ID,
SHA-256 of `populus/public-network/v1`. A key/value config file is also
accepted with `--config FILE`; supported keys are `listen`, `bootstrap`,
`identity_key`, `max_node_ids`, and `network_id` (repeat `listen` and
`bootstrap` for multiple values). Network IDs do not authorize membership.
Nodes may start provisionally without bootstrap peers or genesis configuration.

The runtime supports transport bootstrap, bounded contact discovery,
nonce-correlated address observations, signed candidate registration
messages, and adapters to the existing direct and delegated ingest state
machines. Authority membership is still caller-installed, and permissionless
ownership conflict reconciliation, automatic lease renewal, and complete
restart recovery are not implemented. A vote is reported as accepted only
after an installed authority state machine accepts it; otherwise the process
returns a typed refusal.
