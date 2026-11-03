# Phase 6 libp2p audit

Reviewed again on 2026-11-02. The original sub-agent report is preserved below.

## Resolution

| Finding | Status | Why |
|---|---|---|
| Node did not start libp2p | Fixed | `Node` owns `populus_network::Transport`. CLI `listen <multiaddr>` drives it. No Kademlia feature or `populus-sim` dependency. |
| No protocol message over TCP/QUIC | Fixed for direct votes | Loopback TCP and QUIC tests send canonical `DirectVote` bytes and decode them. Malformed bytes become `DirectIngestError`. |
| Identify and ping not observed | Fixed | `identify_and_ping_events_are_observed_on_loopback` waits until both event kinds are forwarded. |
| PeerId/NodeId binding | Not implemented | Noise authenticates only `PeerId`. Binding bytes are not frozen before the scarcity-proof review. Recorded in `IDEAS.md`. |
| Authority/routing envelopes | Not implemented | `populus-protocol` says envelopes are not defined and must not be invented. The node therefore decodes every inbound request as a direct vote. Recorded in `IDEAS.md`. |
| Separate caller-cancel API | Not added | The plan's cancellation test is connection cancellation. `populus-network` covers pending and queued failure on local and remote disconnect. |
| Tests not under `tests/` | Not moved | Loopback tests are Level-5 socket tests inside the crates. Directory layout is not the requirement. |
| Inbound 1 MiB bound | Unchanged | Transport still rejects above the frame limit before allocation. Downstream decoders must keep their own bounds; direct-vote decoding already does. |


## Original report

## 1. Checklist

| Requirement | Status | Evidence |
|---|---|---|
| libp2p dependency with TCP, QUIC, Noise, Yamux, DNS, identify, ping, request-response; no Kademlia | **PASS** | `Cargo.toml:17-27` |
| Real `Swarm` and transport construction | **PASS** | `crates/populus-network/src/lib.rs:284-305`, `538-560` |
| TCP + Noise + Yamux | **PASS** | `crates/populus-network/src/lib.rs:541-546` |
| QUIC | **PASS** | `crates/populus-network/src/lib.rs:547` |
| DNS | **PASS** | `crates/populus-network/src/lib.rs:548-550` |
| Identify and ping wired | **PASS** | `crates/populus-network/src/lib.rs:147-181`, `508-513` |
| `/populus/transport/1` request-response protocol | **PASS** | `crates/populus-network/src/lib.rs:22`, `188-199` |
| Swarm-independent adapter API | **PASS/PARTIAL** | Private Swarm and public façade: `crates/populus-network/src/lib.rs:280-285`; however the adapter itself is tightly coupled to Swarm internally. |
| 4-byte big-endian framing | **PASS** | `crates/populus-network/src/lib.rs:40-70` |
| Reject oversized frames before allocation | **PASS** | `crates/populus-network/src/lib.rs:47-52` |
| Reject oversized requests/responses before queue/send | **PASS** | `crates/populus-network/src/lib.rs:383-386`, `417-430` |
| 64 active + 64 queued/failure capacity | **PASS/PARTIAL** | Capacity accounting: `crates/populus-network/src/lib.rs:387-395`; dispatch: `528-536`. |
| Explicit queue-full result | **PASS** | `crates/populus-network/src/lib.rs:211-219`, `393-395` |
| 30-second timeout | **PASS** | `crates/populus-network/src/lib.rs:193-195` |
| PeerId distinct from Populus NodeId | **PARTIAL** | Transport uses `PeerId`: `crates/populus-network/src/lib.rs:242-269`; no integration with `NodeId` or routing exists. |
| Custom routing, not libp2p Kademlia | **PASS** | No `kad` feature/dependency; custom routing exists separately. |
| Node starts libp2p | **FAIL** | `crates/populus-node/src/main.rs:1-3` is an empty `main`; node has no network dependency: `crates/populus-node/Cargo.toml:1-11`. |
| Protocol/cluster messages exchanged over transport | **FAIL** | No `populus-network` use from node, routing, or cluster; searches show only isolated transport tests. |
| Local TCP test | **PASS** | `crates/populus-network/src/lib.rs:796-798` |
| Local QUIC test | **PASS** | `crates/populus-network/src/lib.rs:840-843` |
| Framing and size tests | **PASS** | `crates/populus-network/src/lib.rs:609-682` |
| Cancellation/disconnect tests | **PASS/PARTIAL** | Disconnect tests exist: `crates/populus-network/src/lib.rs:989-1060`, `1071-1247`; no general caller/task cancellation test. |
| Backpressure test | **PASS** | `crates/populus-network/src/lib.rs:845-916` |
| Tests are Level-5 localhost tests | **PARTIAL** | Tests use real loopback sockets, but are embedded unit tests rather than organized under `tests/`; `TESTING.md:99-103`, `tests/README.md:12`. |
| Deterministic/no arbitrary sleeps | **PASS** | Tests use bounded `timeout`, not `sleep`; e.g. `crates/populus-network/src/lib.rs:745-789`. |

## 2. Functional integration verdict

**The transport itself is substantially implemented and functional, not merely stubbed.** It constructs real libp2p TCP/QUIC Swarms, negotiates Noise/Yamux, supports DNS, identify, ping, request-response framing, limits, timeout, disconnect handling, and loopback tests.

However, **Phase 6 is not functionally integrated into Populus**. `populus-node` does not start a transport, and no routing or cluster protocol uses the adapter. It is currently a standalone transport library with good tests, not a working Populus node network.

## 3. Missing behavior/tests

- Start and drive `populus_network::Transport` from `populus-node`.
- Connect transport `PeerId` to separately maintained scarce-network `NodeId` contacts.
- Define and implement application message encoding/dispatch for routing and cluster protocols.
- Add end-to-end node-level tests proving a Populus protocol message crosses TCP and QUIC.
- Add explicit malformed request/response integration tests through the Swarm codec, not only direct framing tests.
- Add caller/task cancellation tests; current “cancellation” is specifically peer disconnect.
- Add tests proving identify and ping events are actually observed and consumed.
- Move or duplicate localhost tests into the declared Level-5 test structure if that organization is required.

## 4. Security/design issues

- Frame allocation is bounded correctly: `crates/populus-network/src/lib.rs:47-58`.
- Outbound payloads are checked before queueing: `crates/populus-network/src/lib.rs:383-386`.
- Responses are checked before sending: `crates/populus-network/src/lib.rs:417-430`.
- Queue accounting includes active, queued, and failed events: `crates/populus-network/src/lib.rs:387-395`.
- No evident PeerId/NodeId confusion in the transport, but **there is no mapping or authenticated binding at all** between them.
- Inbound requests up to 1 MiB are accepted and surfaced to callers; downstream protocol handlers must retain the bound and avoid unbounded secondary decoding/allocation.

## 5. IDEAS.md design notes

Add a protocol integration design covering:

1. A transport-to-routing identity binding: `PeerId` as connection identity, scarce-derived `NodeId` as signed/application identity.
2. Application envelope/versioning over `/populus/transport/1`.
3. Routing and cluster message dispatch through the adapter without exposing `Swarm`.
4. Handling multiple `PeerId`s or addresses for one `NodeId`.
5. Authentication/authorization of cluster messages independently of Noise transport identity.
6. Explicit behavior when a transport peer claims an already-known or conflicting `NodeId`.