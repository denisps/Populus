# Future implementation ideas

- Define authorization and key-continuity rules for mutable revision chains.
  Phase 3 validates immutable linkage and sequence progression but does not
  decide who may publish a successor or how producer keys can rotate. Two
  different revisions can both be valid successors of the same predecessor.
  A later rule should require a quorum-visible head, or a signature from a
  key authorized by the previous revision, before either fork is accepted.
- Add versioned signature algorithms beyond Ed25519 only after defining
  negotiation, compatibility, and migration behavior for existing content.
- Do not disqualify an authority until liveness and misbehavior evidence are
  specified. Equivocation proofs already exist. Absence is not evidence.
  Replacement for unavailability must stay separate from permanent
  disqualification. A future rule should accept only quorum-signed complaints
  that include the challenged request and its timeout, and one authority must
  not be able to remove another by itself.
- Specify concurrent membership replacement before relying on generation
  numbers alone. A replacement should name the departed member and the
  proposed joiner, carry generation = previous + 1, and become current only
  when a strict majority of the surviving previous members sign that same
  view. Conflicting proposals from one signer are equivocation. Differing
  known-neighborhoods must not be resolved by a local tie-break.
- Bind transport `PeerId` to scarce `NodeId` without collapsing them. Noise
  authenticates only the libp2p key, so a peer can currently claim any
  `NodeId`. A future session announcement should sign
  `populus/peer-binding/v1 || PeerId || NodeId` and record conflicts when one
  `PeerId` announces two `NodeId`s. Multiple `PeerId`s per `NodeId` need an
  explicit refresh rule. Do not derive `NodeId` from `PeerId`, and do not
  freeze this encoding until the scarcity-proof story is reviewed.
- Let routing replace a dead contact only after transport liveness says that
  contact's bound `PeerId` failed a defined number of probes. Full buckets
  currently reject new contacts forever, which is correct until that signal
  exists and wrong if closer live nodes can never enter. Do not evict merely
  because a bucket is full.
- Make daily finalization a signed cluster statement. Each authority now
  finalizes from its local clock, so one fast clock can reject a vote that
  another authority still accepts. A day should become cluster-final only
  after a strict majority publishes a finalize statement for that `UtcDay`
  and each signer is past the grace deadline. Until then, sketches stay
  provisional and mergeable.
- Count distinct first-accepted `ClientId`s in the direct-rate window, not
  raw deliveries. The current advisory trigger counts deliveries, so retries
  and duplicates can recommend delegation without a larger audience. Keep
  accepting the votes; change only the rate input, and cover it with the
  existing idempotent-sketch oracle.
- Keep HLL union, difference, and intersection estimates out of authority
  decisions. If an analytics helper is added, return the estimate with its
  error bound and do not offer it through the authority state API.
- Enforce metrics budgets only after a recorded baseline exists. `gate pr`
  still skips selected `cargo-mutants` and `iai-callgrind` checks because
  those harnesses are not installed. Add one instruction-count bench for HLL
  insert and routing lookup, then fail the gate on a hot-path increase above
  10 percent or a release binary increase above 5 percent unless the change
  explains it.
- Split partial neighborhoods from initialized clusters in the type system.
  `select_authorities` may return fewer than four members, while
  `MembershipView` already rejects that. A distinct partial type would stop
  callers from treating a short result as a cluster.
- Give identify its own agent version string. It currently reuses
  `/populus/transport/1`, which couples peer identification to the
  request-response protocol id and will make version negotiation harder.
- Measure IPv6 `/48` collapse against cloud and tunnel-broker Sybil supply
  in the Phase 16 scenarios before any v2 identity change. Over-merging is
  the accepted v1 cost; the open question is how often one account can buy
  multiple `/48`s.
- Define a versioned application envelope before any non-vote message shares
  the request-response stream. The node currently decodes every inbound
  request as a `DirectVote` and drops the raw bytes on failure. The first
  shared encoding should be a bounded version tag plus payload, reject
  unknown versions as typed errors, and leave successful events typed. Do
  not freeze those bytes until the first authority message exists; until
  then, do not invent a parallel envelope in the transport adapter.
