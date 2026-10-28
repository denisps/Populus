# Future implementation ideas

- Define authorization and key-continuity rules for mutable revision chains.
  Phase 3 validates immutable linkage and sequence progression but does not
  decide who may publish a successor or how producer keys can rotate.
- Add versioned signature algorithms beyond Ed25519 only after defining
  negotiation, compatibility, and migration behavior for existing content.
