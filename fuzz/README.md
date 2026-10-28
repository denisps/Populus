# Fuzzing

The `id_parsers` target fuzzes Phase 1 identifier, CID, epoch, and
`NetworkIdentity` byte and hex parsers. The `content_decoder` target exercises
the bounded Phase 3 body, signed-object, and mutable-revision decoders.
The `fuzz/corpus/content_decoder` seeds are lowercase hexadecimal so they remain
reviewable in source control; the target exercises both raw and decoded input.

Add target harnesses under `fuzz_targets/` as additional untrusted decoders are
implemented.
