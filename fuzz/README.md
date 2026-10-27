# Fuzzing

The `id_parsers` target fuzzes Phase 1 identifier, CID, epoch, and
`NetworkIdentity` byte and hex parsers. Its corpus includes valid examples so
mutations also exercise parsing beyond the initial format checks.

Add target harnesses under `fuzz_targets/` as additional untrusted decoders are
implemented.
