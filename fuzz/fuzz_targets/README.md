# Fuzz targets

`id_parsers.rs` exercises the Phase 1 identifier and canonical encoding parsers.
`content_decoder.rs` exercises all Phase 3 content decoders with arbitrary bytes.
Its checked-in corpus includes valid body, signed-object, and revision vectors.
Add focused harnesses for later untrusted decoder families as those phases land.
