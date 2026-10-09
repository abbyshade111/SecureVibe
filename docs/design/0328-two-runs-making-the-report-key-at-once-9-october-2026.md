# Two runs making the report key at once (9 October 2026)

Found while building the gap analysis's finding 22(b): on unchanged `main`, the MCP server's resource tests failed about
one run in six. The tests share one key folder per process, and two of them sealed a report at the same moment before
any report key existed. `Key::load_or_make_named` (`crates/sv-check/src/seal.rs`) saw no key, made one, and created the
file with a call that fails when the name is taken; the second run's call failed, its seal with it, and its report was
written but left unsealed, so the MCP server did not offer it as `sv`'s. A reader in between could also find the file
made and still empty, and refuse it as "does not hold a report key". The same can happen outside the tests: the MCP
server and a terminal command writing their first reports at once on a computer with no key yet.

**What changed.** A run that makes the key writes it whole to a file of its own beside the key's name, readable by its
owner only, then links that file into place with a call that fails when the name is taken, and removes its own file
either way. The key's name therefore only ever holds a whole key, and a run that loses the race reads and uses the key
that won. The key's format, its folder, and its file's permissions are unchanged, and so is every seal made with it.

**Held by** `crates/sv-check/tests/seal_key_race.rs`: sixteen threads making the key in a fresh folder at once, twenty
times over. Every run gets the key that was kept, exactly one made it, and nothing else is left in the folder; the
control makes it once and then reads it. Put back to the old code, the test failed three runs of three. With the fix,
`cargo test -p sv-cli --lib resource` passed ten runs of ten, against one failure in six before.
