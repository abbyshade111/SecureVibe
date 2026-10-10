# A crash in sv ends as sv's failure, and an unreadable hints file is a gap (9 October 2026)

Backlog 226 (the observability review), part 1, items 5 and 6, built by session stackvet-e9.

**A crash (item 5).** `main` turned an `Err` into exit 3, but nothing caught a panic: it ended with Rust's own
"thread 'main' panicked" line, symbols stripped in a release build, and 101, a code no document names, so a pipeline
could not tell it from anything else. Now `main` runs the command under `catch_unwind` and, on a panic, prints that
`sv` itself failed, a fault in `sv` and not in the app, what and where, and that nothing was assessed, and exits 3.
The release profile still unwinds, and the message comes after the unwinding, so whatever cleans up on the way out
(the run's containers, the report folder's lock) still does. A hook (`crash.rs`) notes the panic on the main thread
only and stays silent there; on any other thread it keeps Rust's own line, because `sv mcp` survives a check thread
that panics and must not say `sv` failed. Catching a panic per check is part 3, item F, and the owner's.

The test needs a panic to catch, and nothing in `sv` panics on purpose, so a debug build panics at the start of `run`
when `SV_PANIC_FOR_TEST` is set; the switch is behind `cfg(debug_assertions)` and no released `sv` has it.

**An unreadable hints file (item 6).** When `level-hints.json` did not load, the report went on without the level 1
hints and said so only on stderr, which nobody reading the report through MCP sees; the report then read as though
the code showed nothing that a level 1 app should be asked about. It is now a gap, "whether the code agrees with the
answers that set the level", naming the file and saying to reinstall `sv` or point `SV_DATA_DIR` at a complete copy.
Looking for others of the same shape in the report's path found none: `reach.json`, `human-checks.json`, and the rest
fail the run with an error; the SARIF catalog passes over an unreadable rules file on purpose and describes those rules
from their findings; `masked_in` shows nothing rather than an unmasked line without the secret rules.

**Tests.** `crates/sv-cli/tests/crash.rs` (exit 3, the words, the place, and no Rust line) and
`crates/sv-cli/tests/level_hints_unreadable.rs` (a copy of the data with `level-hints.json` broken: the gap is in
`report.json`). With the hook and the catch taken out, and with the gap dropped, each fails.
