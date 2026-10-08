# Give the tests' scratch folders a name of their own per run

**Status:** done, as its markers read on 8 October 2026

Twelve test helpers make their scratch folder
at a fixed name in the shared temporary folder (`sv-clean-{name}` in `crates/sv-check/tests/clean_coverage.rs`, and
the same shape in `suppressed.rs`, `suite.rs`, `unread_files.rs`, `adapters.rs`, `codeql.rs`, `citations.rs`,
`aisvs.rs`, `sv-scan/tests/scan.rs` and a unit test in `sv-check/src/config.rs`). Two `cargo test --workspace`
runs at once on one computer share the folder, and one run's clean-up deletes the other's files mid-test: on
5 October 2026 two `clean_coverage` tests failed this way while another session's full run was going, and passed
with `TMPDIR` pointed at a private folder. Make each name unique per run and per call, and remove the folder
when the test ends. **Claimed on 5 October 2026 by session practical-banach-b1faa1**, at the owner's asking, in
branch `claude/scratch-names`. **Done the same day**: DESIGN, "The tests' scratch folders, one per run and per
call".
