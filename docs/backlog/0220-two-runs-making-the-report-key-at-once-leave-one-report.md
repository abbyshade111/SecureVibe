# Two runs making the report key at once leave one report unsealed

**Status:** claimed by securevibe-e2, 9 October 2026

Found 9 October 2026 by session securevibe-e2, while building the gap analysis's finding 22(b). On unchanged `main`,
`cargo test -p sv-cli --lib resource` failed about one run in six: two tests sealed a report at the same moment before
any report key existed, and `Key::load_or_make_named` (`crates/sv-check/src/seal.rs`) made the key file with a call that
fails when the name is taken. The second run's seal failed, its report was left unsealed, and the MCP server did not
offer it as `sv`'s; a reader in between could also find the key file empty. The same can happen outside the tests,
when the MCP server and a terminal command write their first reports at once on a computer with no key yet. Very
likely the unexplained `test` failures on #1192 and #1195 the same morning, whose logs this session could not read.

The fix: write the key whole to a file of its own, link it into place with a call that fails when the name is taken,
and on losing, read and use the key that won. The key's format, folder, and permissions are unchanged, so no record
is proposed (ADR-026, ADR-034, and ADR-043 govern the file; each gets an "unchanged" line).
