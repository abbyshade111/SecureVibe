# Errors that say what to do: shipped data that does not parse, and no container backend (10 October 2026)

Backlog 226 (the observability review), part 2, item 16, built by session stackvet-e9.

**A data file `sv` ships that does not parse.** Fourteen places read one of the data files that come with `sv`
(`secret-rules.json`, `prompts.json`, `adapters.json`, the applicability rules and their overlay, and the rest), and
each said only `parsing <path>` above the parser's own words. The person cannot fix that file, and it most likely
belongs to another version of `sv`. Each now says so through `sv_frameworks::data::not_understood`: the file is one
`sv` ships, it most likely belongs to another version, reinstall `sv` or point `SV_DATA_DIR` at the `data` folder
that came with this one, and nothing about the app was checked. The parser's words follow, as before. Two places
that parse the person's own files keep the plain wording: `stackvet.toml` (which already explains a misplaced
field) and a report folder's `report.json` in `sv explain`.

**No container backend, or one that refused.** `NoBackend` and `BackendFailed` said what failed and that the running
app's checks are not assessed, but not what to do. Each now ends with the next step: get Docker running with Linux
containers (Docker Desktop, or `colima start` on a Mac) or start it again if it stopped, run this again, and
`sv doctor` shows what it finds.

Not built here: the MCP server's "check stopped before it finished", which waits for open pull request #1325 since
that rewrites `crates/sv-cli/src/mcp/`.

**Tests.** `crates/sv-cli/tests/data_not_understood.rs` runs `sv report` with a copy of the data folder whose
`secret-rules.json` is cut short, and reads the four parts of the message on stderr; with the old wording it fails.
`a_backend_that_is_missing_or_refuses_says_what_to_do` in `crates/sv-run/src/lib.rs` reads the next step in both;
without it, it fails.
