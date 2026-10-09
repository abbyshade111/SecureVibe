# The readers of untrusted input, fuzzed weekly (9 October 2026)


Backlog 0191, part 3 (the end-of-day write-up of 8 October 2026); ADR-077. The owner's decision of 9 October 2026:
"go ahead with the fuzzing please".

**The problem.** `sv` reads what it does not control: lines on the MCP server's input, an app's `stackvet.toml`, the
lockfiles and test reports an app ships, and the reports outside tools write after reading the app. A file planted in
an app that makes `sv` panic stops the check, and the person gets no report at all. The tests feed each reader the
inputs someone thought of.

**What changed.**

- `fuzz/`, a crate of its own outside the workspace (`exclude = ["fuzz"]`), built only with nightly Rust and
  `cargo-fuzz`, with four targets: `mcp_line` (the server's own loop, `sv_cli::mcp::serve`, now public; an empty
  folder served, so a tool call is refused rather than checking anything), `manifest`, `lockfiles` (every lockfile
  format through `sv_check::sbom::read_as_every_lockfile`, a hidden public door, and the app's test report as JUnit,
  TAP, or JSON), and `tool_reports` (every adapter's SARIF reader). Each asserts only that the reader returns.
- `fuzz/seed.sh` copies starting inputs from the repository's examples and fixtures into `fuzz/corpus/`, which is
  not committed, nor are the build or the crashes kept (`.gitignore`).
- `.github/workflows/fuzz.yml`: Mondays at 08:00 UTC and by hand, each target for five minutes, a crash's input kept
  as an artifact for 30 days. Not a required check, and nothing in the build, the tests, or the image changes.

**Tried here.** One minute a target: `manifest` 148,801 runs, `lockfiles` 455,123, `tool_reports` 23,416,
`mcp_line` 13,892, and no crash. A panic planted in `Manifest::parse` on any text holding one chosen word was found,
and its input written out, within the two minutes given; the planted line was then taken out.

**A crash, when one comes,** is fixed test first: its input added to the ordinary tests, seen failing on stable Rust,
then the reader fixed, so the fix is held where every pull request runs.
