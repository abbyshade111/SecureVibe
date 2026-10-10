# Run semgrep with usage reporting and its version check off, and accept Opengrep when semgrep is not installed. Done on 3 October 2026

**Status:** done, 10 October 2026

(DESIGN, "Semgrep without usage reporting, and Opengrep in its place"). Each of eleven
guards was broken in turn and caught: eight by two tests or more, and three (the loader's two refusals and the
report's `stand_in` field) by the one test written for each. Not tried against a real Opengrep through `sv` since
the change; it was through a stand-in on 29 September.
The owner's decision of 3 October 2026, from the evaluation above. **Claimed on 3 October 2026 by session
securevibe-e10**, in branch `claude/semgrep-quiet-opengrep-fallback`. The semgrep adapter adds `--metrics=off` and
sets `SEMGREP_ENABLE_VERSION_CHECK=0`; when `semgrep` is not found, `opengrep` is run in its place, without
`--metrics` (Opengrep refuses the option), and the report says which of the two ran.

**Checked against origin/main, 10 October 2026:** built: `adapters.rs` sets `SEMGREP_ENABLE_VERSION_CHECK=0` and leaves out `--metrics=off` for Opengrep; tests in `tests/adapters.rs` and `tests/stand_in.rs`.
