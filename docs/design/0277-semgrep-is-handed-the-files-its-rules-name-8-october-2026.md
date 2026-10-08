# Semgrep is handed the files its rules name (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, the rest of 1.2; BACKLOG, item 34; ADR-018, Later). Semgrep reads only
the files `sv` names to it, and `sv` named only code. Ten rules the packs load read only other files: nginx's
`*.conf` (its TLS versions, V12.1.1; an `alias` that lets a path walk out of its folder, V5.3.2), `web.config` (debug
mode, V13.4.2; cookie settings, V3.3.1), an `.npmrc` token, and an MCP configuration's key. They ran over nothing.

- **What is handed.** The code files, as before, and each other file of the app that a rule in the map names in its
  `paths.include` (`handed_files` in `crates/sv-check/src/adapters.rs`). The files `sv` itself leaves out
  (installed dependencies, links) are left out here too.
- **What counts as unread.** Measured with semgrep 1.180.0: Semgrep leaves out, saying nothing, a handed file no rule
  it loaded reads, and a `generic` rule with no `paths.include` reads every file. Before, any handed file missing from
  its list held back its whole clean run, which was right only while every file had a reader. Now a file counts only
  when a loaded rule in the map reads it: one its `paths.include` names, one its language's parser reads
  (`SEMGREP_EXTENSIONS`: Semgrep's JavaScript parser reads `.ts` and `.tsx` as well, and neither reads `.mts`), or any
  file for a rule of any language. Today the packs' 45 key-pattern rules read every file, so nothing changes in
  practice; the check stays right if a pack stops loading them.
- **Coverage.** `tools/coverage.py` no longer leaves out the rules that read only such files, so their requirements
  count through Semgrep, and `docs/COVERAGE.md` says that every rule a pack loads reads files `sv` hands it.

Tests: `crates/sv-check/tests/unread_files.rs` (`a_file_no_loaded_rule_reads_is_not_called_unread`,
`a_configuration_file_a_rule_names_is_handed_over_and_must_be_read`, `which_files_a_loaded_rule_reads`), with the
stand-in for Semgrep the file already had. Each guard was broken in turn and a test went red: every handed file
counted, the configuration files not handed, the JavaScript parser without TypeScript, and the loaded set ignored.
