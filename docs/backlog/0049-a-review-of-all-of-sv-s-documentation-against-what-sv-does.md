# A review of all of `sv`'s documentation, against what `sv` does now

**Status:** claimed by securevibe-e10, as its markers read on 8 October 2026

Asked for by the owner on 5 October 2026,
after many changes in a short time. Every document a person or an AI tool reads, read against the code and the
merged changes since it was last revised: `README.md`, `docs/GETTING-STARTED.md` (the owner's own guide),
`docs/PROMPTS.md`, `docs/COVERAGE.md`, `docs/PARTIAL-CHECKS.md`, `docs/REQUIREMENTS.md`, `docs/THREAT-MODELING.md`,
`docs/SEMGREP-FALSE-ALARMS.md`, `sv --help` and each command's help, the specification `sv init` prints
(`crates/sv-manifest/src/spec.rs`), the MCP server's instructions and tool descriptions (`crates/sv-cli/src/mcp.rs`),
and the examples' comments. Known gaps when it was asked for: `docs/GETTING-STARTED.md` names none of `sv plan`,
`sv brief`, or `sv preflight`, and `README.md` does not name `sv preflight`. For each document: what it says that is
no longer true, what `sv` does that it leaves out, and every number it gives (of tools, commands, checks,
requirements) checked against the code. Plain language throughout, for a reader who is not a programmer. Records
(`docs/adr/`) and DESIGN are histories and are not rewritten; a record that no longer matches gets a dated "Later"
entry instead.
**Claimed on 6 October 2026 by session securevibe-e10**, at the owner's asking to take the next unclaimed item, in
branch `claude/docs-review`. CLAUDE.md's `SV_DATA_DIR` line is left to session securevibe-e2, which claimed it.
**Part 1 done the same day:** every document read against `main` at `e9179b22` by five read-only helper agents,
one per group of documents, and each correction written here checked against the code by the session itself.
- `docs/GETTING-STARTED.md`: thirteen tools, not six; an owner's answer counts only once recorded with `sv review`,
  now explained, with how to give the container the key folder; the design-time steps (`sv plan`, `sv brief`,
  `sv preflight`); where the report is; exit code 3 for `sv check`; where a moved program looks for its data.
- `README.md`: the signed-out questions are more than four; seven wrong passwords, not six (the cap of 26 said);
  `--fail-on attention` leaves out findings marked only for information; exit 3 for `sv check` and `sv audit`;
  the report's five files and folder; the outside tools `--tools` runs; the coding rules are 18, drawn from 27 of
  68 requirements; `sv preflight` and `sv prompts` named; SBD-MT-06 and SBD-AC-06 in `design-decisions.md`; an
  answer recorded with `sv review`.
- `docs/PROMPTS.md`: three faults in `sv` the trials found are marked fixed; 3 of 14 design-time prompts shown to
  work; V13.3.1's wording.
- `docs/THREAT-MODELING.md`: built, not proposed; 115 citations of 101 requirements; a "Since" section (v1
  archived, MT-03 not built, `sv plan`'s threats, an answer never settles a threat, ATLAS).
- `docs/SEMGREP-FALSE-ALARMS.md`: the licence's non-commercial condition; option C is not what `sv` runs (440 of
  the 868 findings, and 164 of the 555 false alarms, from rules it runs); `SKIP_DIRS` since H6; the CSV's name;
  which recommendations are built.
- `docs/PARTIAL-CHECKS.md`: 57 of the 382 have gained a check; `signed_in.rs` is a folder.
- `examples/partly-passing`: `/tmp` is writable too.
- `docs/REQUIREMENTS.md` and `docs/COVERAGE.md` are generated and current (`tools/coverage.py --check` passes);
  what is wrong in them is the generator's, below.
**Part 2, still claimed:** the text inside the code: `sv --help` and each command's help (`crates/sv-cli/src/main.rs`),
the specification `sv init` prints (`crates/sv-manifest/src/spec.rs`), the MCP server's instructions and tool
descriptions (`crates/sv-cli/src/mcp.rs`), and `tools/coverage.py`'s prose.
**Part 2 done the same day:** the help (`sv run`, `sv check`, `sv audit`, `sv report`, `sv bundle`, `sv review`,
`sv sbom`, `sv mcp`, `--version`, and the exit codes, which are only check's, report's, and audit's); the spec (the
starter's `[stack.run.users]` commented out, `admin-actions` needing `admin`, data names spelled as listed, `tls`,
the unanswered claim state, `sv brief` for a feature's prompts, a test report's credit, and "Tests worth writing
first"); the MCP server's instructions and five tool descriptions; and `tools/coverage.py`'s prose and its `\u{…}`
escapes. With that, the review is done.
