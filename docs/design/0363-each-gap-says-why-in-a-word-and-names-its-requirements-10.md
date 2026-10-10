# Each gap says why in a word, and names its requirements (10 October 2026)

Backlog 226 (the observability review), part 2, item 20's remainder, built by session securevibe-e2; the record is
ADR-066, "Later, 10 October 2026: each gap says why in a word, and names its requirements".

**The problem.** A gap (`sv_report::Gap { what, why }`) said in sentences what `sv` did not examine. A program reading
`report.json` could tell neither why (an option not given, a tool missing, a file that would not parse, something
only a person can check) nor which requirements a gap spoke of, and the trial scorer split the text on commas to
guess.

**What was built.**

- `Gap` gains `reason: GapReason` and `requirements: Vec<String>` (left out of the JSON when empty). The reasons are
  `not-asked`, `not-installed`, `could-not-read`, `no-reader`, `stopped`, `person-only`, `planned`, `partial`,
  `left-out`, and `outdated`, each documented on the enum. There is no default: each of the 69 places that builds a
  gap says which, and a new one does not build until it does.
- `requirements` holds only the ids a gap already names, through `requirement_ids`, which splits the same list the
  sentence prints. A gap that names none carries none.
- An outside tool that did not run now says why (`sv_check::adapters::NotRunCause`: not installed, stopped, could not
  read its report, left out by `sv`'s own rule, or nothing to read), so the gap for it is not one word for all.
- Why the app could not be started reaches its gap by the kind of failure (`run_gap_reason`).
- The MCP `stackvet_check` tool's `notExamined` declares both fields.
- `tools/prompt_trial.py` reads `requirements`, and reads a report from before this by its text as it did.

**Choices worth knowing.**

- The claim proposed eight words. Three gaps fitted none, so two were added:
  - `outdated`: the manifest read under its old name, or one that changed while the run read it.
  - `left-out`: installed or built code, links not followed, and folders the owner names as not the app, all set
    aside on purpose.
- An outside tool refused because it would run from inside the app is `left-out`, since `sv`'s own rule refused it.

**Tests.**

- `crates/sv-cli/tests/report_gap_reasons.rs`: the real `sv report --tools`, with nothing on the PATH, on
  `examples/flask-booking`. Every gap carries one of the ten words; the running app's is `not-asked` and Bandit's is
  `not-installed`.
- `crates/sv-cli/src/requirement_ids_tests.rs`: ids split and trimmed, empties dropped.
- `crates/sv-check/src/adapters/not_run_cause_tests.rs`, with stand-in tools: one missing, one that fails, and one
  that writes no report, each with its cause.
- The MCP schema tests, which failed until the schema declared the fields.

**Broken on purpose, each put back:**

- The running app's word changed (1 red).
- Empty ids kept (1 red).
- The three tool causes swapped (3 red).
