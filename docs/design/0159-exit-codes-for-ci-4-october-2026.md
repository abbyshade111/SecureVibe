# Exit codes for CI (4 October 2026)

The deep review of `sv` at `eff3f17` found that `sv check` and `sv report` exited 0 whatever happened: with findings,
with files they could not read, and on an empty folder (BACKLOG, R6). It suggested `sv audit`'s convention: 1 for
something needing attention, 2 for something not assessed, 0 only otherwise. Measured before building it, that would
have failed every pipeline. On the five apps in `examples/` and on apps made with `sv init`, a plain static `sv check`
always had a low finding (no `security.txt`) and two to four checks that need something the app lacks (a Dockerfile or
Procfile, a git repository, a package manifest, a `.gitignore` of its own), and `sv report` always had 121 to 230
requirements "not verified by anything". The owner decided instead (ADR-029):

- **0: the run finished.** Findings alone do not change it.
- **2: a check could not run**, always. The list is exact, in `exit::Gaps::of_files` and, for the report,
  `report_gaps`:
  - no file of the app was read as text, apart from `securevibe.toml` and `security-notes.md`;
  - a file or folder that could not be opened or read, or was too large to read even in pieces;
  - a file in a language the code rules read that was not opened;
  - a file the parser could not make sense of;
  - a language present that nothing here reads (today Objective-C, and a web page whose script could not be taken out);
  - a code rule whose query would not compile;
  - `sv report --run` when the app could not be started: every check of the running app was asked for, and none ran.

  Not on it: a file read and found not to be text, such as an image, since every web app has one and the credential
  rules read text; the checks that need something the app does not have; requirements nothing verified; questions
  nobody answered. Those are what a static run is, and the report says so; a status that is always 2 says nothing.
- **1: something needs attention**, only when asked: `--fail-on attention` for any finding of low severity or worse,
  `--fail-on attention:SEVERITY` for that severity or worse. Accepted risks still count, as they do in the report.
- **`--fail-on not-assessed`** makes 2 wider: a symbolic link not followed or an entry that is not an ordinary file
  (left out by default because `CLAUDE.md` pointing at `AGENTS.md` is common and harmless), and in `sv report` a
  `--tools` tool that did not run or ran only in part, and an `--advisories` comparison that did not cover the whole app
  (`sv audit`'s own 2). Never "not verified by anything". `--fail-on any` is both; several words go with commas.
  1 outranks 2.
- **3: `sv` itself failed**, from every command: `main` now ends any error with 3 (no `securevibe.toml`, a manifest it
  cannot read, a folder that is not there, an advisory database it cannot open, an option or `--fail-on` word it does
  not know). Before, an error exited 1, which in `sv audit` also meant a known vulnerability, so a pipeline could not
  tell "`sv` broke" from "your app has a problem". That moves `sv audit`'s errors from 1 to 3; its 0, 1, and 2 are
  unchanged, and now come from the same constants (`exit.rs`). Ctrl-C still exits 130.

A run that exits other than 0 ends with a line saying which status and why, after everything else it printed. Each
command's `--help` says what its statuses mean, and `sv --help` lists the four. The MCP tools have no exit status:
`securevibe_check` and `securevibe_write_report` return text, and `isError` only when a call is refused, so
`--fail-on` is not offered there. `sv bundle` keeps 0 when it finished; it packages a report, it is not a gate.

Measured after building it, on the same apps: every example exits 0 by default, an app holding only `securevibe.toml`
exits 2 ("no file of the app was read"), and with `--fail-on attention:medium` the two apps with a medium finding exit
1. On five real apps on this computer with a manifest, four exit 0 and one exits 2, for an HTML page whose script could
not be taken out to be read; one more, without a manifest, exits 2 from `sv check` for three TypeScript files the parser
could not make sense of (H25's cost, now visible).

**Tested** through the real binary in `crates/sv-cli/tests/exit_codes.rs`, each status reached on purpose: `sv check`
0 with high findings and no `--fail-on`; 1 with `--fail-on attention` for a low finding and not with
`attention:high`, then 1 with `attention:high` once a high finding is there; 2 for an Objective-C file, a Python file
that does not parse, a folder holding only `securevibe.toml`, an empty folder, and a file with no read permission
(the test says so when it runs as a user who can read anything), with an image beside the code as the control that
stays 0; a symbolic link 0 by default and 2 with `--fail-on not-assessed`; 3 for a missing folder, an unknown
`--fail-on` word, and an unknown option. `sv report`: 0, 1 with `attention:high` and 0 with `attention:critical`, 2
for `--run` with nothing to start and for an Objective-C file, 3 with no `securevibe.toml`, a broken one, and no
folder. `sv audit`: 0, 1, and 2 as before, and 3 for a broken manifest, a missing folder, and an advisory folder that
is not there, each of which exited 1 before. No existing test asserted 1 for an audit error; the tests that asserted
`sv report` succeeded where a check could not run on purpose now expect 2 (`examined.rs`, `one_walk.rs`,
`run_status.rs` with `--run`, and the control in `options.rs`, whose folder holds only `securevibe.toml`), and
`options.rs` names `--fail-on` among the options.

Seven guards broken in turn, each caught: no default 2 at all (seven tests red, among them `run_status.rs`'s two),
errors exiting 1 again (three, one per command), `--fail-on attention` ignored (four), an image counted as unread
(one, the image control written for it), `--run` that could not start counted only as partial (three), `--fail-on
not-assessed` ignored (two), and a folder with nothing read not counted (two).
