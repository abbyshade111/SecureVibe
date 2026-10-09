# Fail only on what is new: --baseline (9 October 2026)


Backlog 0191, part 1 (the end-of-day write-up of 8 October 2026); ADR-029, "Later, 9 October 2026: `--baseline`".

**The problem.** `--fail-on attention` is all or nothing: an app with known findings fails every run until each is
set aside through `sv review`, which is a person's work per finding. A team that wants CI to catch *new* problems
first had no way to say "these were here already".

**What changed.**

- `crates/sv-cli/src/baseline.rs`: `--baseline <folder>` is taken from the arguments, and the folder's `report.json`
  is read before anything else (so the folder may be the one the new report is written into). It keeps every
  fingerprint the older findings carried, earlier forms included, and the app's name. `holds` matches a finding by
  its fingerprint or any earlier form, in either report; an empty fingerprint matches nothing.
- `exit::Gaps::status_of`: the same status, with the findings counted named in the reason; with a baseline only the
  findings it does not hold are given, as "new finding(s), not in the baseline".
- `sv report` marks the report inside the step that builds it, before any file is written: `Report.baseline`
  (`BaselineNote`: the folder, and the fingerprints held), a line at the top of `security.md`, `compliance.md`, and
  `report.html` saying how many findings are new, a note on each held finding in `security.md` and `report.html`, and
  `baselineState` (`new` or `unchanged`) on each SARIF result, which GitHub's code scanning reads.
- `sv check` prints the same count and marks each held finding.
- Refusals, exit 3: no `report.json`, one without an app name or a list of findings, or one for another app's name.
- The help for both commands and the README say what it does.

**What it does not do.** It hides nothing and counts nothing differently; only exit 1 changes. It does not compare
anything but findings: a requirement credited in the baseline and not now is not its business. Two apps with one
name are not told apart, since `report.json` records only the name.

**Held by** `crates/sv-cli/tests/baseline.rs` (12, through the binary) and `crates/sv-cli/src/baseline/tests.rs` (4).
Broken on purpose nine ways, one at a time, each now turning two tests red or more: the report's exit ignoring the
baseline (2), `sv check`'s ignoring it (2), earlier fingerprint forms ignored (2), an empty fingerprint taken as
held (2), another app's baseline accepted (2), the note left out of `security.md` (2) or `report.html` (2), SARIF's
`baselineState` left out (2), and an unreadable baseline taken as an empty one (2). All but the first first went red
in one test each; each got a second before this was written.
