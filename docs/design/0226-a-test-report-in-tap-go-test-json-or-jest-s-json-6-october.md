# A test report in TAP, `go test -json`, or jest's JSON (6 October 2026)

`sv` credits a requirement from the app's own tests only when a test naming it passed. When the whole suite fails,
the runner's own report says which tests still passed, and until now only JUnit XML was read. TAP and the JSON that
`go test -json`, jest, and Vitest write were not, so an app tested with `node --test`, `bats`, plain `go test`, or jest
without its JUnit add-on got nothing from a suite with one failing test. The backlog named this when the JUnit reader
was built.

`test_report::parse` reads all four. It tells the form by how the file opens, never by its name: `<` is JUnit XML, a
`TAP version` line or a TAP plan or result line is TAP, a JSON object holding `testResults` is jest's or Vitest's, and
JSON objects one to a line holding `Action` are Go's. Each reader gives back the same cases JUnit does, so the matching
and crediting in `suite.rs` are unchanged. `sv report` now reads a failed suite's report through
`suite::reported_cases`, which a test reaches without Docker.

Each reader keeps the JUnit reader's rule: it fails closed. Reading a failed test as passed credits a requirement
nothing established, so anything a reader was not written for refuses the whole report, and crediting falls back to
the exit code, which credits nothing from a failed suite.

- **TAP** (versions 13 and 14). `ok` and `not ok`, a `# SKIP` or `# TODO` directive (neither is a pass), subtests four
  spaces in, YAML blocks skipped whole, and `\#` in a name. Refused: a top level with no plan, a plan whose count
  differs from the results, a subtest level short of its plan, a `Bail out!`, another version, and any line that is
  none of these.
- **`go test -json`.** A test's last word decides: `pass` is a pass; `fail` and `skip` are not. A test that started and
  never got a last word, after a panic or a time-out, is a case that did not pass, so a same-named case cannot be
  credited past it. Refused: a line that is not JSON, and an action Go does not write.
- **jest and Vitest JSON.** One case per entry in `assertionResults`, named by its `fullName`. Only `passed` is a pass.
  The six other statuses jest writes are not passes; any other status refuses the report. A file that could not run
  has no results, so nothing in it is credited.

The specification `sv init` prints and the README name the forms and how to ask each runner for one.

Broken on purpose fourteen ways, each caught:
- a SKIP or TODO read as a pass (2 tests);
- `not ok` read as `ok` (3);
- the plan's count not checked (1);
- a missing plan accepted (1);
- a bail-out accepted (1);
- an unknown TAP line accepted (1);
- a subtest's plan not checked (1);
- `\#` not unescaped (1);
- Go's `fail` read as `pass` (2);
- an unfinished Go test passed (1);
- an unknown Go action accepted (1);
- jest's other statuses read as passed (2);
- an unknown jest status accepted (3);
- the JUnit reader used alone (1).

The first run's last break, the JUnit reader restored in `sv report` itself, could not be caught by any test. That
code runs only under `--run`, with Docker. The choice moved into `suite::reported_cases`, where the crediting test
reaches it.

Not checked against reports each runner wrote on this machine. The samples in the tests follow each format's own
description and the shapes those runners document. A report from a runner version that writes something new is
refused, not misread.
