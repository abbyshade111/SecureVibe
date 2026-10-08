# Read the test runner's own report

**Status:** done, as its markers read on 8 October 2026

Done on 24 September 2026. Left over: matching is an exact
identifier match, so jest — which concatenates its `describe` blocks into the reported name — mostly
will not match and its tests stay uncredited. A runner that reports a name unlike the declaration
loses coverage silently rather than loudly. The parser understands JUnit XML only; TAP and the
runners that emit their own JSON are not read.
**The name matching claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("keep going"), in
branch `claude/securevibe-e9-runner-names`: a declared test matched to the names jest, Vitest, Mocha, pytest's
parameters, and Go's subtests report, and credited only when every case that matches it passed (today a failing
case of the same name as a passing one is ignored). TAP and runners' own JSON stay unread.
**Done the same day** (DESIGN, "A test is found under the names its runner gives it"): matched as a whole part of
the name the runner reports, and credited only when every case that could be it passed.
**TAP and runners' own JSON claimed on 6 October 2026 by session securevibe-e2**, at the owner's word ("continue to
work off the backlog picking whatever item you want"), in branch `claude/securevibe-e2-test-reports`: a declared
`test-report` in TAP (versions 13 and 14, as `node --test`, `bats`, and `prove` write it), in `go test -json`, or in
the JSON jest and Vitest write (`--json`, `--reporter=json`) read the way JUnit XML is, failing closed on anything
it does not recognize.
**Done the same day** (DESIGN, "A test report in TAP, `go test -json`, or jest's JSON"): `test_report::parse` tells
the form by how the file opens and reads each into the cases JUnit gives; a skipped or TODO test, a test that never
finished, and any status but passed are not passes; a TAP report with no plan, a count that differs from its plan,
or a bail-out is refused whole. Fourteen guards broken in turn, each caught. Read from the formats' own
descriptions and from samples written here, not from reports produced by each runner on this machine.
