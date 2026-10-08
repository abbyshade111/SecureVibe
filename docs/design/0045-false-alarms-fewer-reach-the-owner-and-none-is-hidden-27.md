# False alarms: fewer reach the owner, and none is hidden (27 September 2026)

The investigation that started this found no way to set a finding aside, the same line reported twice
when two tools saw it, a finding in test code looking like one in the app, and a `confidence` on every
finding that no report showed. The two false alarms of the owner's first build (above) are why it
matters: an AI coding tool reads a warning as an instruction, and rewrites correct code until it stops.
Part 1, here, changes what reaches the owner and the tool without hiding anything. Part 2, a person's
record that a finding is a false alarm or an accepted risk, is its own entry in the backlog.

**One weakness on one line is one finding.** `merge_same_place` in `sv-check` merges findings on the
same line of the same file that share a CWE, whichever tools raised them: `sv`'s own SQL rule and
Bandit's B608 on line 5 are one problem, seen twice. The one kept is the most severe, then the one `sv`
is surest of. It takes every requirement and CWE of the others and names their rules in
`also_reported_by`, so nothing they were evidence about is lost, and the report says "Also reported
by". Findings with no CWE in common stay apart, being two problems. So do the running-app probes and
the settings, dependency, and answer checks: they all give a place that is not a line of code ("the
running app", line 1), and two of them there are two different things. It runs where the report is
built. `sv check` runs only `sv`'s own rules, which do not overlap, so it is not wired there, rather
than being code no test could reach.

**How sure, said in words.** Each finding already carried a confidence. It is now shown as
*confirmed*, *likely*, or *possible*, in every report, in the SARIF (`properties.certainty`), in `sv
check`, and to the AI tool through MCP. A *possible* one says to read the code before changing
anything, and that if it is not a problem the code can stay. All three still count as needing
attention; the word says how much to trust the finding, not whether to count it.

**Test code is named, not skipped.** A finding in a file the usual conventions mark as a test or a
sample (`tests/`, `__tests__/`, `*.test.ts`, `*_test.go`, `test_*.py`, `*Test.java`, `examples/`, and
the like; `is_test_path`) says so. It still counts: test code can hold a real key, and sample code gets
copied.
