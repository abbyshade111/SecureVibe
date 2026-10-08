# A finding that says it leaves the credit alone does (4 October 2026)

The family-hub build of 3 October (BACKLOG, "What the owner hit building family-hub", item 6) found a finding whose
text and effect disagreed. `tests.name-does-not-match-requirement` says a test named for a requirement shares no words
with it, at `info` severity and low confidence, and its own advice says "about a third of these are honest tests
written in different words, which is why this does not take the credit away". But `sv_report::build` made any finding
naming a requirement "needs attention", so V6.3.3 and V2.3.2, each with a passing test, lost their credit to it. The
owner then did what the warning invites, read the tests and recorded the warnings as false alarms, and that made it
worse: a requirement with a finding set aside as a false alarm can never be *checked* by another check, so V10.5.2 and
V10.1.2 read "not verified".

**What changed.** `Finding::withholds_credit` (in `crates/sv-check/src/finding.rs`) says whether a finding keeps a
requirement from being *checked*. It is false only for a rule named in `INFORMATION_ONLY`, at `info` severity, with no
other rule merged into it; today the list holds the test-name rule alone. The report shows such a finding beside the
requirement's status, in a new `information` list on each requirement line and in the status cell of both the Markdown
and HTML tables ("also noted, for information, and not counted against it"), and still lists it among the findings. A
false-alarm review of one leaves the credit standing, since that review is the warning's own advice. The rule's advice
now says so too.

**Kept narrow on purpose.** Keying this on `info` severity alone would have stopped a tool's lowest-level result
(SARIF `none`, or a CVSS score of 0.0, both mapped to `info` in `adapters.rs`) and a known vulnerability with a 0.0
score (`cvss.rs`) from counting. Those are a tool saying something is wrong, and nothing in their text says the credit
stands, so they still make the requirement need attention. The other kinds of finding that sound advisory were read
for the same mismatch and do not have it: a low-confidence ("possible") finding still needs attention, as
`Finding::certainty` says; an accepted risk stays among the findings and its note says "it still needs attention";
a finding in test code is "said beside it, never used to hide it" and still counts; a finding naming a requirement
that does not apply is listed apart. The "not a failure" sentences in the signed-in checks are reasons for *not
assessed*, not findings.

**Tested.** Three report tests: the test-name finding beside a passing test leaves the requirement *checked* and is
named in both tables; a real finding beside it (a high one, a tool's at `info`, the test-name rule raised to `low`,
and one with another rule merged in) still makes it need attention; and the test-name finding set aside as a false
alarm leaves the credit, where a real one set aside does not. The suite's own test asserts the finding it makes is
the one the report treats as information. Seven guards broken in turn, each caught: every finding withholding credit
(three tests), any false alarm blocking *checked* (one), the severity condition and the merged condition dropped (one
each, the control), no finding withholding credit (twelve, across the report and threat tests), and the note left out
of either table (one each).
