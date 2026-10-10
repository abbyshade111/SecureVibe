# False alarms, part 1: fewer of them reach the owner

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 27 September
2026, after an investigation by session securevibe-e2 of how `sv` handles findings that are wrong.
Today there is no way to set a finding aside, the same line can be reported by two tools as two
findings, a finding in test code looks like one in the app, and each finding's `confidence` is
recorded and never shown. With an AI coding tool in the loop a false alarm is not noise: the tool
rewrites correct code until the warning stops (see "Two false alarms rated high changed correct
code"). Three changes, none of which hides a finding: findings from different tools on the same file,
line, and kind of weakness (CWE) become one finding naming every tool that raised it; a finding in
test code or sample files says so; and a finding `sv` is not sure of is shown as a *possible* problem,
apart from a *confirmed* one, both still counted as needing attention. **The owner's decision, 27
September 2026: go ahead.** **Claimed the same day by session securevibe-e2.** **Done the same
day:** see DESIGN, "False alarms: fewer reach the owner, and none is hidden". Merging is done where the
report is built, and not in `sv check`, which runs only `sv`'s own rules and has nothing to merge.
