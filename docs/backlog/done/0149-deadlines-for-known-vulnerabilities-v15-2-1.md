# Deadlines for known vulnerabilities (V15.2.1)

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 26 September 2026.
V15.2.1 asks that the app contains no component that has *breached the documented remediation time
frame*; the advisory check reads every known vulnerability as a breach, so an advisory published
yesterday and one ignored for two years look the same. The owner states the time frames as policy
numbers (`[policy] fix-within-days`, one per severity), and each advisory's published date says how
long it has been known. Past the deadline stays a finding on V15.2.1; within it stays a finding with
a due date, but no longer claims V15.2.1 is breached. A clean comparison credits it exactly as now,
and nothing here credits more than that. **Claimed on 26 September 2026 by session securevibe-e8.**
**Done on 26 September 2026.** `[policy] fix-within-days` in securevibe.toml, the publication date
read from each OSV record, and `sv audit` printing past the time frame first, then not judged, then
inside it. Anything that cannot be judged — no time frame for that severity, no date, no clock — still
counts against V15.2.1, and an unrated advisory is held to the shortest time frame. See DESIGN, "Late,
not merely known". Left over, found while doing it: **`sv report` never runs the advisory comparison**,
so V15.2.1 has no evidence in the report whatever `sv audit` says, and the checklist sends the owner
to `sv audit` by hand. Bringing it into the report needs `--advisories` on `sv report`.
**Claimed on 26 September 2026 by session securevibe-e8. Done the same day:** `sv report
--advisories DIR` puts the findings, the clean result, and what could not be compared into the
report, and without a database the report says it compared nothing rather than staying silent. See
DESIGN, "In the report too". The MCP server still takes no database, deliberately.
