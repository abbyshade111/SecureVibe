# The build loop written down, and the report saying what it shows (9 October 2026)


Backlog 0006, finding 22(d) of the gap analysis of 7 October 2026; ADR-076. The owner chose this option on 9 October
2026: "observability is really important, so let's go with the first option".

**The problem.** `sv`'s promise to a person who is not technical is the build loop: the AI coding tool checks the
app through `sv` while it builds, fixes what is found, and checks again. Nothing recorded that this happened, so a
report written once at the end read the same whether the tool checked forty times or never.

**What changed.**

- `crates/sv-cli/src/build_loop.rs`: `record` appends one line to `stackvet-report/build-loop.jsonl` for a call: the
  time, the tool's name, and, for a call that checked the app, how many findings, requirements checked, needing
  attention, and not assessed. Never an argument, a path, or a finding's text. The folder is made one level at a time
  and never through a link, and the file is opened without following one. `read` sums the record up for a report.
- The MCP server (`crates/sv-cli/src/mcp/mod.rs`) writes each call down after answering it, for a folder that holds a
  `stackvet.toml`; a check leaves its counts for that line (`crates/sv-cli/src/mcp/tools.rs`). Only the server `sv mcp`
  starts writes; nothing that goes wrong in writing changes a tool's answer.
- Every report written into a report folder reads the record first (`crates/sv-cli/src/report_folder.rs`), so
  `sv report` at a terminal and `stackvet_write_report` both say it. `report.json` carries it as `build_loop`, under
  the report's seal, and each report says it in one paragraph at the top: how many calls and checks, from when to
  when, the counts at the first and the last check, that it credits nothing, and what the seal covers. With no
  record: "Nothing shows that sv was used while this app was built ... That is not a finding." Turned off with
  `build-loop-record = false` under `[app]`: the report says it cannot tell.
- `build-loop.jsonl` is one of the names a report folder may hold (`sv_scan::ecosystems::REPORT_FOLDER_NAMES`), so
  the next report is written beside it and the folder is still offered as `sv`'s.

**Why not seal the record itself.** It grows with every call, so it would break the folder's seal between reports.
The report seals what it read instead; ADR-076 says what that does and does not catch.

**Tested.** Eight tests: the record's own five (a line written as it is read back, with no room for an argument; the
summary of calls, checks, the two ends, and an unreadable line; a call written and read back; turned off; a link
where the record or its folder goes, not written through and not read) and three through the server (two checks
written down and the report saying "asked sv 2 times" in all three of its formats, the folder still sealed as `sv`'s
after a second report; no record; turned off). Each guard was broken in turn and caught: the server not writing
down (1 test), the report not reading the record (3), the manifest's setting ignored (2), both link guards removed
together (1; either alone is held by the other), the record not one of a report folder's names (1), and the tests'
servers writing by default (1).

**Not done.** The record says that `sv` was asked, not what the tool did between two checks; which findings were
fixed and which were set aside is a question for the observability review (backlog 0226).
