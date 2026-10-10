# A second review of all of `sv`'s documentation, and the paper's figures and analyses

**Status:** done, 10 October 2026

Asked for by the owner on 7
October 2026 ("the deep scrub and review of the documentation to get everything up-to-date, including the figures
and analyses for the paper that are now out-of-date as well"). The first review (above, 6 October 2026) was done
before the install step (ADR-052), the record checks (ADR-053), the two checks of ADR-055, the prompt library's
trials, and more. Every document a person or an AI tool reads, and `docs/paper/`'s documents, figures and data,
read against `main`; records and DESIGN get dated entries rather than rewrites. **Claimed on 7 October 2026 by
session paper-facts**, after the write-up. Read on `main` just before this claim: no other session had claimed it.
**Part 1 done on 8 October 2026:** the documents a person or an AI tool reads, each sentence checked against the
code: README, GETTING-STARTED, PROMPTS and the prompt library's notes, design-time prompts, CLAUDE.md, the data
README, PARTIAL-CHECKS (63 of the 382 now have a check, recounted), SEMGREP-FALSE-ALARMS and THREAT-MODELING (dated
notes), the decision-record index, the CodeQL workflow's comments, the examples, and the Governs lines of ADR-044
and ADR-045. One fault in `sv` itself was found and fixed on its own (the item above). Still to do: the wording
inside the code (the specification, the MCP tools' descriptions, the help), and the paper.
**The paper done the same day**, the cut-off kept as the owner chose ("Keep the cut-off, add a new part"):
`docs/paper/TRIALS.md` for the nine trials, with `figure-trials.html` made from their committed results by
`docs/paper/trials/make_figure.py`; `SINCE-THE-CUTOFF.md` carried on to `main` at `01b10f60`, counted there, with a
correction of its own (11 records at `4c3c5e0`, not 12); the artifact index; and the health-tracking app's wording
made the same everywhere.
**The wording inside the code done the same day** (ADR-035, Later): the specification (the app's own tests' status,
`--fail-on attention`, the `[data]` level, the tests-to-write list, `within-minutes`, the install step), the MCP
server's descriptions and instructions, the prompts' "Not tested" labels (now "Tried, not shown to work" and "Not
tried yet"), the help on the install step's download, and the feature briefs' settings; and the preflight now reads
the install step, by calling it. With that, the second review is done.

**Checked against origin/main, 10 October 2026:** built: commits `e40d0ba7`, `436e612a`, `8f99c802`; `docs/paper/TRIALS.md`, `figure-trials.html`, `SINCE-THE-CUTOFF.md`; `PARTIAL-CHECKS.md` says "63 of these 382".
