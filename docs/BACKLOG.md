# SecureVibe — what is still to do

> Written under `agnostic/` and moved to the repository root on 26 September 2026 when `sv` became the top of the
> repository; paths written `agnostic/…` in older items are now at the root (`agnostic/data/…` is `data/…`).
> v1's own backlog is on the `v1` branch.

**Where the items are.** Until 8 October 2026 every item was an entry in this file, which had grown to 8,600 lines
with no "Done" section. Each is now a file of its own under `docs/backlog/`, named by a number that keeps the order
the items stood in here and by its title, unchanged, so a reference of the form `BACKLOG, "title"` in the code or the
documents still finds it by a search of that folder. Its third line is its status: `open`, `claimed by <session>,
<date>`, `done, <date>`, or `partly done: <what remains>`. The record of why is `docs/adr/ADR-061.md`. This file holds
the rules and the roadmap, and no item and no list of items: a list every item adds a line to would bring back the
conflicts the layout is for, and a test fails when one appears here (`crates/sv-cli/tests/backlog_board.rs`).

**The rules.** Claim an item before starting it, in a commit of its own, and merge that pull request before building:
`python3 tools/backlog.py claim <number> --by <session>` sets its status line, and refuses an item another session
holds or that is done. A message to another session is not a claim. When the work lands, `python3 tools/backlog.py
done <number>` marks it, or `done <number> --remains "..."` when part of it stays open; a note of what was built goes
in the item's text, as before, and the design entry holds the detail. A new item is `python3 tools/backlog.py new
"Its title"`, which writes an open file numbered one past the highest; two pull requests open at once may take the
same number, which harms nothing. An item's parts keep their numbers inside it and are claimed and marked in their
own text, as before; the item's status says `partly done` with what remains. `python3 tools/backlog.py list --open`
prints every open item, `summary` the counts, and `--check` holds the layout. A branch written before the split
conflicts here once it merges `main`; the steps to mend it are at the top of the script.

## Roadmap

Written 8 October 2026 by session securevibe-review, at the owner's asking, after the day's review and architecture
assessment; the reasons are in the end-of-day write-up, which is with the owner. This section is the order of work,
not its record: a claim and a done note go on the item itself, as always, and this section is rewritten only when
the order changes, by whoever changes it, with the date. **A session with no word from the owner takes the first
unclaimed sub-item below, in this order, claims it, and lands it before taking the next.** `python3 tools/backlog.py
list --open` prints every item with anything open, read from the items' own markers, so nobody reads 8,000 lines to
find it; `python3 tools/backlog.py summary` prints the counts. Items are named by their titles here; find one by
searching `docs/backlog/` for it, or `python3 tools/backlog.py show <number>` prints one. Check an item against `main` before claiming: some were overtaken by later work and want
a done note rather than a build.

**Phase 1: close what is known to be broken.** Safety and honesty first; each numbered sub-item is claimable on
its own. The two reviews of the code merged 1 to 6 October and the MCP hardening list, which the first version of
this section put here as 41 findings with none claimed, are done by their own notes: each names several parts at
once ("Items 1 to 3 done the same day"), which the board at the split read as open. A reviewer caught it on 8
October, and their files say `done` now.

1. "From the review of 8 October 2026: the medium and low findings, for any session to pick up", in the order 4
   (the planted report marker), 2 (the npm download addresses and the linked dependency file), 1 (Ctrl-C under
   `--tools`), 3 (gosec, CodeQL, and the links the tools follow), 5 (the honesty gaps), 6 (the low ones), 7 (the
   spellings and the home path). The first three are the last known ways `sv` writes or fetches where it was not asked.
2. "Found by the documentation review (6 October 2026), in `sv` itself": items 1 and 3 to 7.
3. The smaller open parts of the older reviews: "A review of `sv` on 27 September 2026" (the one open part),
   "The running-app checks, reviewed on 3 October 2026" (its open part and the ten partly done), "Two blind spots
   found testing the prompt library", "Three false alarms on code that does the safe thing" (item 3), "Two limits
   cato-pipeline hit" (its open part), and "Improving the MCP server" (its open part).

**Phase 2: the shape, from the architecture assessment.** "From the architecture assessment of 8 October 2026: the
four costs worth paying down": item 8 in its fuller form (the guard per check, so a silent check is impossible rather
than tested for), then 9 (the stand-in protocol defined once), 10 (the MCP server's record and the check injected
into `Server`; the tool fold only if the owner says), 12 (the small typing fixes, then the library move), and the
second half of 11 (`ast.rs` and `sbom.rs` along their seams). The library move last, as two or three short pull
requests, since it is the one that most changes how `main.rs` reads.

**Phase 3: the records.** "Records owed, from the first weekly review of the decision records (30 September 2026)",
"Records owed, from the second weekly review (5 October 2026)", "Records that disagree with what was built, or are
missing", and the open parts of "A weekly review of the decision records". Each owed record is debt every later pull
request pays again in "unchanged, because" lines; the weekly review wants a fixed day.

**Phase 4: the product.** In this order, because the first is the paper's central claim and the rest build on it:

1. "The loop trials cannot compare security with the arms that have no `sv`", then "The loop: `sv` as the MCP server
   an AI tool uses while it builds" (items 3, 4, and 6).
2. "Test the prompt library where the prompts have something to fix" and the open parts of "A prompt library".
3. "Design-time prompts from the Secure by Design checklist" (15 prompts, none claimed) and the open parts of
   "Design-time help before any code".
4. The open findings of "From the gap analysis of 7 October 2026" (items 1, 9, 10, 11, 13, 16, 17, 21, 22; item 33
   is this section and the "Backlog management" item).
5. "A dashboard view for `sv`" (items 1 to 4) and "A private page for the owner" (items 2 to 4).
6. "From the end-of-day write-up of 8 October 2026: ideas for `sv` itself" (at the end of this section's items).
7. The open parts of "Research OWASP's Agentic Skills Top 10".

**Phase 5: when nothing above is open.** "Corroborators for the remaining claims", "What a new tool, service, or
process would reach" (item 7), "More adapters", "A checklist for what only a person can check", "Let the owner
confirm what the AI coding tool said", "False alarms, part 2" and "part 3", the leftovers of "Packaging `sv`" and
"Promote `sv` to the top of the repository", "What the remaining Level 1 and 2 requirements need", "More questions
for the running app", the paper's three items ("Eight places where the paper's earlier files disagree with the
record", "Two more analyses for the paper", "Two analyses for the paper, and a stale count"), and "Evaluate Opengrep
against semgrep", whose title says it was done on 29 September while its parts read as open: read it and either
write its done notes or close it. "Research: could the Kaspa blockchain" is the owner's own question and waits for
them.

**Process, any time, each cheap:** "Process: shorter CI, a merge queue decision, and a nightly routine on `main`",
and the owner's decision on "One file per backlog item, with a status line", which would make the status above a
line in each item's file rather than a reading of its prose.

