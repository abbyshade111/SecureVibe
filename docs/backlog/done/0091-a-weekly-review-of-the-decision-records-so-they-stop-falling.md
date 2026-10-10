# A weekly review of the decision records, so they stop falling behind what is built

**Status:** done, 10 October 2026

Asked for by the owner
on 27 September 2026, after the ADR analysis (`docs/paper/ADRS.md`) found records out of date within two days
(ADR-008, ADR-010), `main` contradicting a record for five days (ADR-012), and `sv`'s two largest choices, Rust
and Docker, never written down. **Not claimed.** Once a week, one session:
1. **Reads every record in `docs/adr/`, and the index,** against the code and the week's merged pull requests
   (`git log --first-parent --since="1 week ago" origin/main`).
   **Part status:** done, 10 October 2026
2. **For each record, says in one line whether it still matches what was built.** Where it does not, it either
   amends the record in place (a dated "Later" section, as ADR-016 does) or writes a superseding record (as
   ADR-018 does for ADR-012). Nothing in a record is quietly rewritten.
   **Part status:** done, 10 October 2026
3. **Lists decisions made in that week's code with** no record, and writes the ones that would be costly to undo
   without their reasons, such as a language, a runtime, a fence, or a rule about evidence.
   **Part status:** done, 10 October 2026
4. **Checks each record's cited requirement ids against `data/frameworks`,** as the ADR analysis did.
   **Part status:** done, 10 October 2026
5. **Records the review itself in this backlog, with** the date and what changed, so a skipped week is visible.
   **Part status:** done, 10 October 2026

**Scheduled on 4 October 2026**, at the owner's asking: the routine "Weekly decision-record review" runs every
Monday at 8:45 Eastern in a fresh session, claims the week's review here first, and also reports how many days each
new record came after its decision and how the week's `ADR-0NN: unchanged, because ...` lines were used.

v1's records on the `v1` branch are archived and are out of scope. A correction to one of them is made as the
"records that disagree with what was built" entry above describes.

**Reviews.**
- **The first, for the week to 30 September 2026: claimed that day by session securevibe-e2**, at the owner's
  asking, in branch `claude/securevibe-e2-adr-review`.
  **Done the same day.** Every record, and the index, read against `origin/main` and the 441 merges of the eight
  days to 29 September (about 200 of them claims; the rest read by title, about fifteen opened in full):
  - ADR-015 matches; its count of yes-or-no facts ("about twenty-five") is 35, and a dated "Later" section says so.
  - ADR-016 matches: `data/knowledge` holds three files, and what reads each is as its own "Later" section says.
  - ADR-017 matches: every file `sv` writes into an app's folder is one it lists.
  - ADR-018 matches in its decision; its "twelve rules across fourteen languages" is 18 across fifteen, and a
    "Later" section says so. The index's "fourteen" gains the same date.
  - ADR-019 matches but for one sentence: the app's own container is not run read-only, so "the only writable
    place" is not true, and the report folder has no size limit. A "Later" section says so, the code's comment is
    corrected, and whether to run the app read-only is its own entry below.
  - ADR-020, merged the same day (#463), matches the code; its one slip (`--tools` belongs to `sv report` and `sv bundle`)
    is fixed there.
  - Cited requirement ids: ADR-015 to ADR-019 cite none; ADR-020's V1.4.1 to V1.4.3 exist and fit, and none is
    cited as met.
  - Decisions made in the week's code with no record, each costly to undo without its reasons, are the entry
    "Records owed" below.
- **The second, for the week to 5 October 2026: claimed on 5 October 2026 by session securevibe-e10**, at the
  owner's asking ("do the ADR weekly review if it hasn't already been done yet"), in branch `claude/adr-review-2`.
  The scheduled routine's first Monday (5 October) left no claim and no review here.
  **Done the same day.** Every record, ADR-015 to ADR-037, and the index, read against `main` at `56068c64` and the
  week's merges (348 since 29 September, about 185 of them not claims), with five read-only helper agents, one per
  group of records and one for the week's merges; the session checked the findings it wrote down against the code
  itself. Each record's dated entry is "Later, 5 October 2026 (the second weekly review)".
  - **Match:** ADR-015, 016, 017, 019, 022, 023, 024, 028, 029, 030, 031, 032, 033, 034, 035, 036, 037. Of these,
    ADR-015, 017, 019, 022, 023, 024, and 030 had a file that carries their decision missing from their Governs list,
    now added; ADR-019 also records that every run that signs in now starts the stand-in model (#710), ADR-030 that
    the plan is fenced as data over MCP (#704), and ADR-031 how it is held.
  - **Did not match, and amended:** ADR-018 (21 rules, not 18; Opengrep standing in for Semgrep, the owner's choice
    of 3 October, had no record), ADR-020 and ADR-025 (seven `unsafe` blocks in the workspace, five in `sv`; three
    JavaScript helpers compiled in, which ADR-020 never mentioned), ADR-021 (39 rows, not 36; H15's refusals; the
    claim and the build behind its Status line), ADR-026 (`design-decisions.md`'s sections are sealed too), and
    ADR-027 (an IPv6 address is judged by the IPv4 one inside it in two forms only, and the documentation ranges are
    let through; the code's fix is the entry "`sv probe` and the IPv6 forms that carry an IPv4 address" below).
  - **How late each new record came.** ADR-021 to ADR-025, the records the first review asked for: 5 to 8 days after
    their decisions. ADR-026: about two hours, in its own pull request. ADR-027 to ADR-036: none; five of them were
    written first, as `proposed`, with the claim. ADR-037: about 20 minutes, in its own pull request, after the
    owner decided a record was owed.
  - **The `ADR-0NN: unchanged, because ...` lines,** since the check began (4 October, 17:33 UTC): of 191 pull
    requests merged since, 50 carried at least one, 73 lines in all, most for ADR-018 (16), ADR-019 (10), and
    ADR-026 (9). None gives a reason shorter than 40 characters. The eight a helper flagged as likeliest to be wrong
    (#615, #630, #710, #720, #722, #741, #756, #776) were read: each reason holds, though #615's and #710's described
    changes their records now carry as "Later" entries.
  - **Cited requirement ids** all exist in `data/frameworks` and fit what is said; none is cited as met where it
    should not be.
  - **Decisions with no record,** and two questions for the owner: the entry "Records owed, from the second weekly
    review" below.

**Decided by the owner, 10 October 2026:** done. Two weekly reviews are on main (week to 30 September, and week to 5 October). The routine continues outside the backlog.
