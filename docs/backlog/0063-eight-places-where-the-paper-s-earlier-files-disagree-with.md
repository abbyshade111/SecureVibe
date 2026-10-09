# Eight places where the paper's earlier files disagree with the record

**Status:** done, 9 October 2026

Found on 28 September 2026 by the
coordination and fault analyses above. **Claimed on 28 September 2026 by session admiring-murdock-875699**, at
the owner's asking. Check each against its source before changing it.
1. `figure-how-caught.html` says 50 of the 267 changes "mention a claim". Three of the 50 (#56, #67, #71) use
   "claim" to mean an assertion: 47 were claims of work, 42 of them touching only the backlog.
2. `figure-how-caught.html` counts 7 faults in `sv` found by one session reviewing another's work. It misses
   `11b0e6c`, `6225f3f`, and `672d4af`, each of whose messages says another session found it; the total is 10.
3. `figure-how-caught.html` counts 8 faults found by v1's evaluation harness; `faults.csv` has 13, adding
   `2a5d2e8`'s four and `d46f119`.
4. `TIMELINE.md` says 214 of the 267 changes were pull requests. Twelve more on 26 September (#128 to #221) were
   pull requests rebased onto `main` and appear as direct commits, so the figure is 226.
5. `TIMELINE.md` and `figure-how-caught.html` stop at 10:52 on 27 September; `main` had 469 changes by 16:18 on
   28 September. Either extend them or say where they stop.
6. `TOP10.md` files the fence-test weakness (#148) as found by "running the suite";
   `figure-how-caught.html` files it as "breaking a guard". The backlog says it was found running the suite on
   the owner's Mac.
7. `TOP10.md` cites a `mkdirSync` fix, `a562749`, that is on neither `main` nor `v1`, only on
   `origin/claude/ci-hang`. Check whether it reached either in another form.
8. `TOP10.md` says no verdict that failed open was caught by a failing test. That holds for its eight; two others
   were (`faults.csv` SV-10 and SV-49, `corrections.csv` rows 22 and 47).

**Done the same day.** Each was checked against its source first; six held as written, and two were worse
than stated:
- 3: the full harness count is 14, not 13. The ledger had also missed `00456fe`, whose own title says the harness
  caught it, so `faults.csv` gained a row (V1-77) and the fault totals in `TESTS-AND-FAULTS.md`,
  `COORDINATION.md`, and their figures are now 149 (81 in v1).
- 7: the fix never reached `v1` in any form. The whole `claude/ci-hang` branch (`3e78e98`, the test fix, and
  `a562749`, the rule) is unmerged, and `v1` as archived still has the test line that hung CI
  (`server/tests/llm/safety.test.ts`, the `/proc/definitely/not/writable` call). `TOP10.md` and `faults.csv` now
  say so. Patching `v1` is a separate decision, made on the `v1` branch if at all.
  **The owner decided on 28 September 2026 to patch `v1`: merging `claude/ci-hang` into the `v1` branch is
  claimed on 28 September 2026 by session admiring-murdock-875699.** The tags `v1-paper` and `v1-final` stay
  where they are.
  **Done on 28 September 2026** (#396, `5ddffb8`, merged 20:51 Eastern): `claude/ci-hang` was merged into `v1` by
  way of `claude/v1-ci-hang`, which also says so in `ARCHIVED.md`, and `v1`'s
  `server/tests/llm/safety.test.ts` no longer asks for `/proc/definitely/not/writable`. `TOP10.md` already said
  so. Recorded here on 4 October 2026 by session securevibe-e9, which found the claim still open.
Also corrected while there: `COORDINATION.md` said review found fewer faults than the owner's use; it found more
(28 against 26).
**Its status claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and pick up new
items as you merge"), from the roadmap (Phase 5, the paper's three items), in branch
`claude/stackvet-e9-paper-notes`. Read against `main` just before this claim, all eight were checked and corrected on 28 September, and the `v1` patch that 7 led to merged as #396; only its status line reads as open. The item is owed a done note,
not a build. No other session had claimed it.
**Done 9 October 2026, by session securevibe-e9, with nothing built:** all eight were checked and settled on 28
September, as the note above says, and the patch to `v1` that 7 led to merged as #396. Read again on `main` before
this note: `figure-how-caught.html` gives 47 claims of work, 42 touching only the backlog; `TIMELINE.md` gives 226
pull requests and says where its record stopped; `TOP10.md` names the two caught by a failing test (SV-10 and SV-49)
and says the `claude/ci-hang` fix reached `v1` by #396; and `faults.csv` has V1-77. Only the status line, which
counts markers rather than reading the note, still said seven were open.
