# Records owed, from the first weekly review of the decision records (30 September 2026)

**Status:** done, 4 October 2026

Each is a decision
in code merged that week with no record, and costly to undo without its reasons. Its reasons are mostly already in
`DESIGN.md` and the pull requests named. **Not claimed; each can be claimed on its own**, and which ones are worth a
record is the owner's call.
**The owner's decision, 4 October 2026:** write records for items 1 to 5; fold item 6 into an existing record as a
line rather than a record of its own; item 7 needs none.
**Items 1 to 6 claimed the same day by session securevibe-e2**, at the owner's word, in branch
`claude/securevibe-e2-records-owed`: records ADR-021 to ADR-025 for items 1 to 5, and item 6 as a line in ADR-019.
**Done the same day:** ADR-021 (a crash's or a rate limiter's answer is never the app refusing), ADR-022 (whose
word counts), ADR-023 (false alarms and accepted risks a person records), ADR-024 (an unanswered data list holds the
app to level 2), ADR-025 (`sv run` has an end), and ADR-019, "Later, 4 October 2026", for item 6. Item 1's "29
passes" is 36 by the table today; ADR-021 gives both.
1. **A crash's or a rate limiter's answer is never read as the app refusing** (#412, #416, #418, #420). Undone
   quietly, 29 passes come back that rest on an answer the app never gave.
2. **Whose word counts, and at which tier:** an AI tool's answers are marked as its own, the owner's are credited
   at their own tier, and checks made by hand are recorded (#175, #242). The index points to v1's ADR-006; `sv`'s
   own statuses have no record.
3. **False alarms and accepted risks a person records, and test code's findings listed apart** (#297, #303,
   #316). These can move a finding out of the count, so the limits on them need their reasons.
4. **An unanswered data list holds the app to ASVS level 2** (#265): ADR-015's rule that silence is not a "no",
   carried into choosing the level, which ADR-015 does not mention.
5. **`sv run` has an end:** time limits on Docker calls and on the tests, a suite stopped at its limit credits
   nothing, Ctrl-C tears down, and a killed run's leftovers are removed by the next (#332, #336, #369). This is also
   where all five `unsafe` blocks came in.
6. **The release build relies on a panic unwinding, so a crash still removes the app's containers** (#330; the
   reason is in a comment in `Cargo.toml` and in `DESIGN.md`). Switching to `panic = "abort"` to save size would
   leave fenced containers running. It could be a line in ADR-019 or ADR-020 rather than a record of its own.
7. **The container image is published from CI and runs as user 10001** (#333). Lower than the rest.
