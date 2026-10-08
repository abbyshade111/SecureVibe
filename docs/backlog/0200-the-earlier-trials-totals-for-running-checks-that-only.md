# The earlier trials' totals for running checks that only report findings were too small

**Status:** done, as its markers read on 8 October 2026

Found on 7 October 2026
by session paper-facts (the revision protocol's Amendment 2): the scorers of the prompt-library, delivery and at-start
tests counted a running check as asked only when one of its rules said something, where `protocol.md` says when the
app started, so a build the prompt had fixed was left out of the total. Recounted the same day: the prompt-library
trial's verdicts stand (its rule counts builds), but the delivery and at-start tests judge by shares, and in each
`private-pages-no-store` on Haiku moves from "not shown" to "no reading". The "of N" figures in `README.md`,
`delivery.md` and `start.md`, and those two verdicts, are to be corrected.
**Claimed on 7 October 2026 by session paper-facts**, at the owner's word ("go ahead with step 1"), in branch
`claude/step1-fixes`. Read on `main` just before this claim: no other session had claimed it.
**Done the same day** (`score_recount.py`): the figures corrected in `README.md`, `delivery.md`, `start.md`, the
library and the guides, and the three verdict files replaced by the recount. The prompt-library trial's verdicts
stand; `private-pages-no-store` on Haiku is "no reading" in the delivery and at-start tests. Found on the way:
`data/design-prompts.json` and ADR-028 said the revised `design-limits` and `design-sign-in` were tried in the
revision trial, which left design prompts out; corrected, with a dated correction on ADR-028.
