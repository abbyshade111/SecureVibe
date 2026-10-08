# The earlier trials' "signed in" may be too high

**Status:** done, 8 October 2026

Found on 8 October 2026 by the Haiku 5.5 trial's Amendment 1 (`docs/prompts/library-trial/haiku55.md`):
`score_revision.py`'s `signed_in()`, used by the revision, recipe and sentences scorers, counts a started app as
signed in unless `sv` says signing in failed. An app whose seed command crashed ("nobody to sign in as"), or that set
no `[stack.run.users]` ("`sv` signs in only when securevibe.toml"), is counted too, and the signed-in checks are
counted as asked of it. To do: recount those trials with the corrected test (`score_haiku55.py`'s `signed_in`), and
say in each write-up, dated, whether any count or verdict moves. Their build folders were deleted on 8 October 2026,
so only what their committed results files hold can be recounted; where a result needs the report itself, say so.
  **Done the same day** (`docs/prompts/library-trial/recount_signed_in.py`, `signed-in-recount.json`). Read from the
  committed run summaries, which keep each build's run status and its sign-in gaps; the old test reproduced from them
  matches every build each results file recorded, in all six trials. Four builds change: three Haiku builds in the
  revision trial that set no `[stack.run.users]`, and one Haiku build in the recipe trial whose seed crashed. The
  recipe trial's five signed-in prompts were asked of 0 Haiku builds, not 1; no other count of builds asked or with
  the problem moves, no verdict or stage 2 arm moves, and no harm flag appears or goes; the first library trial,
  delivery, start, recipe stage 2 and the sentences are unchanged. Dated notes in `revision.md`, `recipe.md` and
  `haiku55.md`.
