# The earlier trials' "signed in" may be too high

**Status:** claimed by paper-facts, 8 October 2026

Found on 8 October 2026 by the Haiku 5.5 trial's Amendment 1 (`docs/prompts/library-trial/haiku55.md`):
`score_revision.py`'s `signed_in()`, used by the revision, recipe and sentences scorers, counts a started app as
signed in unless `sv` says signing in failed. An app whose seed command crashed ("nobody to sign in as"), or that set
no `[stack.run.users]` ("`sv` signs in only when securevibe.toml"), is counted too, and the signed-in checks are
counted as asked of it. To do: recount those trials with the corrected test (`score_haiku55.py`'s `signed_in`), and
say in each write-up, dated, whether any count or verdict moves. Their build folders were deleted on 8 October 2026,
so only what their committed results files hold can be recounted; where a result needs the report itself, say so.
