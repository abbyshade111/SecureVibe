# The trial runner prints nothing while it checks

**Status:** done, as its markers read on 8 October 2026

Found on 7 October 2026 by the owner, watching the revision
trial: the Terminal tab said "to check: 104" for three hours, and only counting `report.json` files showed progress.
`tools/prompt_trial.py` and the trial scripts should print one line as each build's check finishes.
**Claimed on 7 October 2026 by session paper-facts**, at the owner's word ("go ahead with step 1"), in branch
`claude/step1-fixes`. Read on `main` just before this claim: no other session had claimed it.
**Done the same day:** `tools/prompt_trial.py` prints `[3/104] build: started, 95s` on stderr as each check
finishes, so it shows even when the summaries are sent elsewhere.
