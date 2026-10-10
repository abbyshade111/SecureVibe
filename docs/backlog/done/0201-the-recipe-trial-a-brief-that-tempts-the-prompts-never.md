# The recipe trial: a brief that tempts the prompts never fairly tested

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 7 October 2026
("I approve the way it's written and there is plenty of credit available, please go ahead with both parts"). A
Flask app with pinned packages and `install = true` (`docs/prompts/trial-4/recipe-brief.md`), a baseline of 20
builds, then an arm for each prompt whose problem the baseline found in at least 5 of 10, by the rule fixed in
`docs/prompts/library-trial/recipe-protocol.md`. **Claimed on 7 October 2026 by session paper-facts**, in branch
`claude/recipe-trial`. Read on `main` just before this claim: no other session had claimed it.
**Done the same day** (`docs/prompts/library-trial/recipe.md`): 40 builds, $18.09. `production-server` shown on
Sonnet (5 of 10, then 0 of 9) and marked shown by the owner; `password-rules` not shown (10 of 10, then 8 of 10);
six prompts no reading, done right unprompted; three not reached by their checks (first written as four: corrected, `same-site-redirects` was reached and done right). The install step worked for every
Sonnet app; Haiku's apps mostly did not start, as its builders could not try a Flask app they could not install.
