# Claude Haiku 5.5 against Haiku 4.5: results

Run on 8 October 2026 by `haiku55-protocol.md`, written and merged before any build (#1069). 20 builds on the recipe
brief, 10 with `claude-haiku-5-5` and 10 with `claude-haiku-4-5-20251001`, each by Claude Code 2.1.293 and checked by
`sv report --run` from one release build of `main`, `39b99fc6`. **$6.16** of the owner's API credit: Haiku 5.5 $1.25
($0.125 a build), Haiku 4.5 $4.82 ($0.48 a build), and the uncounted smoke build $0.09. That is $0.16 over the
protocol's upper estimate, because the Haiku 4.5 builds cost more each than in the recipe trial ($0.376). No billing
errors; no transcript holds the key. Results: `haiku55-results.json`, by `score_haiku55.py`; the run: `run_haiku55.sh`.

## Can the apps be tested?

| | Haiku 4.5 | Haiku 5.5 |
|---|---|---|
| Wrote an app | 10 of 10 | 10 of 10 |
| A settings file `sv` could read | 8 | **10** |
| The install step failed | 3 | **0** |
| Started under `sv run` | 3 | **9** |
| `sv` signed in | 0 | **8** |
| Stopped to ask and wrote nothing | 0 | 0 |

By the protocol's rule: **started, shown** (the control failed it in 7 of 10, Haiku 5.5 in 1). **Signed in, not
shown:** the control failed it in all 10 and Haiku 5.5 in 2, and the rule allows at most 1; from none to 8 of 10 is
the largest change in the table, and it still does not meet the rule fixed before the run. **Readable settings, no
reading:** the control failed it in only 2, too few to show a change. (Signed in as corrected by Amendment 1; first
scored as 2 and 9.) For comparison, the
recipe trial's Haiku 4.5 builds (another Claude Code, an older `sv`, not counted): 8 readable, 2 started, 1 signed in by the earlier test (Amendment 1).

Why each failed, from `sv`'s own words in each report:

- **Haiku 4.5, 7 builds:** two crashed on a page template left unclosed (Jinja's `endblock` missing); three named
  package versions that do not exist (`pytest-junitxml==1.2.2`, `pytest-junitxml==1.14.0`, `zxcvbn==4.4.28`), so the
  install step could not finish; two wrote `[finding-review]` as a table where the specification asks for a list
  (`[[finding-review]]`), so `sv` refused the file.
- **Haiku 4.5, signing in:** of its 3 apps that started, two had seed scripts that crashed, so there were no
  accounts to sign in as; in the third, signing in did not open the private page.
- **Haiku 5.5, 1 build:** crashed at start calling a sanitizing library with an argument it does not have
  (`Cleaner(callbacks=...)`).
- **Haiku 5.5, signing in:** one app that started left `[stack.run.users]` out of its settings on purpose, its comment
  saying the sign-in checks need a seed script it had not written, so `sv` never signed in.

## The prompts' problems

Among the builds each check could ask, Haiku 5.5 had **none** of the twelve problems the recipe brief tempts: 0 of 8,
9 or 10 for each, against Haiku 4.5's 1 of 8 (`password-hashing`) and 1 of 3 (`production-server`). Haiku 4.5's
running checks could ask only the 3 builds that started, and its signed-in checks none.

Two code rules raised findings in every Haiku 5.5 app and are not counted, as the protocol scores each prompt by its
own checks: `ast.sql-built-by-hand` (V1.2.4) and `ast.open-redirect` (V3.7.2). Read by hand in four apps, each is a
false alarm the rule cannot see past: the sort column is taken from a fixed list of the app's own before it reaches
`ORDER BY` (four of four read), and the redirect target is checked to name no other site before it is used (one read).
That `sv` flags a checked redirect is already recorded in `docs/PROMPTS.md` (`same-site-redirects`); the same blind
spot for a column chosen from a fixed list is new here. The running checks for both (`probe.sql-injection`,
`probe.open-redirect`) found nothing in the 9 Haiku 5.5 apps that started.

## What this shows, and what it does not

- Haiku 4.5's trouble in these trials was mostly that its apps could not be run: broken templates, invented package
  versions, a settings file `sv` refused, seed scripts that crashed. With the same brief, specification and checks,
  Haiku 5.5's apps started 9 times in 10 and were signed in to 8, at a quarter of Haiku 4.5's cost a build.
- With nothing pasted, Haiku 5.5 avoided every problem the recipe brief tempts. By the recipe trial's rule (an arm for a
  prompt whose problem stage 1 finds in at least 5 builds), **stage 2 has no arms**: there is nothing for a prompt to
  fix in Haiku 5.5 on this brief.
- Ten builds a model, one brief, one tool. The prompts were shown to work on Haiku 4.5 where it could be tested; this
  says nothing about whether they are still needed with Haiku 5.5 on other briefs.
- A sign that `sv`'s own code rules need work: two rules flagged safe code in every app of the better model.

## Amendments

1. **8 October 2026, while checking the results: what "signed in" counts.** The scorer reused the earlier trials'
   test (`score_revision.py`), which counts a started app as signed in unless `sv` says signing in failed. Read by
   hand, three apps were counted although `sv` never signed in: two Haiku 4.5 apps whose seed command crashed ("With
   no accounts there is nobody to sign in as") and one Haiku 5.5 app with no `[stack.run.users]`. The protocol's
   measure is "`sv` signed in", so `score_haiku55.py` now also counts those two messages as not signed in, and its
   "asked" for the signed-in checks follows. Signed in went from 2 and 9 to 0 and 8, and its verdict from shown to
   not shown. The rule itself is unchanged. The same test was used by the earlier trials' scorers, so their
   signed-in counts may be too high in the same way; they are not recounted here (BACKLOG).
