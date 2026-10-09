# Apps built with `sv` against apps built without it: results

Run on 8 October 2026 by `protocol.md`, written and merged before any build (#1115). 20 builds by Claude Haiku 5.5
(`claude-haiku-5-5`) on `brief.md`, 10 without `sv` and 10 with `sv mcp` attached, by Claude Code 2.1.293; every app's
settings file written by one blind tester (Haiku 5.5, file tools only), on copies named by random codes; every copy
checked by `sv report --run` from one release build of `main`, `2b9c1846`. **$3.57** of the owner's API credit: builds
without `sv` $0.41, with it $2.81, the tester's 20 runs $0.35. No billing errors; no transcript holds the key. No copy
was left out: every tester wrote only `securevibe.toml`, and `sv_seed.py` where it chose to, as the file check showed.
Results: `results.json` (with the check-by-check counts); the table from code to build: `blind-map.json`; the run:
`run_loop_compare.sh`, `blind_tester.py`, `score_loop_compare.py`.

## What the builders did with `sv`

Every build with `sv` attached used it, 5 to 21 tool calls each: all ten read the specification, the coding rules
(`securevibe_guidance`) and the run-settings check (`securevibe_preflight`); `securevibe_check` was called 25 times in
all, the feature briefs (`securevibe_before`) 14. No build without it named SecureVibe anywhere.

## Security, of the apps that started

| | without `sv` | with `sv` |
|---|---|---|
| Apps that started under `sv run` | 10 of 10 | 6 of 10 |
| `sv` signed in | 10 | 6 |
| Running-app findings per app | 10, 10, 11, 11, 12, 12, 12, 12, 12, 14 (middle 12) | 2, 3, 3, 4, 5, 5 (middle 3.5) |
| Own-code findings at high or critical, per app | 2 in nine, 3 in one (middle 2) | 0, 0, 0, 0, 0, 1, 2, 3, 4, 5 (middle 0.5) |

**Running-app findings: fewer with `sv`, by the protocol's rule**: every app built with it that started has fewer
than every app built without it. **Own-code findings: no difference by the rule**: the arms overlap.

Check by check, the apps that started (10 without, 6 with):

| Check | without `sv` | with `sv` |
|---|---|---|
| Security headers missing (`probe.security-headers`, `probe.private-page-headers`, `probe.opener-policy-missing`) | 10 each | 0 each |
| The server's version shown (`probe.version-disclosed`) | 10 | 0 |
| A common or breached password accepted (`probe.common-password-accepted`, `probe.breached-password-accepted`) | 10 each | 1 each |
| A private page cacheable (`probe.private-page-cached`) | 9 | 0 |
| Signing out leaves the session open (`probe.logout-keeps-session`) | 10 | 2 |
| No limit on wrong passwords (`probe.failed-sign-ins-unlimited`) | 10 | 2 |
| No limit on creating records (`probe.create-rate-unlimited`) | 9 | 5 |
| Sign-up says whether an account exists (`probe.signup-reveals-account`) | 10 | 6 |
| No sign-out link on the page (`probe.no-sign-out-link`) | 6 | 4 |

Of the twelve problems the recipe brief tempts, by the recipe trial's rule: **`password-rules` shown** (10 of 10
without `sv`, 1 of 6 with it) and **`production-server` shown** (10 of 10, 0 of 6); the other ten no reading, as
neither arm had them.

## The harm: four apps built with `sv` did not start

Every app built without `sv` started; four built with it did not, each because the install step could not finish:
three pinned `zxcvbn==4.4.28`, a version that does not exist (4.4.27 and 4.5.0 do), and one pinned two packages whose
versions conflict. `zxcvbn` is the package `sv`'s `password-rules` prompt names, as `zxcvbn==4.5.0`; that prompt is
among those `sv` gives a builder at the start. Five of the eight builds that used it pinned it as the prompt says, and
three wrote a version of their own. So the advice `sv` gives cost three apps their start here, though it was followed
wrongly. Their own-code findings are counted above; nothing about them running was seen.

## What this shows, and what it does not

- Built by Claude Haiku 5.5 from the same request, the apps made with `sv` attached had a third as many running-app
  findings as those made without it, every one fewer than every one without, across headers, passwords, sessions and
  limits, not one check alone.
- **It rests on the six that started.** Four apps built with `sv` could not be run, three for a package version the
  builder got wrong while following `sv`'s advice; they are left out of the running-app measure, as the protocol
  fixes. Had they started, they might have had more findings.
- **The tester was not fully blind.** The copies' names and the files the protocol removes hid the arm, but eight of
  the ten copies built with `sv` still named SecureVibe somewhere the protocol left in place (a `README.md`, a
  `DECISIONS.md`, a `.gitignore`, a comment in the code), so the tester could have told those apps apart; no copy built
  without `sv` named it. What it wrote reached both arms' apps alike: `sv` signed in to every app that started (10 of
  10, 6 of 6), and the running-app checks answered per app were 25 to 31 without `sv` and 24 to 31 with it.
- Ten builds an arm, one model, one brief, one tool.
- Both arms were checked by the same `sv`, which is also what the loop arm was helped by: the measure is `sv`'s own
  checks, so a problem no check reaches cannot be seen to change.

## Amendments

None.
