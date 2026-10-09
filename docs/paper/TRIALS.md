# The trials, 5 to 8 October 2026

After the cut-off, the project turned from building `sv` to asking whether it changes what an AI coding tool builds.
Eleven trials were run in four days: **505 builds and 20 blind-tester runs, $160.26** of the owner's API credit (the
tenth and eleventh, on 8 October, added here that day). Each was run to a protocol
written before any build, and each has its own write-up, results files, scripts and scorers in `docs/prompts/`. This
file brings them together for the paper; `figure-trials.html` shows every pasted-prompt comparison, and is made from
the trials' committed results by `trials/make_figure.py`, so it cannot drift from them. Where a result was corrected
after it was first written, the corrected one is given and the correction is said.

None of this was measured the way the cut-off's analyses were: these are new experiments, not a recount of the
record. They also fall after the paper's cut-off (`157ddc3`), so nothing in the other files depends on them.

## How a trial is made

- **The builder:** Claude Code, run headless in a fresh folder, with Claude Sonnet 5.5 or Claude Haiku 4.5 (and, in the tenth and eleventh, Claude Haiku 5.5), told the
  owner is away so it should not stop to ask. Nobody answered it during a build.
- **The brief:** a short description an owner might write. Until the recipe trial, a club app (sign-in, private
  notes, a booking, an AI assistant, an admin page) in Python's standard library; from the recipe trial, a recipe
  club on Flask with pinned packages.
- **The check:** `sv report --run`, which starts the app in a container on a network with no way out, signs in as two
  test users, and asks the questions behind each check. Nothing a build did reached the internet, and each trial
  checked that the owner's API key appeared in no transcript.
- **The rule, fixed before any build:** a prompt is **shown** to work when its problem was in at least 5 of the builds
  without it and in at most 1 with it; **not shown** when it stayed in 2 or more; **no reading** when it was in fewer
  than 5 without it, as there was too little to fix. Harm is reported beside every verdict: fewer apps starting or
  signed in to, an app refusing its own forms.
- **Amendments:** anything decided after a result was seen is written into the protocol with its date and reason.

## The trials

| trial | when | builds | cost | the question | write-up |
|---|---|---|---|---|---|
| Loop pilot | 5 Oct | 6 | $1.86 | Does a builder use `sv`'s tools when they are attached, and can its app be tested? | `docs/prompts/loop-pilot/` |
| Loop arms | 5 Oct | 18 | $4.78 | Which part of the loop does the work: the specification, the check, the plan? | `docs/prompts/loop-arms/` |
| Loop at scale | 5–6 Oct | 70 | $21.34 | The same, five builds a cell, with the specification in every request | `docs/prompts/loop-scale/` |
| Prompt library | 6 Oct | 90 | $21.12 | Does pasting a library prompt remove the problem it is for? | `library-trial/README.md` |
| Delivery test | 6 Oct | 60 | $19.36 | Do two new sentences make settings readable, and does `sv` deliver prompts that work? | `library-trial/delivery.md` |
| Prompts at the start | 7 Oct | 40 | $18.11 | Do the shown prompts work given at the start of every build? | `library-trial/start.md` |
| Revision trial | 7 Oct | 110 | $35.28 | Do the reviews' revisions keep working, and do five new prompts work? | `library-trial/revision.md` |
| Recipe trial | 7 Oct | 40 | $18.09 | A Flask brief that tempts the prompts never fairly tried | `library-trial/recipe.md` |
| Three sentences | 7 Oct | 30 | $10.59 | Do the three sentences added from the trials work? | `library-trial/sentences.md` |
| Haiku 5.5 | 8 Oct | 21 | $6.16 | Does Claude Haiku 5.5 build apps that can be tested, where Haiku 4.5 could not? (20 builds and a smoke build) | `library-trial/haiku55.md` |
| With and without `sv` | 8 Oct | 20 | $3.57 | Built from the same request, does an app built with `sv` attached have fewer security problems than one built without it? (and 20 blind-tester runs) | `loop-compare/results.md` |
| **All** | | **505** | **$160.26** | | |

## What they found

- **The specification is what makes an app testable.** In the loop arms no build without `sv`'s server wrote a
  settings file `sv` could read, so none could be tested; with it, eleven of twelve could. At scale, with the
  specification in every request, every Sonnet build could be tested.
- **Builders fix what the check names.** With `sv` attached, builders checked, fixed, and checked again: the
  `.gitignore` that let `.env` be committed, named by the check, was fixed in every loop build told of it. Findings
  `sv` saw only in the running app, which the builder's check did not run, did not change.
- **A prompt pasted into the request works where its problem is common.** Of the 21 comparisons with builds on both
  sides, 10 were shown, 4 not shown, and 7 had no reading (`figure-trials.html`). Prompts for security headers, keys
  and `.env`, private pages, AI-feature guards, window isolation, a security contact, a production server, and
  password rules removed their problem. The library now marks 10 of its 22 coding prompts shown to work, against 2 of
  the 17 it held before the trials. Each status was set by the owner from the verdicts; where a model, a check, or a
  harm flag qualified a result, `docs/PROMPTS.md` says so.
- **Delivery through `sv` mid-build did not work; at the start it did.** Prompts offered in the feature briefs mostly
  never reached the builders (the brief refused until a settings file existed). Given in full at the end of the
  specification and the server's opening instructions, keys and `.env` went from 9 of 10 Sonnet builds to none, the
  first delivery through `sv` the rule calls working (ADR-044, Later).
- **With the shown prompts at the start, little was left for the revisions.** In the revision trial several problems
  were already rare without anything pasted, so most revised and new prompts had no reading. All four revisions were
  kept.
- **Some of `sv`'s checks rested on one sample, and the trials found it.** The common-password check tried one word,
  the cross-site check asked only the home page, and the record check read once (ADR-053, ADR-055). In the recipe
  trial every build wrote its list of common passwords from memory and passed the one-word check; with the prompt
  naming a list package, all ten pinned it and the problem went from 10 of 10 to 0 of 10.
- **Apps that use packages can be tested since ADR-052.** Every Sonnet Flask app in the recipe trial was installed and
  checked behind the fence. Haiku mostly could not be tried: 3 of its 10 apps crashed on faults trying them would have
  shown, and 2 pinned versions that do not exist.

## The tenth trial: Claude Haiku 5.5 (8 October)

Through the first nine, Claude Haiku 4.5 was the model whose apps could least often be tested, so most of its
comparisons had no reading. When Claude Haiku 5.5 was released the owner asked whether those problems remained. Ten
builds of each model on the recipe brief, one Claude Code (2.1.293) for both, each model named by its full id, by a
protocol fixed before any build with the same kind of rule as the prompts (`library-trial/haiku55-protocol.md`).

| On the recipe brief | Haiku 4.5 | Haiku 5.5 |
|---|---|---|
| A settings file `sv` could read | 8 of 10 | 10 of 10 |
| The install step failed | 3 | 0 |
| Started under `sv run` | 3 | 9 |
| `sv` signed in | 0 | 8 |
| Cost a build | $0.48 | $0.125 |

Started: **shown** by its rule. Signed in: **not shown**, as the rule allowed one failure and there were two, though it
went from none to eight. Haiku 4.5's failures were the earlier ones again (templates left broken, package versions that
do not exist, a settings section in the wrong form, seed scripts that crashed); Haiku 5.5's one was a library called
with an argument it does not have. With nothing pasted, Haiku 5.5 had none of the twelve problems the recipe brief
tempts, so there was nothing for a prompt arm to fix. The trial also found `sv`'s SQL code rule flagging safe code in
every Haiku 5.5 app (a sort column chosen from a fixed list), fixed the same day (backlog 215, ADR-018, Later).

## The eleventh trial: apps built with `sv` and without it (8 October)

The question the loop trials could not answer (backlog 38): built from the same request by Claude Haiku 5.5, does an
app built with `sv` attached have fewer security problems than one built without `sv` at all? Ten builds of each, on
the recipe brief with its line about SecureVibe taken out, and every app's settings file written by one tester from
the code alone, so the comparison is of the apps, as the owner chose on 5 October (`loop-compare/protocol.md`).

| | without `sv` | with `sv` |
|---|---|---|
| Apps that started | 10 of 10 | 6 of 10 |
| Running-app findings per app (middle) | 10 to 14 (12) | 2 to 5 (3.5) |
| Own-code findings at high or critical (middle) | 2 to 3 (2) | 0 to 5 (0.5) |

**Running-app findings: fewer with `sv`, by the loop protocol's rule**, every app built with it that started below every
app built without; the gap is broad (security headers, the server's version, common passwords, private pages cached,
sessions after sign-out, limits on wrong passwords). Own-code findings: no difference by the rule. **The harm:** four
apps built with `sv` did not start, three because the builder pinned a version of the password package `sv`'s prompt
names that does not exist (the prompt gives the right one), so the measure rests on the six that started. The tester
was not fully blind: eight of the ten copies built with `sv` still named it in a file the protocol left in place,
though `sv` signed in to every app that started in both arms. The builds with `sv` used it, 5 to 21 tool calls each.

## What they changed in `sv`

ADR-044 (the shown prompts reach the builder, and since 7 October at the start of every build); the specification's
sentences on settings, `signup`, `seed` and `admin`; ADR-048 (a citation corrected: V11.4.2 as well as V11.4.4);
ADR-052 (the install step); ADR-053 (another user's records, and *checked in part*); ADR-055 (three common
passwords, and the cross-site check on the signed-in pages). Each record says what in the trials led to it.

## What they taught about running trials

- **Count what a check could reach.** A check that only ever reports problems leaves no trace when it passes, so "0 of
  10" can be a clean app or a check that never ran. The recipe trial's scorer was corrected for this.
- **Score by the protocol's words.** The scorer reused from the first trial counted a running check as asked only when
  it said something; recounted on 7 October, two verdicts judged by shares moved, and none judged by counts
  (`library-trial/score_recount.py`).
- **No verdict from nothing.** A stopped run once printed "shown" from 0 of 0; the scorers now refuse.
- **A cost guard checks assumptions as well as spending.** The recipe trial's $0.60 guard, set from Haiku's costs,
  stopped a Sonnet arm at $0.65; the owner chose to go on at $0.80. And the credit itself ran out partway through the
  revision trial: 38 builds failed on billing, were set aside, and were run again once the owner had topped it up (its
  Amendment 1).
- **Read the signed-in count, not only the failures.** The scorers counted a started app as signed in unless `sv`
  said signing in had failed, which also counted apps whose seed crashed or that described no sign-in. Found by the
  Haiku 5.5 trial before its results merged (its Amendment 1), then recounted for every earlier trial from the
  committed run summaries (backlog 214): four builds changed (three in the revision trial, one in the recipe trial),
  and no verdict, arm or harm flag moved.
- **Check the claim against the code before writing it down.** Three statements were corrected before they reached
  anyone, and one after: the recipe trial first reported `same-site-redirects` as not reached, when the sign-in
  redirect is asked automatically; `library-trial/recipe.md` carries the dated correction.

## What they cannot show

The builders were three models of one vendor, through one tool, from briefs written for the trials; ten builds an arm is
enough to see a problem that is common go away, not to measure a small effect, and a prompt with no reading is
untested, not useless. `sv`'s checks are the measure throughout, so a fault no check reaches cannot be seen to change.
