# The trials, 5 to 7 October 2026

After the cut-off, the project turned from building `sv` to asking whether it changes what an AI coding tool builds.
Nine trials were run in three days: **464 builds, $150.53** of the owner's API credit. Each was run to a protocol
written before any build, and each has its own write-up, results files, scripts and scorers in `docs/prompts/`. This
file brings them together for the paper; `figure-trials.html` shows every pasted-prompt comparison, and is made from
the trials' committed results by `trials/make_figure.py`, so it cannot drift from them. Where a result was corrected
after it was first written, the corrected one is given and the correction is said.

None of this was measured the way the cut-off's analyses were: these are new experiments, not a recount of the
record. They also fall after the paper's cut-off (`157ddc3`), so nothing in the other files depends on them.

## How a trial is made

- **The builder:** Claude Code, run headless in a fresh folder, with Claude Sonnet 5.5 or Claude Haiku 4.5, told the
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
| **All** | | **464** | **$150.53** | | |

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
- **Check the claim against the code before writing it down.** Three statements were corrected before they reached
  anyone, and one after: the recipe trial first reported `same-site-redirects` as not reached, when the sign-in
  redirect is asked automatically; `library-trial/recipe.md` carries the dated correction.

## What they cannot show

The builders were two models of one vendor, through one tool, from briefs written for the trials; ten builds an arm is
enough to see a problem that is common go away, not to measure a small effect, and a prompt with no reading is
untested, not useless. `sv`'s checks are the measure throughout, so a fault no check reaches cannot be seen to change.
