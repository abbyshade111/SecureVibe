# The recipe trial (7 October 2026)

Run to `recipe-protocol.md`, fixed before any build: the recipe brief (`docs/prompts/trial-4/recipe-brief.md`), a
Flask app with pinned packages and `install = true`, the first trial of apps that use packages. Every build was
checked by `sv report --run` from one release build of `main`, `9833eacc`. **$18.09** of the owner's API credit:
stage 1 $7.41 (Haiku 4.5 $3.76, Sonnet 5.5 $3.65), stage 2 $10.68. No transcript holds the key.

Three things happened that the protocol did not plan for, each in its Amendments: stage 2 stopped at its cost
guard and went on at the owner's word; the scorer's "asked" counted checks that could not reach the feature they
are for; and the scorer gave a verdict from "0 of 0" before it was corrected.

## Stage 1: the baseline

| | Haiku 4.5 | Sonnet 5.5 |
|---|---|---|
| Wrote an app | 9 of 10 (one stopped to ask permission) | 10 of 10 |
| A settings file `sv` could read | 8 of 9 | 10 of 10 |
| Install step: failed (a pinned version that does not exist) | 2 | 0 |
| Started under `sv run` | 2 | 10 |
| `sv` signed in | 0 (first given as 1) | 10 |

*Recounted on 8 October 2026* (backlog 214; `recount_signed_in.py`): the one Haiku app counted as signed in had a seed
command that crashed, so `sv` had no accounts to sign in as; the scorer counted it because nothing said signing in had
failed. Corrected, `sv` signed in to no Haiku app, and the five prompts whose check needs signing in
(`password-rules`, `same-site-redirects`, `check-every-request`, `changes-from-own-pages`, `files-under-own-names`)
were asked of no Haiku build: 0 of 0, where `recipe-stage1.json` records 0 of 1. An arm needed at least 5 asked, so no
arm and no verdict moves.

**The install step's first real use worked**: every Sonnet app's packages were downloaded in the separate container
and the apps ran fenced. Its two refusals were right, and named the cause: Haiku pinned `pytest-junit==1.0.1` and a
similar package that do not exist.

**Haiku's apps mostly did not start.** Three crashed on their own code (a database setting never set, a security
add-on called wrongly, a Flask setup step in the wrong place), one used `build = "pip install …"` instead of
`install = true` (and `sv` said so), one stopped to ask permission, and one wrote a settings file `sv` could not
read. The builders could not install Flask on this computer, which the protocol stated before the run, so none could
try its app before handing it over; with the standard-library club app they could. So Haiku gave readings only from
the checks that read the code.

**Sonnet, per prompt** (builds with the problem, of the builds asked):

| Prompt | Sonnet | Reading |
|---|---|---|
| `password-rules` | **10 of 10** | an arm (every one a common password accepted; no app accepted a short password or changed one) |
| `production-server` | **5 of 10** | an arm (five ran Flask's development server, which sends `Werkzeug/3.1.3 Python/3.12.15`; five served through waitress or gunicorn unasked) |
| `password-hashing`, `no-shell-with-input` | 0 of 10 | no reading: done right unprompted, credited in every build |
| `sanitize-rich-text` | 0 of 10 | no reading: 9 of 10 used an HTML sanitizer unprompted |
| `changes-from-own-pages`, `check-every-request` | 0 of 10 | no reading: credited in every build; the record checks in full, as every app declared `update` and `delete` |
| `cross-site-access` | (0 of 10 at `/`) | **not reached at the tempted place**: the check sends its stranger `Origin` only to the health path, `/`, never to `/api/recipes`, though every app listed it among its private pages |
| `plain-error-pages` | 0 of 10 | no reading, and a weak one: the check is credited from a missing page's answer alone (gap analysis 1.6) |
| `same-site-redirects` | 0 of 10 | no reading: done right unprompted. The sign-in page's return address, the place the brief tempts, is asked of every app with a sign-in, listed or not (corrected below) |
| `files-under-own-names` | (3 asked) | **not reached**: 7 of 10 did not declare the photo upload |
| `database-placeholders` | (1 asked at the search) | **not reached at the tempted place**: the check asks the record's id and the query values of listed private pages; three apps listed a search page, and only one with a search term to ask |

Haiku: `production-server` 2 of 2 and `password-hashing` 1 of 8; every other prompt was asked of at most 2 builds,
or had no problem in the 8 whose code was read.

## Stage 2: the arms the rule named

| Prompt | Model | Without it | With it | Verdict |
|---|---|---|---|---|
| `production-server` (with its sentence of 7 October) | Sonnet | 5 of 10 | **0 of 9** | **shown** (Fisher p = 0.03) |
| `password-rules` | Sonnet | 10 of 10 | 8 of 10 | not shown |

- **`production-server`: every app switched to gunicorn** (5 of 10 without the prompt). One of the ten did not start:
  two gunicorn workers set up the same SQLite file at once ("database is locked"). One in ten is below the harm rule,
  and it is a fault of following the prompt, so the prompt gains a sentence for it, not yet tried. Marked shown at
  the owner's word.
- **`password-rules`: followed, and the verdict rests on one word.** All ten builds wrote a common-password list and
  refused what was on it, as the prompt asks; with no network, and nothing to install on this computer, each wrote
  its list from memory. `sv`'s check tries one common password, `123qweasdzxc`. The two lists that held it passed,
  one of 1,406 entries and one of only 443; the eight that did not failed, among them one of 20,340 lines. So the
  count says whether a list written from memory happened to hold that word, more than how good the list is: the
  check rests on one sample, the weakness the gap analysis found in V8.2.2 (a backlog item). A prompt that names a
  pinned package shipping a real list (`zxcvbn`, a ready-made wheel the install step can give the app) is the next
  thing to try.

## What follows

- **`production-server` is shown** (owner, 7 October 2026), and reaches every builder at the start (ADR-044).
- **`password-rules`: not shown**; try it again naming a package with a real list.
- **The brief should name the features `sv` can test.** Two prompts had no reading because the builders did not
  list their upload or their search page in `securevibe.toml`. A third,
  `cross-site-access`, because `sv`'s check asks only `/`: it should ask the API addresses the app lists too (a
  backlog item). The specification asks for
  them; the next brief, or the specification's wording, should make plain that a check can only reach what is listed.
- **Haiku cannot try a Flask app it cannot install.** The next trial with packages should either let builders install
  into a folder of their own (with the network that needs) or accept that Haiku's reading comes from the code alone.

## Files

`recipe-protocol.md`; `run_recipe1.sh`, `run_recipe2.sh`, `run_recipe2b.sh`; `score_recipe1.py`, `score_recipe2.py`;
`recipe-stage1.json`, `recipe-stage2.json`; `recipe-summaries.txt` (each checked build's summary).

## Correction, 7 October 2026

`same-site-redirects` was first reported here as not reached, because 8 of 10 apps listed no page under
`redirects`. That was wrong: the redirect check asks the sign-in page's return address of every app with a sign-in,
without its being listed (`crates/sv-check/src/signed_in/redirects.rs`), and that is the place the brief tempts. Every
Sonnet app had a sign-in, so the check reached all ten, and none sent the browser outside the app: no reading, done
right unprompted. `redirects` is for return addresses outside sign-in. So three prompts were not reached, not four.
Found while writing the specification's wording for the next pull request.
