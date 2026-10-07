# The revision trial: protocol, written before it runs

After the independent reviews in `docs/prompts/reviews/` (7 October 2026), at the owner's word: the revised prompts and
the five new ones, tried where the problem each is for was common. Fixed before any build; a change after a result is
seen goes in "Amendments", dated, with its reason.

## How a build is made

As in `protocol.md` (the prompt-library trial): headless Claude Code 2.1.286 on the owner's API credit, no MCP server,
in a fresh folder; the plain brief with `sv init`'s specification at the top and the loop protocol's owner-away
sentence as its Amendment 5 has it; in a prompt's arm, the prompt's text at the end after "Follow this while you
build:". Two differences, for every arm alike: `git` is allowed (`--allow-git`), and the specification is the one on
`main` at the run, which ends with the prompts shown to work (ADR-044, "Later, 7 October"). Each build is checked by
`sv report --run`, one at a time, by one release build of `main`, its commit recorded.

So every arm, the no-prompt arm included, has the shown prompts at the start; a prompt's arm adds its own text, pasted.
The question each arm answers is what the pasted prompt adds to that.

## The arms

Ten builds an arm. Each prompt is tried on the model whose builds had its problem most in the loop trials' item 6: (counts are each prompt's own check, in the 9 Haiku and 10 Sonnet builds with no server; those builds did not have the shown prompts at the start that every arm here has, so these baselines are an upper bound)

| Arm | Model | Its check | Item 6's no-server builds with the problem |
|---|---|---|---|
| no prompt | Haiku 4.5 | (every rule below) | |
| `limits-without-asking` (new) | Haiku | `probe.failed-sign-ins-unlimited`, `probe.create-rate-unlimited` | 7 of 9 |
| `production-server` (new) | Haiku | `probe.version-disclosed`, `probe.content-type` | 8 of 9 |
| `isolate-the-window` (new) | Haiku | `probe.opener-policy-missing`, `probe.csp-no-report` | 8 of 9 |
| `security-contact` (new) | Haiku | `config.security-contact` (credits nothing) | 9 of 9 |
| `secrets-in-the-environment` (revised) | Haiku | the `secrets.` rules, `config.gitignore-covers-env` | 9 of 9 |
| `security-headers` (revised) | Haiku | `probe.security-headers`, `probe.private-page-headers` | 8 of 9 |
| `git-from-the-start` (revised) | Haiku | `config.secrets-file-committed`, `config.gitignore-covers-env` | 9 of 9 |
| no prompt | Sonnet 5.5 | (every rule below) | |
| `ai-feature-guard` (revised) | Sonnet | the three `probe.ai-*` rules | 10 of 10 |
| `isolate-the-window` (new) | Sonnet | as above | 10 of 10 |

110 builds. Left out, with the reason: `password-rules`, `password-hashing`, `database-placeholders`,
`same-site-redirects`, and `changes-from-own-pages` (their problems were rare in item 6, so this brief would give no
reading), and `files-under-own-names` (the club app takes no uploads, so its running check cannot be asked). Each
waits for a brief that tempts its shortcut.

## The measures and the rule

As in `protocol.md`: for each prompt, its problem among the builds its check could be asked of, against the same
model's no-prompt arm; **shown** when the no-prompt arm had it in at least 5 and the prompt's in at most 1; **not
shown** when the no-prompt arm had it in at least 5 and the prompt's in 2 or more; **no reading** below 5. Because the
no-prompt arm here already has the shown prompts at the start, a baseline below 5 means the start delivery has done
the work, and is reported so.

- **A revised prompt keeps `shown`** when its arm is shown, or when its no-prompt baseline is below 5 and its own arm
  has the problem in at most 1. Otherwise its revision is undone and the earlier text restored, said in the library.
- **Harm**, as before, beside the reading among apps that started; and two more the reviews named: an app that refused
  its own forms (`probe.own-forms-refused`), and an app that would not start for a key `sv run` cannot give it.
- **`security-contact`** is reported as what it is: a file, which says nothing about the app's security.

## Cost

About $0.25 a build without the server: about $28 for the 110, each capped at $1.50 ($165 at most). The owner approves
the size before the run; the run stops if the first ten average more than $0.60.

## Amendments

1. **7 October 2026, after the builds and before any result was read: 38 builds run again after the credit ran out.**
   The owner's API credit ran out during the eighth arm; the last 8 builds of `git-from-the-start` and all 30 Sonnet
   builds ended at once with "Credit balance is too low", before reaching the model. After the owner topped up, the
   same 38 were built again with the same script, `sv` and settings (`run_revision_rest.sh`), a few hours after the
   others. Builds were picked by the error in their transcripts, so the two of `git-from-the-start` that had finished
   stay. The stopped attempts are kept in the trial folder's `no-credit/`.
2. **7 October 2026, while scoring: "could be asked" as `protocol.md` defines it.** The scorer reused from the
   earlier trials counted a running check as asked only when one of its rules gave an answer. `protocol.md` says a
   running check could be asked when the app started, a signed-in one when `sv` signed in, and the AI checks when the
   AI feature answered; the scorer now says so (`score_revision.py`). Found because Sonnet's `isolate-the-window` came
   out "0 of 0": its rules only ever report a finding, so the builds it fixed were counted as not asked. A build with
   the problem always has a finding, so no count of builds with the problem and no verdict changed, only the totals.
   The earlier trials' totals for such rules were too small in the same way. Recounted the same day: the prompt-library
   trial's verdicts stand (its rule counts builds, as this one's does), but the delivery and at-start tests judge by
   shares, and in each the verdict for `private-pages-no-store` on Haiku moves from "not shown" to "no reading" (3 of
   7 and 3 of 8 builds without it had the problem, under half). Corrected in `delivery.md` and `start.md`.
3. **7 October 2026, while scoring: `security-contact`'s check.** The library lists no rule for it, since it credits
   nothing; as this protocol's table says, it is scored by `config.security-contact`, as a check of the code.
