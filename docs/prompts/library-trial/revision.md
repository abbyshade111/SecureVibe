# The revision trial (7 October 2026)

Run to `revision-protocol.md`, decided before any build: 110 headless Claude Code builds of the club app, no MCP
server, `git` allowed, the specification from `main` (which ends with the prompts shown to work, ADR-044), ten builds
an arm. Every build was checked by `sv report --run` from one release build of `main`, `eebb24d9` (the revisions'
merge). **$35.28** of the owner's API credit: $22.57 for the 80 Haiku 4.5 builds, $12.71 for the 30 Sonnet 5.5
builds. No transcript holds the key.

**Two things happened that the protocol did not plan for**, both in its Amendments:

1. **The credit ran out partway**, stopping the last 8 builds of `git-from-the-start` and all 30 Sonnet builds before
   they reached the model (each ended at once with "Credit balance is too low", costing nothing). After the owner
   topped up, those 38 were built again, a few hours later, by the same script, `sv` and settings
   (`run_revision_rest.sh`). The stopped attempts are kept, not deleted, in the trial folder's `no-credit/`.
2. **The scorer reused from the earlier trials counted a running check as asked only when one of its rules said
   something.** The protocol says a running check could be asked when the app started. For a rule that only ever
   reports a finding, the old count left out every build the prompt had fixed: Sonnet's `isolate-the-window` came
   out as "0 of 0". Scored now by the protocol's words. A build with the problem always has a finding, so this
   changes no count of builds with the problem and no verdict here, only the totals. The delivery and at-start tests
   judge by shares, so there it moves one verdict each (Amendment 2).

## Results, by the protocol's rule

| Prompt | Model | Without it | With it | Verdict |
|---|---|---|---|---|
| `isolate-the-window` (new) | Sonnet | 10 of 10 | **0 of 10** | **shown** |
| `security-contact` (new) | Haiku | 8 of 8 | **0 of 9** | **shown** (credits nothing) |
| `isolate-the-window` (new) | Haiku | 7 of 7 | 4 of 10 | not shown |
| `production-server` (new) | Haiku | 7 of 7 | 8 of 8 | not shown |
| `limits-without-asking` (new) | Haiku | 4 of 5 | 1 of 6 | no reading |
| `secrets-in-the-environment` (revised) | Haiku | 4 of 8 | 1 of 7 | no reading; revision kept |
| `ai-feature-guard` (revised) | Sonnet | 3 of 10 | 0 of 10 | no reading; revision kept |
| `security-headers` (revised) | Haiku | 0 of 7 | 0 of 7 | no reading; revision kept |
| `git-from-the-start` (revised) | Haiku | 0 of 8 | 0 of 10 | no reading; revision kept |

Counts are builds with the problem, of those the prompt's check could be asked of. "Without it" is the model's arm with
no prompt pasted, which still has the shown prompts at the start of its specification.

**Harm: none by the rule.** No prompt's arm started fewer apps or was signed in to less often than the arm without it,
by three or more; no median of running-app checks answered fell by five or more; no app refused to start for a key
`sv run` cannot give it, and none refused its own forms.

*Recounted on 8 October 2026* (backlog 214; `recount_signed_in.py`, `signed-in-recount.json`): the scorer counted a
started app as signed in unless `sv` said signing in had failed, so three Haiku builds that set no `[stack.run.users]`,
which `sv` therefore never signed in to, were counted as signed in. Corrected, one arm each signs in once less:
`isolate-the-window` 9 of 10 (not 10), `secrets-in-the-environment` 5 (not 6), `security-headers` 5 (not 6). None of
those prompts' checks needs signing in, so no count of builds asked or with the problem moves, no verdict moves, and
there is still no harm by the rule.

## What lies under the verdicts

- **The prompts at the start are doing the work for the revised four.** In the loop trials' item 6, before any prompt
  was given at the start, Haiku's apps had missing headers in 8 of 9 and an unprotected `.env` in 9 of 9, and Sonnet's
  AI feature all three faults in 10 of 10. Here, with the shown prompts at the start and nothing pasted, Haiku's
  headers were missing in **0 of 7**, `.env` was committable in **0 of 8**, and Sonnet's AI feature had a fault in
  **3 of 10**. (Haiku's secrets count without a prompt, 4 of 8, is all one rule reading the made-up passwords of
  sample users in `seed.py` and the tests; the arm with the prompt had one such, in `seed.py`.) So the baselines fell below five and the rule gives no reading; each revised prompt pasted on top had the
  problem in at most one build, so by the protocol each revision is kept. The comparison with item 6 is across trials
  (item 6 had no `git` and an older `sv`), so it shows the direction, not a measured effect.
- **`ai-feature-guard`'s hidden-characters part now arrives.** In the at-start test (`start.md`) a reply's hidden
  characters still reached the page in 9 of 10 Sonnet apps. Here, with the revised prompt at the start, 3 of 10 had
  any of the three faults, and with it pasted too, none.
- **`isolate-the-window`: followed in every build read, and on Haiku still missed on error pages.** Builds 1, 4 and 7
  of both models set both headers in the one helper every page goes through, as the prompt asks. In Haiku's build 7,
  Python's own error pages (`send_error`, for 403 and 404) do not go through that helper, so they went out without the
  window header, and `sv` checks every page. Sonnet's apps did not leave that gap. A line for the prompt, to try next:
  "Python's built-in server writes its own error pages; send the headers on those too, or write the error pages
  yourself."
- **`production-server`: the content type fixed, the version not.** Without the prompt 3 of 7 apps sent a body with no
  or a wrong `Content-Type`; with it, 0 of 8. But every Haiku app in every arm told the world its server's version,
  because the brief asks for Python's standard library, so the builders kept its built-in server, which sends
  `Server: BaseHTTP/0.6 Python/3.x` on every answer. The prompt names gunicorn and asks for no version in any header,
  but not how to do that on the built-in server: set `server_version` and `sys_version` on the request handler. The
  prompt assumed a framework this brief rules out; the fix is that one sentence, to try next.
- **`security-contact` works and says nothing about security.** Builds 1, 4 and 7 each wrote a `SECURITY.md` and
  served `/.well-known/security.txt`; `sv` found no missing contact in any of the nine it could read, and found it
  missing in all eight without the prompt. `sv` reports its absence as a low
  finding and credits no requirement for its presence, on purpose.
- **`limits-without-asking`: no reading, and a good sign.** The problem was in 4 of the 5 Haiku apps `sv` could sign in
  to without the prompt, one short of the rule's five; with it, 1 of 6 (Fisher's exact test, p = 0.08). Builds 1, 4
  and 7 each wrote the limits into `security-notes.md` under "Business Limits"; builds 1 and 4 also under the sign-in
  heading the prompt names, and build 7 under "Sign-in Rate Limiting".
- **Settings files `sv` could not read: 12 of 80 Haiku builds (15%), none of 30 Sonnet**, the same rate as the
  delivery test's Part A (3 of 20). Six put `admin` or `seed` under `[stack.run]` (they belong under
  `[stack.run.users]`), three wrote `ai = true` under `[capabilities]` (it is `enabled = true` under
  `[capabilities.ai]`), and three made a typing slip. A build `sv` cannot read is not one a running check can be asked
  of, so these count in no arm's totals; every arm kept enough builds to be scored.

## What follows

- **Marked shown, at the owner's word (7 October 2026):** `isolate-the-window`, with Haiku's 4 of 10 recorded beside it,
  and `security-contact`, recorded as crediting nothing. Both now reach every builder at the start (ADR-044).
- **`production-server` and `limits-without-asking` are not shown.** The first waits for its one sentence on the
  built-in server; the second for a brief whose baseline is higher.
- **Two sentences for the specification**, from the unreadable files: where `admin` and `seed` go, and how to turn on
  the AI capability. Both in the backlog.

## Files

`revision-protocol.md`; `run_revision.sh`, `run_revision_rest.sh`; `score_revision.py`; `revision-verdicts.json`;
`revision-summaries.txt` (each checked build's summary).
