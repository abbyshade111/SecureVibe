# A prompt library: the CSA guide's prompts, reworked, and new ones from what went wrong

**Status:** done, 9 October 2026

Asked
for by the owner on 3 October 2026, after a review of `sv` against the Cloud Security Alliance's
*Secure Vibe Coding Guide* (K. Huang, 9 April 2025): of its 53 checklist items, `sv` checks 12 and
part of 21, at commit `93b7bfa`. The review is the shared page
https://claude.ai/code/artifact/90a78da2-3fb3-4f12-96b0-b89c8e754fc1. **Claimed on 3 October 2026 by session
securevibe-e10**, at the owner's asking, in branch `claude/prompt-library`. Three things to settle before any
prompt is written:

1. **The guide's prompts are not copied as they stand.** Two reasons:
   - **Some are weak in ways that hurt a beginner.** "Generate a function that sanitizes user input
     to prevent XSS attacks" tends to produce a home-made sanitizer, when the safe answer is the
     framework's own escaping and a proven library (V1.2.1, V3.2.2, V1.3.1). Thirteen of the
     roughly sixty are requests for prompts ("give me prompts for…") rather than prompts.
   - **They are CSA's copyrighted text.** Copying about sixty of them needs CSA's permission or
     license terms, which nobody has checked yet; the Semgrep Rules License took the owner's own
     review. Rewriting each in our words, with a link back to the guide, avoids the question.
2. **The lessons from real builds make better prompts than the guide's.** From the owner's first
   build on 26 September 2026 and the review of it (see "What the owner's first build from
   scratch found in `sv`"):
   - Write `securevibe.toml` before any code, and delete a capability you are not sure of rather
     than leaving it `false`.
   - Never rewrite working code to silence a finding. If it looks like a false alarm, say so and
     leave the code.
   - Name a requirement in a test only where the test proves it, and read its wording with
     `securevibe_explain` first.
   - Put the app in git from its first commit, or the check for a committed secret never runs.
   - Let the app's AI provider address be set from the environment, so `sv`'s test model can
     stand in for it.
3. **Each prompt names the requirements it targets.** Then `sv` can offer the right prompt for a
   requirement that still has no evidence, through `sv prompts` and an MCP tool beside
   `securevibe_questions`. The citation guard that holds the rules to their requirements holds
   the prompts too, so a prompt cannot claim a requirement its words do not touch.

**How a prompt is known to work:** the check it targets, run on an app built with it, and failing
on one built without it. The same discipline as every other check here.
**The owner's decisions, 3 October 2026:**
1. **Our own words.** Every prompt is written fresh in plain language, crediting and linking to the guide where
   it inspired one. No CSA text is copied.
2. **The first batch:** about fifteen, the lessons from the owner's first build and prompts for the Level 1 areas
   `sv` checks most (secrets, access control, injection, headers, CORS, error pages, uploads).
3. **Both ways of getting them:** a page in `docs/` first, then `sv prompts` and an MCP tool.
4. **Each is tested before it ships:** the same small app is built twice by fresh helper agents in a throwaway
   folder, once with the prompt and once without, and `sv` checks both. A prompt ships only when its check
   passes on the build with it and fails on the build without. A lesson with no check that could show it
   working is listed apart, not shipped as a tested prompt.
**First batch tried, 3 October 2026:** nine prompts, in `data/prompts.json` and `docs/PROMPTS.md`. Two shown to
work (the settings file first, and git from the first file). Seven not shown: for four the build without the
prompt already did the safe thing, and for three `sv` raised a false alarm on the build that followed the prompt
(now an item under "Next"). Still to do: the rest of the batch (access control, headers, CORS, error pages), a
second app brief where the plain build does the unsafe thing, and `sv prompts` with its MCP tool.
**The rest of the first batch claimed on 4 October 2026 by session securevibe-e10**, at the owner's asking, in
branch `claude/prompts-batch1-rest`: four prompts (security headers, cross-site access, error pages, and who may
open what), each tried with `sv report --run` on the club app the design-time prompts were tried on
(`docs/prompts/trial/brief.md`), with and without the prompt.
**Done the same day** (`data/prompts.json`, `docs/PROMPTS.md`). All four were tried and not shown: both builds
without a prompt already passed `probe.security-headers`, `probe.cors-any-origin`, `probe.error-detail-leak`,
and the four access checks, every run signed in and answering all 40 requests. A copy of one of those builds with
each fault put back (headers removed, `Access-Control-Allow-Origin: *`, a stack trace on errors, the admin page
open to members) was caught on every one, so the clean results are passes and not blind spots. The guide has no
item on headers; that prompt cites ASVS V3.4 instead. The runs needed the builds under the home folder, which is
all Colima shares with containers: `sv` said so and reported the first attempt not assessed.
**The owner's decision, 4 October 2026:** prompts not shown to work stay in the library, in full, marked as not
tested, rather than set aside. Done the same day in `docs/PROMPTS.md` and `data/prompts.json`.
**`sv prompts` and its MCP tool claimed on 4 October 2026 by session securevibe-e10**, at the owner's asking, in
branch `claude/prompt-library-untested`: a command and a `securevibe_prompts` tool that read `data/prompts.json`,
give each prompt with its status (tested or not), and can pick the prompts for one requirement; and a test that
holds each prompt's requirements to what its check's rules cite. Prompts in other files (the design-time page)
join when they are written in the same form.
**Done on 4 October 2026** (DESIGN, "Prompts the AI tool can fetch"): `sv prompts [--requirement ID]` and
`securevibe_prompts` give the library, the prompts shown to work first, each marked shown or not tested where the
person reads it; `tools/coverage.py` holds each prompt's requirements to its rules' citations. Not done: offering
the prompts for the requirements an app still has no evidence for, which needs a report first.
**Offering the prompts for the requirements an app still has no evidence for claimed on 7 October 2026 by session
securevibe-e9**, at the owner's word ("go ahead with the prompt item"), in branch
`claude/securevibe-e9-prompts-for-gaps`: `sv prompts --app <folder>` and `securevibe_prompts` with a `path` read the
app's last report (`securevibe-report/report.json`), and offer the prompts whose requirements it shows unproven or
failing, those shown to work first, each saying which of the app's requirements it is for. With no report, they say
to make one first. The feature brief and the guidance (ADR-044) are not touched. Read on `main` just before this
claim: no other session had claimed it.
**Done the same day** (DESIGN, "Prompts for what an app's last report shows unproven"). A real `sv report` and
then `sv prompts --app` hold the report's shape to what is read. Every part of the 3 October decisions is now built.
**Claimed on 4 October 2026 by session securevibe-e10**, at the owner's asking, in branch
`claude/prompts-design-and-brief-2`: (a) `sv prompts` and `securevibe_prompts` also give the design-time prompts
in `data/design-prompts.json`, with the Secure by Design controls each helps answer, and `tools/coverage.py` holds
them to their rules' citations as it does the others; (b) a second app brief, written the way a beginner might ask,
whose plain build takes the shortcut the four prompts not yet shown were written against (a key pasted into the
chat, a command built from a title, passwords with only the standard library, formatted notes), built with and
without each of those four prompts.
**Done the same day** (DESIGN, "The design-time prompts in `sv prompts`, and a second test app"). (a) `sv prompts`
and `securevibe_prompts` read both files; `--requirement` takes a Secure by Design control too. Holding the
design-time prompts to their rules' citations found two naming a rule whose requirement they had deliberately not
claimed (V16.3.2, V7.3.2); each now says so, with the reason, under `not_claimed`. (b) The second app did not tempt
the plain build: it read the pasted key from the environment, ran the program without a shell, hashed with
`scrypt`, and cleaned the editor's HTML with `sanitize-html`, and `sv` found nothing in any of the five builds. The
four prompts stay not tested. Putting each shortcut back was caught for the key and the command, and missed for
the sanitizer: two new items under "Next".
**Marked done 9 October 2026 by session securevibe-e9**, from the roadmap (Phase 4, item 2), read against `main`: every part of the owner's decisions of 3 and 4 October has a done note above (the first batch, the rest of it, `sv prompts` and its MCP tool, the prompts for an app's unproven requirements, the design-time prompts in `sv prompts`, and the second app brief). The status line's "0 of 7 parts done" was the 8 October split reading the numbered decisions as parts. The new items the second app brief raised are their own entries.
