# Poll: two questions about the v1 archive

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Decided on 27 September 2026; see the end of the entry. Opened on 27 September 2026 at the owner's asking
("poll the group"), by session securevibe-e2. **Not claimed, and nothing is built until the owner
decides.** Both questions were left open by the move (see "Where it stands" above, and the v1
builder's "v1's CI needs no decision" and "The evaluation harness" notes). Every session and person
is asked to add a view under "Views" below, each under its own name, as its own commit on this pull
request's branch or as a comment on the pull request. Disagreeing is useful; so is "no view".

**1. Should CodeQL keep scanning v1's code?** What is true today, checked rather than assumed:
`main`'s `codeql.yml` scans `main` only, and `v1`'s own copy of the file runs only on pushes to
`main` and on a schedule, and GitHub runs scheduled workflows from the default branch alone, so
**v1 is not scanned at all now.** The tags `v1-paper` and `v1-final` are protected by a ruleset
(checked the same day: active, `refs/tags/v1-*`, updates and deletions refused, no bypass).
- *A. Leave it unscanned.* v1 is frozen for the paper; no one is meant to deploy it, and an alert
  nobody will fix is noise. Costs nothing.
- *B. Scan it once a week.* A small patch on the `v1` branch (never on the tags) adding `v1` to
  its CodeQL triggers, and the schedule moved into `main`'s file, since only `main`'s schedule
  runs. Alerts would show in the Security tab under the `v1` branch. Useful only if someone would
  act on them, for instance by warning readers of the paper who run v1's code.
- *C. Scan it once, now.* One run by hand, the result recorded in `ARCHIVED.md` on the `v1` branch
  as "the known issues at archive time", and no scanning after.

**2. Should `sv` keep v1's five sample answer sets (`evals/golden/*.json`)?** They are five saved
sets of v1's wizard answers, deliberately varied (sign-in or not, uploads, AI, payments; a clinic,
a habit tracker, a home log, a marketplace, a team inventory). They live on the `v1` branch and
at both tags. Nobody has checked whether `sv`'s `securevibe.toml` can express each of them.
- *A. Leave them with v1.* Nothing is lost; they stay reachable at the tags.
- *B. Turn them into five `securevibe.toml` test cases for `sv`.* They would test which
  requirements apply to varied apps (sensitive data raising the level, uploads, AI, payments),
  which `sv`'s tests cover today with hand-made manifests. Some work, and only worth it if they
  catch something the current tests would not.
- *C. Copy them into `sv` as examples of how to describe an app*, with no tests attached.

**Session securevibe-e2's leaning, one view among others:** 1C then leave it (one honest record of
what the archived code carries, without an alert list nobody owns), and 2B only if a quick check
shows two or more of the five exercise a condition no current test does; otherwise 2A.

**Views.** None came in. The other sessions were not running while it was open.

**The owner's decision, 27 September 2026: as leaned above** ("go ahead with your
recommendations"). Taken up by session securevibe-e2 the same day.
- **1C.** A patch on a branch cut from `v1` (`claude/v1-codeql-once`) keeps CodeQL's results as a
  run artifact as well as sending them to the Security tab, and the workflow was started once by
  hand on that branch (run 36336131545): both legs, JavaScript and TypeScript (576 TypeScript, 8
  JavaScript, 7 HTML, and 3 workflow files read) and Rust, finished. **No open alerts:** the owner
  read the Security tab filtered to that branch, 0 open and 12 closed (matching alerts dismissed or
  fixed before, not re-examined one by one), since this environment could neither download the
  artifact nor read the tab. Recorded in `ARCHIVED.md` on the `v1` branch (#272). Nothing scans v1
  again.
- **2A.** The quick check found none of the five sets exercises a condition no current `sv` test
  does: between them they use sign-in, uploads, AI, email, payments, scheduled jobs, a public API,
  outside services, and the level-2 data categories, and `real_data.rs` already walks every
  condition. What they carry beyond that (roles, retention, region, business impact) is not
  something `sv`'s manifest asks. They stay with v1, reachable at both tags.
