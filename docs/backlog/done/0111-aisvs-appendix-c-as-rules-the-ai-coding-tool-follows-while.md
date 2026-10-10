# AISVS Appendix C as rules the AI coding tool follows while it writes the app

**Status:** done, as its markers read on 8 October 2026

Asked for by the
owner on 27 September 2026: Appendix C is better used as a reference while coding than as report
lines. Its 68 requirements are written for an auditor ("Verify that…"), and no check in `sv`
reaches any of them. About 20 are things the tool itself can do or avoid while writing code: keep
`.env` values out of the chat (AC.3.1), treat fetched pages and tool results as data and never as
instructions (AC.3.3, AC.3.4), run the check after each feature (AC.4.2), say when it touched
sign-in, access, cryptography, CI, or deployment files (AC.4.4), add only packages that exist
(AC.13.3), never merge or deploy its own work (AC.8.1), write GitHub Actions without
`pull_request_target` checkouts or persisted credentials (AC.12.1–AC.12.3). About 15 are the owner's
decisions, already asked through `securevibe_questions` and the security notes, and about 30 are
organization or pipeline infrastructure the applicability rules already set aside for most apps.

The plan, agreed with the owner the same day:
- A data file of those rules, each an imperative sentence citing the Appendix C requirements it
  comes from, about 1,200 tokens in all rather than the appendix's 5,800.
- Filtered by the app: a rule is given only when a requirement it cites applies, so CI rules reach
  only an app with a pipeline.
- `sv rules` writes them into `AGENTS.md` between markers, so a later run refreshes that section and
  leaves everything else in the file alone; other tools are pointed at it, each tried before it is
  written down.
- An MCP tool, `securevibe_guidance`, gives the rules for one topic when the tool is about to do that
  work (a CI workflow, a new dependency, content fetched from outside), and the server's opening
  instructions name it.
- **Credit where it is due:** every copy of the rules names OWASP AISVS 1.0 Appendix C, links to it,
  carries its license (CC BY-SA 4.0), and says the text was adapted. The share-alike terms reach the
  rules text, not the owner's code.
- **It credits nothing.** Handing the tool a rule is not evidence the rule was kept, so no requirement
  changes status because the rules were written.

**Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking. **Done the same
day:** 18 rules in `data/coding-rules.json`, `sv rules`, and `securevibe_guidance`, credited and
licensed on every copy. See DESIGN, "Appendix C as rules the AI coding tool follows while it codes".
Left open: trying which tools read `AGENTS.md` on their own, and whether a `@AGENTS.md` line in
`CLAUDE.md` is followed, before the walk-through says so.
