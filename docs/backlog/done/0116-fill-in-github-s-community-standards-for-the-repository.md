# Fill in GitHub's community standards for the repository

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 26 September
2026, from the repository's *Insights → Community standards* page. **Claimed on 27 September 2026 by
session securevibe-e8**, at the owner's asking ("continue to work off items in the backlog, your
choice"). **The owner's choices, the same day:** the standard Contributor Covenant, with reports
through GitHub (the repository's private reporting form, since GitHub has no private messages).
**Done the same day:** `CODE_OF_CONDUCT.md` (the Contributor Covenant 2.1, word for word from its
source, with the reporting route filled in), `CONTRIBUTING.md` (the build and test commands CI runs,
claiming a backlog item, and the rules every change keeps), `.github/ISSUE_TEMPLATE/` (a bug report that
asks which `sv`, the command, and what the report said it did not examine, and turns security problems
away to the private form; an idea that asks how `sv` would know; and the links on the new-issue page),
and `.github/pull_request_template.md` (what changed, how it was verified, what was not, and what it
closes), linked from the README. What remains is the owner's to check: the *Community standards* page
should now show every item. Done: description,
README, license, and the security policy (`SECURITY.md`, `sv`'s own since 27 September 2026). Missing:
- **Code of conduct** (`CODE_OF_CONDUCT.md`). Which one is the owner's choice; the Contributor
  Covenant is the usual default. It names a contact for reports, and that address is the owner's to give.
- **Contributing guide** (`CONTRIBUTING.md`): how to build and test `sv`, the checks a change must
  pass, and the rules that already bind every session and are worth stating for people too (claim a
  backlog item before starting it; evidence tiers are honest; American English with the Oxford comma).
- **Issue templates** (`.github/ISSUE_TEMPLATE/`): at least a bug report and an idea. A bug report
  for a security tool should ask for `sv`'s version, the command, and what was not examined, and
  should send anything that looks like a vulnerability in `sv` itself to the security policy
  instead of a public issue.
- **Pull request template** (`.github/pull_request_template.md`). Worth care: every session writing
  pull requests here fills in whatever template exists, so its sections become the shape of every
  PR description. Keep it short: what changed, how it was verified (with what was *not* verified),
  and the backlog entry it closes.

**Ready to start:** the move has landed, so the files describe `sv` and go at the root (or in
`.github/`). The security policy names `sv` now; the issue template's security link can point at it.
