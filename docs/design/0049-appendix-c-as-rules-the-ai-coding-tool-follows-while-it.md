# Appendix C as rules the AI coding tool follows while it codes (27 September 2026)

Asked for by the owner: OWASP AISVS 1.0 Appendix C, *AI-Assisted Secure Coding*, is better used as a
reference while the app is being written than as lines in the report. Its 68 requirements are
written for somebody auditing an organization ("Verify that…"), and no check in `sv` reaches any of
them. Read one by one, they fall into three groups:

- **About 20 the coding tool itself can act on while it writes code:** keep keys and people's data out
  of the chat (AC.3.1, AC.3.2), treat fetched text and tool results as data and never as instructions
  (AC.3.3, AC.3.4, AC.11.1–AC.11.3), check after each feature and never weaken a check (AC.4.2,
  AC.4.3), leave review to the owner and name the security-critical files (AC.4.1, AC.4.4, AC.4.5),
  add only packages that exist (AC.13.3), never merge, deploy, or change the guard rails on its own
  (AC.8.1–AC.8.4), write CI workflows that keep secrets from forks (AC.12.1–AC.12.3, AC.12.5,
  AC.12.7, AC.7.1, AC.7.2), say what it generated (AC.10.1), and send a leaked key to be
  replaced (AC.14.1, AC.14.2).
- **About 15 are the owner's decisions** (a written workflow, how the tool was chosen, a playbook for
  an incident), and are already asked through the design questions and the security notes.
- **About 30 are pipeline and organization infrastructure** (signed provenance, review bots,
  screening outside contributions, runner isolation), which the applicability rules already set aside
  for an app that says it has no pipeline or outside contributors.

`data/coding-rules.json` holds the first group as 18 rules, each one imperative sentence citing the
requirements it comes from, grouped under nine topics: about 1,000 tokens, against the appendix's
5,800, small enough to live in every conversation. `crates/sv-check/src/coding_rules.rs` reads them.

**Who gets which.** A rule is given unless every requirement it cites does not apply to the app, by
the same applicability rules the report uses; one that still applies is enough to keep it. So an app
whose `securevibe.toml` says it has no CI pipeline gets no GitHub Actions rules, and the text says
how many were left out. Without a `securevibe.toml` yet, the first step of a new app, every rule is
given. One rule is given to every app whatever applies, and says why in the data: "only packages that
exist" cites AC.13.3, which is written about outside contributions, but a coding tool naming a
package that does not exist, or a look-alike of one that does, is the same risk arriving from the
tool itself. A rule marked that way without a reason is refused at load.

**Two ways to the tool.**

- `sv rules [PATH]` writes them into the app's `AGENTS.md`, the file many coding tools read before
  they work in a folder. It writes only between its own two markers: a file with none gets the
  section after whatever the owner wrote, a later run replaces only that section, and writing the
  same rules again changes nothing. One marker without the other, or the two out of order, is
  refused and the file left as it was, since guessing where the section ends could delete the
  owner's writing. `--print` shows the rules instead.
- `securevibe_guidance`, the MCP server's eighth tool, gives the same rules, for all topics or one,
  as text and as structured content. The server's opening instructions tell the tool to call it
  before it starts writing code, and again with a topic before work in that area. The topics in its
  schema are tested against the data file's, so neither can gain one the other lacks.

Which tools read `AGENTS.md` on their own, and whether Claude Code follows a `@AGENTS.md` line in
`CLAUDE.md`, has not been tried here yet; the README says so.

**Credit, on every copy.** Every rendering, in `AGENTS.md`, from `--print`, and from the MCP tool for
one topic or all, ends with the same paragraph: adapted from OWASP AISVS 1.0 Appendix C, by the
OWASP AISVS project and its contributors, with a link to it, licensed under CC BY-SA 4.0 with a link
to the license, what was changed, and that the adapted text is shared under the same license, which
does not reach the app's own code. The MCP tool's structured content carries the attribution as
fields too. The README says the same in its own section.

**Corrected the same day:** "least-privilege-workflows" first cited AC.7.4 as well. AC.7.4 names
`permissions:` blocks, but asks that *changes* to them get dual control and a security-team review,
not that they be small; the workflow check read it the same way and cites nothing for the token's
permissions. The citation is gone, and the rule rests on AC.12.2 and AC.12.3.

**It credits nothing.** Handing the tool a rule is not evidence that it was kept. No requirement's
status reads the rules, the report does not mention them, and the text itself says they are
instructions and not a check.

**Checked like every other citation.** Each rule cites its requirements with a phrase naming what
the two have in common, and the citation guard holds that phrase against the requirement and against
the rule, as it does for the threat model. Its first run caught seven phrases that shared nothing
with the rule they joined, every pairing right and every phrase too narrow: the same lesson as the
threat model's, found before anything shipped. The phrases were rewritten, and one rule now says
"secret" where the requirement does.

**Tested.** The module's own tests (who gets which, the always-given rule, the credit on the whole
text and on one topic, each rule naming its citations, the size, and the four ways an `AGENTS.md`
can be found); the MCP tool (the topics, a topic with its credit, what is left out for an app without
a pipeline, an unknown topic, the opening instructions); `sv rules` through the binary (beside the
owner's text and again after it, filtered by the manifest, `--print` writing nothing, broken markers
leaving the file alone); and the image smoke test, which now asks the published image for the rules
and their license. Thirteen breaks were made in turn, and each turned two or more tests red; see the pull request.
