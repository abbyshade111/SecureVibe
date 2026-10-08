# The reports

Everything else here prints to a terminal, where a line scrolls past and is gone. A report is kept, sent
to somebody, and read by a person who was not there when it ran — which is why it is the most dangerous
thing in the workspace to get wrong. A terminal line saying *not assessed* that nobody reads costs
nothing; the same omission in a document somebody files as evidence of a security review is how an app
ships believing it was checked.

`sv report` writes `report.html` (one file, no external requests), `compliance.md`, `security.md`,
`findings.sarif` and `report.json`. Three rules, each with a test that fails when it is broken:

- **There is no pass.** An applicable requirement is *needs attention*, *checked*, or *not verified*.
  `Checked` means one automated check looked at it and was satisfied — deliberately not called a pass,
  because one config check being happy is not an ASVS requirement met, and the report says so in the
  words around the number. A finding always outranks a satisfied check on the same requirement.
- **What was not examined comes first.** In both the security report and the compliance report, before
  anything that was found. A list of findings read on its own reads as the whole truth about the app,
  and it is only the truth about the part that was looked at.
- **A finding about a requirement the app is not being assessed against gets its own section** rather
  than being dropped. It means either the requirement was excluded when it should not have been, or a
  check is citing a requirement that has nothing to do with it, and both are worth a look.

### What was examined, for a program (28 September 2026)

`gaps` tells a person what was not examined, in sentences. A program reading `report.json` needs the
same thing in a form it can act on: the owner's cato-pipeline turns `sv` findings into a plan of action
and closes an item when its finding stops appearing, and from `gaps` alone it could not tell a finding
that was fixed from one nobody looked for this time. A tool that did not run, a check that could not
read what it needed, or code rules silenced by a language without a parser all make findings disappear.

So `report.json` carries `examined`: one entry per family of findings, each with `rules` (the start of
every `rule_id` it speaks for: `bandit.`, `ast.`, or one check's whole id), a `state`, and, unless it
ran in full, `why`. **The longest entry that a finding's `rule_id` starts with decides for it, and a
finding no entry matches was not looked for.** The states:

- `ran`: it looked at everything it reads. A finding of this family missing from the report was looked
  for and not found.
- `partly`: it looked at some of the app. A missing finding may be in the part it did not read.
- `not-run`: it did not look.
- `nothing-to-examine`: there was nothing of its kind to look at, such as a tool for a language the app
  does not use. Without this, removing an app's last Python file would leave Bandit's findings looking
  unexamined forever.

The entries are decided where the gaps are, from the same facts, so the two cannot disagree: a symbolic
link nothing followed leaves every check that reads files `partly`; an unopened or unparsed file, or a
language with no parser, leaves the code rules (`ast.`) `partly`; a code rule whose query would not
compile, or that has not been taught a language present, gets an entry of its own; a check that could
not run (`config.secrets-file-committed` outside git) gets a `not-run` entry of its own under a family
that ran; known vulnerabilities (`advisory.`) ran only when the comparison covered the whole app, as
`sv audit` counts it; an outside tool that was told to skip part of the app is `partly`; the running
app (`probe.`) is never more than `partly`, because what sits behind a sign-in and the requirements no
question reaches are always in the gaps. Families this list does not name are not looked for, as far as a program
can tell, which is the safe reading. (Since 5 October 2026 it names `tests.`, `design.`, and `hand.` too: "A review
names one finding, and says whether its rule looked".) Each of these
has a test in `crates/sv-cli/tests/examined.rs` or beside the code, and removing each guard turns its
test red.
