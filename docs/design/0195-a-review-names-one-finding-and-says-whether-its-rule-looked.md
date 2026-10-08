# A review names one finding, and says whether its rule looked (5 October 2026)

Two items of the deep review, done together because both are about how a `[[finding-review]]` entry finds its
finding. **R3**: an entry that matched nothing was always told "no finding matches it any more ... or the finding is
gone and the entry can be removed", also when its rule had not run. On family-hub, 7 of the 25 entries were for
`tests.name-does-not-match-requirement`, which is reported only when `--run` runs the app's tests, and a plain
`sv report` told the owner their findings were gone. **A2**: the fingerprint was a hash of the rule, the file, and the
flagged line's text, so two identical lines (`cur.execute(sql, (uid,))` in two functions) shared one, and a review of
one covered both; and a change to the line that sets the value (`sql = "...?"` becoming `sql = "..." + user`) left the
false alarm standing.

**Three messages, from what the report already knows.** An entry that matches no finding now says one of:

- *gone*: the check that reports its rule looked at its file, so the line changed (now also: a line above it that
  sets a value it uses) or the finding is gone and the entry can be removed;
- *not looked for this time*, with why: it needs `--run` or `--tools`, the file did not parse cleanly or was not
  opened, there is no parser for its language, the rule has not been taught it. "This is not a sign the finding was
  fixed: keep the entry";
- *unknown to this version*: `sv` has no such rule, so nothing in it could have found it; also "not a sign the
  finding was fixed".

Which one is decided from `examined` (DESIGN, "What was examined, for a program"), so the message and `report.json`
cannot disagree; for the checks that read files (`ast.`, `secrets.`, `config.`), from whether they read the entry's
own file, since a symbolic link elsewhere does not make a finding in this file unknowable. `examined` gained three
entries to make that possible: `tests.` (ran when the suite passed, `partly` when it failed and its runner's report
said which tests passed, `not-run` otherwise, with why), and `design.` and `hand.`, which read the owner's answers on
every run. A rule is unknown when its family is neither `sv`'s own nor an outside tool's, and, for the two families
`sv` reads from `data/` (`ast.` and `secrets.`), when the rule itself is not there. For the checks written in Rust
(`config.`, `probe.`, ...) and the outside tools, whose rules are not listed anywhere `sv` can read, a misspelled
rule under a known family reads as *gone* when its family ran; that is a limit, said here. The report's and
`report.html`'s paragraph over these entries says that a not-looked-for or unknown entry is not a sign of a fix, and
what the AI coding tool is told over MCP adds "never remove it or tell the owner the finding is gone".

**Today's fingerprint** (`crates/sv-check/src/review.rs`, `fingerprint`) is `v2-` and sixteen hex characters of
SHA-256 over the rule, the file, the trimmed line, the lines above it that set a name it uses, and which of the lines
with all of that the same it is, counted from the top. For each name on the line, the lines kept are the nearest one
above that assigns it (`=`, `:=`, a declaration, a type after a colon), and any between that add to it (`+=`, `.=`,
`||=`, up to eight). It is read as text, the same in all fourteen languages, without a parser: a keyword argument or
an `x = ` inside a string above counts as an assignment too. That only adds lines to watch, so a false alarm comes
back to be looked at more often, never less. Moving the line, adding lines elsewhere, or a comment keeps the
fingerprint; changing the line, or a line that sets what it uses, ends it. The enclosing function was the other
choice the review offered; it would have needed a parser per language and still not noticed the assignment changing.
**A limit of the occurrence count**: an identical line with identical assignments added above an existing one takes
the earlier one's number, so its entry moves to the new line and the old one comes back to be looked at. Nothing is
hidden that was not identical in every way the fingerprint reads. A finding with no line of code (a probe, a
settings check) keeps the fingerprint it had, from its title.

**Entries written before this keep working.** A fingerprint of sixteen hex characters and nothing else is the earlier
form, and is matched as it always was, by the line's text, when exactly one finding is on a line with that text; that
covers PR #604's entries naming a rule merged into another finding as well. Where several findings are on lines that
read the same, it matches none of them and says so: "its fingerprint is in the form `sv` used before 5 October 2026,
which named a line by its text alone, and 2 findings are on lines that read the same (lines 24 and 50), so which one
it means cannot be told", with what to do. Before, it silently took the first. One entry now matches one finding.
**Seals still verify**: the seal covers the entry's fields as written, and the report never rewrites an entry, so a
sealed entry in the earlier form counts exactly where it named one finding, with "Recorded through `sv review` on
this computer" as before; it never falls into "the seal does not match". `sv review` writes today's fingerprint in
place of an earlier one that names one line, when the person records an entry that did not yet count, and seals it
over that; one that names several lines it leaves as it is, saying why.

**How it meets R11** ("One entry answers for one finding", merged the same day): R11's rule decides which entry
answers for which finding, in either form: each entry that counts takes the first finding it matches that no earlier
entry has taken, a repeat adds nothing, and a contradiction leaves the finding standing. The one case where the two
disagreed, an entry in the earlier form matching identical lines, the owner decided on 5 October 2026: it answers for
none of them and says so, rather than taking the first (ADR-023). A repeat or a contradiction is never told its
finding is gone: its finding is there.

**Measured on family-hub** (a copy, nothing of the owner's changed): of the 25 entries, the 7 for
`tests.name-does-not-match-requirement` now say "not looked for this time (the app's own tests run only with
--run)"; 16 match the one finding each matched before; 2 are on lines that read the same (two lines in
`reminders.py`, three in `test_breached.py`) and say so; 3 say gone, their rule having read their file and found
nothing there. None was sealed, so none counted before or after: each still asks for `sv review`. Measured again
after merging R4: the three entries for `secrets.credential-assignment` (in `account.py`, `test_breached.py`, and
`test_mfa.py`) were written over the line as written and now say they were recorded by an older `sv`, as R4 decided,
so 11 match as before, 1 is on identical lines (`reminders.py`), 3 are gone, and 7 were not looked for.

**For a program reading `report.json` or SARIF**: every finding on a line of code has a new fingerprint, so a tool
that tracks findings by it (GitHub's code scanning reads `partialFingerprints`) sees each once as new. The SARIF key
stays `svFingerprint/v1`; the value says its form.

How it is held: in `review.rs`, `identical_lines_each_need_their_own_review`,
`a_change_to_the_line_that_sets_its_value_ends_the_review_and_others_do_not`,
`an_entry_with_the_earlier_fingerprint_matches_its_one_finding_and_says_when_it_cannot_tell`,
`an_entry_that_matches_nothing_says_whether_it_was_looked_for`, and
`a_second_entry_for_a_finding_already_set_aside_is_not_called_gone`; in `crates/sv-cli/src/review.rs`,
`an_earlier_fingerprint_on_identical_lines_is_left_and_todays_shows_its_one_line`; end to end,
`an_entry_that_matches_nothing_says_whether_its_rule_looked_and_an_earlier_one_still_counts`
(`crates/sv-cli/tests/finding_review.rs`), which reaches each message on purpose in the report and over MCP (a
`--run`-only rule without `--run`, an outside tool without `--tools`, a file that does not parse, a rule this version
lacks, and a rule that ran clean), and `sv review` writing today's fingerprint in
`what_a_person_records_counts_and_the_report_says_where_its_seal_was_checked`. Thirteen guards were undone in turn, each
caught by one to three tests: the occurrence count, the lines above read at all, the lines that add to a value
(caught only once a case with `sql +=` below an `sql =` was added: the first fixture changed the nearest line), the
earlier form on identical lines, the earlier form read at all, the three messages, the second entry not called gone,
the unknown rule, the tests' entry in `examined`, whether the file was read, the MCP sentence, and `sv review`'s
writing and refusing.
**Each finding also says what it was called before** (`earlier_fingerprints` in `report.json` and in the MCP results, left out when it did not change). A tool that tracks findings across runs by fingerprint, as cato-pipeline's POA&M does, would otherwise read every code finding as closed and a new one opened, once, when the form changed. Identical lines shared one earlier fingerprint, so it can name more than one finding; a tracker gives it to the first. Held by `a_finding_says_what_it_was_called_before_its_fingerprint_changed_form`.

**With R4** ("A credential's fingerprint says nothing the report does not", merged the same day): every line read
for a fingerprint, in either form, is masked first as the report masks a credential (`review::masked`), the flagged
line and the lines above it that set a name it uses alike, since a password is as often assigned on the line above
as on the flagged one. No fingerprint `sv` computes, keeps, or gives is a hash over a credential as written.
`earlier_fingerprints` gives only the masked earlier form, the one R4's `sv` gave, which says nothing the report does
not: on a line with no credential it is the hash of the line as written, so a tracker still carries those findings
over; on a line holding one it is not the form an `sv` before R4 gave, so a tracker keyed by that older hash sees the
finding as new once, which is the price of not publishing it. An entry recorded before R4 for a credential's line is
handled as R4 decided: it no longer matches, and says it was recorded by an older `sv` and should be recorded again. Its message no longer repeats that entry's fingerprint, the one hash that could give the credential back: on a copy of family-hub it had copied three such hashes from `securevibe.toml` into `report.json`.
Held by `no_fingerprint_given_for_a_finding_is_over_a_credential_as_written` (`review.rs`, a credential on the flagged
line and on a line above, against every unmasked hash in either form) and, end to end,
`no_fingerprint_given_for_a_credential_is_over_its_value_as_written` (`finding_review.rs`: `report.json`, the SARIF,
both reports, and the whole MCP reply, with a planted unsafe hash found first by the same check). Breaking the guards:
reading lines unmasked turned six tests red; giving the earlier form over the line as written, four; dropping R4's
note about older reviews, giving it for lines with no credential, or repeating the old hash in it, one each.
