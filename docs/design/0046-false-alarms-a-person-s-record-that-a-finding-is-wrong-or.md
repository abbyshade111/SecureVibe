# False alarms: a person's record that a finding is wrong, or accepted (27 September 2026)

Part 2 of the false-alarm work, built to the owner's five decisions (BACKLOG, "False alarms, part 2").
A person who has read the code can set a finding aside with a `[[finding-review]]` entry in
securevibe.toml: the finding's rule, file, and fingerprint, a verdict, why, who, and when.

**Two verdicts.** A *false alarm* (the code is fine) leaves the list of things to fix and goes to its
own section, "Set aside by a person", with the reason. An *accepted risk* (a real problem, lived with
for now) stays on the list, labeled with who accepted it, when, and why.

**A set-aside finding credits nothing.** When a false alarm was a requirement's only finding, the
requirement is shown by whatever else is known about it, and never as *checked*, even if another
check's clean run would otherwise make it so: the rule saw something there, and a person's word that
it was wrong does not show the protection is in place. An accepted risk still needs attention.

**Only a person's word counts.** An entry by `ai-tool`, or with no `by`, is listed as the tool's
proposal, quoting what it said, and the finding still counts. The tool is told, in the interview and
in every MCP result that has one, that its proposal counts only once the person has read the code and
put their own name in `by`, and never to write that name itself. `sv` cannot tell who typed a name,
as for confirmations; what it can do is make the rule plain to the tool and show every entry it acts
on, with its author, in the report.

**The fingerprint.** Sixteen hex characters of SHA-256 over the rule, the file, and the flagged line's
text with its spaces trimmed (`sv_check::review::fingerprint`), printed beside every finding. Moving the
line keeps the name, and changing the line gives a new one, so a false alarm about a line lapses when
the line changes: the entry stops matching, the finding is back, and the entry is listed as no longer
matching anything. Only the hash is kept, so the line a key was found on is never copied into
securevibe.toml. A finding with no line of code (a running-app probe, a settings check) is named by its
title instead, and having nothing to watch, a false alarm about one lapses after 90 days, as every
accepted risk does. An entry can name a rule that was merged into another finding (part 1).

**Keys and passwords.** A finding of the secrets scan can be set aside as a false alarm only with a
reason of at least 80 characters that says why it is not a real one (a test value, a published
example, one already revoked), against 40 for anything else. It cannot be an accepted risk: a real key
is replaced and taken out of the code, and one that is not real is a false alarm.

**Nothing is dropped quietly.** An entry that does not count (a proposal, no date, a date to come, a
short reason, an unknown verdict, a lapse, a fingerprint that no longer matches) is listed with its
reason, in the report and to the AI tool.

**The SARIF agrees with the report.** Every result carries `partialFingerprints["svFingerprint/v1"]`.
A false alarm is included, with a `suppressions` entry of kind `external` giving the person's reason,
so a tool reading the file, GitHub's Security tab among them, shows it as dismissed. An accepted risk
is not suppressed, and carries `properties.acceptedRisk` with who, when, and why.
