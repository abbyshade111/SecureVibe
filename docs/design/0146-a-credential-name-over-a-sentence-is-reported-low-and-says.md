# A credential name over a sentence is reported low, and says so (4 October 2026)

On family-hub (3 October) `secrets.credential-assignment` rated `WRONG_PASSWORD = "Your current password isn't
right."` high and advised changing the credential (BACKLOG, "What the owner hit building family-hub", item 7, the
credential half). The rule takes a name that says "credential" with a quoted value of 8 to 200 characters that is not
a placeholder and has enough variety of characters, and a sentence passes. The owner's decision: keep reporting such
a value, since a real passphrase can be a sentence, but at low severity and saying "this reads like a sentence".

**What reads like a sentence** (`reads_like_sentence` in `crates/sv-check/src/secrets.rs`), kept narrow because it
lowers a finding: three or more ordinary words, one space apart, the last ending in `.`, `?`, or `!`. An ordinary
word is letters only, with an apostrophe or hyphen between letters (`isn't`, `sign-in`), a comma after any but the
last, written in lowercase, with a capital first letter, or all in capitals. A digit or other symbol in a word, a
letter case mixed inside one (`pAsS`), two spaces, a leading or trailing space, or no closing mark, and it is not a
sentence. Such a value is reported at `low` severity and low confidence (so its certainty reads "possible", which
tells the reader to look before changing code); its title, description, impact, and advice say it reads like a
sentence and what to do in either case: a message is a false alarm to record, a passphrase is moved out and changed.
Everything else keeps `high` and medium confidence, as before. Two words ending in a period (`Wrong password.`)
stay high: too short to tell from a two-word passphrase, and the decision did not ask for them.

**The value now runs to the quote that opened it.** Either quote used to end the value, so the reported line was
judged as `Your current password isn` (no closing mark, and the wrong length in the finding). The pattern now pairs
`"…"` and `'…'`, as `redact_text` already did; without this the sentence test could not have seen the sentence.

**Redaction is unchanged, on purpose.** A sentence finding still carries `Secret::redact`'s four characters and
length, never the value, and `redact_text` still cuts any value under a credential's name whatever its shape: a
passphrase that is a sentence is still a passphrase. A finding at `low` still makes its requirements need attention
and still stops the scan's clean claim, since the owner chose to keep reporting it; setting it aside as a false alarm
is the way to clear it.

**Where else the shape goes.** No vendor rule in `data/secret-rules.json` matches a sentence. Bandit's B105 does
(any string under a name like `password`), and with `--tools` it and this rule merge on the same line (both CWE-259).
`merge_same_place` keeps the more severe, then the surer: both are now `low`, and the adapter gives every tool
finding medium confidence, so Bandit's "Bandit reported B105" is kept, this rule's sentence note is lost, and it is
named only in "also reported by". Seen with the real Bandit on a one-file app. Before this change this rule's `high`
was kept. Fixed the same day, at the owner's asking: see "The merge keeps `sv`'s words" below.

`docs/REQUIREMENTS.md` used to describe this rule by its impact ("if it fails: Anyone who can read the code…"),
which `tools/coverage.py` read as the first string literal after the rule; the impact now depends on the value, so
the script reads the rule's `ASSIGNMENT_WHAT` instead ("looks for: A value that looks like a credential, …").

**Tested** with four tests in `secrets.rs`: the family-hub line and five other messages are reported low and
"possible", with the note in title, description, and advice, the whole value judged, and the value redacted; eleven
controls (passphrases without a closing mark, with a digit, symbols, hyphens, or mixed case, two spaces, two words,
key- and token-shaped values) are each shown reported and still `high`; a table of what is and is not a sentence; and
a value with the other quote inside it read whole, and a sentence still cut by `redact_text`. `sv check` on a
one-file app gives `[low] … reads like a sentence (WRONG_PASSWORD)`, "found: Your… (30 more characters)". Nine
guards broken in turn, each caught: never a sentence (two tests), the closing mark alone enough (two), either quote
ending a value (two), the sentence kept at medium confidence (one) or high severity (one), two words enough (two),
mixed case allowed (two), digits allowed (two, after a digit-inside-a-word control was added when only the table
caught it at first), and the sentence not redacted (one).

**The merge keeps `sv`'s words** (same day, at the owner's asking). A merged finding must never lose the explanation
of why it is rated as it is. `merge_same_place` (`crates/sv-check/src/finding.rs`) now chooses the finding whose words
are kept by severity first, so a merge never lowers one; then `sv`'s own rule before an outside tool's; and only then
the surer. "Surer" alone was the wrong test between the two: every tool finding gets medium confidence because `sv`
did not judge it, so it compared a judgment with a placeholder. `sv`'s own rules are told by name (`is_svs_own`: a
list of `sv`'s own prefixes, not of the tools, so a tool added to `data/adapters.json` and missed is treated as a
tool, the safe way to be wrong; a test checks every adapter and every data-file rule). The kept finding keeps its own
confidence, since two reports of one line make neither more certain. It still takes every requirement and CWE and
names the others in "also reported by". Now it also carries the redacted value if it had none. When it is a tool's,
kept for being more severe, it says in one line how each of `sv`'s own rules among the others rated the line
("`sv`'s own rule `secrets.credential-assignment` reported this line too, as low and possible: … reads like a
sentence"). A tool's text is never copied into the kept finding, because it can quote the value (S8, not changed
here). On the family-hub line the report now shows `sv`'s finding, which shows four characters of the value, where
it used to show Bandit's message quoting the value whole.

A person's review names a finding by its rule's fingerprint, and the rule kept on a line can now change. So
`review::apply` (which now takes the app's folder) also accepts an entry naming a rule merged into a finding when the
entry's fingerprint is the one the finding would have under that rule. A review written against Bandit's B105 on that
line still counts. This was already possible before: adding a tool could change the kept rule and orphan a review.

**Outcomes that change.** At the same severity, `sv`'s own finding is kept over a tool's even when `sv` is less sure
(for example `ast.open-redirect`, "possible", over a tool's medium). The result then reads "possible", where it used
to read "likely" in the tool's words. A tool finding kept over a less severe `sv` finding gains the one line on `sv`'s
rating, and the redacted value if it had none. Every outcome the existing merge tests held is unchanged: the most
severe still wins (semgrep's critical over `sv`'s high SQL finding), and at the same severity the surer `sv` finding
is still kept.

**Tested.** Four unit tests:
- `sv`'s words kept at the same severity, in both input orders, with confidence not raised and Bandit's quoting
  message not copied.
- A more severe tool finding kept, with `sv`'s rating said once and the redacted value carried.
- `sv`'s less sure rule kept, with "possible" left as it is.
- Every adapter and data-file rule classified.

One review test checks an entry against Bandit's fingerprint. Its controls are another line, and a rule not merged
in. Two end-to-end tests in `crates/sv-cli/tests/false_alarms.rs` run `sv report --tools` on the family-hub line: one
with a stand-in writing Bandit 1.9.4's own SARIF for it (a control on another line shows that the stand-in's finding
was read), and one with the real Bandit, which on a machine without Bandit says so and stops. Bandit was installed
here, so that branch ran.

Ten guards broken in turn, each caught:
- `sv`'s own rule not preferred: four tests.
- `sv`'s own preferred over severity: two, one of them the existing three-tool test.
- The merge raising confidence: four.
- No line on `sv`'s rating: one.
- The redacted value not carried: one.
- A tool's message copied: three.
- Every rule taken as `sv`'s own: five.
- No rule taken as `sv`'s own: six.
- The review fallback removed: one.
- The review fallback taking any rule: one.
