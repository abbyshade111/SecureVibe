# Semgrep follow-ups 2 and 4: secrets in test code, and a stored hash is not a credential (5 October 2026)

Two of the follow-ups from the Semgrep false-alarm measurement of 4 October (`docs/SEMGREP-FALSE-ALARMS.md`; BACKLOG,
"could C's false alarms be brought down").

**2. The secret rules' findings in test code are listed apart with the rest.** Nothing needed changing: nothing ever
kept them out. `Finding::in_test_code` decides from the path (`is_test_path`) or a mark (Rust test code, a folder the
manifest says is not the app) for every finding alike, `sv`'s own secret rules and every tool's included, and the
reports list test code apart from it. Read against the measurement's own file, `docs/semgrep-false-alarms.csv`, all
92 secret-rule findings the reader put in test code are test code to `sv`, as are 111 of all 112; the one missed is
`run_tests.py`, the script that runs an example's tests, which no test runner's naming convention covers. No true or
unsure finding in the corpus is moved apart. Being listed apart is not being hidden: such a finding still counts
against the requirements it names, and the note beside it says test code can hold a real key.

**4. A stored password hash under a name that says so is not reported as a credential.** `secrets::is_stored_hash`
takes, exactly:

- a bcrypt hash (`$2`, an optional `a`, `b`, `x`, or `y`, `$`, two digits, `$`, and 53 characters of bcrypt's
  alphabet) under a name that says password, hash, or digest (`password`, `passwd`, `pwd`, `hash`, `digest`); or
- a hex digest of 32, 40, 56, 64, 96, or 128 digits (MD5, SHA-1, and the SHA-2 family) under a name that says hash
  or digest.

A name that also says key, secret, token, salt, pepper, seed, or HMAC is never taken in, whatever its value: a key
for hashing is a key. A hex value under a name that says only password is still reported: a password made of hex
digits is a password, and the measurement's blanket hex filter (its C) hid a real 64-digit token secret. Other hash
formats (Argon2, PBKDF2, `crypt`) are not taken in. Where it applies:

- **`sv`'s assignment rule** (`secrets.credential-assignment`) passes over such a value, as it passes over a
  placeholder, a reference, or a value SOPS keeps encrypted.
- **Other tools' secret rules**: Semgrep's (`generic.secrets.*`, Opengrep's too), Bandit's B105, B106, and B107, and
  gosec's G101 (`adapters::without_stored_hashes`). Their findings name a line, not a value, so the line is read
  again from `sv`'s listing, and the finding is dropped only when the line holds such a hash and nothing else that
  could be a credential: with the hash taken out, `sv`'s own secret rules find nothing in it and it holds no run of
  16 or more letters and digits mixed. A line that cannot be read again keeps its finding, as does every other rule's.
  Bandit and gosec are included because they fire on the same line for the same reason; Semgrep's rules alone would
  have left Bandit's B105 reporting the hash on its own.

A run whose only finding was dropped this way counts as a run that found nothing, so its rules' requirements are
credited, as `sv`'s own secret scan's are when all it saw was a placeholder. That follows from the premise: the line
holds no credential.

**What it costs and spares in the measured corpus.** The measurement's narrow filter (C2: a digest or bcrypt hash under
a password, hash, or digest name) removed 7 false alarms and no true finding. The rule built here is narrower still, as
this follow-up was briefed: on the corpus's secret-rule lines outside test code, rebuilt by shape with values made at
run time, it spares NodeGoat's three commented-out bcrypt hashes and nothing else; pygoat's seven MD5 and SHA-256
digests, under a field named `password`, are still reported, which is what never sparing a hex password costs. Every
true finding (dvcsharp's token secret, NodeGoat's ZAP key, pygoat's pasted session token) and the unsure one
(juice-shop's expected password) are kept. The apps were not kept by the measurement; their lines were read again at the
commits it names, and no value from them is in this repository.

How it is held: `a_stored_password_hash_is_not_a_credential_and_a_hexy_password_still_is`,
`a_line_with_a_stored_hash_and_nothing_else_is_all_another_tool_s_secret_rule_is_spared`, and
`the_measured_corpus_s_secret_rule_lines_keep_every_true_finding` (`crates/sv-check/src/secrets.rs`);
`a_tool_s_secret_rules_spare_a_stored_hash_and_keep_a_hexy_password_and_test_code` through a tool's run
(`crates/sv-check/src/adapters.rs`); `the_secret_rules_findings_in_test_code_are_listed_apart_with_the_rest` over the
measurement's file (`crates/sv-check/tests/false_alarm_corpus.rs`); and
`a_password_in_a_test_file_is_reported_apart_and_a_stored_hash_not_at_all` through `sv report`
(`crates/sv-cli/tests/test_code_apart.rs`). With the real Semgrep and Bandit (`sv report --tools`), Semgrep's
`detected-bcrypt-hash` fired on a stored hash and Bandit's B105 on the same line, and neither is in the report.

Eight guards were broken in turn. Caught: the assignment rule not passing over a hash (two tests), a hex value under
a password name taken in (five), the key-word exclusion removed (two), tools' findings not dropped (one, the only
place that wiring is), the rest of the line not judged (two), secret rules' findings in test files not marked as test
code (two), and files named `.spec.` not test code (the corpus test). Not caught by these: dropping the `test` folder
from what is test code, because every corpus file in `test/` is also named like a test; `finding.rs`'s own tests hold
that.
