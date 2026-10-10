# Later, and not a priority: could C's false alarms be brought down, if `sv` is to reach all 50?

**Status:** done, 10 October 2026

Asked for by the owner on 26 September 2026, for if the semgrep coverage is expanded down the line.
Not claimed. The license question above comes first, since it decides whether C can be run at all. (No
longer a blocker: the owner reviewed the license on 26 September 2026, and on 30 September 2026 confirmed that
this work is unblocked.)
**Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking ("I definitely still want to look
into reducing false alarms from tool C; more research into reducing false alarms for all languages would be great
as well"), as research first, in branch `claude/securevibe-e9-false-alarms`.
**Research done the same day** (`docs/SEMGREP-FALSE-ALARMS.md`, one row per finding in
`docs/semgrep-false-alarms.csv`). Option C's 1,034 rules were run over 25 apps in six languages: 11 well-kept real
apps, 9 deliberately vulnerable ones, and `sv`'s 5 examples, each given the file list `sv` itself would give.
Every first-party finding was read.
- **Measured:** 868 findings: 555 false, 301 true, 12 unsure. The clean apps were quiet (31 findings in all, 24
  false). 317 false alarms (57%) were in third-party JavaScript kept inside the app (jQuery, Bootstrap, and the like
  in `public/`, `static/`, or `assets/`), and 112 (20%) were in test code. 309 findings repeat a line another
  rule already named.
- **Three changes lose no true finding:** treating bundled library files as not the app's code (shown apart), test
  code apart (the secret rules included), and one finding per line naming every rule. Together they take the
  corpus from 868 to 359 findings, and false alarms from 555 to 104, keeping all 239 true lines. A narrow
  secret-rule exception and documentation paths take it to 341 and 86, still with none lost.
- **What costs true findings:** a blanket hash filter on the secret rules, gating the Django rules by framework (6
  lost), and a broad "worth a look" tier. A narrow tier for five rules costs one.
- **Also found:** `sv` never hands `.json` files to Semgrep, so the 57 `generic-api-key` findings on
  `securevibe.provenance.json` in the earlier measurement cannot happen in a real `sv` run, if it scanned the folder.

**Follow-ups, each claimable on its own, and they apply to today's packs as well as to option C:**
1. **Bundled third-party library files shown apart, detected by** a known library's file (as retire.js does) rather
   than by long lines alone, and checked on apps the test was not written against.
   **Claimed on 6 October 2026 by session securevibe-e9**, at the owner's asking to pick another item, in branch
   `claude/securevibe-e9-bundled-libraries`: a copy of a library kept in the app, known by its own banner, has its
   findings listed apart, named for the library, and still counted; checked on library files and first-party code
   the test was not written against.
   **Done the same day** (DESIGN, "A copy of another project's library is listed apart"; ADR-023, Later): known
   by a string only the library writes or the comment it opens with naming a version; its findings listed after the
   app's own, named for the library, and still counted. On the library files at hand every bannered copy is named,
   and none of the 661 first-party files of this repository and v1 is.
   **Part status:** done, 6 October 2026
2. **The secret rules' findings in test code kept apart with the rest.**
   **Part status:** done, 10 October 2026
3. **One finding per file and line, naming every rule and requirement.**
   **Claimed on 6 October 2026 by session securevibe-e9**, at the owner's word ("Yes, please go ahead with both of
   those", asked whether to reverse the rule that findings with no CWE in common stay apart), in branch
   `claude/securevibe-e9-one-per-line`. **Record, `Status: proposed`** (to be a "Later" entry on ADR-023): after
   what a person set aside is applied, the findings left on one line of one file are one finding. The most severe
   is kept, as the merge of one weakness already keeps it; it takes every requirement and CWE of the others, and
   lists each other problem by its rule, severity, requirements, and fingerprint, with `sv`'s own rules' titles
   (an outside tool's text can quote the value it found, so its rule is named instead). Reviews stay per problem:
   they are applied before the gathering, so a false alarm recorded for one rule never sets aside another
   problem on the same line. SARIF keeps one result per problem, for the tools that read it.
   **Done the same day**, and the record accepted (ADR-023, "Later, 6 October 2026: one finding per line of code";
   DESIGN, "One finding per line of code").
   **Part status:** done, 6 October 2026
4. **The narrow secret-rule exception:** a hex digest or bcrypt hash assigned to a password or hash field.
   **Follow-ups 2 and 4 Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking to continue with the backlog, in branch
   `claude/semgrep-follow-ups-2-4`.
   **Done the same day** (DESIGN, "Semgrep follow-ups 2 and 4"). *2:* nothing kept the secret rules' findings
   out of the split: `Finding::in_test_code` reads the path for every rule alike, and all 92 secret-rule findings
   the measurement found in test code are test code by it (111 of its 112 test-code findings in all; the one
   missed is an example's `run_tests.py`). Now held by a test over `docs/semgrep-false-alarms.csv`, which also
   shows no true or unsure finding is moved apart, and by a test that a real password in a test file is still
   reported, listed apart, and counted. *4:* a bcrypt hash under a name that says password, hash, or digest,
   or a hex digest of MD5 to SHA-512 length under one that says hash or digest, is not reported by `sv`'s
   assignment rule, nor by Semgrep's secret rules, Bandit's B105 to B107, or gosec's G101 when it is the only
   thing on the line that could be a credential. A hex value under a name that says only password is still
   reported, as is anything under a name that also says key, secret, token, salt, pepper, seed, or HMAC. On the
   corpus's secret-rule lines, rebuilt by shape, it spares NodeGoat's three bcrypt hashes and keeps every true
   finding; pygoat's seven digests under `password` stay reported, the price of never sparing a hex password, so
   it removes 3 of the 7 the measurement's C2 did. Real Semgrep's `detected-bcrypt-hash` fired on a stored hash
   and the report no longer shows it. Eight guards broken in turn: seven caught. The eighth, dropping the `test`
   folder from what is test code, was not by these tests, because every corpus file in `test/` is also named
   like a test; `finding.rs`'s own tests hold it.
   **Part status:** done, 5 October 2026
5. **Only then, and the owner's choice:** the narrow "worth a look" tier (`unsafe-dynamic-method`,
   `detect-non-literal-regexp`, `prohibit-jquery-html`, `plaintext-http-link`, `var-in-href`), which costs one real
   finding in this corpus.
   **The owner's decision, 6 October 2026: yes**, as long as a "worth a look" finding is still shown in full, only
   listed apart. **Claimed the same day by session securevibe-e9**, in branch `claude/securevibe-e9-worth-a-look`.
   **Record, `Status: proposed`** (a "Later" entry on ADR-023): the five rules' findings are listed apart under
   "worth a look", in full and still counted, as test code's are.
   **Done the same day** (DESIGN, "Five Semgrep rules listed apart as "worth a look""; ADR-023, Later): listed
   after the app's own, in full, still counted, and marked in SARIF; only when nothing else backs the finding up.
   **Part status:** done, 6 October 2026
Where to start, from both measurements: which rules make the false alarms (`var-in-href`,
`html-in-template-string`, `detect-non-literal-regexp`, `unsafe-dynamic-method`, and
`generic-api-key` on the hashes in `securevibe.provenance.json`), counted per rule against real
faults over the golden apps and the examples; what `sv` knows that semgrep does not (a value from
the app's own settings, a test file, a template that escapes by default, a file `sv` writes); and
whether findings only the added rules make should be shown apart, as "worth a look".

**Two instances from the owner's own builds, added on 4 October 2026 by the cato-pipeline session** (usability
analysis for `docs/paper`), from the transcripts. Both are with today's packs, not option C.
- *family-hub, 3 October (Flask, Python).* Semgrep's `django-no-csrf-token` rule gave about 50 medium findings
  (43 in the last report of the day) on Flask templates that do carry a token, through `{{ csrf_field() }}`, which
  the rule does not know. Each cites V3.5.1, so V3.5.1 reads "needs attention" though `sv`'s own running-app
  check (`probe.cross-site-request-accepted`) checked it on the same run. `sqlalchemy-execute-raw-query` did the
  same on plain `sqlite3` calls. The rule is Semgrep's; what `sv` controls is that it runs a Django rule on an app
  whose packages show Flask and no Django, shows it at medium, and lets it outweigh its own check. This is the
  measured cost above (gating Django rules by framework lost 6 true findings in the corpus), seen from the other
  side: an app where every one of them was false.
- *my-first-app, 4 October (Express).* `detect-non-literal-regexp` fired on `src/refresh/verify.js:71`, a regular
  expression built from a price whose dots and commas the code had already escaped. The AI tool rewrote the
  working price matching without a regular expression, "which cleared the last code warning", without asking.
  The finding cites V1.3.12, which is above that app's target level; `sv` still listed it among the findings at
  medium, and the AI tool treated it like any other. The rule is Semgrep's; what `sv` shows, and at what
  weight, for a requirement the app is not held to is `sv`'s. This is follow-up 5's rule.
**The owner's decision, 6 October 2026** ("I agree with all your recommendations", 6 October 2026): when `sv`'s own running-app check verified a requirement in the
same run, an outside tool's finding that contradicts it is listed under "worth a look" rather than counted against
it; and a finding about a requirement above the app's target level is listed in a group of its own, apart from the
findings that count. **Claimed the same day by session securevibe-e9**, in branch
`claude/securevibe-e9-outranked`. **Record, `Status: proposed`** (a "Later" entry on ADR-023): both are listed in
full, still named in the report, and still seen in SARIF; the first no longer keeps a requirement `sv` checked from
being credited, the second never decided an applicable requirement's status in the first place.
**Done the same day** (DESIGN, "A finding outranked by `sv`'s own run, and one about a requirement the app is not
held to"; ADR-023, Later): `Finding::outranked`, set by the report; both kinds listed apart, in full, and marked in
SARIF, `report.json`, and the MCP server's schema.

**Checked against origin/main, 10 October 2026:** built: bundled libraries marked in `finding.rs`; test-code split at `finding.rs:298`; one finding per line; narrow secret exception; worth-a-look. Part 2 is that test-code split.
