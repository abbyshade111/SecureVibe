# Ten requirements a person must answer, and nothing anywhere tells them how

**Status:** done, as its markers read on 8 October 2026

Found on
26 September 2026 while drawing the coverage maps. **Claimed on 26 September 2026 by session
securevibe-e8.** `applicability.json`'s `manualOnly`
now holds 26 requirements — ones no check may ever settle. Guidance for them lives in three
catalogs: `data/human-checks.json`, `data/security-notes.json`, and `data/design-questions.json`.
Ten are in none of them, so the report marks them unverified and offers the reader nothing:

| | Level | |
|---|---|---|
| V5.4.3 | L2 | files from untrusted sources are scanned by antivirus |
| C7.2.1 | L2 | the reliability of generated answers is assessed with a confidence estimate |
| C7.2.2 | L2 | answers below the confidence threshold are blocked or fall back |
| C11.1.1 | L1 | the model has had alignment or safety training |
| C11.1.2 | L1 | a version-controlled alignment test suite runs on every model release |
| C11.1.3 | L1 | models are evaluated against known adversarial techniques for their modality |
| C11.1.4 | L2 | models are hardened against adversarial inputs |
| C11.3.1 | L1 | query-pattern analysis feeds an extraction-attempt detector |
| C12.2.2 | L2 | behavioral anomaly detection identifies probing behavior |
| C12.2.3 | L2 | custom rules detect coordinated jailbreak and prompt-injection attempts |

Nine of the ten are AISVS, which is the part of the work that has grown fastest, so the gap is
where the framework moved and the catalogs did not follow.

**The fix is a test, not a list.** `crates/sv-check/tests/human_checks.rs` already guards the other
direction thoroughly — every check names a requirement that exists, no requirement is explained by
two catalogs, every check shares vocabulary with its requirement, every check is at level one or
two, every check is written for somebody who is not a programmer. Nothing guards *this* direction:
that every requirement `sv` can never settle is asked by some catalog. A test that fails with the
unasked ids listed would have caught all ten as they were added, and will catch the next one, which
writing ten entries by hand will not.

Also worth a decision rather than an assumption: `AC.1.4`, `AC.4.1`, and `AC.6.3` are `manualOnly`
and asked nowhere either, but the Secure by Design controls carry no level, and
`every_check_is_at_level_one_or_two` says human checks are deliberately L1 and L2 only. Whether the
checklist is its own guidance, or wants entries too, decides whether the count is ten or thirteen —
and the test should encode whichever answer is chosen.

**Done the same day.** Twelve entries in `data/human-checks.json`, not ten: `AC.4.1` and `AC.6.3`
are the AISVS appendix on AI-assisted development and carry levels (1 and 2), so they belong with
the others; `AC.1.4` is level 3 and stays out, as the checklist leaves out level 3 everywhere. The
test is `every_requirement_only_a_person_can_settle_is_explained_somewhere` in
`crates/sv-check/tests/human_checks.rs`: every `manualOnly` requirement at level 1 or 2 must be in
one of the three catalogs. Removing an entry names it; widening the test to level 3 names `AC.1.4`.
The twelve reach the owner through the report's checklist and the interview (`sv questions`), and
can be recorded in `[checked-by-hand]`.
