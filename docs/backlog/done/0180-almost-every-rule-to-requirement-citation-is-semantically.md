# Almost every rule-to-requirement citation is semantically wrong

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 24 September 2026 —
remapped, and guarded by `crates/sv-check/tests/citations.rs`. Left over: Brakeman's rule ids had
never been seen in a real SARIF run — done on 25 September 2026: they were mostly wrong (BRAKE0002 is
cross-site scripting and was mapped as SQL, BRAKE0013 is eval and was mapped as OS command injection,
BRAKE0016 is file access and was mapped as SQL, BRAKE0102 is a 2016 Rails CVE, not a secret, and
BRAKE0000, SQL injection itself, was unmapped). Remapped from `warning_codes.rb` in Brakeman 8.0.6,
forty ids, and tested against a real run over `crates/sv-check/tests/fixtures/brakeman/app` whose
output is kept beside it; fifteen ids appear in that run, and the guard cannot catch a swap between requirements that
share vocabulary. Found on 24 September 2026 by the
test-crediting mismatch check, firing on the example app written to demonstrate it. ASVS 5.0 `V1.2.1`
is *output encoding for an HTTP response, HTML or XML document*. It is cited by `ast.sql-built-by-hand`,
`ast.dynamic-code-execution`, bandit's `B608` and `B307`, gosec's `G201`/`G202`, and three Brakeman
rules — none of which have anything to do with output encoding. Parameterized queries are **V1.2.4**;
OS command injection is **V1.2.5**, not the `V1.2.2` that nine adapter rules cite (`V1.2.2` is URL
encoding). The pattern repeats across the file: eight rules cite `V11.3.1` (block modes and padding)
for weak hashes, which are `V11.4.1`; `G404` (`math/rand`) cites `V11.4.1` (hash functions) when
unpredictable randomness is `V11.5.1`; `G304` (file paths) cites `V1.2.3` (JavaScript encoding) when
it is `V5.3.2`; `G107` (SSRF) cites `V1.2.4` (database queries) when it is `V1.3.6`; `G402`/`B501`
(TLS verification off) cite `V13.1.1`, which asks that communication needs be *documented*.

This is the third time this class has been found here — five checkers citing `AC-NN` ids that did not
exist, then every probe citation being semantically wrong — and it is the failure the whole product is
most exposed to, because a wrong citation is not visibly wrong. It puts a finding, or a green line,
against a requirement nobody examined, and the reader has no way to tell.

Two things are needed, and the second matters more. Remap `data/adapters.json` and `data/ast-rules.json`
by reading each requirement's text. Then write the guard that would have caught it without an example
app happening to exist: every citation in the data files compared against the requirement it names, by
shared vocabulary, the same comparison `suite.rs` already makes for tests. A citation nothing checks is
a citation that drifts.
