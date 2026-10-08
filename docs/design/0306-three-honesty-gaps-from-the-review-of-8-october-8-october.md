# Three honesty gaps from the review of 8 October (8 October 2026)


From the review of 8 October 2026, item 5 (`docs/backlog/0188-…`): three places where something not checked read as
something checked.

**A manifest not compared with its lockfile.** Since 3 October `sv` says when a manifest asks for other versions than
its lockfile holds (DESIGN, "When a manifest and its lockfile disagree"), and when some packages could not be held to
it. But when the manifest itself could not be read (not text), or was of a kind `sv` compares and could not be
understood (`package.json` that is not JSON), the comparison was dropped without a word, and the report read as the
two agreeing. Such a comparison is now recorded as not made, with the reason (`Comparison::whole`), and said where the
others are: on screen by `sv sbom`, as a row in the report's list of what was not assessed, and in the CycloneDX
document. The bill of materials is still the lockfile's and still complete; only the comparison is missing. A
manifest of a kind `sv` does not compare is still passed over, as before.

**The credit census, per requirement.** A check citing two requirements, whose tests only ever saw it credit one,
passed the census. It now fails on such a requirement (ADR-059, Later). On the day, no check did.

**The test model without Node.** `crates/sv-run/tests/model_provider.rs` passed, checking nothing, wherever `node` was
missing, CI included if its runner ever lost it. With `SV_REQUIRE_BACKEND=1`, which CI sets, it now fails and says
why, as the fence tests do without Docker.

**Breaks.** Each failed a test: an unreadable manifest dropped again, one not understood dropped again, the screen
and report going back to the old test, and the sentence for a comparison not made removed
(`crates/sv-check/src/sbom/not_compared_tests.rs`, `crates/sv-cli/tests/manifest_not_compared.rs`); the census rule
taken out (`crates/sv-check/tests/census_per_requirement.rs`); and the Node test run with no `node` on its path,
which failed with `SV_REQUIRE_BACKEND=1` and passed, saying nothing was checked, without it. Not tested: the CycloneDX
property, which uses the same `not_all_compared` as the two places that are.
