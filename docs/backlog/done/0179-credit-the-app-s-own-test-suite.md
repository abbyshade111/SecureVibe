# Credit the app's own test suite

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 24 September 2026 — `crates/sv-check/src/suite.rs`.
A test counts only for a requirement it names, and only when the suite it belongs to passed. Matching
tests to requirements by their words was considered and refused: it would credit a requirement on the
strength of a name somebody chose for other reasons. v1's mismatch check is ported as it was —
reporting, never withholding credit, because about a third of its flags are honest tests phrased
differently. What is left over from this item: the suite's coverage is still all-or-nothing on one
exit code, so a suite with one failing test credits nothing. Reading a test runner's own report
(JUnit XML, `pytest --junitxml`) would fix that and is its own item.
