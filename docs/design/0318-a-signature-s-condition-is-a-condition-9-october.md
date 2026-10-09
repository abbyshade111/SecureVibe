# A signature's condition is a Condition (9 October)

The technology signatures (`data/tech-signatures.json`) and the claim corroborators (`data/claim-corroborators.json`)
each name the condition they answer, such as `xml` or `multiple-services`. In `sv-scan` that name was kept as plain
text and turned into a `Condition` only when the scan ran; a name that matched no condition was skipped without a
word. A misspelling in either file therefore left one condition unanswered by the scan, and nothing said why.
Everywhere else in `sv`, an unknown condition name is refused when the file is read.

Now `Signature.condition` is a `Condition`, read by the same rule as the rest: a name the file misspells stops the
load with `unknown condition` and the name. Every name in both files was checked against the list of conditions
before the change, and all are known, so no report changes. The architecture assessment of 8 October 2026 named this
as the first of item 12's smaller seams; the rest of that item stays open.

A test (`crates/sv-scan/tests/condition_names.rs`) loads a one-signature file with a real name, then the same file
with a misspelled one, and shows the second refused by name. The existing tests that print or compare the condition
read it through `Condition::name`.
