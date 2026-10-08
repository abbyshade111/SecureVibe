# Findings in test code, listed after the app's own (27 September 2026)

The v2 self-assessment (`docs/paper/SELF-ASSESSMENT-V2.md`) found that 189 of the 252 findings on
`sv`'s own product code were in its tests, and most of those were inside Rust `#[cfg(test)]` modules,
which live in the same file as the code they test. Mixed together, three findings in four were about
test code, and the ones about the product were hard to find.

**Rust tests are recognized inside the file.** A file's name cannot say where Rust's unit tests are,
so `mark_rust_test_code` in `sv-check` reads each Rust file a finding is in, with the same
tree-sitter grammar the code rules use, and marks a finding (`marked_test_code`) when its line is inside
an item under `#[cfg(test)]`, `#[test]`, or a test runner's own attribute such as `#[tokio::test]`,
or anywhere in a file that starts `#![cfg(test)]`. Comments and strings that only mention
`#[cfg(test)]`, and `#[cfg(not(test))]` or `#[cfg(feature = "test")]`, are the app's own code. A
Rust file that cannot be read marks nothing. The folder and file names `is_test_path` already knew
(the earlier section) still decide it for every other language.

**Listed apart, and still counted.** `security.md`, the HTML page, and the MCP text list the app's own
findings first under "things to fix", then a second list, "in test or sample code", which says why it
is apart and that each one still needs reading. The short version names the app's findings before
any in a test, and its headline says how many are in test code. When every finding is in test code,
the report says "Nothing was found in the app itself" and adds, as the clean report does, that this
is not the same as the app being secure. Nothing about a requirement's status changes: a finding in a
test still makes its requirement need attention, because a key in a test is still a leaked key and a
pattern in a sample still gets copied. This moves findings down the page; it does not lower the bar.
SARIF was already marking each finding `inTestCode`, and now includes the Rust case.

Not done: `sv check` (the credentials scan on its own) does not look inside Rust files for tests; its
findings in `tests/` and the like say so, as before. Item 1 of the same backlog entry, letting a
manifest name fixture and example folders so they cannot overrule it, is a separate piece of work.
