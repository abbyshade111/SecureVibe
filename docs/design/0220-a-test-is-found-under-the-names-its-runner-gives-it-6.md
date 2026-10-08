# A test is found under the names its runner gives it (6 October 2026)

Left over from "Read the test runner's own report" (BACKLOG). When the app's suite fails, `sv` credits only the tests
the runner's JUnit report says passed. It matched a test by its exact name, which runners often do not report:
- jest and Mocha put the `describe` titles first (`search V1.2.4 binds its parameters`), and Vitest joins them with
  ` > `;
- pytest adds a parameter (`test_x[empty]`), and Go a subtest (`TestX/quotes`).

Each of these was never credited from a failing suite. And a name was taken as passed when any case of that name
passed, so two classes each with `test_V1_2_4_bound`, one failing, credited V1.2.4.

- **Matched as the runner writes it** (`suite.rs`, `reports`). A title from `it('…')`, `test('…')`, or `describe('…')`
  matches a reported name that is the title, or has it as a whole part set off by spaces (first for a `describe`,
  last for a test, or between). An identifier from `def`, `func`, `fn`, `sub`, or `void` matches the name, or the
  name followed by `[` or `/`. `searchV1.2.4 …`, `test_x_more`, and `TestXAll` are other tests.
- **Every case that could be the test has to have passed** (`reported_passing`). At least one case has to match, and
  a failing or skipped one among them credits nothing. So the wider matching can only ever take credit away from a
  name it matches too widely, never add it. A suite that passed outright still credits without reading the report, as
  before.
- `SuiteOutcome::Failed` now carries the runner's cases, failed ones included, rather than the names that passed.
  TAP and runners' own JSON are still not read.

How it is held: `a_test_is_found_under_the_names_runners_give_it` (jest and Mocha, Vitest, exact, pytest's parameter,
and Go's subtest, with names that only look alike as its control) and
`a_failing_case_that_could_be_the_same_test_credits_nothing` (same names and parameters, with the failing cases gone as
its control). Eight guards were undone in turn. Seven were caught. The eighth, a separate rule for Vitest's ` > `, was
caught by nothing because ` > ` is set off by spaces already, and it was taken out.
