# The app's own tests are a tier of their own (ADR-050, 7 October 2026)

The gap analysis (`docs/GAP-ANALYSIS.md`, 1.1) found the app's own tests credited at the highest tier. A passing test
that named a requirement made it *checked*, the same as one of `sv`'s own checks, and the short version said "an
automated check looked and found nothing wrong". The AI coding tool writes both the tests and the command that runs
them, and nothing here reads whether a test asks what its requirement asks. Its *answers* are the lowest tier there is
(ADR-022), and its tests were the highest. The owner chose to fix it on 7 October 2026.

- **A status of its own.** *Tested by the app's own tests* (`app-tested` in `report.json`), below *checked* and above
  *documented by the owner*. The report keeps every credit with the check id `app-tests` out of `checked_by`, so a
  test can never be *checked* however it arrives. A requirement that one of `sv`'s checks also satisfied is *checked*,
  with the test shown beside it.
- **Counted apart, everywhere a count is shown.** It has its own row in the tables and its own line in the short
  version, the terminal, and the AI coding tool's summary, and a chapter column when any chapter has one. The opening
  sentence says how many "have been tested only by the app's own tests (written by your AI coding tool, and not a
  check of `sv`'s)". No label says the tests "passed", since the report's guard keeps that word for denials. They
  "ran without failing".
- **Only code is read.** A requirement id counts only in a file of a language `sv` reads (`Listing::code_files`). A
  Markdown note or a text file under `tests/` that lists requirements credits nothing.
- **What a test cannot show, it cannot credit.** A test naming a requirement that asks for documentation, a deployment
  setting, or a process (the report's `not_for_tests`), or one only a person can settle, is supporting evidence only.
- **No threat is settled by it**, and it stays on the list before going live. No prompt is offered for it, as for
  the other tiers that are evidence of some kind.
- **What is not covered.** The end-to-end count test cannot produce this status without a container backend to run
  the app in, so it accepts zero for this one status and says why. `sv-report`'s
  `the_app_s_own_tests_are_a_tier_below_a_check_of_sv_s` holds the tables, the short version, and the sum to it
  instead.
- **Guards, each broken on purpose.** Each was put back.
  - Letting the app's tests into `checked_by` again: four tests red.
  - Dropping the new status from the order a status is chosen in: four red.
  - Crediting a requirement on `not_for_tests` through a test: one red,
    `a_test_naming_a_requirement_tests_cannot_show_only_supports_it`.
  - Reading every file under `tests/` rather than code: one red, `a_note_or_a_text_file_among_the_tests_is_not_a_test`.
  - Putting these requirements in a threat's checked list: one red, `the_app_s_own_tests_do_not_settle_a_threat`.
  - Leaving them out of the opening sentence: one red, `every_status_has_a_row_and_the_rows_add_up`.
