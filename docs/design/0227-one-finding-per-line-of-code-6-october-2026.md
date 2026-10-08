# One finding per line of code (6 October 2026)

Semgrep follow-up 3 (BACKLOG), decided by the owner on 6 October 2026 (ADR-023, Later). The false-alarm measurement of
4 October found 309 of 868 findings on a line another rule had already named. `merge_same_place` made one finding of
one weakness reported twice (a CWE in common), and kept different problems on one line apart on purpose. They were
still separate entries for one place to change.

- **Gathered after the reviews** (`finding::one_per_line`, called at the end of `decisions_then_reviews`). What a
  person set aside is gone first, so a verdict on one rule never takes another problem on the same line with it.
- **The worst leads**, as `merge_same_place` chooses: most severe, then `sv`'s own rule, then the surer. It names every
  requirement and CWE of the others, so the line still counts against all of them.
- **Each other problem is kept whole** in `Finding::also_on_this_line`. The reports and the MCP server say each beside
  the line ("Also on this line, a problem of its own: …"), with its severity, certainty, requirements, and fingerprint,
  so it can be set aside on its own. For `sv`'s own rules they give its title and fix; an outside tool's rule is
  named, not quoted, since its words can carry the value it found.
- **SARIF keeps one result per problem**, each under its own rule, so the tools that read it see what they did before.
  `report.json` holds the others inside the line's finding, and the MCP schema says so.
- Findings without a line of code (the running app, its output, settings, the test suite) are not gathered.

How it is held:
- `what_is_left_on_one_line_is_one_finding_led_by_its_worst_and_holding_the_rest` (`finding.rs`), with other lines,
  other files, and running-app findings as its controls.
- `a_false_alarm_on_one_problem_never_sets_aside_another_on_its_line` (`review.rs`).
- `a_line_is_gathered_after_the_reviews_so_a_verdict_sets_aside_one_problem_only` (`main.rs`), which holds the order.
- `two_problems_on_one_line_are_one_entry_naming_both_and_two_sarif_results` (`crates/sv-cli/tests/one_per_line.rs`),
  end to end through `report.json`, `security.md`, and SARIF.

Nine guards were undone in turn, and each was caught. One more, letting an information-only finding lead a line and
still withhold credit for the others, was taken out: findings about the test suite are never on a line of code, so
it could not happen.
