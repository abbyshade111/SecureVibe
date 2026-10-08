# A clean credential scan claims V11.1.1 and C9.5.4

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Withdrawn on 25 September 2026 by session
securevibe-e8: not a fault. V11.1.1 and V13.3.1 are on `manualOnly` in `data/knowledge/applicability.json`,
so a clean scan supports them and checks neither (pinned by
`the_requirements_a_clean_scan_cannot_settle_include_the_ones_it_was_settling` and
`end_to_end_a_clean_scan_supports_the_secrets_controls_and_checks_none_of_them`); the coverage count
that suggested otherwise had not read that list. C9.5.4 is classified `scanner-clean` on purpose, and
stays; `docs/COVERAGE.md` says what a clean scan does and does not show about it.
