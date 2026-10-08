# The tier is on the value (8 October 2026)

Item 4 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026"), first half. A credit (`sv_check::Verified`) landed in *attested*, *stated*, *by hand*, or *documented* by which
of four lists it was passed to the report in, assembled by hand in `main.rs` from the design answers, the checks by
hand, the notes, and the confirmations; the app's own tests were told from `sv`'s checks by the check's name; and the
owner's `yes` was told from the tool's by a string match on the check id inside the report. Nothing held the four lists
to what was in them: a credit put in the wrong list was that tier.

Now each credit says what it rests on, `Verified::tier` (`sv_check::Tier`: *checked*, *tested by the app's own
tests*, *documented*, *by hand*, *attested*, *stated*), set where the credit is made (`design.rs`, `hand.rs`,
`notes.rs`, `confirm.rs`, `suite.rs`) and nowhere else; `Inputs` has one list; and `sv_report::status_of` decides a
requirement's status from its findings, whether a false alarm was set aside on it, and the tiers of its credits, with a
unit test per tier, one for the order, one for a finding, one for *checked in part* (ADR-053), and one for a false
alarm set aside (ADR-023). What a report says is unchanged: the tier is not written into any file, since the status is
what a reader is given. With the owner's design answer given the tool's tier on purpose, four end-to-end tests
failed (`confirmations.rs`, `counts_add_up.rs`, and both in `owner_answers.rs`), and none of the report's own: those
build their credits with the tier set by hand, so they hold `status_of` and `build`, and the end-to-end tests hold the
producers. Restored, all pass.
