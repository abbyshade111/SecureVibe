# The "what has to be answered" table prints a condition's exclusion sentence as its question

**Status:** done, as its markers read on 8 October 2026

Found on 5 October
2026 by the cato-pipeline session while building R12 (its branch was superseded by securevibe-e9's, #674, and
closed as #682; this finding was not on `main`). `question_for` in `crates/sv-report/src/lib.rs` says it turns the
condition's reason "round" into a question, but returns `default_not_applicable_reason()` unchanged, so the table
of requirements nobody has placed asks, for example, "No WebSocket library is used" instead of "Does the app use
WebSockets?". *Read*, and seen in the report of a one-file WebSocket app. Fix: a question per condition (in the
data beside the reason, or derived from the condition), and a test that no row of that table reads as a statement.
**Claimed on 5 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
branch `claude/securevibe-e2-questions`.
**Done the same day** (DESIGN, "What has to be answered is asked"): each condition carries a question beside its
reason, in the one place both are written (`crates/sv-frameworks/src/condition.rs`), and the table asks it: "Does
the app use WebSockets?". A test holds every condition to a question of its own that is not its reason, and another
renders every condition as a row, in the Markdown and the page, and finds no statement. Four guards broken in turn,
each caught.
