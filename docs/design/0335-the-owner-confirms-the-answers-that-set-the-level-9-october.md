# The owner confirms the answers that set the level (9 October 2026)


Gap analysis of 7 October 2026, finding 17, its last part (`docs/GAP-ANALYSIS.md`, 4.1); ADR-024, "Later, 9 October
2026: the owner confirms the answers that set the level".

**The gap.** The level rests on `[app] audience` and `[data] categories`, which the AI coding tool usually writes.
Since this morning the report says so, and asks about what the code shows. Nothing let the owner say "yes, these are
right", so the level line read the same for an app whose owner had checked the answers as for one nobody had.

**What changed.**

- `[scope-review]` in `stackvet.toml` (`sv_manifest::ScopeReview`): the audience and categories as confirmed, `by`,
  `on`, and `seal`. `ScopeReview::still_holds_for` compares them with the answers now, the categories as the level
  reads them (case, spaces, and order aside), an unanswered list never equal to an empty one.
- `sv_check::seal::scope_review_fields`: what the seal covers, who and when first, then the audience, then whether
  the list was answered and each category, so a list of any length cannot be read as another field.
- `sv review` asks last, after every other entry and apart from their count, whenever the answers are not confirmed
  or have changed since: it shows both answers and the level they give, and takes only `owner`. It asks even when
  nothing else is waiting, which for most apps is every time until the owner confirms.
- `LevelWhy.confirmed` in `sv-report` (`confirmed`, `changed`, or `not-counted`), and the level line worded from it.
  The seal is checked as every other seal is, so on CI, given the list in `SV_TRUSTED_SEALS`, it counts there too,
  and says the key's passphrase cannot be told there (ADR-043, Later, this morning).
- The starter file describes `[scope-review]` and says never to write it by hand; the README says what `sv review`
  now asks last.

**Found on the way.** A test typed `owner` for a finding that turned out not to be asked about; the word then went to
the new last question and confirmed the answers. Typed into a test's input all at once, that is how input works; a
person at a terminal sees each question. The test now says so and checks that only `[scope-review]` was added.

**What it does not do.** It changes no level, raises nothing, and counts toward nothing. Who may confirm is the
owner alone; a teammate who knows the audience cannot.

**Held by** `crates/sv-cli/src/review/scope_tests.rs` (9) and `crates/sv-cli/tests/scope_confirmed_report.rs` (9,
through the binary, with a real key, on this computer and on one given only the list). Broken on purpose nine ways,
one at a time: the audience not compared (2 tests red), the categories compared as written (2), an unanswered list
taken for an empty one (2), the seal not checked by the report (2), never asked (6), any name taken (2), the
audience left out of what is sealed (2), the report ignoring the confirmation (4), and not asked when nothing else
waits (6). Five of them first went red in one test each, and the unanswered list in none: each got another test
before this was written.
