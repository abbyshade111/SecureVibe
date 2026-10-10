# Decision records written with the change, not after it

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 4 October 2026, after the
appendix review showed every one of `sv`'s first eleven records was written one to seven days after its decision,
and only when a review noticed (`docs/paper/ADRS.md`). Four parts: a rule in `CLAUDE.md` saying what counts as a
decision and that its record (a new ADR, or a dated "Later" entry) goes in the same pull request, written first as
"proposed" for anything substantial; a "Decision record" section in the pull-request template; a "Governs:" list of
paths on every `sv` record, and a CI check that fails a pull request touching a governed path unless it changes
that record or says `ADR-0NN: unchanged, because …`; and a test that every test, file, and ADR number a record
names exists. The weekly review below becomes a scheduled task. **Claimed the same day by session securevibe-e9**,
in branch `claude/securevibe-e9-adr-upkeep`. Other sessions: please leave `docs/adr/` to it until this says done.
**Done the same day.** The rule is in `CLAUDE.md` and `docs/adr/README.md` ("When a record is written, and how it
stays true"), and the pull-request template has a "Decision record" section. ADR-015 to ADR-026 each have a
**Governs:** list; `tools/adr_check.py`, run by `.github/workflows/decision-records.yml`, fails a pull request that
touches a governed file without changing the record or giving an `ADR-0NN: unchanged, because ...` line. Replayed
on earlier pull requests, it would have caught #558 (ADR-019, the fence's gateway) and #588 (ADR-020 for the new
dependency, ADR-022, ADR-023, and ADR-026). `crates/sv-cli/tests/decision_records.rs` checks the records' tests,
files, patterns, cited numbers, and index; five references broken in turn, each caught, and the script's own
self-test caught two of its guards broken (a third guard was redundant and was removed).
