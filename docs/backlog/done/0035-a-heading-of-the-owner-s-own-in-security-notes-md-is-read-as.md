# A heading of the owner's own in `security-notes.md` is read as part of the answer above it

**Status:** done, as its markers read on 8 October 2026

Found on 4 October
2026 by session paper-facts, writing the design-time prompts. `read_answers` (`crates/sv-check/src/notes.rs`) ends a
section only at a heading that starts with a requirement id (`section_id`), so `## A note from me` and what follows
it become part of the section above. Read in the code; **not reproduced end to end**: tried on a copy of
`examples/flask-booking`, where even a properly written answer was not counted, so the setup was wrong and the
question open. If it holds, text under a stray heading below an unanswered section could make it look answered, at
the tier its `Written by:` line gives. The prompts are kept from causing it (a test holds them to `sv`'s headings);
an owner or a tool writing a heading of their own is not. Ways out, for the owner: end a section at any heading, or
report a heading `sv` does not know as a gap.
**Claimed on 4 October 2026 by session paper-facts**, at the owner's word, in branch `claude/notes-headings`. First
step: reproduce it end to end, with a test, before any fix; the way out is then the owner's to choose, and its
record is written with it.
**Reproduced the same day** (`crates/sv-cli/tests/notes_headings.rs`): with `## A note from me` under V2.1.1, which
nobody answered, the report called V2.1.1 *stated by the AI coding tool*, with or without a `Written by:` line in the
note, and the same under a `###` heading; still so on `main` after R7 the same day.
**Done the same day**, at the owner's choice of "end a section at any heading, and say what was skipped" (ADR-022,
"Later, 4 October 2026: a section ends at any heading"; DESIGN, "A heading of one's own ends the answer above it").
