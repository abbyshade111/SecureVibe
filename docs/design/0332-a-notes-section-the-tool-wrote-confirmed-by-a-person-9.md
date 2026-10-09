# A notes section the tool wrote, confirmed by a person (9 October 2026)

Finding 22(c) of the gap analysis of 7 October 2026 (BACKLOG, "From the gap analysis of 7 October 2026"). A design
answer or a check made by hand that the AI coding tool gave can be confirmed by a person, and the report then shows it
as confirmed, never as the person's own (ADR-022). A section of `security-notes.md` had no such path. An owner who
agreed with a section the tool worked out from the code changed its line to `Written by: owner` and sealed it, and the
report called it *documented by the owner*, with nothing left to say the tool drafted it.

**What changed.**

- `sv review` now offers each section marked `Written by: AI coding tool` for confirming, after the owner's own
  entries. The person types their name, or `owner`; the tool's own name is refused, and Enter leaves the section as the
  tool's word.
- The seal it writes is made over a domain of its own, `security-notes-confirmed`, with the requirement and the answer.
  The section keeps its `Written by: AI coding tool` line. If the line is changed to `owner` afterwards, the owner's
  fields are checked and the seal does not hold for them, so the tool's draft never becomes the owner's word. An
  owner's seal moved onto a tool's section confirms nothing either.
- Confirmed, the section counts at the documented tier, as an owner's sealed section does, and is credited as
  `notes.confirmed`. The report shows it as "written by the AI coding tool, confirmed through sv review", and its line
  says the tool wrote it and a person confirmed it. The count row for the tier now says it may be either.
- The report's advice on a tool's section, the guide (step 5), and the MCP server's description of the notes tool say
  to confirm a section the tool worked out, and to mark as the owner's only what the owner decided.

**What it does not change.** Sections marked `Written by: owner`, and their seals, are read exactly as before, so no
seal already written stops holding. An unmarked section is not offered: it must say the tool wrote it. A confirmed
section whose answer changes is the tool's word again, as an owner's is.

**A cost.** Each section the tool wrote is offered every time `sv review` runs until it is confirmed, as the owner's own
unrecorded entries are; leaving one counts as nothing either way.

**How it is held.** `crates/sv-check/src/notes/confirmed_tests.rs` (confirmed, unconfirmed, flipped to the owner's, an
owner's seal on the tool's section, and a changed answer); `crates/sv-cli/src/review/confirm_notes_tests.rs` (the
tool's name refused, a person's taken, only the seal line added, and leaving it untouched); and
`crates/sv-cli/tests/notes_confirmed.rs`, end to end through `sv report`. Two existing `sv review` tests now show the
tool's section offered for confirming between the owner's. Four guards broken in turn, each caught:
- One seal domain for both: the flipped and the moved-seal tests, and the end-to-end test, failed.
- No credit for a confirmed section: its own test failed.
- The label never shown as confirmed: the end-to-end test failed.
- The tool allowed to confirm its own section: the review test failed.
