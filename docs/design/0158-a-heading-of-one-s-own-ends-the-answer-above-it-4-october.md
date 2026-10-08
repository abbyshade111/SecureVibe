# A heading of one's own ends the answer above it (4 October 2026)

Found writing the design-time prompts, and reproduced the same day (BACKLOG, "A heading of the owner's own in
`security-notes.md`"). The reader ended a section only at the next section's heading, so a heading of anyone else's,
and everything under it, became the answer to the section above. With `## A note from me` under V2.1.1, which nobody
had answered, the report called V2.1.1 *stated by the AI coding tool*: with or without a `Written by:` line in the
note, and the same under `###`. It was still so after the same day's change that keeps the owner's text (R7, "The
notes file keeps what the owner wrote outside the answers"), which had made `sv`'s own headings end a section and kept
headings of the owner's inside the answer above them.

At the owner's choice ("end a section at any heading, and say what was skipped"; ADR-022, "Later, 4 October 2026"):

- **A heading of the first three levels ends the section above it.** What follows a heading of somebody's own after a
  section is part of no answer: it goes with the other text that is not under a question, which R7 keeps word for word
  in a section of its own near the top and the report does not read. A `####` heading, and `##` with no space after
  it, stay inside the answer they are in, so an answer can still have parts. Headings before the first section are
  `sv`'s own title and introduction, as before.
- **The seal is held to the same boundary**, so `sv review` never places one under a `Written by:` line in somebody's
  note below a section.
- **The report names each such heading, and the section it followed, as a gap**, saying the text was not read as an
  answer, that notes of one's own are fine there, and how to make one part of an answer. The gaps already say the same
  of a `Written by:` line nothing was made of.
- **One of R7's tests changed.** It held that `## Notes we keep` inside an answer was part of that answer. Keeping the
  owner's text was R7's point, and the text is still kept; whether it counts as the answer is this decision. The test
  keeps its other two heading-like lines, which stay in the answer.


**Broken in turn.** Eleven guards: the old reader (5 tests red, the end-to-end one among them), `###` and `#` not ending
a section, `####` ending one (caught by this test and by R7's own), the reader ignoring a heading of one's own, the
heading not listed, the heading line itself not kept, the seal placed by the old boundary, the evidence and the report
each saying nothing, and headings before the first section taken as somebody's (13 red, most of them R7's). Each was
caught. A first run, before R7 was merged, reported the end-to-end test as catching nothing: the script named a test
file in the wrong crate, cargo refused to start, and the script read that as no failures. It now stops when a run
reports no tests.
