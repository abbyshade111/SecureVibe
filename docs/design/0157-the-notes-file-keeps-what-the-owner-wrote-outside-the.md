# The notes file keeps what the owner wrote outside the answers (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 3, R7) found that `sv notes`, and the MCP tools
`securevibe_notes_file` and `securevibe_record_answer`, which write through the same function, rebuilt
`security-notes.md` from the answers alone, though the tool told the AI coding tool it "keeps everything". Reproduced
before the fix on a copy of `examples/tested-notes`: a paragraph the owner wrote above the first question and a quote
in an answer were gone after one `sv notes`, and a file with one byte that is not UTF-8 was read as no file at all and
written over with a blank template, every answer in it lost. Reading the code found more: a bullet added to `sv`'s
list of facts was dropped with them, an answer lost the indentation of its first line, a second section for the same
question was silently ignored, a heading for a requirement `sv` no longer asks about was replaced by `sv`'s own
title (or dropped, with nothing under it), and the heading `sv` puts over answers to questions that no longer apply,
with its paragraph, was read as part of the answer to the last question above it, which then counted as *stated by the
AI coding tool* from `sv`'s own words.

**What is `sv`'s, and what is kept.** The reader (`sv_check::notes::read_answers`, which now takes the catalog) drops
only what `sv` writes: the title line, its paragraphs (in every wording since the file was first written, so a file
from 27 September does not have the old paragraph kept as the owner's), the question as the catalog asks it now, the
italic line quoting the requirement, the facts line and the bullets under it that begin as `sv`'s facts do, and the
placeholder. Everything else under a question's heading is that question's answer, carried across as it was, with only
blank lines at its start and end left out, and a heading the file already has is kept as it was. Everything that is
neither, wherever it was (above the first question, under `sv`'s headings), is kept word for word and in order in a
section of its own near the top, "Kept as you wrote it: text that is not under a question", which says that the report
does not read it. So is a quoted block at the top of a section that is not the question as asked now: it may be an
earlier wording of the question, so it is not counted as an answer, and it may be the owner's, so it is not dropped.
Lines are split on the newline alone, so a Windows line ending stays on the line it was on.

**Refused, writing nothing, and why.** A file that is there but is not UTF-8 text, or cannot be read, is refused, so
it is never written over; and so is a file with two sections for one question, since which is the answer is the
owner's to say and keeping both leaves the file read two ways. Both say how to put it right. `sv notes` and the MCP
tool say when a kept section was written, and the tool's description says what it keeps and when it refuses.

**What is still not kept**, stated: the question and the facts are `sv`'s and are written afresh each time, so an
owner's edit inside the quoted question, or to a bullet of `sv`'s facts that still begins as `sv`'s do, is replaced; a
second copy of one of `sv`'s whole paragraphs is dropped; and a heading's `##` or `###` is set by where the section
is (a question that applies, or one that no longer does), though its words are kept. Text after a section's heading is
that section's answer, as before, even when the owner meant it for the file as a whole.

`record_answer`'s refusal to replace an owner's section without a `Written by:` line (R8) is a different fault in
`write_notes` and is not changed here; the tool's answer is written through the same writer, so it now keeps the
owner's text elsewhere in the file. One effect on seals (R1, the same day): a quote or a bullet in an answer that the
reader used to drop is now part of the answer, so a seal recorded over such a section before this change no longer
matches, and the report says so and how to record it again.

**Tested.** Reproduced first with a copy of `examples/tested-notes` (the review's write-up names the code, not its fixture) (a preface, a quote in an answer, and a byte that
is not UTF-8), then held by unit tests beside the reader (`crates/sv-check/src/notes.rs`): the owner's text before,
between, and after `sv`'s sections, in order; text that looks like a heading (in the preface, inside an answer, a
requirement `sv` does not know, one with nothing under it, a retitled question); two sections for one question,
refused; an empty file; a file of more than five megabytes, kept whole; a byte-for-byte round trip (Windows line
endings, an indented first line, trailing spaces, a fenced block, tabs, accents); an earlier wording of the question
and of the paragraph above; every fact `sv` writes recognized as `sv`'s; and kept text never counted as an answer.
End to end, `crates/sv-cli/tests/notes_keep_owner_text.rs` runs `sv notes` and checks that a refusal leaves the file's
bytes as they were, and an MCP test does the same for both notes tools. Sixteen guards broken in turn, each caught:
the kept section not written (8 tests), the preface not gathered (7), a quote at the top of a section dropped (2) or
one further down (4), every bullet under the facts dropped (2) or none recognized (12), the question never recognized
(9), the heading over old answers not ending a section (2), duplicates not refused (2), an unreadable file read as no
file (2), headings not kept (2), a heading with nothing under it dropped (2), answers trimmed whole (2), the earlier
paragraph not recognized (4), the line ending dropped (2), and `sv`'s own paragraph under a question kept (1, a
fixture for files from before this change). Seven were at first caught by one test each; a fixture was added for each
but the last, which only a file from before this change can show.
