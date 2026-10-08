# The AI coding tool writes over only its own answer (5 October 2026)

R8 of the deep review: `securevibe_record_answer` refused to replace a section marked `Written by: owner`, and
replaced everything else. An owner who wrote an answer in their own editor and left out the `Written by:` line, which
nothing asks them to add, lost it the next time their AI coding tool recorded an answer to the same question.
Reproduced first, with a test that wrote the owner's sentence under a question with no mark and saw the tool's
answer take its place. R7's fix (DESIGN, "The notes file keeps what the owner wrote outside the answers") did not
cover this: it keeps what is outside the answers, and this is the answer itself.

- **The rule** (`Answers::tool_may_write`, `crates/sv-check/src/notes.rs`): the tool's answer goes only under a
  question with nothing under it (blank lines count as nothing), or over a section marked
  `Written by: AI coding tool`, the mark `sv` writes on everything the tool records. Anything else may be the owner's
  words and is refused: an answer with no mark, however short ("TBD"); one marked with the tool's own italic line,
  which is the tool's wording and not `sv`'s mark; one marked as anybody else's, or with two marks that disagree; and
  the owner's mark, with or without an answer under it.
- **Whose word it is, and whether it may be thrown away, are two questions.** ADR-022 counts an answer with no mark
  as the tool's, because crediting the owner on nobody's say-so overstates; that is unchanged, and the report still
  says so. Writing over it is a different act: it destroys text that may be the owner's, so it is refused.
- **A refusal writes nothing** and leaves the file byte for byte as it was. The reply says why ("the answer to V2.1.1
  does not say who wrote it, so it may be the person's own"), that nothing was written, and what the owner can do:
  edit the answer themselves, or delete everything under the question so that the tool can record its own.
- **The other ways answers are written** do not write over an answer: `sv notes` and `securevibe_notes_file` keep
  every answer as written (R7), and `sv review` only adds a seal line under a section marked as the owner's, from
  the owner's own terminal. The instructions the tool reads with the questions now say the same rule for a tool
  without the MCP server, which edits the file itself, and the tool's description says it too.

How it is held: `the_tool_never_writes_over_an_answer_it_did_not_mark_as_its_own` (`crates/sv-cli/src/mcp.rs`),
which checks each refusal leaves the file's bytes unchanged and that each setup read back with the writer it meant,
and fills an empty question and replaces the tool's own answer; and
`the_tool_writes_only_where_nothing_is_or_over_its_own_marked_answer` (`crates/sv-check/src/notes.rs`). Seven guards
were undone in turn and each turned at least one test red: not calling the rule at all (two tests), letting through
an unmarked answer, the review's case (two), one marked as somebody else's (two), or the owner's (three), not
recognizing an empty question (five), refusing the tool's own answer (three), and refusing a question the file does
not have yet (one). An eighth, treating only a section with no characters at all as empty rather than one of blank
lines, changed nothing, because the reader already drops blank lines around an answer; the check stays as it is for
a caller that builds the sections itself.
