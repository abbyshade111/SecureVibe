# Answers the AI tool records, always as its own (4 October 2026)

The AI coding tool wrote the person's answers into `security-notes.md` itself, told by the questions to start one
with `Written by: owner` when the person gave it. Once, it credited its own answers to the owner (see "Who wrote it"
in `crates/sv-check/src/notes.rs`). The rule was held only by the instructions the tool was given (BACKLOG,
"Improving the MCP server", item 1).

**What the owner decided.** `sv` cannot tell whether the person said something or the tool only says they did, so
the tool should have no way to say "the owner said this". Everything it records is its own word, at the lowest tier,
and an answer becomes the owner's only when the owner changes the line themselves.

**What was built.** `securevibe_record_answer` takes a question's id and the answer, and writes the file the same way
`securevibe_notes_file` and `sv notes` do, with that one answer in place of what was under its question and
`Written by: AI coding tool` above it. There is no argument for who wrote it. It refuses:

- a question that is not asked of this app;
- a section the owner wrote, however short; the tool's answer never replaces theirs;
- an answer with a line saying who wrote it, a `Written by:` line or an emphasized "Written by …" line, either of
  which would make the section unreadable or, read alone, the owner's;
- an answer with a heading, which would end the section, or with a line `sv` writes itself (a quoted line, the
  placeholder, "What `sv` found:", or a requirement's own wording), which the report drops;
- an answer under 40 characters, which the report does not count.

The file is written under a new name and renamed into place, and never through a link. Recorded again, the tool's
answer replaces its own earlier one. The questions (`securevibe_questions`) now tell the tool to record through it,
to show the person what it wrote, and never to write or change the `Written by:` line for them; README and
GETTING-STARTED say the same to the person.

Without the MCP server, the tool can still edit the file, and the questions say to mark its answer as its own; nothing
in a file can stop a tool that edits it from writing `Written by: owner`. What changes is that the server, the way the
questions send it, offers no path to that line.

Two tests: every refusal above sends a case and finds the file unchanged, and an answer recorded twice and then one
the owner wrote are read back as the report reads them; and a notes file that is a link is refused with its target
untouched. Thirteen guards broken in turn, each caught. Two parts of one guard (the facts line and a requirement's
wording) were caught by nothing at first, and each got a case. A read-back after writing, which no answer these let
through could fail, was taken out.
