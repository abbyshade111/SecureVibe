# Improving the MCP server

**Status:** partly done: 5 of 6 parts done, 0 claimed, 1 open, as its markers read on 8 October 2026

Proposed on 3 October 2026 by session securevibe-e2, at the owner's asking, and put
here by the owner's word. **Not claimed; each can be claimed on its own.** None is measured yet.
1. **A tool that records the person's answers, with who gave them.** Today the AI tool edits `security-notes.md`
   itself, and the backlog records that this once credited the tool's own answers to the owner. A
   `securevibe_record_answer` tool would write each answer with its author, so the rule is held by the code rather
   than by instructions.
   **The owner's decision, 4 October 2026:** build it, with every answer the tool records marked as the AI tool's
   own, at the lowest tier. `sv` cannot tell whether the person said something or the AI tool only says they did,
   so the tool takes no "the owner said this"; an answer counts as the owner's only when the owner confirms it
   themselves, at the terminal or by editing the file. **Claimed the same day by session securevibe-e2**, at the
   owner's word, in branch `claude/securevibe-e2-record-answer`.
   **Done the same day** (DESIGN, "Answers the AI tool records, always as its own"): `securevibe_record_answer`
   writes the answer under its question marked `Written by: AI coding tool`, never replaces a section the owner
   wrote, and refuses an answer that says who wrote it or would not read back as written. The questions now tell
   the tool to record through it and never to change the line for the person. Thirteen guards broken in turn,
   each caught.
2. **Keep the last report until the app's files change.** Every call builds the whole report again, and
   `securevibe_questions` runs the full check to list questions. Kept, "check after each feature" would be quick.
   **Measured on 3 October 2026, and not worth building yet:** with a release build, `sv check` of
   `examples/flask-booking` took 0.13 seconds, and three MCP calls on it 0.2 seconds together; only a folder the
   size of this repository took long (6 seconds). A kept report would save little for the apps `sv` is for, and one
   kept past a change to the app would say something no longer true.
3. **Declare the shape of each tool's structured result** (`outputSchema`, in the 2025-06-18 protocol), so a
   client can rely on it. None is declared now.
   **Claimed on 3 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
   branch `claude/securevibe-e2-output-schema`.
   **Done the same day** (DESIGN, "The shape of each tool's result, declared"): seven tools declare their result's
   shape, closed to fields it does not name, and a test holds every tool's real result to it. Seven ways broken,
   each caught.
4. **Progress notifications during a long check**, so the tool does not look stuck.
   **Claimed on 3 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
   branch `claude/securevibe-e2-mcp-progress`.
   **Done the same day** (DESIGN, "Saying how a check is going"): a client that gives a progress token hears each of
   a check's seven stages as it starts, and nothing after the answer. Eight guards broken in turn, each caught.
5. **Offer the written reports as MCP resources** the tool can open, rather than only files on disk.
   **Claimed on 3 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
   branch `claude/securevibe-e2-mcp-resources`.
   **Done the same day** (DESIGN, "The written reports, offered as resources"): every report `sv` wrote below the
   root is listed, and its five files read back, in both the initializing and the stateless protocol; nothing that
   is not a file of a marked report folder can be listed or read, links included. Nineteen ways broken, each caught.
6. **The newest protocol version.** The newest the server speaks is 2025-06-18; whether a later one has been
   published, and what it changes, needs checking before it is added.
   **Claimed on 3 October 2026 by session securevibe-e2**, at the owner's asking to continue with the backlog, in
   branch `claude/securevibe-e2-protocol-version`. Two later versions are published, 2025-11-25 and 2026-07-28
   (their schemas in the specification's repository); what each changes for a stdio server that offers only tools
   is the work.
   **Done the same day** (DESIGN, "The newer protocol versions, 2025-11-25 and 2026-07-28"): a client that opens
   with `initialize` may have 2025-11-25, and one that names 2026-07-28 on each request is answered statelessly,
   with `server/discover`; wrong arguments come back as a tool's result. Nine ways broken, each caught.
