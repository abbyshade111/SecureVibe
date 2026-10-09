# The MCP server's record, the check given to it, and its text held in step (9 October 2026)

Item 10 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026: the four costs worth paying down"), without the fold of two tools into two others, which waits for the owner.
The record is ADR-066. Nothing a check concludes changed.

**The server's record.** ADR-066 gathers what the module doc and eight design entries decided one at a time: only what
`sv report` does and never more than a terminal's default, only inside the folder it was started for, nothing on its
output but the protocol, a time limit under a minute, the app's text fenced as data, and the AI tool's word kept as
its own. It governs the server's own files (`mod.rs`, `tools.rs`, `confine.rs`, `protocol.rs`, `catalog.rs`), so a
change to them now meets it in the "Decision records" check. It also decides that requests are read on the thread
that answers them until a client is seen to give up on a `ping` sent during a check. ADR-041 now governs the server's
side of the report lock, `mcp/report_writing.rs`; `main.rs` stays ungoverned, as the owner decided on 6 October.

**The check is given to the server.** `Server` held a field there only in tests (`hold`), which kept a check open
until the test let it go, so the time-limit test could ask again while a check was surely still running. It ran the
real check of `examples/flask-booking` three times for each of six tools. The check is now a field of its own,
`check`, which is `assemble` (the check `sv report` makes) unless a test gives another. The time-limit test makes one
real report, then gives each server a check that waits for word on a channel and hands back a copy of it. Dropping
the channel's other end lets it, and every later check, go at once. The test counts the checks made (three for each
tool: the one that ran out of time, and two that finished), so a server that ignored the check it was given fails it.
The test took 17 seconds and takes under 3.

**The text held in step.** Four places tell an AI tool the way to build: the opening instructions, the tool list, the
spec (`sv init` prints it, and `stackvet_spec` gives it), and the prompt the guide gives the person to paste. They were
kept in step by hand. The spec gave a feature's brief before its design-time prompts, and the instructions gave them
the other way about. Now:

- The tool list is in the order the instructions first name each tool, the order an app is built in: `stackvet_spec`,
  `stackvet_prompts`, `stackvet_plan`, `stackvet_before`, `stackvet_guidance`, `stackvet_preflight`, `stackvet_check`,
  `stackvet_questions`, `stackvet_write_report`, `stackvet_notes_file`, `stackvet_record_answer`, `stackvet_explain`,
  `stackvet_bundle`. It was in the order the tools were written. `tools/image_smoke.py` checks the new order.
- The spec now gives the design-time prompts before the brief, as the instructions do.
- `crates/sv-cli/src/mcp/flow_text_tests.rs` holds the instructions to name every tool in the list's order, and the
  guide's pasted prompt and the spec's commands (`sv prompts`, `sv plan`, `sv brief`, `sv preflight`, each the
  terminal's way to a tool) to name theirs in the same order.
- The same file reads every string an AI tool reads from the server before it calls a tool on an app: the
  instructions, every name, title, and description in the tool list and the prompt list, and the spec. It fails on a
  British spelling (a list of 34, `-s` forms included) and on a sentence that says an app or a requirement is safe,
  secure, compliant, certified, verified, approved, or passed, unless the sentence denies it ("do not tell the person
  the app is secure"). A word list alone forbade the server's other senses of the words ("a CI step must pass
  `--fail-on`", "the whole suite passes", "secure coding", the `compliance` format), so the test looks for a word that
  says it of something ("is", "are", "looks", "as", and the rest) just before one of them. "What is safe to do twice"
  is about doing, and passes. None of the strings failed either rule when the test was written.

How each is held, by breaking it:

- The server given a check, and `report_for` using the real one anyway: the time-limit test failed on its count.
- A second check let start beside one still running: the time-limit test failed where it expects the refusal.
- `stackvet_check` and `stackvet_preflight` swapped in the list: the order test failed, with the protocol test and
  the sections test, which read the list too.
- The pasted prompt naming `stackvet_check` before `stackvet_guidance`: its order test failed, and only it.
- The spec's old sentence put back: its order test failed, and only it. Nothing else read either order before.
- "The app is secure once this is clean" in a tool's description, and "behaviour" in the instructions: the text test
  failed on each, by name.

Not done here, as the item says: the fold of `stackvet_questions` into `stackvet_check` and of `stackvet_notes_file`
into `stackvet_record_answer` (the owner's call: their VS Code flow names `stackvet_questions`), and a thread of its own
for reading requests (ADR-066, point 9).
