# Hand the three question lists to the AI coding tool, and label what it answers

**Status:** partly done: see its done note; what remains is not yet written, as its markers read on 8 October 2026

Asked for by
the owner on 26 September 2026: the security notes, the design questions, and the checklist of what
only a person can check, packaged so the AI tool that wrote the app can answer them. The owner's
decision, the same day: a design answer from the AI tool is labeled *stated by the AI coding tool*,
its own tier below *attested by the owner*. **Claimed on 26 September 2026 by session
securevibe-e8.** Found by walking through `sv mcp` as an AI tool would, on a copy of
`examples/flask-booking` with no manifest:
- The check names the sixteen design questions by id only, with no question and no advice on where
  to look, so the tool would need sixteen `securevibe_explain` calls, and those give the ASVS text,
  not the question.
- It tells the tool to "run `sv notes`", which the MCP server has no way to do.
- The checklist of what only a person can check does not reach the tool at all.
- A contradiction says only "the code says otherwise"; `sv scope` says why (`pyjwt` in
  `requirements.txt`), and the tool is not told.
- The starter manifest has every capability set to `false`, while its own instructions say an
  unsure capability should be `true` and a line nobody answered should be left out. A tool that
  leaves a line as it found it has answered "no".

**The label is done the same day:** `by = "owner"` or `by = "ai-tool"` on a design answer, and the
tier *stated by the AI coding tool* below *attested by the owner*; an answer without `by` counts as
the tool's. See DESIGN, "The AI coding tool's answers, a tier lower still". **Next, and the owner's
refinement the same day:** the tool interviews the owner through the three lists, one question at a
time, offering what it knows of the code as a tip, and records the answers for the report. **Done
the same day:** `securevibe_questions` and `sv questions`, `securevibe_notes_file`, the check pointing
at them, and a contradiction saying what the code showed. See DESIGN, "The interview: the tool asks,
the owner answers". Left over:
- Where an answer to a check by hand is recorded. Today nothing records one, so the tool walks the
  owner through them and the report cannot tell.
  **Claimed on 26 September 2026 by session securevibe-e8**, with the owner's agreement to the design
  the same day: a `[checked-by-hand]` section in securevibe.toml (`result` done, problem, or
  not-yet; `on`, a date; `by`; and `how`, required), current for 90 days, reported as *checked by
  hand by the owner* just above *attested by the owner*, a tool's `done` as *stated by the AI coding
  tool*, and `problem` as needs attention.
  **Done the same day.** See DESIGN, "Checks made by hand, and what was seen".
- The starter manifest's capabilities all read `false` (above). Not changed here: it is the manifest
  contract, and worth its own decision.
  **The owner's decision, 27 September 2026: comment the capability lines out**, so a line nobody
  answered is unanswered, not a quiet "no". **Claimed the same day by session securevibe-e8.** **Done the
  same day:** every capability line in the starter file reads `# name = ?`, a `?` left in an
  uncommented line is refused rather than read, and the instructions say to answer each line or
  leave it commented out, never to guess `false`. `tls` keeps its default mode, and `[data]
  categories = []` still reads as "no personal data", which only lowers the target level; that is
  a quiet "no" of the same kind, left for its own decision.
  **The owner's decision, 27 September 2026: fix it the same way** ("let's fix the personal data
  starter file issue"). **Claimed the same day by session securevibe-e2.** **Done the same day:**
  the starter file's line reads `# categories = ?`, and a list nobody answered (no `[data]` at
  all, or the line left commented out) no longer buys level 1: the app is held to level 2 and the
  report and `sv scope` say why and how to answer, in the same words. `categories = []` is still
  an answer, "nothing about people", and still gets level 1. Only apps for `just-me` or `my-team`
  can change level this way; `customers`, the default, and `public` were level 2 already, and the
  note is not shown for them. Unanswered and answered-with-nothing, the starter file writing `[]`
  again, the note missing, and the note blamed on a public app are each caught by one or two
  tests.
- Fifty-five questions on the Flask example is a lot to be asked. The tool is told the owner may stop
  at any point; ordering them by level, or by what is most at stake, would help.
  **Claimed on 27 September 2026 by session securevibe-e8**, at the owner's asking ("continue to work
  off items in the backlog, your choice").
  **Done the same day:** the questions come level 1 first, since the catalogs hold only levels 1 and 2
  (16 and 51 questions), and within a level an unanswered question comes before one only the AI
  coding tool has answered, which needs confirming rather than answering. The interview says so. No
  sort, no tie-break, and level 1 put last are each caught by one test that reads the whole order.
