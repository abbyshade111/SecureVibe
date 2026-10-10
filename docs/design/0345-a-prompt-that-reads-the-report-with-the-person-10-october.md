# A prompt that reads the report with the person (10 October 2026)


Backlog 0217, part 5, as the owner chose on 9 October 2026 ("as recommended"). Built by session securevibe-e2.

**The problem.** A person who is not technical gets `compliance.md`, `security.md`, `report.html`, and a dashboard.
The report already leads with what was not examined and never says a requirement passed, but it is long, and the
person usually reads it through their AI coding tool. That tool, asked "what does my report say?", is free to start
with the good news and to round "nothing found by the checks that ran" up to "your app is secure".

**What was built.** One prompt, not a new tool: the AI tool can already read the report's files.
- `crates/sv-cli/src/report_prompt.rs` holds the words once. They ask the tool to start with what was not checked
  ("What was not examined", the "Not run this time" line, and the requirements not verified or not yet placed) and
  what each means for the person; then at most three things to do first, from "What to do next" and the worst
  findings in "The short version", in the report's order, never more than the report gives; then the person's
  questions. They forbid saying the app is secure, safe, compliant, or that it passed, softening the report, or
  passing off the tool's own observations as StackVet's. With no report there, the tool says so and does not guess.
- `sv prompts report` prints it, with its mark ("Not tried yet.") and the line every prompt carries, that a prompt
  is an instruction, not evidence. `sv prompts` now takes that one word and refuses any other, where before it
  passed over a word it did not know.
- The MCP server offers it as the prompt `read-my-report`, after the design-time prompts, in both protocols. It
  carries no Secure by Design credit line: it is StackVet's own text, not drawn from the checklist.
- `docs/prompts/report.md` shows it to a person, and the guide links it where it says where the report is.

**What it is worth.** Nothing as evidence: it reads no file of the app's and credits nothing. It has not been tried
in an AI coding tool, and the page and the mark say so. What the tests hold
(`crates/sv-cli/tests/report_prompt.rs`, 5, and `crates/sv-cli/src/mcp/report_prompt_tests.rs`, 2): every name the
prompt puts in double quotes is a heading or line in the `compliance.md` a real `sv report` writes, in the folder the
prompt names; what was not checked comes before what to do; the forbidding sentences are there; `sv prompts report`
prints it and refuses more; the page holds the same words; and the server lists and sends it.

**Broken on purpose, each put back:** a section the report does not have named in the prompt (3 red: the report
test, the order test, and the page test), and the prompt left out of the server's list (3 red: the new MCP test and
the two existing prompt-list tests). A word after `sv prompts` was refused before this change, which the first run
of the new test found.
