# Prompts for what an app's last report shows unproven (7 October 2026)

The last part of the prompt library's decisions of 3 October 2026 was "`sv` can offer the right prompt for a
requirement that still has no evidence", left undone because it needs a report first. It reads the app's last one.

- **Where.** `sv prompts --app <folder>` reads `<folder>/securevibe-report/report.json`, and `--report <file>` names
  another. `securevibe_prompts` takes the app's folder as `path`, under the same root as every other tool. With no
  report there yet, both say to make one first (`sv report`, or `securevibe_write_report`). Asked for one requirement
  and for an app at once, both say to pick one.
- **What counts as unproven.** A requirement whose status in the report is `needs-attention` (a finding),
  `not-verified` (nothing shown either way), `attested` (only the owner's word), or `stated` (only the AI tool's).
  `checked`, `by-hand`, and `documented` are each evidence of some kind already, so no prompt is offered for them.
- **What is offered.** Each prompt of either library (coding and design-time) whose requirements, or Secure by Design
  controls, include one of those. Those shown to work come first, as everywhere prompts are given. Each says which of
  the app's requirements it is for and what the report said of each, in words ("a finding", "nothing shown yet").
- **What it is worth.** Nothing, as before: a prompt is an instruction, and the offer says to make a new report
  afterwards. It is read from the report as written, so it says what was true when the report was made.
- **What it does not touch.** The feature brief and the guidance (ADR-044) still give the prompts shown to work while
  a feature is built. This is the other moment, after a report.
- **The app's file is not repeated.** `report.json` is a file in the app's folder, so the MCP tool reads it only when
  it is not a link out of the folder. Only requirement ids the library itself names reach the text, each followed by
  fixed words for its status.
- **Guards, each broken on purpose.** Counting a `checked` requirement as unproven, not putting the prompts shown to
  work first, offering every prompt, swapping the words for a status, allowing one requirement and an app at once
  (once in the MCP tool and once in `sv prompts`), and reading a `report.json` that is a link: each turned a test red
  (`crates/sv-cli/tests/prompts_for_gaps.rs`, and the two `securevibe_prompts` tests in `mcp.rs`), and was put back.
