# `sv`'s plan is too big for an AI tool to take in as one answer

**Status:** done, as its markers read on 8 October 2026

Found on 5 October 2026 by session
paper-facts, in the loop pilot. `securevibe_plan` gave 115,618 characters for the club app, and Claude Code saved it
to a file instead of passing it on; `securevibe_check` gave 50 KB for one build, handled the same way. The builder
then read them in parts with a script. A short answer first (what to build, the run settings, the decisions to
make) with the rest by section, or a size the common tools pass whole, would let a builder read what it is given.
**Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking to take the last of the
pilot's findings, in branch `claude/plan-in-parts`.
**Done the same day** (DESIGN, "The plan and the check in parts an AI tool takes in whole"; ADR-030, "Later"):
`securevibe_plan` and `securevibe_check` answer within 40,000 bytes, text and structured result each, a budget set
from Claude Code's two limits as the pilot's transcripts and its program show them (25,000 tokens refused; 50,000
characters saved to a file). A short answer is given whole, as before; a long one in sections and pages, the first
answer starting with what to decide and what `sv run` needs (plan) or what was not examined and the findings
(check), and ending with how to ask for every other part; `"section": "all"` gives the whole. The structured result
is cut the same way, since Claude Code reads it instead of the text. Tested by asking for every page of the club
app's plan and of a long check: each under the budget, fenced, and of its declared shape, and the pages joined are
the whole answer, text and lists. Eleven guards broken in turn, each caught; two only by a unit test written for
them. No build was run through a real AI tool with it.
