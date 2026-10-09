# A glossary for the guide and the reports (9 October 2026)


Backlog 0217, part 7, as the owner chose on 9 October 2026. Built by session securevibe-e2.

**Why.** The guide is for someone who has never opened a terminal, and it uses words such as terminal, Docker, image,
git, MCP, and "not assessed" before saying what they are. Each step that assumes one of them is a place to stop.

**What was built.** `docs/GLOSSARY.md`: twenty words, each explained in a sentence or two of plain American English,
from "AI coding tool" to "Report". The guide points to it before step 1 and links the first use of Docker, terminal,
git, MCP, and "not assessed". What it says about StackVet's own names (the image, the three settings files, the report
folder) is held by a test to what `sv` uses, so it cannot drift from the program.

**Tests.** `crates/sv-cli/tests/glossary.rs` (6): every `GLOSSARY.md#…` link in the guide, the glossary, and the
README lands on a heading (by the anchor GitHub makes, itself tested); the guide's pointer comes before step 1; the
five words the guide relies on are explained and linked; every word has an explanation of at least a dozen words; and
the names match `sv`'s.

**Broken on purpose, each put back** (`gbreaks.py` in the session's scratchpad): a heading renamed (2 red), the
guide's pointer removed (2), a link to a word that is not there (2), an explanation cut to one word (1), and the image
written with the old name (1). The last two are each held by the one test written for exactly that, which was
expected; the first three were held by one test each until the test naming the guide's words was added.

**Not done.** The reports do not link the glossary yet: `report.html` opens no network connection and lives in the
person's folder, so a link would point at GitHub; whether to carry a few definitions inside the report is part 5's
question. Nobody who is not technical has read it yet (part 8).
