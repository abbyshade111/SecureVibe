# The loop at scale (6 October 2026)

Item 6 of "The loop" (`docs/prompts/loop-scale/README.md`): five builds a cell, Sonnet 5.5 and Haiku 4.5, on `sv` at
`cd2478f8` with the preflight and the instructions that say when to check, and `sv init`'s specification in every
request (protocol amendment 3), so the arms without the server could be tested at last. Seventy builds, $21.34.

**Results.** With the specification, every Sonnet build was testable in every arm, at about the same level: the
specification, not the server, makes a Sonnet app testable. Haiku varied within every arm, and no arm was above another
by the rule. The loop arm did what the instructions now ask: every build checked, Haiku's all checked again after a
fix, and where the check named the committable `.env` the builders fixed it, which almost no build in another arm did.
At five a cell that is a pattern seen, not a difference by the rule.

**What it found in the trial.** Limiting an arm by refusing tools, not hiding them, made the builders give up on all of
SecureVibe's tools: the check arm never checked. Hidden, the check and the plan were asked for far more often
(amendment 4). Item 3's arms were limited the refused way, and its write-up now says so.

**What it found in `sv`.** A crash at start is reported by the first line of the error, which says nothing; the
preflight does not check the start command's file; two Haiku builds still stopped to ask the owner. Each is in the
backlog.
