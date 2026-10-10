# Tell the builder, before it is done, what the code already shows about the running app

**Status:** done, as its markers read on 8 October 2026

Found on 6 October
2026 by session paper-facts, counting item 6's findings by group: the loop arm fixed nearly every problem in its
code that `securevibe_check` named, and its running apps had as many problems as every other arm's (per ten checks
answered, Sonnet 1.0 against 0.8 to 1.1, Haiku 2.4 against 2.0 to 2.6), because `sv run`'s checks are the only ones
that see them and the MCP server never starts the app. Several of the commonest are visible in the code without
running it: no limit on wrong passwords, the security headers, the session cookie's attributes, the AI feature's
screening of what it is sent. A part of `securevibe_preflight` (ADR-035), or of the check, that reads the code for
these and says "`sv run` will look for this, and the code does not seem to have it", running nothing, would give the
builder the chance the loop already takes with what the check says. Each would credit nothing, as the preflight
does; the run stays the evidence. The next loop trial could measure whether the running apps' findings then fall.
**The owner's decision, 6 October 2026: yes**, as a planned change between trials, with the next trial measuring
whether the running apps' findings fall. **Claimed the same day by session securevibe-e9**, in branch
`claude/securevibe-e9-preflight-hints`. **Record, `Status: proposed`** (a "Later" entry on ADR-035): the preflight
also says, for each of the commonest running-app findings that the code shows no sign of handling, that `sv run`
will look for it; each is an answer of "Look", credits nothing, and never says the app is safe or unsafe.
**Done the same day** (DESIGN, "The preflight says what `sv run` will look for"; ADR-035, Later; the loop protocol's
amendment 6): wrong passwords, the security headers, the session cookie's `SameSite`, and a screen on what an AI
feature is sent, in a section of their own; the next trial measures whether the running apps' findings fall.
**A second claim, withdrawn the same day.** Session securevibe-e2 claimed this item too (#840) without seeing
securevibe-e9's claim, which reached `main` first and stands. Before that was seen, securevibe-e2 had built a version,
with its tests, docs, and an ADR-035 "Later" entry, in branch `claude/securevibe-e2-builder-hints-build` (not merged).
It covers a limit on wrong passwords, the four security headers, the session cookie's SameSite, and an AI feature's
screening, limit, and off switch, counted apart from what the run needs. It answers "looks right" and "could not
tell" as well as "look at this", where the record above gives only "look at this". It is there for securevibe-e9 to
use or leave; securevibe-e2 does no more on this item.
