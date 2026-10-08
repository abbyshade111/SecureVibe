# A deep gap analysis of SecureVibe, start to finish

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 7 October 2026: "a deep gap
analysis of SecureVibe - the process start to finish, etc. and let me know where there are blind spots or areas for
improvement". The whole path a person takes, read against the code: installing `sv`, writing `securevibe.toml`,
building with an AI coding tool and the MCP server, `sv check`, `sv run` behind the fence, `sv probe`, the reports,
reviews and seals, and what the counts claim. A reading, not a build: the result is a document in `docs/` that
names each blind spot with the evidence for it, and proposals for the owner to choose from; nothing in `sv`
changes with it.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word, in branch
`claude/securevibe-e2-gap-analysis`.
**Done the same day** (`docs/GAP-ANALYSIS.md`): five reviewers, one stage each, read-only, with the most serious
claims checked again in the code. Findings in seven parts (credit stronger than the evidence, false alarms, what is
never looked at, whose word counts in the build loop, getting started, the reports, the project's own health), the
coverage numbers by kind of run, and ten places to start. Nothing is built from it until the owner chooses; the
ones that change evidence, what `sv` runs, or the repository's settings are marked as decisions.
