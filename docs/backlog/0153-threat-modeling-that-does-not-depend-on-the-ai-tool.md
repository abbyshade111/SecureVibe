# Threat modeling that does not depend on the AI tool

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done. Asked for by the owner on 25 September
2026. The investigation is done (session securevibe-e8): `docs/THREAT-MODELING.md`. In short, v1's
rule-based STRIDE model (32 threats citing 80 different requirements, decided by about 20 facts about the app) needs no
AI, and `sv` already knows nearly every fact it asks; ported to a data file, each threat would show
what the evidence says about it (found, checked in part, not verified, cannot place) and never that
it is mitigated. Three pull requests. The owner answered the three
questions on 25 September 2026: no likelihood/impact scoring, v1 to read the same data file later,
and a section of the report rather than a file of its own. **Claimed on 25 September 2026 by session
securevibe-e8.** All three are done: the rules as data, each threat's status from the evidence,
a "Threats" section in the reports, and twelve threats for what v1 did not model (MCP tools,
retrieval, several services, WebSockets, several tenants): 42 threats, 115 citations. Left over: v1
reading `data/knowledge/threats.json` in place of its own rules, a change to v1's design engine that
the owner has agreed to and that is its own piece of work.
