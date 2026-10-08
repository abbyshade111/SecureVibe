# Research OWASP's Agentic Skills Top 10, and what it would mean for `sv`

**Status:** partly done: 2 of 4 parts done, 0 claimed, 2 open, as its markers read on 8 October 2026

Asked for by the owner on 7 October
2026. A reading, not a build: what the list is (its version, date, status, and license, and whether it
is a numbered list of risks like the other Top 10s or a set of requirements `sv` could cite), where it overlaps what
`sv` already reads (AISVS 1.0, its Appendix C, and the AI-feature, MCP, and agent checks), and what it adds. For each
item: whether an app built with an AI coding tool could have the problem, whether `sv` could check for it (reading
the code, the running app, or neither), and what that would take. Also whether it bears on how `sv` itself is used
by an AI coding tool (the MCP server, the prompts, the coding rules). The result is a document in `docs/` and
proposals put here, each for the owner to decide; adding it as a framework `sv` cites, like ASVS and AISVS, is a
decision with a record of its own, as the frameworks it already loads were. Read the list's own text before saying
what any item asks, as with every citation.
**Claimed on 7 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the backlog
when ready", after asking for this item), in branch `claude/securevibe-e2-agentic-skills`, for the reading and the
document; any proposal it makes is left here for the owner. Read on `main` just before this claim: no other session
had claimed it.
**Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("feel free to pick your next backlog
item"), in branch `claude/securevibe-e9-agentic-skills`. Read on `main` just before this claim: no other session had
claimed it.
**Done the same day:** `docs/AGENTIC-SKILLS-TOP-10.md`, read from the list's own repository at `d6f7d7d` (owasp.org
is blocked here).
- **What it is:** a list of ten risks, not requirements; version 1.0 still in public review; CC BY-SA 4.0.
- **Its references:** its ASVS references use ASVS 4.0's numbering, and each points elsewhere in 5.0. It never
  mentions AISVS.
- **Where it reaches an app built with an AI tool:** AISVS C9.3 and C10.1 already ask the same things.
- **The gap:** the person's own AI tool's files in the project folder, which `sv` leaves out on purpose
  (`launch.rs`).

Three proposals, each for the owner to decide (the document has the detail):
1. **Read the AI coding tool's own files in the project folder** (hooks that run commands, permission settings that
   allow everything, MCP servers started unpinned, base-address overrides), and report them in a section of their
   own, apart from the app's grade, as notices. AST02, AST03, AST07. No ASVS or AISVS requirement fits, so it cites
   none. Small to medium. **The owner said yes; not claimed.**
2. **Hidden characters in the instruction files committed in the folder** (`AGENTS.md`, `CLAUDE.md`, `SKILL.md`,
   `.cursor/rules/`, and their like): Unicode tag characters and right-to-left overrides, only ever a finding. AST04.
   Cites none. Small. **The owner said yes; not claimed.**
3. **Adopting the list as a framework `sv` cites:** this session recommends not now, and looking again at its v1.0
   release (planned for the fourth quarter of 2026). **The owner agreed.**

**securevibe-e2's reading, done the same day** (#901, merged before the owner's decision below reached it; its
document was then replaced by securevibe-e9's, as the owner decided, keeping its extra point), read from the project's own repository at `d6f7d7d`, since
owasp.org is blocked here. The list is about the skills AI agents load, not the apps they build; it is in public
review, lists risks rather than requirements, and its ASVS links use ASVS 4.0's chapters. Where it meets `sv`: apps
that are agents (AISVS C9.3.1, C9.3.7, C10.4.8, C10.1.1, and V1.5.2, the last two already checked), and `sv` itself
as a tool an agent uses. **Four proposals, none built, each the owner's:** (1) do not load it as a framework until
version 1 is out; (2) look for invisible characters in the project's instruction files (`SKILL.md`, `AGENTS.md`,
`CLAUDE.md`, `.cursor/rules`); (3) say what a committed `.claude/settings.json` would run (hooks, a different
`ANTHROPIC_BASE_URL`), which `sv` leaves out today on purpose; (4) nothing new for C9.3.7 and C10.4.8 beyond the
usual coverage work.
**Two sessions claimed this item, eight minutes apart** (securevibe-e9 at 12:42 UTC in #898, securevibe-e2 at 12:50
UTC in #900, before #898 reached `main`), and both wrote the document. **The owner's decision, 7 October 2026:** keep
securevibe-e9's (#899), on whose proposals the owner had already answered, and add the one point securevibe-e2's
(#901) had that it lacked. #901 reached `main` first; its document is replaced by this one: the AISVS requirements nearest the list that no check credits (C10.4.8, and C9.3.7, which
is only ever found failing).
**The owner's answers to the three proposals, 7 October 2026:** "yes to 1 and 2, agree on 3". Proposals 1 and 2 are to
be built; the list is not adopted for now.
**Proposals 1 and 2 claimed the same day by session securevibe-e9**, at the owner's word, in branch
`claude/securevibe-e9-ai-tool-files`. **Record, `Status: proposed`: ADR-049**, which writes down all three answers.
Read on `main` just before this claim: no other session had claimed them.
**Done the same day** (DESIGN, "The AI coding tool's own files, apart from the app"; ADR-049, accepted). The report's
new section, "What your AI coding tool's files let it do", reads Claude Code's settings, `.mcp.json`, and
`.vscode/mcp.json`. `config.instructions-hidden-characters` finds tag characters and direction overrides in the
instruction files. Cursor's files are named and not read: its documentation could not be reached here.
