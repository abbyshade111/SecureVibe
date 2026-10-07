# OWASP's Agentic Skills Top 10, and what it would mean for `sv`

Research the owner asked for on 7 October 2026 (`docs/BACKLOG.md`, "Research OWASP's Agentic Skills Top 10"), written
the same day by session securevibe-e9. It is a reading, not a build. Every proposal at the end is for the owner to
decide. Adding the list as a framework `sv` cites would be a decision with a record of its own.

**Where it was read.** This machine's network blocks owasp.org, so the list was read from its own repository,
`github.com/OWASP/www-project-agentic-skills-top-10`, at commit `d6f7d7d` (12 August 2026). That repository is the
source of the pages owasp.org shows. What each item asks is taken from its own page (`ast01.md` to `ast10.md`).

## What the list is

- **A list of risks, not requirements.** There are ten numbered risks, AST01 to AST10, each with a severity, a
  description, real incidents, attack scenarios, and "preventive mitigations". Like the other OWASP Top 10s, nothing
  in it is written as "verify that…", and it has no level for each item. So it cannot be cited the way `sv` cites
  ASVS and AISVS, where a check either speaks to a requirement or does not. The most it could be is a "related risk"
  beside a finding.
- **What "skills" means.** Reusable, named behaviors that an AI agent loads to do a whole task, with the agent's own
  permissions. The list covers OpenClaw's `SKILL.md`, Claude Code's skills and settings (`.claude/settings.json` and
  hooks), Cursor's and Codex's `manifest.json`, and VS Code extensions. In its own words, MCP tools define *what* an
  agent can do, and skills define *how* it uses them.
- **Its version and status are not settled.**
  - The pages call it version 1.0, "2026 Edition", with a badge saying it was updated in March 2026.
  - The project's own timeline puts the v1.0 release in the fourth quarter of 2026.
  - It asks for public comments on a "merged v1 draft" in a Google Doc.
  - Its status line reads "New Project Proposal — active development", under OWASP's incubator badge.
  - A whitepaper named v0.5 is also published.
- **License and authorship.** The license is Creative Commons Attribution-ShareAlike 4.0. The project lead is Ken Huang,
  who also wrote the Cloud Security Alliance's Secure Vibe Coding Guide that `sv`'s prompts credit.
- **Its own cross-references are not reliable.**
  - **ASVS:** every reference uses ASVS 4.0's numbering, and in ASVS 5.0, the version `sv` reads, each points somewhere
    else. AST03's "ASVS V4 (Access Control)" is "API and Web Service" in 5.0, and authorization is V8. AST04's "V5.5
    (Deserialization)" is V1.5 in 5.0. AST06's "V12 (File/Resource)" is "Secure Communication". AST02's and AST07's
    "V14.2 (Dependency)" is "General Data Protection"; dependencies are V15.2. AST08's "V14.3" is "Client-side Data
    Protection".
  - **The LLM Top 10:** its numbering is mixed. AST06 cites "LLM08 (Excessive Agency)", the 2023 list's number, while
    AST03 and AST09 cite "LLM09 (Misinformation / Excessive Agency)", two different 2025 items as one.
  - **AISVS:** it is not mentioned anywhere in the repository.

## Where it touches `sv`

A skill can sit in two places that matter here:

1. **In the person's own AI coding tool.** The tool `sv`'s users build with has skills, hooks, permission settings,
   and MCP servers, often kept in the project folder (`.claude/`, `.cursor/`, `.mcp.json`, `AGENTS.md`). This is where
   most of the list applies to someone who builds with an AI coding tool. Today `sv` deliberately leaves these files
   out of its app checks: `crates/sv-check/src/launch.rs` (`developer_tool_config`) says what they start "runs on the
   developer's computer, which C10.1.1 is not about". That is right for the app's grade, and it is also why nothing in
   `sv` looks at them at all.
2. **In the app itself, when the app is an agent** that loads tools, plugins, or skills. AISVS already covers this:
   - **C9.3** asks for tool and plugin isolation (C9.3.1), manifests that declare privileges (C9.3.3) and are enforced
     (C9.3.4), and external resources checked against an allow-list before they are installed or invoked (C9.3.7).
   - **C10.1** asks for MCP components from trusted sources, cryptographically verified (C10.1.1), allow-listed
     (C10.1.2), and sandboxed when run locally (C10.1.3).

   The list adds no requirement here that AISVS lacks. Its value is the incidents and attack scenarios. Two of the
   AISVS requirements nearest it get no credit from any check `sv` has (`docs/COVERAGE.md`), a point from session
   securevibe-e2's reading of the same list:
   - **C10.4.8** (level 3) asks that an MCP client keeps a snapshot of its tools' definitions and asks again before a
     changed tool is used. It is AST07's update drift for MCP tools. No check speaks to it.
   - **C9.3.7** (level 2) asks that resources a model names are checked against an allow-list before an agent installs
     or invokes them. `probe.ai-output-fetched` can only ever find it failing.
   The list is evidence that both matter, not a new requirement.

## Each item

"Could an AI-built app have it" means the app itself, or the folder it is built in. "`sv` could check" says by what
means: reading the code or files, the running app, or neither.

| Item | What it asks, in short | Could an AI-built app or its folder have it | What `sv` already reads that overlaps | Could `sv` check it, and what it would take |
|---|---|---|---|---|
| **AST01 Malicious Skills** (critical) | Skills from a registry carrying hidden payloads; sign skills, scan them for behavior, sandbox them, protect the agent's identity files (`SOUL.md`, `MEMORY.md`). | Yes, in the folder: a skill the person installed. | Nothing. | **No**, not as malware detection: the list itself (AST08) says pattern matching fails. Listing which skills are in the folder is possible (proposal 1). |
| **AST02 Supply Chain Compromise** (critical) | Registries with no provenance; pin nested dependencies to hashes; **treat repository config files (hooks, `.claude/settings.json`, `ANTHROPIC_BASE_URL`) as executable code**. | Yes: a cloned project whose AI-tool settings run a command when it is opened. | Lockfile and pinning checks for the app's own dependencies; `config.mcp-server-unpinned` (C10.1.1) for MCP servers the app starts. | **Yes, by reading files**: hooks that run commands, MCP servers started unpinned, and base-URL overrides in the AI tool's own settings (proposal 1). |
| **AST03 Over-Privileged Skills** (high) | Permission manifests, per-skill credentials, network allow-lists; flag write access to `AGENTS.md`, `SOUL.md`, `MEMORY.md`; never treat tool output as instructions. | Yes, in the folder: an AI tool told to allow every command without asking. In an agent app, AISVS C9.3.3 and C9.3.4. | `record-tool`'s `read-only` marking (ADR-045); the prompt-injection and tool checks for AI features. | **Partly, by reading files**: the AI tool's own permission settings (proposal 1). |
| **AST04 Insecure Metadata** (high) | Safe parsers (`yaml.safe_load`), schema validation; **flag zero-width characters, base64, and "ASCII smuggling" hidden in skill prose**. | Yes: an instruction file in the folder with characters a person cannot see. | `ast.unsafe-deserialization` (V1.5.2) already names `yaml.load`; `probe.ai-hidden-content-passed` (C7.3.4) checks hidden characters in a model's *replies*; `sv`'s MCP server writes invisible characters from the app's folder as escapes. | **Yes, by reading files**: hidden characters in the instruction files committed in the folder (proposal 2). |
| **AST05 Untrusted External Instructions** (high) | Content a skill fetches at run time becomes instructions; pin it by hash, inline it, allow-list its hosts. | Rarely: an app's AI feature whose instructions are fetched from a web address when it runs. | The fetch checks (`probe.fetch-goes-anywhere`); AISVS C9.3.7. | **Not reliably.** Telling a fetched prompt from fetched data in code would have many false alarms. |
| **AST06 Weak Isolation** (high) | Containers by default; agent control interfaces on localhost *with* authentication; authenticate WebSockets, from localhost too. | Yes, for an agent app; AISVS C9.3.1 and C10.1.3. | The WebSocket checks (`probe.websocket-origin-unchecked`, `probe.websocket-without-session`); `sv` itself runs apps fenced (ADR-019). | Already partly, on the running app. Nothing new proposed. |
| **AST07 Update Drift** (medium) | Pin installed skills to content hashes, verify updates, keep an inventory. | Yes, in the folder. For the app's own packages, the same idea is already checked. | Lockfiles, pinning, advisories; C10.1.1; C6.1 model pinning. | Only as part of proposal 1 (unpinned MCP servers in the tool's own settings). |
| **AST08 Poor Scanning** (medium) | Scanners built for code miss malice written in prose; treat scanner results as advisory; scan every file; the scanner's own model can be injected. | This one is about scanners, `sv` among them. | `sv`'s rule that something not found is never a pass, and its reports listing what was not read. | Nothing to build. It is a reason to keep proposal 2 "only ever a finding". |
| **AST09 No Governance** (medium) | Inventories, approval steps, audit logs, offboarding for skills in an organization. | For a team, yes; for one person building an app, mostly not. | AISVS C9.4 (agent identity and audit). | **No.** It is an organization's process, not something in the code. |
| **AST10 Cross-Platform Reuse** (medium) | Security metadata lost when a skill moves between platforms; a universal skill format. | No: it is about registries and formats. | Nothing. | **No.** |

## Whether it bears on how `sv` itself is used by an AI coding tool

`sv` is an MCP server and a source of prompts and coding rules that an AI coding tool reads. Four points from the list:

- **What `sv` hands the AI tool is instructions in all but name** (AST05). The prompts and coding rules come from
  `sv`'s own `data/`, shipped with `sv` and versioned with it, never fetched when it runs. `sv` opens no network
  connection of its own. That is the property AST05 asks for, and it should stay that way.
- **Text from the app's folder reaches the AI tool with invisible characters written as escapes** (`crates/sv-cli/src/plan.rs`
  and the MCP hardening of 3 October). This is AST04's mitigation 3 and AST08's mitigation 8, already in place.
- **`sv` writes a section into `AGENTS.md`.** AST03 asks that write access to an agent's instruction files get
  elevated review. `sv` writes only between its own markers, keeps everything outside them, and says what it wrote.
  That is in line with the list. Nothing to change.
- **How `sv` itself is installed** (AST02, AST07). The list's concern for a skill applies equally to an MCP server: is
  the copy a person runs the one that was reviewed? `sv`'s install script and container image are outside this
  research. Whether they offer a pinned, verifiable version is a question for whoever owns releases. It is not
  answered here.

## Should `sv` cite it?

**Not yet, in this session's view.**

- It is a list of risks, not requirements.
- Its v1.0 is still in public review.
- Its own references to ASVS and the LLM Top 10 are out of date or inconsistent.
- Most of it is about skill registries and agent platforms, not about an app.

Where it does reach an app built with an AI tool, AISVS C9.3 and C10.1 already ask the same things, and `sv` cites
them. Worth reading again when v1.0 is released (planned for the fourth quarter of 2026). Adopting it is the owner's
decision, with a record of its own.

## Proposals, and the owner's answers

**The owner's answers, 7 October 2026:** "yes to 1 and 2, agree on 3". Proposals 1 and 2 are to be built, under a
record of their own; the list is not adopted for now.

These are also put in `docs/BACKLOG.md`, under this item.

1. **Read the AI coding tool's own files in the project folder, and report what they let the tool do, apart from the
   app's grade.**
   - **What to read:**
     - hooks that run commands (Claude Code's `hooks` in `.claude/settings.json`);
     - permission settings that let the tool run anything without asking;
     - MCP servers in `.mcp.json` or `.cursor/mcp.json` started unpinned, with the pin check
       `config.mcp-server-unpinned` already does;
     - base-address overrides such as `ANTHROPIC_BASE_URL`, which send the tool's own traffic elsewhere.
   - **Why (AST02, AST03, AST07):** a project folder someone shares, or one an AI tool set up, can run commands on the
     next computer that opens it.
   - **What it would take:**
     - each tool's settings format read from its own documentation;
     - a section of the report of its own, since these concern the person's computer, not the app.
   - **Citation:** no ASVS or AISVS requirement fits, so it would cite none (as `config.security-contact` cites none),
     unless the owner adopts this list. The person may have chosen any of these on purpose, so each is a notice, not a
     finding.
   - **Effort:** small to medium.
2. **Hidden characters in the instruction files committed in the folder.**
   - **Which files:** `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, `.cursor/rules/`, `.github/copilot-instructions.md`, and
     their like.
   - **What to look for:** Unicode tag characters and right-to-left overrides, which a person reading the file cannot
     see and an AI tool reads as text.
   - **Why (AST04):** this is how instructions are hidden from the person who reviews a file.
   - **What it would take:** a findings-only check over those files. It would leave out the zero-width joiner, which
     ordinary emoji use, so only characters with no innocent use in an instruction file count.
   - **Citation:** none, as above.
   - **Effort:** small.
3. **Adopt the list as a framework `sv` cites: not now.** Look again at its v1.0 release.

## Sources

- [OWASP Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/), read from its repository at
  [github.com/OWASP/www-project-agentic-skills-top-10](https://github.com/OWASP/www-project-agentic-skills-top-10),
  commit `d6f7d7d`.
- [Inside the OWASP Agentic Skills Top 10](https://blog.secureflag.com/2026/06/23/owasp-agentic-skills-top-ten/), found in the
  search, not relied on.
- ASVS 5.0 and AISVS 1.0 as `sv` reads them: `data/frameworks/asvs-5.0.0.json`, `data/frameworks/aisvs-1.0.json`.
