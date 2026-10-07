# OWASP's Agentic Skills Top 10, and what it means for `sv` (7 October 2026)

Asked for by the owner on 7 October 2026 (BACKLOG, "Research OWASP's Agentic Skills Top 10"). A reading, not a build:
nothing in `sv` changes with it, and each proposal at the end is for the owner to decide.

**What was read:** the project's own repository, `github.com/OWASP/www-project-agentic-skills-top-10`, at commit
`d6f7d7d` (12 August 2026): its README, its ten risk pages (`ast01.md` to `ast10.md`), its checklist, its license, and
its page of mappings to other frameworks. The project's website, owasp.org, could not be reached from where this was
written (the network rules of this session block it), so the repository, which the website is built from, was read
instead. Nothing below rests on a summary or an article about the list.

## What the list is

- **Its subject is the AI tool, not the app it builds.** An "agentic skill" is a bundle an AI agent loads to do a kind
  of task: instructions written in plain language, often with scripts beside them, described by a small file of
  metadata. The list names four kinds: OpenClaw's `SKILL.md`, Claude Code's skills, Cursor and Codex's `manifest.json`,
  and VS Code's `package.json` extensions. Its risks are about skills that are malicious, over-privileged, unpinned, or
  unscanned, on the computers and agents that load them.
- **It is new and not settled.** The repository calls it an OWASP Incubator project, version "1.0-2026", last updated
  March 2026; its own index says "New Project Proposal — active development", and version 1 is in public review, with
  comments collected in a shared document.
- **It is a list of risks, not of requirements.** Each entry (AST01 to AST10) has a description, a severity (Critical,
  High, or Medium), real incidents, attack scenarios, and "preventive mitigations". None is written as a "Verify that…"
  requirement, as ASVS and AISVS are, so there is nothing in it a check can be said to meet.
- **Its links to ASVS use ASVS 4.0's chapters.** It maps AST03 to "ASVS V4 (Access Control)", AST04 to "ASVS V5.5
  (Deserialization)", AST06 to "ASVS V12 (File/Resource)", and AST01 to "ASVS V14 (Configuration)". Those are the
  chapter names of ASVS 4.0. In ASVS 5.0, which `sv` uses, V4 is API and Web Service, V5 is File Handling, V12 is Secure
  Communication, and V14 is Data Protection. Its ASVS references cannot be carried over to `sv`'s by number. It does
  not mention AISVS at all; its other mappings are to the OWASP Top 10 for LLM Applications, CWE, CSA's MAESTRO, and
  governance frameworks.
- **License:** Creative Commons Attribution-ShareAlike 4.0, the same as ASVS's.

## The ten risks

| | Risk | Severity | In a sentence (from its page) |
|---|---|---|---|
| AST01 | Malicious Skills | Critical | Skills that look legitimate carry hidden payloads, in code or in the plain-language instructions, and run with the agent's full permissions. |
| AST02 | Supply Chain Compromise | Critical | Skill registries lack the provenance controls of npm or PyPI; configuration files (hooks, `.claude/settings.json`, `ANTHROPIC_BASE_URL`) have become ways to run code. |
| AST03 | Over-Privileged Skills | High | Skills are given more access than their job needs, so a prompt injection can turn a legitimate one into a weapon. |
| AST04 | Insecure Metadata | High | A skill's metadata is attacker-controlled input: it can misstate its permissions, and unsafe parsing of it (`yaml.load`) can run code on load. |
| AST05 | Untrusted External Instructions | High | A skill points the agent at a web page or remote file whose content becomes part of its instructions, and can change after review. |
| AST06 | Weak Isolation | High | Skills run with the agent's full file, shell, and network access; agent control interfaces listen on every network address. |
| AST07 | Update Drift | Medium | Installed skills are not pinned to a known version, or update themselves without checks. |
| AST08 | Poor Scanning | Medium | Scanners built for code miss skills, which mix code with plain-language instructions. |
| AST09 | No Governance | Medium | Organizations have no inventory, approval, logging, or revocation for the skills their people install. |
| AST10 | Cross-Platform Reuse | Medium | A skill moved from one tool to another loses the security settings its first format had. |

## Where it meets what `sv` does

`sv` checks the app, not the computer it was built on, and it does so deliberately: the check for MCP servers started
without a pinned version (`config.mcp-server-unpinned`, C10.1.1) leaves out `.claude/`, `.cursor/`, `.mcp.json`, and the
other folders that configure a developer's own AI tools, because what they start runs on the developer's computer,
which C10.1.1 is not about (`crates/sv-check/src/launch.rs`, `developer_tool_config`). Most of this list is about
exactly those files. So for most of it the honest answer is that `sv` does not look, by design.

Where it does meet `sv`, it meets in two places: apps that are themselves agents, and `sv` as a tool an agent uses.

**Apps that are agents.** An app that gives a model tools, plugins, or skills of its own is held by AISVS, which `sv`
already loads, to much of what the list asks:

- AST03 and AST06, least privilege and isolation for each tool: **C9.3.1**, "each tool/plugin executes in a
  least-privilege sandbox or is otherwise isolated from model operations". `sv`'s running checks ask some of this of an
  app's AI feature (the agent's limit on tool rounds, C9.1.2; tools reached through the test MCP server), and none
  reads a sandbox.
- AST05 and AST01, installing or calling what the model names: **C9.3.7**, "external resources named in model output
  are verified against an approved allow-list or registry before the agent installs or invokes them". No check of
  `sv`'s speaks to it yet.
- AST07, a tool changed after it was approved: **C10.4.8**, "MCP clients maintain a snapshot of tool definitions and …
  any change to a tool definition triggers re-approval". No check of `sv`'s speaks to it yet.
- AST02, where the app's MCP servers come from: **C10.1.1**, which `config.mcp-server-unpinned` already finds failing
  when an app starts a server at whatever version is newest.
- AST04's unsafe parsing: **V1.5.2** (ASVS 5.0, safe deserialization). `ast.unsafe-deserialization` already finds
  unsafe deserialization in the app's own code, Python's `yaml.load` among it.

An app built with an AI coding tool can have any of these if it is an agent. Most apps `sv` sees are not; for those,
the list asks nothing of the app.

**`sv` as a tool an agent uses.** `sv` is not a skill, but its MCP server and its prompts reach the AI coding tool, so
the list's questions can be asked of it:

- **AST05 (instructions fetched at run time):** `sv`'s instructions, prompts, and coding rules are compiled in or read
  from its own data folder; it fetches nothing (it opens no network connection of its own, apart from `sv probe`).
  Nothing an agent is told by `sv` can change after release.
- **AST03 and AST06 (privilege and isolation):** its MCP tools are marked read-only where they are, serve only the
  folder named by `--root` (the home folder and `/` refused), and the app it runs is started in a container on a
  network with no way out. Text from the app's folder reaches the AI tool fenced, so an instruction hidden in it is
  shown as data (the same idea as AST08's last mitigation, that a scanner's own model is attackable).
- **AST03, mitigation 3 (writes to instruction files):** `sv rules` writes the coding rules into the app's
  `AGENTS.md`, a file the list says deserves extra care, but only when the person runs it, and only between `sv`'s own
  markers. The MCP server does not write it.
- **One tension to keep in mind:** AST06 says an agent's control interface should listen only on the local computer,
  never on every address (`0.0.0.0`). `sv`'s specification tells builders to have the app listen on `0.0.0.0`, because
  `sv` runs it in a container and asks it from another. The two are about different things (an app's web port inside
  `sv`'s fenced container, and an agent's control port on someone's computer), but a builder could read one as the
  other. The specification already says why; it is worth keeping that sentence.

**The checklist's pipeline questions** (B1 to B4, at the end of its checklist) come closest to `sv`'s own work: "Is
AI-generated code passing SAST before repository commit?" is what `sv check` and the loop do; "Are all dependencies
pinned to immutable hashes, not version ranges?" is near what `sv`'s version-pinning check asks, though it asks for
exact versions, not hashes; and "Are all AI-generated dependency names validated against live registries?" (a model
inventing a package name an attacker then registers) is something `sv` does not do, and could not do live, since it
opens no network connection.

## What `sv` could do, for the owner to decide

None of these is built, and each widens what `sv` looks at, so each is the owner's to choose. They are in order of
how much they would cost against how much they would show.

1. **Do not load the list as a framework `sv` cites, for now.** It is a list of risks, not requirements; it is in
   public review; and its ASVS links use the old numbering. Read it again when version 1 is published. If it then has
   requirements, or a mapping to ASVS 5.0 and AISVS, adding it would be a decision with its own record, as each
   framework `sv` loads was.
2. **Look for hidden characters in the instruction files in the app's folder.** `SKILL.md`, `AGENTS.md`, `CLAUDE.md`,
   `.cursor/rules`, and the like are read by the AI tool as instructions. The list (AST04, mitigation 3) and the
   incidents it cites show zero-width and other invisible characters used to hide instructions from the person who
   reviews them. `sv` already finds such characters in an AI feature's answers (C7.3.4). Reading the project's own
   instruction files for them is cheap and would cite no requirement of the app: a finding about the project, not the
   app, said as such.
3. **Say what the project's AI-tool settings would run.** A committed `.claude/settings.json` with hooks, or an
   `ANTHROPIC_BASE_URL` pointing elsewhere, runs commands or sends the work somewhere else when someone opens the
   project (AST02, mitigation 4, with the CVEs it names). `sv` leaves these files out today, on purpose. Listing what
   they would run, without judging it, would tell the owner what they are trusting; judging it would be a larger
   change to what `sv` is for.
4. **The AISVS requirements above that no check speaks to (C9.3.7, C10.4.8)** are already in `sv`'s frameworks and
   would be found in the usual way, through `docs/COVERAGE.md`, for apps that are agents. This list adds evidence that
   they matter, not new requirements.
