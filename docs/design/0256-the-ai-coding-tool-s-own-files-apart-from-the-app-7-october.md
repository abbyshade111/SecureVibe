# The AI coding tool's own files, apart from the app (7 October 2026)

The owner's answers to the Agentic Skills Top 10 research (`docs/AGENTIC-SKILLS-TOP-10.md`) were "yes to 1 and 2,
agree on 3" (ADR-049). The person builds with an AI coding tool, and the tool keeps files in the project folder that
`sv` used to leave out on purpose, because they are not the app. Two things now read them. Neither counts toward the
app's grade.

**What the tool's settings let it do** (`crates/sv-check/src/ai_tool.rs`, `read`). The report gains a section, "What
your AI coding tool's files let it do". Each line is a file, the tool that reads it, what it lets the tool do, and the
OWASP Agentic Skills Top 10 risk it speaks to, named in words, since `sv` does not cite that list. They are notes,
not findings: they credit nothing, find nothing, and change no requirement's status. Each format was read from the
tool's own documentation:
- **Claude Code** (`.claude/settings.json`, `.claude/settings.local.json`), from its settings reference and hooks
  guide. It reads:
  - each hook that runs a command, sends a web request, or calls an MCP tool, with the event it runs on;
  - each setting whose value is a command it runs (`apiKeyHelper`, `statusLine`, and the rest);
  - `ANTHROPIC_BASE_URL` and other addresses in `env`, which send its traffic, and its key, elsewhere;
  - `permissions.allow` letting it run any command;
  - `enableAllProjectMcpServers`.

  The settings reference says a `defaultMode` of `bypassPermissions` or `auto` has no effect from a project's
  settings, so it is not noted. A test holds that, since noting it would be a false alarm.
- **MCP servers** in `.mcp.json` (read by Claude Code, and by VS Code's agent host, in the portable `mcpServers` shape)
  and `.vscode/mcp.json` (VS Code's `servers` shape, from its MCP configuration reference). Each server started is
  named with its command. One started from a package with no exact version says so, judged as
  `config.mcp-server-unpinned` judges the app's own servers, which still leaves these files out. A server reached by
  address is named with it.
- **Cursor** is not read. Its documentation could not be reached from where this was built, so its files are named
  under "Not read" rather than read by a guess at their format.

These files are read from every listed file, editor folders included: VS Code keeps its MCP servers in
`.vscode/mcp.json`, which the other checks leave out with `.vscode` as not the app. The first test run found that.

**Characters hidden in its instruction files** (`config.instructions-hidden-characters`, `hidden_characters`).
- **Which files:** `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, `.windsurfrules`,
  `.github/copilot-instructions.md`, and the files under `.github/instructions/`, `.cursor/rules/`, and
  `.claude/skills/`, `commands/`, and `agents/`.
- **What it looks for:** Unicode tag characters (U+E0000 to U+E007F) and the controls that override the direction of
  text (U+202A to U+202E, U+2066 to U+2069). A person reading the file sees neither, and the tool reads both.
- **What is left alone:**
  - the zero-width joiner, which joins emoji;
  - a run of tag characters after U+1F3F4, the black flag, which is how emoji write the flags of England, Scotland,
    and Wales.
- **What it is:** only ever a finding. It cites no requirement, as `config.security-contact` does not, since nothing
  in ASVS or AISVS asks this of a file in the project.

Twelve guards broken in turn, each caught:
- `bypassPermissions` noted;
- editor folders skipped;
- a flag emoji counted;
- direction controls ignored;
- any Markdown file taken for an instruction file;
- Cursor's files read by a guess;
- the pin not judged;
- any `Bash(…)` rule taken for "any command";
- every variable in `env` noted;
- the hidden-character finding given a requirement;
- the section shown when it is empty;
- the notes not escaped in the HTML report.
