# How `sv` works

A short account of SecureVibe's second version, for the paper. The figure is `figure-how-sv-works.html`. It was
drawn from `main` on 29 September 2026. Its sources are `crates/sv-cli/src/main.rs` (the commands),
`crates/sv-run/src/docker.rs` (the fence and its services), `crates/sv-report/src/lib.rs` (the ranking), and
`data/adapters.json` (the outside tools).

## Description

`sv` does not write the app. The owner builds it in their own AI coding tool, in any language, and `sv` grades
what was built against OWASP ASVS 5.0, AISVS 1.0, and the Secure by Design checklist. Four things go in:

- the app's folder;
- `securevibe.toml`, a manifest the AI coding tool fills in from the spec `sv init` prints (the stack, how to
  start the app, its test users, and its answers to design questions);
- `security-notes.md`, the owner's written answers to the questions no tool can settle;
- advisory data the owner downloaded.

`sv` first works out which requirements apply (`sv scope`). It then gathers evidence in five independent stages:

1. **It reads the code** (`sv check`). One walk of the folder covers credentials, configuration and start
   commands, a bill of materials, tree-sitter rules in 15 languages, and the app's own tests that name a
   requirement.
2. **It runs outside tools** (`--tools`). These are Semgrep, Bandit, CodeQL, gosec, and Brakeman, each rule
   mapped to the requirements it can speak to.
3. **It compares every package against known vulnerabilities** (`sv audit`), offline.
4. **It starts the app behind a network fence and asks it questions** (`sv run`). The fence is a Docker network
   made with `--internal` for each run and confirmed internal before anything starts. Inside it, a test model
   stands in for the AI service and also serves a test MCP tool. A test sign-in provider, a mail catcher, and a
   headless browser run there too. The questions come as a stranger, as signed-in users, of the AI feature, and
   of an MCP server.
5. **It asks the live site** (`sv probe`). This is the one network connection `sv` makes of its own: at most four
   read-only requests to an address the owner types.

Each requirement then takes the strongest evidence behind it:

- a finding (*needs attention*) outranks everything;
- below it, in order: *checked*, *documented by the owner*, *checked by hand by the owner*, *attested by the owner*,
  *stated by the AI coding tool*, and *not verified*.

A stage that cannot run marks what depended on it *not assessed*, never a pass and never a failure. The
report (`sv report`, in HTML, Markdown, SARIF, and JSON) opens with what was not examined. It also carries a
threat model, the tests worth writing, and what only the owner can check, and it never says a requirement passed.
`sv bundle` seals the app and its report with a SHA-256 for every file. `sv mcp` serves the same checks to the AI
coding tool, which closes the loop: the tool reads the findings, changes the app, and runs the checks again.

## Caption

**Figure: How `sv` works.** The owner and their AI coding tool supply the app, its manifest, the owner's notes,
and downloaded advisory data (left). `sv` scopes the applicable requirements, reads the code, runs outside tools,
compares packages with known vulnerabilities, questions the running app inside a Docker network with no route
out, and optionally asks the live site four read-only questions (center). Each requirement is given the strongest
evidence found for it, a finding outranking all else, and the report leads with what nothing examined (right).
The MCP server returns the findings to the AI coding tool.
