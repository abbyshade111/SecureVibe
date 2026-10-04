# How `sv` works

A short account of SecureVibe's second version, for the paper. The figure is `figure-how-sv-works.html`. It was
first drawn from `main` on 29 September 2026 (`fc8d951`) and is redrawn from `main` at the cut-off, `157ddc3`
(11:37 on 4 October 2026). Its sources are `crates/sv-cli/src/main.rs` (the commands), `crates/sv-cli/src/mcp.rs`
(the MCP server), `crates/sv-run/src/docker.rs` (the fence and its services), `crates/sv-report/src/lib.rs` (the
ranking), `data/adapters.json` (the outside tools), and `data/ast-rules.json` (the code rules). What changed in the
five days between the two drawings is listed at the end.

## Description

`sv` does not write the app. The owner builds it in their own AI coding tool, in any language, and `sv` grades
what was built against OWASP ASVS 5.0, AISVS 1.0, and the Secure by Design checklist. Four things go in:

- the app's folder;
- `securevibe.toml`, a manifest the AI coding tool fills in from the spec `sv init` prints (the stack, how to
  start the app, its test users, and its answers to design questions);
- `security-notes.md`, the owner's written answers to the questions no tool can settle. The AI coding tool can
  write an answer there too, through `sv`, and it is always marked as the tool's own;
- advisory data the owner downloaded.

Two things go the other way, to the AI coding tool before it writes code: rules to follow while it codes, from
AISVS Appendix C (`sv rules`, written into the app's `AGENTS.md`), and prompts to give it, each marked as shown to
work or not (`sv prompts`).

`sv` first works out which requirements apply (`sv scope`). It then gathers evidence in five independent stages:

1. **It reads the code** (`sv check`). One walk of the folder covers credentials, configuration and start
   commands, a bill of materials (and whether each manifest agrees with its lockfile), 19 tree-sitter rules in 15
   languages, and the app's own tests that name a requirement.
2. **It runs outside tools** (`--tools`). These are Semgrep, Bandit, CodeQL, gosec, and Brakeman, each rule
   mapped to the requirements it can speak to. Semgrep runs with its usage reporting off; when it is not
   installed, Opengrep, an open-source fork of its engine, runs in its place, and the report says so.
3. **It compares every package against known vulnerabilities** (`sv audit`), offline.
4. **It starts the app behind a network fence and asks it questions** (`sv run`). The fence is a Docker network
   made with `--internal` for each run and confirmed internal before anything starts. The app runs with a
   read-only file system and no capabilities, writing only to two small in-memory folders. Inside the fence, a
   test model stands in for the AI service, serves a test MCP tool, and records what a feature that fetches
   addresses tries to fetch. A test sign-in provider, a mail catcher, and a headless browser run there too. The
   questions come as a stranger, as signed-in users, as one action sent 20 times at the same instant, of the AI
   feature, and of the app's own MCP server. A rate limiter's answer is waited out, and a crash is never read as
   the app refusing.
5. **It asks the live site** (`sv probe`). This is the one network connection `sv` makes of its own: at most four
   read-only requests to an address the owner types, for the certificate and its stapled revocation status, HTTPS,
   cookies, and whether the site still accepts old versions of TLS.

Each requirement then takes the strongest evidence behind it:

- a finding (*needs attention*) outranks everything;
- below it, in order: *checked*, *documented by the owner*, *checked by hand by the owner*, *attested by the owner*,
  *stated by the AI coding tool*, and *not verified*.

A stage that cannot run marks what depended on it *not assessed*, never a pass and never a failure. The
report (`sv report`, in HTML, Markdown, SARIF, and JSON) opens with what was not examined, and names the version
and commit of the `sv` that made it. It also carries a threat model, the tests worth writing, and what only the
owner can check, and it never says a requirement passed. `sv bundle` seals the app and its report with a SHA-256
for every file. `sv mcp` serves the same checks to the AI coding tool through ten tools, offers the written reports
to it as resources, says which of seven stages a long check has reached, and stops waiting after 50 seconds
(`--time-limit` changes it), saying nothing was assessed. That closes the loop: the tool reads the findings,
changes the app, and runs the checks again.

`sv` has fourteen commands: `init`, `scope`, `notes`, `questions`, `rules`, `prompts`, `probe`, `run`, `check`,
`sbom`, `audit`, `report`, `bundle`, and `mcp`.

## What changed between 29 September and 4 October

From the pull requests merged in those five days; each is in `TIMELINE.md`.

| | 29 September (`fc8d951`) | 4 October (`157ddc3`) |
|---|---|---|
| Commands | 13 | 14: `sv prompts` added (#554) |
| MCP tools | 8 | 10: `securevibe_prompts` (#554) and `securevibe_record_answer`, the AI tool's answers recorded as its own (#539) |
| MCP server | tools only; three protocol versions, to 2025-06-18 | reports offered as resources (#488), progress through seven stages (#504), a 50-second limit on a check (#498), each tool's result described (#479), five protocol versions, to 2026-07-28 (#483); nothing written through a link, and every malformed request answered (#474, #477) |
| Code rules | 16 rules, 15 languages | 19 rules, 15 languages |
| Bill of materials | lockfiles read | a manifest that asks for other versions than its lockfile is said, in the report and as a gap (#511, #525, #530) |
| Outside tools | five | the same five; Semgrep's usage reporting off, and Opengrep in its place when Semgrep is absent (#481) |
| The app's container | its folder read-only, the rest of its file system writable | read-only, no capabilities, no new privileges, with an in-memory `/tmp` of 256 MB and a 16 MB report folder (#496) |
| Questions of the running app | as a stranger, signed in, of the AI feature, of an MCP server | also an action sent 20 times at once (#527), a burst against a stated limit (#529), reflected text (#505), a file named `../` (#508), open redirects (#513), where a fetching feature goes (#531), the app's own sign-in token (#544), SQL injection on its own reads (#545), its own MCP server's token and arguments (#524), and what it does when its AI service fails (#500) |
| `sv probe` | at most four requests | still at most four; adds old TLS versions (#495). The stapled revocation question came on the evening of 29 September (#465) |
| Report | — | names the `sv` that made it, by version and commit (#538) |
| Bundle | — | a file name holding a backslash is left out and listed, and no zip entry can climb out of its folder (#555, the deep review's critical finding S1) |

The evidence ranking, the five stages, and the fence's design did not change. What the deep review of 4 October
found and the cut-off had not yet fixed is not in the figure: in particular, finding S2, that a fenced container
could reach the network's gateway, which on Linux is the owner's own computer.

## Since the cut-off

The description and the figure are `sv` at `157ddc3`. By 16:30 the same day (`4c3c5e0`), four things in them had
changed; `SINCE-THE-CUTOFF.md` has the rest.

- **The owner's tiers need `sv review`** (ADR-026). *Documented by the owner*, *checked by hand by the owner*, and
  *attested by the owner* now count only when the owner recorded the answer through `sv review`, a new command that runs
  only in a terminal and seals what it records with a key kept outside the app's folder. Written into
  `securevibe.toml` or `security-notes.md` any other way, the answer is *stated by the AI coding tool*. So are findings
  set aside and confirmations: without a seal they are proposals. On a computer with no key, such as CI, a sealed entry
  counts and says its seal could not be checked. The order of the tiers is unchanged.
- **A finding no longer outranks everything.** One that says it leaves a requirement's credit alone, such as a warning
  about a test's name, now sits beside the credit (#581).
- **Fifteen commands**, with `sv review`; it is not an MCP tool, so there are still ten. **Twenty code rules**, with a
  shell command run with `shell=True` (#587).
- **The fence has no gateway.** S2 is fixed (#558): the network is made with no gateway address where Docker allows it,
  and before the app starts a throwaway container checks that nothing answers where a gateway would be.

## Caption

**Figure: How `sv` works.** The owner and their AI coding tool supply the app, its manifest, the owner's notes,
and downloaded advisory data, and `sv` gives the tool rules and prompts to code by (left). `sv` scopes the
applicable requirements, reads the code, runs outside tools, compares packages with known vulnerabilities,
questions the running app inside a Docker network with no route to the internet, and optionally asks the live
site four read-only questions (center). Each requirement is given the strongest evidence found for it, a finding
outranking all else, and the report leads with what nothing examined (right). The MCP server returns the findings
to the AI coding tool. Drawn from `main` at `157ddc3`, 4 October 2026.
