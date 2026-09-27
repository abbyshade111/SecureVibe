# The project against the OWASP Top 10 for Agentic Applications

SecureVibe is agentic three times over:

- **v1 has AI agents of its own.** One writes and fixes code, one reviews it, one gives a second opinion, and one asks follow-up questions.
- **`sv` is driven by an AI coding tool** over MCP.
- **The project itself was built by several AI coding sessions** working at once for an owner who is not a programmer.

`sv` also checks the AI features of other people's apps.

This maps what happened across all four against the OWASP Top 10 for Agentic Applications. The figure is
`figure-agentic.html`. The companion analysis against the ordinary Top 10 is `TOP10.md`.

## The list

OWASP Top 10 for Agentic Applications, 2026 edition, published by the OWASP GenAI Security Project on 9 December
2025. Names and one-line descriptions are from OWASP's announcement, read 27 September 2026:

| Code | Risk | In short |
|---|---|---|
| ASI01 | Agent Goal Hijack | hidden prompts redirect an agent into unintended actions |
| ASI02 | Tool Misuse | an agent uses a legitimate tool beyond its intended scope |
| ASI03 | Identity & Privilege Abuse | credentials or privileges let an agent act beyond its scope |
| ASI04 | Agentic Supply Chain Vulnerabilities | runtime components an agent relies on are poisoned |
| ASI05 | Unexpected Code Execution | natural language becomes a path to running code |
| ASI06 | Memory & Context Poisoning | what an agent remembers or reads reshapes its later behavior |
| ASI07 | Insecure Inter-Agent Communication | messages between agents are lost, spoofed, or misdirect others |
| ASI08 | Cascading Failures | a false signal propagates through an automated pipeline |
| ASI09 | Human-Agent Trust Exploitation | confident output leads a person to accept what they should question |
| ASI10 | Rogue Agents | misalignment, concealment, or self-directed action |

## Method

- **This list gives no CWEs,** unlike the ordinary Top 10, so every placement below is a judgement against the
  descriptions above. Each item has one main risk; where a second one applies it is named.
- **Three kinds of item.** An *incident* is something that went wrong. A *control* is a defense built on purpose,
  including ones that were never tested by an incident. A *check* is something `sv` asks of another app's AI feature.
- **Sources.** Every item names a commit, pull request, or file. v1's files are read at tag `v1-final`.
- **What the record does not contain.** No session is recorded doing something it was not asked to do, or hiding
  what it did. So ASI10 has controls and a check, and no incident.

## 1. v1's own agents

| Risk | Kind | What | Record |
|---|---|---|---|
| ASI01 | incident | The prompt fence, which stops untrusted text from closing its own `<untrusted_data>` block, used a nested replace; it became one global replace. Found by CodeQL | #19 (`c39bddd`) |
| ASI01 | control | Wizard free text and the generated apps' AI features are screened against `injection-patterns.json`: the high-precision list blocks, the medium list flags. The recorded residual risk is "novel phrasing" | `server/src/llm/screening.ts`; THREAT-MODEL T-02 |
| ASI01 | control | The second opinion may change only settings on an allow-list, and only in the direction that makes the design stricter. Anything else becomes advice and changes nothing. The follow-up questions work the same way | `server/src/llm/flows/peer-review.ts` |
| ASI02 | control | Every tool input is checked before use. Paths are resolved with realpath and a prefix check, "so no symlink, `..` segment or absolute path can leave" the app folder. Protected files cannot be written, secret files cannot be read, and `run_checks` takes commands only from a fixed list. Each refusal is logged as a security event | `server/src/llm/tools.ts` |
| ASI03 | control | `read_file` refuses `.env*`, and secret patterns are redacted before logging: "Never print, log, echo or commit a key" | THREAT-MODEL T-06; `CLAUDE.md` |
| ASI04 | control | The agent has no tool to add a dependency | THREAT-MODEL T-03 |
| ASI05 | control | Generated code runs under Node's permission model and an operating-system network fence limited to this computer; the reports say which fence applied | `27b85e2`; `pipeline/net-fence.ts` |
| ASI05 | control | Uploaded apps are only ever scanned, never run | `CLAUDE.md` |
| ASI08 | incident | The fixing agent was told "1 of 223 failing" but not which test. It re-ran the suite twice, spent budget, and told the owner to run it again: "the AI paid to discover that we were withholding it" | `60310aa`, `5f94d1c` |
| ASI08 | control | The spending cap is split before it is spent (55% writing, 30% review, 15% fixes), and budgets and a kill switch cover a runaway loop | `CLAUDE.md`; T-08 |
| ASI09 | incident | An opt-in AI scanner sent files and charged the owner's key, then reported "skipped": "An owner reading 'skipped' has no other way to learn they were billed" | `a4e4fbf` |
| ASI09 | control | AI review alone is "ai-assessed", never "pass", and a quoted snippet must match the cited file and line (T-09) | `CLAUDE.md`; T-09 |
| ASI10 | control | Protected security files are fingerprinted when the app is made and checked again later. A fix counts only once the detector stops reporting and the number of passing tests has not dropped, so the agent cannot "fix" a finding by deleting the check (T-10) | THREAT-MODEL T-03, T-10 |

## 2. `sv`, driven by an AI coding tool

| Risk | Kind | What | Record |
|---|---|---|---|
| ASI02 | incident | The MCP tool that writes the report followed a symlink inside the app and "wrote all five report files wherever it pointed". The module's comment gives the reason for guarding it: "A model can be talked into asking for `~/.ssh`". Its first test passed with the guard broken | #77 (`2ed3da6`) |
| ASI04 | control | `sv` ships as a container image built and published by CI, with its base images pinned, so a tool that installs it as an MCP server gets a known build | #205, #208, #228 |
| ASI05 | incident | When no helper container could start, the fallback container that sends requests to the app ran without `--read-only`, `--cap-drop ALL`, or `no-new-privileges` | #77 (`45d8125`) |
| ASI05 | incident | The fence test counted any failure as "blocked", so it could pass without proving that the app's container could not reach out | #148 |
| ASI06 | incident | `sv` read its own report folder as the app's code on the next run. Its output became its input, and requirements checked fell from 9 to 1, twice. The AI tool found the cause only by undoing its own changes one at a time (also ASI08) | #220; `docs/BACKLOG.md`, the owner's first build |
| ASI08 | incident | Two false alarms rated high led the AI tool to rewrite correct code until the warnings stopped: "With an AI in the loop a false alarm is not noise: it changes the code" | #220 |
| ASI09 | incident | Security notes the AI tool wrote were credited to the owner: 8 of 12. "The interview already tells the tool to write a note only once the owner agrees; this run shows an instruction is not enough" | #239 |
| ASI09 | incident | The starter manifest answered "no" to every capability, so a tool that left a line alone told `sv` the app had no sign-in: "the most dangerous line in the product" (also ASI08) | #252 |
| ASI09 | open | 18 of the 40 requirements checked on the owner's app came from tests the AI tool wrote and labelled itself: "the author vouching for its own work through the name". Recorded to keep in mind | `docs/BACKLOG.md` |
| ASI09 | control | A person can confirm what the tool wrote, at their own tier and never as "checked". A confirmation stops counting once it is stale, once the file changes, or when "the AI tool confirms itself", and the tool is told never to write one the person did not make | #242 (`4f1fcf8`) |

## 3. What `sv` checks in other apps' AI features

`sv` points the app at a test model running on the fenced network, and at a test MCP server, so nothing is spent and
nothing leaves the machine (`docs/DESIGN.md`, "A test model inside the fence").

| Risk | Check | What it asks |
|---|---|---|
| ASI01 | C2.1.3 | Does a textbook prompt injection reach the model at all? |
| ASI01 | C10.4.2 | Does an instruction injected into an MCP tool's result reach the model? |
| ASI01 | C7.3.2 | Does a reply carrying the app's instructions reach the page? |
| ASI02 | C10.4.1 | Is a tool result of the wrong type passed on unvalidated? |
| ASI02 | C7.3.3 | Does the app fetch an address the model names? |
| ASI08 | C11.2.2 | Does the app hold its AI feature to the rate limit it states? |
| ASI10 | C9.6.1 | Does the AI feature's kill switch work? Tried on a second copy of the app |

## 4. How the project was built: several AI sessions at once

| Risk | Kind | What | Record |
|---|---|---|---|
| ASI03 | control | Git is pre-approved, but each session must still ask the owner, every time, before spending AI credit, changing repository settings or visibility, rewriting history, or deleting anything | `CLAUDE.md` |
| ASI07 | incident | Two sessions each read the backlog, each correctly saw an item unclaimed, and both built it (20 September) | `CLAUDE.md` |
| ASI07 | incident | Two sessions ran the evaluation harness at once for eight minutes, "having each said in a message that they would say something first" | v1 `CLAUDE.md`; `32e5562` |
| ASI07 | incident | Sessions working on `sv` "collided five times in one day" | `docs/BACKLOG.md` |
| ASI07 | incident | A session built an `Answered by:` line on the day another shipped `Written by:`, and withdrew it unpublished | `docs/BACKLOG.md` |
| ASI07 | control | Work is claimed in a committed file, not in a message: a session that is not running never receives the message, and one that is running loses it "after its context is summarized" (also ASI06) | `CLAUDE.md` |
| ASI08 | incident | Nearly every citation in two rule maps was wrong, one or two digits from correct, and copied on. The tests were written from the map, "a test that checks the code against itself" | `docs/DESIGN.md`, "The citations were all wrong" |
| ASI09 | incident | The same sandbox failure was "fixed" twice "by reasoning about what the sandbox probably does", while the error code naming the real cause sat in the results file. It cost three evaluation runs | `CLAUDE.md` |
| ASI09 | control | Findings from the owner's first build were "checked against the code or reproduced", "not taken from the building tool's account of it". Sessions reviewing each other's merged work record what they find before anyone claims the fix | `docs/BACKLOG.md` |

## Summary by risk

| Risk | Incidents | Controls | `sv` checks |
|---|---|---|---|
| ASI01 Agent Goal Hijack | 1 | 2 | 3 |
| ASI02 Tool Misuse | 1 | 1 | 2 |
| ASI03 Identity & Privilege Abuse | 0 | 2 | 0 |
| ASI04 Agentic Supply Chain | 0 | 2 | 0 |
| ASI05 Unexpected Code Execution | 2 | 2 | 0 |
| ASI06 Memory & Context Poisoning | 1 | 0 | 0 |
| ASI07 Insecure Inter-Agent Communication | 4 | 1 | 0 |
| ASI08 Cascading Failures | 3 | 1 | 1 |
| ASI09 Human-Agent Trust Exploitation | 4, and 1 open | 3 | 0 |
| ASI10 Rogue Agents | 0 | 1 | 1 |
| **Total** | **16, and 1 open** | **15** | **7** |

## What this shows

- **The incidents gather under ASI09 and ASI07, the two risks about people and coordination, not attackers.** No
  attack appears anywhere in the record. What went wrong was an AI saying something plausible that a person, or
  another AI, took as settled:
  - a scan that said "skipped" after it had been paid for;
  - notes the tool wrote, counted as the owner's;
  - a default "no" read as an answer;
  - a fix reasoned out instead of read from the error;
  - and sessions that could not hear one another.
- **In both versions the defenses that worked were structural, not instructions.** Allow-lists that only move
  toward the stricter setting, a fence around every path, an AI verdict that can never count as a pass, and claims
  written into a file. Where an instruction was the whole defense, it failed: the interview told the tool to wait for
  the owner's agreement, and "an instruction is not enough".
- **With an AI in the loop, a checker's errors become actions (ASI08).** A false alarm made the AI tool rewrite
  working code; a report folder read as code sent it undoing its own changes; a withheld test name made it pay to
  rediscover the name. The fixes all made `sv`'s signals more exact, because a person was not there to discount them.
- **Tool misuse was guarded before it happened in v1, and happened once in `sv`.** v1's agent had path containment from
  the start. `sv`'s MCP report tool did not until review found the symlink, and its first test would have passed
  without the guard.
- **ASI03, ASI04, and ASI10 have controls and no recorded incident.** That is the absence of an incident, not proof
  of safety: the controls were never tested by an attack.

## Limits

- **Every placement is a judgement.** The list defines its risks in words, not CWEs, and several items touch two
  risks; the second is named.
- **Only what was written down counts.** A near-miss nobody recorded is not here.
- **The development-process items describe AI coding sessions working together, which is how this project was
  built.** They are evidence about that way of working, not about SecureVibe's code.
- **The `sv` checks in section 3 are what `sv` can ask of another app.** They are not results from any app.
