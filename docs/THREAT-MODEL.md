# SecureVibe — Threat Model (STRIDE)

Scope: the SecureVibe tool itself (not the applications it generates, which get their own threat model per project).
This model also covers the adversarial-AI scenarios required by OWASP AISVS Appendix C (AC.2.1): misuse, prompt
injection from untrusted input, insecure output handling, excessive agency, and dependency-chain risk.

Assets: the owner's Anthropic API key; project designs and generated code (business-confidential); the integrity of
the compliance/security reports; the owner's machine (files, network).
Entry points: the local HTTP API (127.0.0.1:4173); wizard free text; generated-app file contents fed to the AI review
and fixer; scanner output fed to the fixer; npm packages installed for generated apps; generated code executed during
tests and the runtime scan; external scanner binaries on PATH.
Trust boundaries: browser ↔ server; server ↔ Anthropic; server ↔ npm; server ↔ generated app process; model output ↔ file system.

| Id | STRIDE | Threat | Likelihood | Impact | Mitigations | Residual | Status |
|---|---|---|---|---|---|---|---|
| T-01 | Spoofing | A malicious web page in the owner's browser calls the local API (DNS rebinding / cross-site requests) to start builds or read designs | medium | high | 256-bit startup token (valid for the process lifetime, compared in constant time, printed only to the owner's terminal) exchanged for an `HttpOnly; SameSite=Strict` cookie; Host allow-list; Origin/`Sec-Fetch-Site` checks; CSRF token on mutations; loopback binding | low | mitigated |
| T-02 | Tampering | Wizard free text or entity names carry prompt-injection payloads that change the design or the generated code's security posture | medium | high | the profile (closed enums) — not the free text — drives all security decisions; quick-mode inference may only raise the posture and needs evidence quotes; injection screening (log + explain; small high-precision block list); untrusted-data framing with an append-only instruction-hierarchy reminder | medium | mitigated (residual: novel phrasing) |
| T-03 | Tampering | The generation/fix agent weakens security controls (edits `src/security`, tests, manifest, `package.json`) | medium | high | tool-layer deny-list of protected paths; sha256 of protected files captured at scaffold and re-verified at compliance time (`sast.protected-file-modified`, `config.protected-files-unchanged`); no `add_dependency`; `run_checks` fixed enum | low | mitigated |
| T-04 | Tampering | Generated code exfiltrates data or modifies files outside the project during tests/DAST | medium | high | Node permission model (fs read/write limited to the app folder), env allow-list without `ANTHROPIC_*`, `HOME`/`TMPDIR` inside the project, timeouts, output caps, process-group kill | medium (network not restricted) | accepted with disclosure in reports |
| T-05 | Repudiation | Nobody can tell which model/prompts produced a file or a review verdict | medium | medium | provenance per file (origin, correlation ids, served model, prompt hash), `llm-audit.jsonl`, stored redacted prompts/responses per run, report provenance block with hashes | low | mitigated |
| T-06 | Information disclosure | The API key or workspace secrets leak into prompts, logs or reports | medium | high | key read from env only; read_file denies `.env*`, keys, databases; redaction of secret patterns before logging; reports never include env values; secrets scanner runs on generated apps | low | mitigated |
| T-07 | Information disclosure | Generated-app contents (which may include the owner's data) are sent to the model | high | medium | only source files are sent (never `data/`); the owner approves the build knowing this; storeFullPrompts can be disabled | medium | accepted with disclosure |
| T-08 | Denial of service | Runaway agent loops or huge tool outputs exhaust money/time | medium | medium | budgets (iterations, USD from usage, wall-clock), per-tool caps, spending cap set by the owner, cancel/kill switch that aborts the stream and kills processes | low | mitigated |
| T-09 | Elevation of privilege | A hallucinated AI citation flips a requirement to "pass" | high | high | AI evidence is weak-tier: at most `ai-assessed`; verbatim snippet must match at file:line on the exact tree sent; low confidence → not-verified; hallucination rate reported | low | mitigated |
| T-10 | Elevation of privilege | The fixer "fixes" a finding by deleting the check or skipping the test | medium | high | `fixed` requires the detector to stop reporting after a full re-run, no new P1/P2, passing-test count not decreased, protected hashes unchanged; diffs saved and shown | low | mitigated |
| T-11 | Tampering | Malicious npm package with install scripts in a generated app's dependency tree | low | high | locked `package-lock.json` shipped with the template; `--ignore-scripts`; `deps.install-scripts-present`; no agent-added dependencies | low | mitigated |
| T-12 | Tampering | External scanner binaries on PATH are trojaned | low | medium | optional tools are only invoked if present; their output is data (parsed JSON), never executed; coverage table names them | low | accepted |
| T-13 | Information disclosure | Reports are shared and contain sensitive details | medium | medium | reports contain file paths and snippets but never secrets; the owner is told what the reports contain | low | accepted |
| T-14 | Spoofing | Someone imports a fabricated "AI review" file into the self-assessment | low | medium | imported reviews are typed `manual (imported AI review)` with importer identity and hashes; never `ai-review` | low | mitigated |
| T-15 | Repudiation | The owner cannot tell that no human reviewed AI-generated code | high | medium | non-dismissable statement in every report until a named human review is recorded (AC.4.1 reported as failing) | low | mitigated |

Action items: none open at design time. T-04 and T-07 are accepted risks disclosed in the report methodology section.
Review cadence: re-run when adding a new tool to the agent, a new provider, network-facing features, or dependency additions.
