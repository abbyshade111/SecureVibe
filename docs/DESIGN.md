# SecureVibe — Design Document

SecureVibe is a local-first "vibe-coding" application. It walks a person — who may have no technical or
security background — through describing the application they want, designs that application following the
**OWASP Secure by Design (SbD) Framework v0.5**, generates the code with Claude, verifies the result against
**OWASP ASVS 5.0.0** and **OWASP AISVS 1.0**, and produces three artifacts:

1. the generated application's source code (runs locally with `npm install && npm start`);
2. a **compliance report** (SbD, ASVS, AISVS) with evidence, findings and recommendations;
3. a **security report** (static analysis, dependency analysis, secret scanning, dynamic scan, tests, AI review)
   where every finding carries context and remediation guidance.

The same three artifacts are produced for SecureVibe itself (`npm run self-assess`).

---

## 1. Guiding principles

| Principle | What it means for SecureVibe |
|---|---|
| **Security is baked in, not asked for** | The user never chooses a security control. Controls are derived from plain-language answers (who uses it, what data it handles, where it runs). The generated app starts from a hardened baseline template; Claude extends it inside guard-rails. |
| **Explain everything** | Every wizard question has *"Why we ask"* and *"What this changes"*. Every report finding has *what it is, why it matters, where it is, how to fix it*. No jargon without an explanation. |
| **Honest verification** | A requirement is only marked *Pass* with attached evidence (a test, a scanner result, a runtime probe, a manifest check, or an AI review citing file and line). Anything automation cannot confirm is *Not verified* with instructions on how a human can verify it. The reports say clearly: automated + AI-assisted verification, not a certification. |
| **Local and self-contained** | Everything runs on the user's machine. The only network dependencies are the Claude API (for generation and AI review), the npm registry (installing packages) and, optionally, vulnerability databases. Without an API key the tool still works in *Demo mode* (baseline app, no AI customization, no AI review). |
| **SbD is the roadmap, ASVS/AISVS are the yardsticks** | The wizard **is** the SbD process (10 steps). ASVS/AISVS are used after the build to evaluate what was built. |
| **Follow AISVS Appendix C ourselves** | SecureVibe is an AI coding tool, so it applies AISVS Appendix C (AI-Assisted Secure Coding) to its own behaviour: provenance metadata on generated artifacts, prompt/response logging with correlation IDs, instruction hierarchy, untrusted-content screening, structured/validated model output, execution budgets, human approval before build, no self-approval. |

---

## 2. What SecureVibe can build (v1 scope)

Server-rendered **web applications** that run locally: Node.js 22+ / TypeScript / Express 5 / SQLite (`node:sqlite`,
no native modules) / EJS templates (auto-escaping) with a JSON API under `/api`. Optional capabilities the user can
turn on by answering questions: user accounts and roles, file uploads, an AI assistant feature (Claude), email
notifications (logged to a file locally), scheduled jobs, and integrations with external HTTP APIs.

Explicit non-goals for v1: native mobile apps, microservice topologies, cloud deployment automation, social/OAuth
login (recommended as a later step and reported as *Not applicable*), retrieval-augmented generation / vector stores.
The UI states this scope up front so expectations are set.

---

## 3. The user journey = the SbD process

The wizard maps one-to-one onto the ten SbD process steps. Users see friendly step names; the report shows the SbD
mapping.

| # | SbD step | Wizard step (user-facing) | What happens |
|---|---|---|---|
| 1 | Capture security requirements | **1. What are you building?** **2. Who will use it?** **3. What information will it handle?** **4. Features & connections** **5. Where will it run?** | Plain-language questions. Answers become the *Design Profile*. Security requirements (CIA, privacy, compliance hints, ASVS target level) are derived automatically and shown back in plain language. |
| 2 | Draft high-level architecture | **6. Review your design** (part 1) | SecureVibe derives components, trust zones, data flows and external dependencies from the profile and renders a diagram (Mermaid) with a plain-language walkthrough. |
| 3 | Apply SbD principles & patterns | **6. Review your design** (part 2) | Patterns are selected automatically (least privilege roles, secure defaults, validated contracts, fail-secure errors, observability, idempotent mutations, timeouts, rate limits…). Each selected pattern is shown with a one-sentence *why*. |
| 4 | Complete SbD review checklist | **6. Review your design** (part 3) | The 36-control SbD checklist (AS/DM/RR/AC/MT) is auto-filled: Yes / No / N-A, with justification and evidence pointers. Distributed-systems-only controls are N-A with an explicit justification. |
| 5 | Internal peer review | **6. Review your design** (part 4: "Second opinion") | An independent Claude review of the design (different prompt/persona) lists gaps and suggestions. The user accepts or dismisses each; accepted ones update the profile. In Demo mode this is skipped and reported. |
| 6 | Risk triage | **6. Review your design** (part 5: "Risk check") | SbD scoring (Yes=0, N-A=0, No Low=1 / Med=2 / High=4) plus the four escalation triggers (sensitive/regulated data, new external exposure, novel technology, Tier-1 impact). Result shown as *Low / Normal / High* with the reasons. |
| 7 | Optional threat modeling | **6. Review your design** (part 6: "Threat model", only when triggered) | Lightweight STRIDE threat model generated per data flow with mitigations mapped to controls. In Demo mode a rule-based threat model from the pattern catalog is used. |
| 8 | Finalize design artifacts | **7. Build** (start) | Design document, ADRs, diagrams, checklist, threat model, and the *Security Contract* (the rules Claude must obey) are written to `design/`. |
| 9 | Handoff to development | **7. Build** | Explicit human approval ("Build my app") → pipeline: scaffold → generate → verify → fix → evaluate → report. |
| 10 | Design-drift watch | **8. Results** / any later edit | Editing answers marks the design as *changed*; the results page shows a *Rebuild needed* banner and the diff of affected controls. |

**Quick mode**: the user only writes a description. Claude infers the profile (structured output). Step 6 shows every
inferred answer as *"We assumed …"* for confirmation. Same pipeline afterwards.

### 3.1 Wizard content rules

* One idea per screen; sensible default preselected; *Recommended* badge where a choice matters for security.
* Each question shows: **Why we ask** (one or two sentences), **What this changes** (the plain-language controls it
  turns on, e.g. "Because you store health information, we will encrypt sensitive fields, require sign-in, add
  admin two-factor authentication and generate a data-retention policy").
* Never use an acronym without expanding it the first time on that screen.
* Free-text fields are length-limited and screened for prompt-injection patterns before being sent to Claude
  (AISVS C2.1 / Appendix C AC.3.3); the profile, not the raw text, drives all security decisions.

---

## 4. Architecture of SecureVibe

```
securevibe/
  package.json              npm workspaces: server, web, shared
  shared/                   TypeScript types + zod schemas shared by server and web
  server/                   Express 5 API, pipeline, scanners, compliance engine, reports, CLI
  web/                      React 19 + Vite SPA (the wizard, pipeline progress, results)
  templates/secure-web-app/ hardened baseline for generated applications (+ manifest)
  data/frameworks/          OWASP ASVS 5.0.0, AISVS 1.0 (+ Appendix C), SbD 0.5.0 checklist as JSON
  data/knowledge/           plain-language explanations, pattern catalog, remediation library, applicability rules
  workspace/                (git-ignored) one folder per user project
  artifacts/self-assessment/ SecureVibe's own compliance + security reports
  docs/                     this document, architecture, threat model, incident response, ADRs
```

### 4.1 Server modules (`server/src`)

| Module | Responsibility |
|---|---|
| `app.ts`, `security/` | Express app, local security posture (see §4.3), error handling, SSE progress channel |
| `api/` | Routes: projects, wizard state, design derivation, pipeline runs, artifacts, health, settings |
| `store/` | Project persistence: `workspace/projects/<id>/project.json` + folders `design/`, `app/`, `pipeline/`, `reports/` (atomic writes, path confinement) |
| `frameworks/` | Loads framework JSON; requirement lookup; applicability engine (profile → applicable requirements + target level); mapping tables (rule → requirements, probe → requirements, manifest control → requirements) |
| `design/` | SbD engine: derive architecture, select patterns, fill checklist, risk triage, threat model, ADRs, design doc, security contract |
| `llm/` | `LlmProvider` interface; `AnthropicProvider` (SDK, streaming, adaptive thinking, prompt caching, fallbacks, refusal handling, retries, budgets, audit log); `MockProvider` (deterministic; used by tests and Demo mode); prompt library; structured-output helpers; the code-generation agent loop with confined file tools |
| `generator/` | Scaffold from template (feature toggles, entity stubs), build the generation brief, run the agent loop, provenance metadata |
| `scanners/` | `sast` (TypeScript-AST rule engine), `eslint` (eslint-plugin-security), `secrets`, `deps` (`npm audit` + lockfile + optional OSV), `config`, `dast` (runtime probes against the app started on 127.0.0.1), `tests` (vitest runner), `external` (semgrep/gitleaks/trivy when present), `normalize` (common Finding schema, fingerprints, dedupe, remediation enrichment) |
| `compliance/` | Evidence collection, per-requirement evaluation (ASVS, AISVS), SbD checklist evaluation and scoring, summary metrics |
| `reports/` | Renderers: JSON (source of truth), self-contained HTML, Markdown; compliance report, security report, design document, SBOM (CycloneDX) |
| `pipeline/` | Stage runner with progress events, cancellation, timeouts, retries, run logs; fix loop |
| `cli/` | `securevibe self-assess`, `securevibe run <projectDir>`, `securevibe verify <appDir>` |

### 4.2 Web app (`web/src`)

Pages: Home (projects list, demo-mode banner, API key status), Wizard (steps 1–6), Build (live progress with
plain-language stage descriptions), Results (run instructions, report viewers, download zip, rebuild banner),
Settings (model, effort, budgets — all with safe defaults). Design system: hand-written CSS, large type, high
contrast, keyboard navigable, mobile-friendly.

### 4.3 Local security posture of SecureVibe (its own SbD/ASVS controls)

* Binds to `127.0.0.1` only (configurable, off by default for LAN).
* **Startup access token**: printed once and embedded in the URL that is opened; exchanged for an `HttpOnly`,
  `SameSite=Strict` session cookie. Protects against other web pages talking to the local API (CSRF / DNS rebinding).
* Host and Origin allow-list (`127.0.0.1`, `localhost`); `Sec-Fetch-Site` check on state-changing requests; CSRF
  token for JSON mutations.
* Strict CSP (nonce-based, no inline scripts in production build), `X-Content-Type-Options`, `Referrer-Policy`,
  `Permissions-Policy`, `frame-ancestors 'none'`.
* JSON body limit, rate limits, request timeouts, zod validation on every route, uniform error model (no stack
  traces to clients), structured pino logs with correlation IDs, separate audit log of LLM calls (model, token usage,
  prompt hash, project id, correlation id — AISVS C12.1 / Appendix C AC.5.1).
* The Anthropic API key is read from the environment or a local `.env` file and is never written to project data,
  logs or reports. The UI only shows *configured / not configured*.
* All file operations are confined to the workspace folder (canonical path check). Child processes (npm, tests,
  the generated app under test) run with a minimal environment, timeouts, output caps, and `--ignore-scripts` for
  installs (supply-chain guard; the template has no native modules).
* DAST probes are only ever sent to a port SecureVibe itself started on 127.0.0.1.
* Execution budgets for the agent loop (max iterations, max tokens, wall-clock) — AISVS C9.1.

### 4.4 Data model (in `shared/`)

* `Project { id, name, createdAt, updatedAt, mode: 'guided'|'quick', profile: DesignProfile, profileVersion,
  design?: DesignArtifacts, designVersion, lastRun?: RunSummary, status }`
* `DesignProfile` — the wizard answers (see §5).
* `DesignArtifacts { securityRequirements[], architecture {components[], trustZones[], dataFlows[], externalDependencies[]},
  patterns[], checklist: SbdChecklistEntry[], peerReview?, riskTriage, threatModel?, adrs[], securityContract,
  applicability: { asvsLevel, asvsRequirementIds[], aisvsRequirementIds[], notApplicable: {id, reason}[] } }`
* `Finding` — normalized finding (see §7).
* `RequirementResult { id, standard: 'asvs'|'aisvs', status, evidence: Evidence[], rationale, remediation?, manualVerification? }`
* `Evidence { type: 'template-control'|'test'|'dast'|'scanner'|'ai-review'|'design'|'manual', ref, summary, location?, passed }`
* `PipelineRun { id, projectId, startedAt, finishedAt, stages: StageResult[], findings, compliance, artifacts, llmUsage }`

---

## 5. Design profile → security decisions

The profile is the *only* input to the security decisions. Key fields and what they drive:

| Profile field | Drives |
|---|---|
| `audience` (`just-me` / `my-team` / `customers` / `public`) | authentication requirement, registration flow (invite-only vs open), rate limits, ASVS level |
| `roles[]` (admin always exists when auth is on) | RBAC middleware, per-route authorization tests, admin MFA (TOTP) recommended/on for sensitive data |
| `dataCategories[]` (`contact`, `financial`, `health`, `government-id`, `credentials`, `children`, `location`, `files`, `business-confidential`, `other-personal`) | data classification (DM-01), field-level encryption of sensitive columns (DM-02), retention/deletion policy + endpoints (DM-05), privacy notice, escalation trigger, ASVS **L2** when any of financial/health/government-id/children/credentials-of-others is present |
| `capabilities` (`fileUploads`, `aiAssistant`, `email`, `externalApis[]`, `scheduledJobs`, `publicApi`, `payments`) | ASVS chapter applicability (V5 files, V4 API…), AISVS applicability (aiAssistant), payment guidance (never store card data; provider-hosted checkout), API keys for `publicApi` |
| `aiAssistant { purpose, dataItCanSee, canTakeActions }` | AISVS controls in the generated AI module: input normalization/limits, instruction hierarchy, injection screening, output schema/length validation, no outbound actions unless `canTakeActions` (then allow-listed tools with confirmation), logging, kill-switch env flag, per-user token budgets |
| `deployment` (`local-only` / `local-network` / `internet-later`) | TLS guidance and HSTS config, exposure trigger, stricter rate limits, cookie `Secure` flag behaviour, reverse-proxy docs |
| `owner { name, contactEmail }` | incident response plan, `SECURITY.md`, security contact in reports |
| `businessImpact` (`low`/`normal`/`high`) | Tier-1 trigger, SbD severity weighting |

---

## 6. The secure baseline template (`templates/secure-web-app`)

Everything Claude generates lives on top of this scaffold, which is itself tested. Layout:

```
src/app.ts                 builds the Express app: helmet (CSP nonces), body limits, session, csrf, rate limits, logging, error handler
src/server.ts              listen on 127.0.0.1 by default, timeouts, graceful shutdown, /healthz /readyz
src/config.ts              zod-validated environment (no secrets in code); refuses to start with weak/missing secrets
src/db/                    node:sqlite wrapper (parameterized only), migrations runner, field-encryption helper (AES-256-GCM, key from env)
src/security/              password hashing (Node built-in; argon2id when available, scrypt otherwise), sessions (server-side store, rolling + absolute timeout, regenerate on login), csrf (synchronizer token + Origin/Sec-Fetch-Site check), authz (requireAuth/requireRole/ownership), rate-limit presets, validation helpers (zod), safe redirects, headers, totp (admin MFA)
src/features/auth/         register/login/logout/password change/reset(token, timing-safe), lockout/backoff, audit events
src/features/admin/        user management, audit log viewer, data export/delete (retention policy)
src/features/_example/     reference feature (CRUD "notes") demonstrating every convention; Claude mirrors it
src/features/uploads/      (toggle) validated uploads: allow-list types via magic bytes, size limits, random names, stored outside web root, served with Content-Disposition
src/features/ai/           (toggle) Claude-backed assistant with AISVS controls (see §5)
src/lib/logger.ts          pino structured logs, correlation ids, PII redaction, security event helper
src/lib/mailer.ts          (toggle) local file mailer in dev; SMTP via env
src/views/                 EJS layouts/partials (auto-escaped output), no inline scripts, CSP nonce helper
public/                    static assets (js/css), no third-party CDN
tests/                     vitest + supertest security tests: headers, csrf, authz denials, rate limiting, validation, session fixation, upload rules, AI guard-rails
docs/                      SECURITY.md, incident-response.md, data-retention.md, architecture.md, ADRs (filled from design)
securevibe.manifest.json   control manifest: control id → description → ASVS/AISVS/SbD refs → verification checks
```

`securevibe.manifest.json` example entry:

```json
{ "id": "TPL-HEADERS-01", "title": "Security headers via helmet with nonce-based CSP",
  "asvs": ["V3.4.1","V3.4.2","V3.4.3","V3.4.5"], "sbd": ["AS-01"],
  "checks": [ {"type":"file-contains","file":"src/app.ts","pattern":"helmet\\("},
              {"type":"test","name":"security headers"}, {"type":"dast","probe":"headers.csp"} ] }
```

The compliance engine only credits a template control when **all** its checks still pass on the generated code —
so if Claude (or the user) removes a control, the report shows it.

---

## 7. Verification pipeline

| Stage | What runs | Notes |
|---|---|---|
| `design-freeze` | Write `design/*.md|json` and the Security Contract | SbD step 8 |
| `scaffold` | Copy template, apply toggles, entity stubs, docs from design | deterministic |
| `generate` | Claude agent loop with tools `list_files`, `read_file`, `write_file`, `delete_file`, `run_checks` | skipped in Demo mode; budgets enforced; outputs validated against schema; paths confined to `app/` |
| `install` | `npm install --ignore-scripts --no-audit --no-fund` | minimal env |
| `typecheck` | `tsc --noEmit` | |
| `lint` | eslint + eslint-plugin-security | findings → SAST |
| `unit-tests` | vitest (template + generated tests) | results are evidence |
| `sast` | TypeScript-AST rule engine (~40 rules: injection sinks, dangerous APIs, weak crypto, insecure cookies/headers, missing authz on routes, raw SQL concatenation, path traversal, open redirect, prototype pollution, unsafe regex, secrets, logging of sensitive fields, EJS unescaped output, missing validation on `req.body` use, `child_process` with user input, `eval`/`new Function`, insecure randomness, TLS verification disabled, CORS `*` with credentials…) | each rule has CWE, ASVS mapping, remediation text and example |
| `secrets` | regex/entropy scanner (Anthropic, AWS, GitHub, Slack, Stripe, private keys, JWTs, generic) | |
| `deps` | `npm audit --json`, lockfile presence/integrity, unpinned ranges, deprecated packages, license inventory, optional OSV batch query; CycloneDX SBOM | network-dependent parts degrade gracefully with a clear "skipped: offline" |
| `config` | `.env.example` present, `.gitignore` covers secrets, strong secret length enforced, node engine pinned, no debug flags, headers config, cookie flags | |
| `dast` | start app on 127.0.0.1:random with a throw-away DB; probes: security headers, cookie flags, CSRF enforcement, authz denials for each protected route, rate limiting on login, error leakage, directory listing / dotfile exposure, CORS reflection, method handling, open redirect, injection smoke tests, oversized body rejection, health endpoint, AI endpoint guard-rails (when enabled) | all probes mapped to ASVS requirements |
| `external` | semgrep / gitleaks / trivy / osv-scanner if found on PATH | optional, clearly labelled |
| `ai-review` | Claude reviews the code against the applicable requirement subset and the findings so far; returns structured `RequirementAssessment[]` and additional `Finding[]` with file:line citations that are verified to exist | skipped in Demo mode → *Not verified* |
| `fix` | Claude fixes open high/critical findings (max 2 rounds), then stages `typecheck`…`dast` rerun | every fix is recorded in the report as "found → fixed" |
| `compliance` | evaluate SbD checklist, ASVS, AISVS | §8 |
| `reports` | render JSON / HTML / Markdown; zip | |

Progress is streamed to the UI (SSE) with a plain-language sentence per stage ("Checking that every page which
should require sign-in actually does…").

### 7.1 Finding schema

```ts
interface Finding {
  id: string; fingerprint: string;                // stable across runs
  source: 'sast'|'eslint'|'semgrep'|'secrets'|'deps'|'config'|'dast'|'tests'|'ai-review'|'external';
  ruleId: string; title: string;
  severity: 'critical'|'high'|'medium'|'low'|'info'; confidence: 'high'|'medium'|'low';
  cwe: string[]; location?: { file: string; line?: number; column?: number; snippet?: string; endpoint?: string };
  description: string;        // what it is, in plain language
  impact: string;             // why it matters
  evidence: string;           // what the tool observed
  remediation: { summary: string; steps: string[]; example?: string; references: string[] };
  mappings: { asvs: string[]; aisvs: string[]; sbd: string[] };
  status: 'open'|'fixed'|'accepted'|'false-positive'; fixedInRound?: number;
}
```

---

## 8. Compliance evaluation

**Applicability** (rule-based, in `data/knowledge/applicability.json` + code):

* ASVS target level: **L1** baseline; **L2** when sensitive/regulated data, public audience, or high business
  impact. L3 requirements are listed as *Out of target level* (not counted) but shown for transparency.
* Chapter/section applicability from capabilities: V10 (OAuth/OIDC) N-A unless chosen (never in v1); V17 (WebRTC)
  N-A; V9 (self-contained tokens) N-A unless API tokens/JWT are generated (v1 uses opaque API keys → N-A with
  reason); V5 (files) only with uploads/downloads; V2.3/V6 sub-sections depend on auth options, etc.
* AISVS applies only when the AI assistant is enabled (or for SecureVibe itself). Chapter-level N-A with reasons:
  C1 (no training), C3 (vendor-hosted model; version pinning still assessed), C4 (hosted provider infrastructure),
  C6 (partial: SDK/model pinning), C8 (no memory/vector store), C10 (no MCP), C9 (only when the assistant can take
  actions), C11 (partial), C2/C5/C7/C12 applicable.

**Evidence and status** per requirement: `pass` requires ≥1 passing evidence and no failing evidence;
`fail` when a mapped finding is open or a probe/test failed; `partial` when evidence is mixed or the AI review says
partial; `not-applicable` with reason; `not-verified` otherwise, always with a *how to verify manually* sentence.

**SbD checklist**: each of the 36 controls gets Yes / No / N-A + justification + evidence pointers from the
design engine and template manifest; the seven Critical controls are called out; the SbD score and escalation
decision are shown. Distributed-systems-only controls (service mesh, DLQ, sagas, autoscaling…) are N-A for a
single-service local app with an explicit justification; if the user picks `internet-later`, the report adds the
deployment-time recommendations instead.

---

## 9. Reports

**Compliance report** — executive summary (plain language, traffic-light per standard), design summary (all SbD
artifacts), SbD checklist table with score, ASVS results per chapter (tables + evidence), AISVS results, findings
that affect compliance, recommendations (prioritised), manual verification list, methodology & limitations,
provenance (model, prompts hashes, run id, timestamps, assessor).

**Security report** — summary counts by severity and source, tool coverage table (ran / skipped and why), findings
grouped by severity with full context and remediation (code examples), fixed-in-pipeline findings, dependency
inventory + SBOM, DAST probe results table, test results, next steps.

Formats: `report.json` (source of truth), self-contained `report.html` (inline CSS, printable, no external
resources), `report.md`.

---

## 10. LLM integration details

* SDK `@anthropic-ai/sdk`; default model `claude-opus-5`; adaptive thinking; `output_config.effort` configurable
  (default `high` for generation, `medium` for review); streaming for generation; `fallbacks: "default"` with the
  server-side fallback beta header; `stop_reason === 'refusal'` handled and surfaced.
* Prompt caching: stable system blocks (role, security contract, template API reference, framework excerpts) carry
  `cache_control`; volatile content last.
* Structured outputs via `output_config.format` (zod → JSON schema) for profile inference, design review, threat
  model, AI review, fix plans. Free-form model text is never executed; file paths are confined; tool inputs
  validated with zod before use (AISVS C7.1, Appendix C AC.11.3).
* Every call is logged to `workspace/llm-audit.jsonl` with correlation id, project id, purpose, model, token usage,
  cost estimate, prompt hash, response hash — never the API key.
* Budgets: max iterations, max output tokens per run, wall-clock; user-visible running totals.
* Untrusted content (user free text, file contents from the generated app when reviewing) is wrapped in clearly
  delimited data blocks with an instruction-hierarchy reminder; user text is screened for injection patterns and
  the UI explains why a text was flagged.

---

## 11. Self-assessment

`npm run self-assess` runs the same scanners, DAST, tests, compliance evaluation and report renderers against
SecureVibe itself using `self-assessment/profile.json` (audience: just-me/local tool; data: credentials (API key)
and business-confidential (the user's designs); capabilities: aiAssistant (code generation), externalApis
(Anthropic, npm); deployment: local-only). Output: `artifacts/self-assessment/`. The AI review evidence may be
supplied from a file (`--ai-review-file`) so a review performed by a separate Claude session can be included; the
report always records who/what performed the AI review.

---

## 12. Key decisions (ADR summary)

| ADR | Decision | Why |
|---|---|---|
| 001 | TypeScript everywhere; single `npm install` | one runtime for the tool and generated apps; simplest local run |
| 002 | Generated apps are server-rendered + JSON API | fewer moving parts to secure (CSP, CSRF, sessions); reliable generation |
| 003 | `node:sqlite` instead of native DB drivers | zero native compilation; `--ignore-scripts` installs become safe |
| 004 | Hardened baseline template + manifest, Claude extends within conventions | controls are implemented and tested once; compliance evidence is mechanical |
| 005 | Startup token + host allow-list for SecureVibe's own UI | protects a localhost tool from cross-site abuse without a login screen |
| 006 | Evidence-gated statuses; *Not verified* is a first-class status | honesty over green dashboards |
| 007 | Built-in TypeScript-AST SAST + eslint-plugin-security; external scanners optional | works on a clean machine; external tools improve coverage when present |
| 008 | `LlmProvider` abstraction with Mock provider and Demo mode | testable without credentials; tool is usable before an API key exists |
| 009 | AISVS Appendix C applied to SecureVibe itself | it is an AI coding tool; provenance, logging, approval gates |

---

## 13. Review-driven revisions (authoritative where they differ from the sections above)

A six-lens adversarial critique of this design (non-technical UX, verification honesty, local-run feasibility, LLM
robustness, template security completeness, report usefulness) produced 84 issues. The following decisions are adopted
and are specified in detail in `docs/CONTRACTS.md`:

1. **Evidence tiers and honest statuses.** Evidence is `strong` (tests, runtime probes), `medium` (manifest/config/scanner
   checks) or `weak` (AI review, generated docs, human attestation). `pass` needs ≥1 strong or ≥2 medium items; AI-only
   evidence renders as `ai-assessed`, docs as `documented`, attestations as `attested`. `manual-only` requirements can never
   pass. Summaries always show four numbers (verified pass / AI-assessed / not verified / fail) — never a single colour.
2. **SbD checklist realism.** Fixed per-control decision rules with `severityIfNo`, actions for every "No", mitigation plans
   for critical "No"s (AC-02 central IdP and AC-05 secret manager are honestly "No" for local apps; AC-01/DM-02 depend on the
   TLS mode; MT-06 needs an owner attestation; MT-07 is met by the hash-chained audit log + retention setting). Escalation is
   computed exactly as the framework states and is satisfied by the generated threat model plus owner acknowledgment, with the
   report stating that no independent AppSec review was performed. A deployment-time re-evaluation is always shown.
3. **Target level.** One level for ASVS and AISVS: L1 only when only the owner/team use it, no personal data, not high impact,
   not internet-bound and no AI assistant; L2 otherwise. The same predicate drives the SbD sensitive-data trigger.
4. **Human review is not faked.** AISVS Appendix C AC.4.1 is reported as failing until a named person records a review of the
   security-critical files ("human review pack"). The AI second opinion is labelled as such (same model, different prompt).
5. **Wizard UX.** One idea per screen; situational questions ("If this app were down for a day, what would happen?");
   "Not sure" on every question picks the safer default and records an assumption; Quick mode still asks the three
   high-consequence questions explicitly and may only *raise* the security posture; step 6 becomes a plain-language
   "Here's what we'll build" summary with a collapsed technical drawer; risk triage is shown as "Extra care level" paired
   with what was done; no scores or the word "escalate" in the wizard.
6. **First run of generated apps.** SecureVibe writes strong secrets and creates the first admin account at scaffold time
   (one-time password shown once); the results page shows a numbered run checklist with copy buttons, and the wizard says
   up front when an authenticator app will be needed.
7. **Locked dependency set.** Generated apps ship a tested `package-lock.json`; the agent cannot edit `package.json`,
   protected security files, tests or the manifest (enforced by the tool layer and re-verified by hashes). Installs use
   `npm ci --ignore-scripts --prefer-offline` with a node_modules fast path; a failed install does not stop static analysis
   or the reports.
8. **Runtime scan that can actually probe generated routes.** Generated apps register every route through a registry with
   an explicit authorization declaration, and expose a test-bootstrap mode (seeded users per role, route export, ready line)
   that the DAST harness uses to probe every route as anonymous / wrong role / non-owner.
9. **Sandboxing stated honestly.** Generated code and its tests run under Node's permission model (file system limited to
   the project folder) with a minimal environment and process-group kill; network is not restricted and the reports say so.
10. **AI review citations must be verbatim.** Each citation includes a snippet that is string-matched at the cited location
    on the exact file tree sent to the model; mismatches become `not-verified` and are counted as a hallucination metric.
    Reviews are batched per chapter. Refusals, fallbacks and served models are logged and surfaced.
11. **Fix loop rules.** A finding is `fixed` only when its original detector no longer reports it after a full re-run, no new
    P1/P2 finding appeared, the passing-test count did not decrease and the protected files are unchanged. Diffs are saved.
12. **Reports for three readers.** An Overview ("Can I use it?", top actions with who/effort), a compliance report (scope,
    coverage limits, design summary, traceability matrix, SbD checklist, ASVS/AISVS/Appendix C results, manual verification
    grouped by who, sign-off, provenance) and a security report (rating method, tool coverage, findings by priority with the
    full template, fixed-during-build with diffs, DAST table, tests, dependencies + SBOM, re-verification commands,
    provenance), plus `findings.sarif`, `provenance.json` and a "Going online safely" checklist when the audience is public.
13. **Providers.** `null` (preview mode: skipped, honestly labelled), `scripted` (tests: refusals, truncation, malformed JSON,
    path escapes, over-budget), `anthropic`. `npm run smoke:api` is the first thing to run once a key exists.
