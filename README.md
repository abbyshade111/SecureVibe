# SecureVibe

**Describe the app you want. Get a working, security-hardened web application — plus the evidence.**

SecureVibe is a local-first "vibe-coding" tool for people who are not security experts. It walks you through a few
plain-language questions about the application you want (who uses it, what information it handles, where it will run),
designs it using the **OWASP Secure by Design Framework**, writes the code with Claude on top of a hardened, tested
starter application, and then verifies the result against **OWASP ASVS 5.0** (application security) and
**OWASP AISVS 1.0** (AI security). You get three things:

1. **Your application's source code** — runs on your own computer with `npm install`, `npm run setup`, `npm start`.
2. **A compliance report** — how the design followed the Secure by Design process, and the status of every applicable
   ASVS / AISVS requirement, with evidence, findings and recommendations.
3. **A security report** — findings from static analysis, dependency analysis, secret scanning, a runtime scan of your
   app, its own security tests and an AI security review. Every finding explains what it is, why it matters, where it
   is and how to fix it.

Already have an app (written by hand or with another AI tool)? Choose **Check an app you already have** on the home
page and upload its folder: SecureVibe scans the code (without running it) and writes the same reports.

Other pages: **Dashboard** (AI spending, builds, security log, open findings), **Human checks** (a step-by-step guide
through the requirements only a person can confirm, from the Reports section) and **Preview your app** (runs a built
app with throw-away data so you can try it).

The same three artifacts are produced for SecureVibe itself: see [`artifacts/self-assessment/`](artifacts/self-assessment/).

## Requirements

* **Node.js 22.13 or newer** (tested on Node 26) — [nodejs.org](https://nodejs.org)
* An **Anthropic API key** for AI generation and AI review ([console.anthropic.com](https://console.anthropic.com)).
  You pay Anthropic for what you use; SecureVibe shows an estimate and lets you set a spending cap before every build.
  **Save credits** (Settings, on by default) builds with Claude Sonnet 5 at the lowest effort with one round of fixes;
  a typical app then costs roughly $2–4, and the default $5 cap is shared between writing the app (up to 55%), the code
  review and the fixes, so a build always finishes within it.
  Without a key SecureVibe runs in **Preview without AI** mode: you can complete the design and build the hardened
  starter app, but nothing is customised or reviewed by AI, and the reports say so.
* Internet access the first time you build (to download packages). Later builds can work offline.

## Run it

```bash
npm install
npm start
```

`npm start` builds the web interface on first run, starts the server on `http://127.0.0.1:4173`, and prints a link that
contains an access token. Open that link (SecureVibe tries to open it for you); use it exactly as printed, with
`127.0.0.1` rather than `localhost`. The link works for as long as SecureVibe keeps running, so you can open it again in
a new tab, but keep it private. The token protects the tool from other web pages on your computer talking to it.

To use AI features, set your key before starting, either in the environment or in a `.env` file next to this README
(it is git-ignored; SecureVibe reads only its own keys from it and never writes the key into reports or logs):

```bash
echo 'ANTHROPIC_API_KEY=your-key' > .env
npm start
```

Without a key SecureVibe runs in preview mode: the wizard, the hardened starter app (with pages for every record you
describe), all scanners and both reports still work; only Claude-written features and AI review are skipped, and the
reports say so. Set `SECUREVIBE_AI=off` (in the environment or `.env`) to use preview mode even when a key is
configured, or switch AI off and on at any time with **Use AI** at the top of the Settings page.

Useful commands:

| Command | What it does |
|---|---|
| `npm run dev` | Development mode (server + web hot reload) |
| `npm test` | SecureVibe's own test suite |
| `npm run self-assess` | Produces SecureVibe's own compliance + security reports in `artifacts/self-assessment/` (runs the test suite first; add `-- --no-ai` to skip the paid AI review). Reviewed scanner decisions live in `self-assessment/triage.json`. |
| `npm run verify -- <appDir> <profile.json>` | Re-verifies an app you edited by hand (no regeneration) |
| `npm run -w server smoke:api` | One small API call to confirm your key works (run this first) |
| `npm run -w server doctor` | Preflight checks in the terminal |
| `npm run -w server reports:rerender -- <projectId> [runId]` | Rebuilds a run's reports from its saved results after a SecureVibe update (no checks re-run, no AI cost) |

**Extra scanners (optional):** if semgrep, gitleaks, trivy or osv-scanner are installed (for example
`brew install semgrep gitleaks trivy osv-scanner`), every build also runs them and their results appear in the security
report. semgrep and trivy download their rules and vulnerability data from the internet when they run.

**Tidying up:** on **My apps**, **Archive** hides an app you may want later (restore it from "Show archived apps");
**Delete** removes it and everything built for it from this computer, after you type its name to confirm.

**Reading your reports:** on **My apps**, click **Reports** next to an app. Pick any earlier build under
**Reports from**, then **Open**, **Download** or **Save as PDF**. Save as PDF opens your browser's print window; choose
"Save as PDF" there. The compliance report ends with the full text of every architecture decision record (ADR), and each
ADR id in the report links to it.

## How a build works

1. **You answer plain-language questions** (about 10 minutes). Every question says why it is asked and what it changes.
   "Not sure" always picks the safer option and records that assumption.
2. **SecureVibe designs the app** following the ten Secure by Design steps: security requirements, architecture and
   trust zones, principles and patterns, the 36-control review checklist, an AI second opinion, risk triage, a STRIDE
   threat model when extra care is needed, design documents, and a hand-off to code generation.
3. **You approve the build.** SecureVibe copies the hardened starter app, generates strong secrets, creates your first
   admin account, and asks Claude to write your features inside strict rules (it cannot touch the security code, add
   packages, or run arbitrary commands).
4. **Everything is verified**: install, type-check, lint, the app's own security tests, static analysis, secret scan,
   dependency scan (with a software bill of materials), a runtime scan that probes every page and API as an anonymous
   user, the wrong role and a non-owner, an AI review that must cite verbatim code, and a fix round for high-priority
   findings.
5. **Reports are written** for you, for a developer and for a security reviewer. A requirement is only "verified" with
   real evidence (a test, a runtime probe, or independent static checks). AI opinions are shown separately and never
   count as verified. Anything that could not be checked is listed with instructions for a person.

## What it can build (version 1)

Web applications that run on your computer or your local network: Node.js + Express + SQLite, server-rendered pages
with a JSON API, optional user accounts and roles (with two-factor authentication for administrators), file uploads,
an AI assistant powered by Claude, email notifications, scheduled jobs and connections to other web services.
Putting an app on the internet is a separate step; SecureVibe produces a "Going online safely" checklist for it.

Not in version 1: mobile apps, microservices, cloud deployment, social/OAuth sign-in, retrieval-augmented AI.

## Where things are

```
securevibe/
  workspace/projects/<id>/app/        your generated application (also app-v1/, app-v2/ … for earlier builds)
  workspace/projects/<id>/reports/    overview, compliance report, security report, design document, SBOM, SARIF, zip
  workspace/projects/<id>/design/     design artifacts (Secure by Design steps 1–8)
  workspace/llm-audit.jsonl           audit log of every AI call (never contains your API key)
  artifacts/self-assessment/          SecureVibe's own reports
  docs/                               design, contracts, architecture, threat model, incident response, ADRs
```

## Security notes

* SecureVibe binds to `127.0.0.1` only. Its UI requires the startup token, checks the `Host` and `Origin` headers, uses
  a strict Content Security Policy and a CSRF token.
* Generated code and its tests run under Node's permission model (file access limited to the project folder) with a
  minimal environment, timeouts and process-group cleanup. Network access is **not** restricted — the reports say so.
* Your API key is read from the environment or `.env` only. It is never stored in project data, logs or reports.
* SecureVibe is an AI coding tool and applies OWASP AISVS Appendix C to itself: provenance metadata for every generated
  file, prompt/response logging with correlation ids, hash-pinned prompts, an instruction hierarchy for untrusted content,
  schema-validated model output, execution budgets, and explicit human approval before any build. It records honestly that
  AI-generated code has **not** been reviewed by a qualified human engineer until you mark such a review as done.

See [`docs/DESIGN.md`](docs/DESIGN.md) and [`docs/CONTRACTS.md`](docs/CONTRACTS.md) for the full design.

## Licence and attribution

MIT. Framework content: OWASP ASVS 5.0.0, OWASP AISVS 1.0 and the OWASP Secure by Design Framework v0.5 are
© OWASP Foundation, licensed under CC BY-SA 4.0. SecureVibe embeds their requirement texts for verification purposes.
