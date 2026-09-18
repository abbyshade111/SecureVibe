# SecureVibe — notes for Claude Code sessions

SecureVibe is a local app that turns plain-language answers into a hardened web app (Node 26, Express 5, EJS,
`node:sqlite`), checks it against OWASP ASVS 5.0 / AISVS 1.0 / Secure by Design, and writes compliance and security
reports. The authoritative design docs are `docs/DESIGN.md` and `docs/CONTRACTS.md`; read the CONTRACTS section for
whatever you touch before changing it.

## Layout

- `server/` — Express API, pipeline, scanners, LLM flows (`src/llm`), compliance engine, reports. Runs with `tsx`.
- `web/` — React 19 + Vite UI. `web/dist` is what the server serves; rebuild it after UI changes (`vite build`).
- `shared/` — zod schemas that are the contract between server and web (`shared/src/*.ts`).
- `templates/secure-web-app/` — the app template every build starts from, with its own security test suite.
  The template is read at build time: template changes take effect on the next build, with no server restart.
- `data/frameworks`, `data/knowledge` — OWASP data, wizard copy, rules. `data/knowledge/wizard-copy.json` is checked
  by `server/tests/knowledge/wizard-copy.test.ts`, which lists every question id explicitly.
- `workspace/` — the owner's projects, `settings.json`, `llm-audit.jsonl`, `logs/`. Never edit a user's project by
  hand except to repair data, and say so.

## Commands (never `npx`; use the workspace binaries)

- Typecheck: `cd server && ../node_modules/.bin/tsc -p tsconfig.json --noEmit` (same in `web/`).
- Web build: `cd web && ../node_modules/.bin/vite build`.
- Server tests (fast, sandbox-safe subset): `cd server && ../node_modules/.bin/vitest run <files>`.
  Tests that start a server or an app need to bind ports and fail in the Claude Code sandbox with `listen EPERM`.
  Run those, and the full suite, through the launch configs in `../.claude/launch.json` (`server-tests`,
  `template-tests`, `preview-test`, `self-assess`, `app-tests`) via `preview_start`; each writes its result to a
  file in the session scratchpad, and the script prints a DONE marker.
- Template suite: the `template-tests` launcher copies an all-features `securevibe.features.json` into the
  template and generates a `.env`; remove `templates/secure-web-app/.env` afterwards if the script left it.
- Self-assessment (SecureVibe checking itself): `npm run self-assess -- --no-ai` is free; without `--no-ai` it
  spends the owner's Anthropic credit. Never run a paid AI step without the owner asking.
- Evaluation harness: `npm run eval` builds the golden apps in `evals/golden/` without AI and compares them with
  `evals/baselines/` (`--update` to save new baselines, `--only <name>` for one app, `--ai` costs money). Run it
  through the `eval-no-ai` launcher (ports); it needs to pass before a template or pipeline change is done.

## Running SecureVibe

- `npm start` builds the web UI on first run and prints a one-time link `http://127.0.0.1:4173/auth/token?t=…`.
  Use `127.0.0.1`, not `localhost`: sessions are only valid on 127.0.0.1 so a session cookie never reaches app
  previews, which run on `localhost:<port>`.
- Builds run in a detached worker process (`server/src/cli/build-worker.ts`, see `pipeline/job.ts`), so restarting
  SecureVibe no longer ends a build; the page reconnects to the run's `events.jsonl`. Still, prefer starting
  SecureVibe in the user's Terminal panel (`run_in_terminal`) rather than `preview_start`, which the desktop app
  may stop after a while. Only the user can stop that process (Ctrl-C); ask, then start it again.
- Restarts are needed for `server/` and `shared/` changes. `web/` changes need only a `vite build`; template and
  `data/` changes need nothing.

## Money and keys

- AI calls cost the owner real money. "Save credits" (Sonnet 5, low effort, one fix round) is on by default;
  the spending cap is split 55% writing / 30% review / 15% fixes so a build never passes it.
- The owner's API keys live in `.env` (root) and are written there by Settings → "Your AI service". Never print,
  log, echo or commit a key. Builds use the service in `settings.aiService` (Anthropic, OpenAI or Google —
  `llm/provider.ts`); the OpenAI/Google providers are fetch-based (`llm/rest.ts`) and tested with a fake fetch. `workspace/llm-audit.jsonl` records every call and its cost; the Dashboard reads it.
- The scripted provider (`server/tests/fixtures/llm/*.json`) replays recorded answers so every AI flow is testable
  for free; add a fixture for any new flow. Tests run against a temporary `SECUREVIBE_HOME` (`tests/setup-home.ts`)
  so they never write into the owner's workspace.

## Rules that hold everywhere

- Evidence tiers are honest: AI review alone is "ai-assessed", never "pass". A "not sure" human answer adds no
  evidence. Do not make a check look stronger than it is.
- The generation agent is fenced (allow-listed paths, validated tool inputs, screened tool output). The second
  opinion and the follow-up questions may only change answers from their allow-lists, and only toward the safer
  side. Keep it that way.
- Generated code runs under Node's permission model (file system limited to the project folder) and behind the
  OS network fence (`pipeline/net-fence.ts`: loopback only on macOS via sandbox-exec, Linux via a network
  namespace). A child that must reach outside hosts needs `network: 'any'`; the reports say which applied.
- Every new question in the wizard needs: the `shared/src/profile.ts` field, the wizard-copy entry, the fixtures
  that build profiles (`tests/fixtures/**`), and the id lists in `wizard-copy.test.ts`.
- Uploaded apps (`origin.kind === 'uploaded'`) are only ever scanned, never run.
- A template change reaches existing apps through "Update to the latest template" (`generator/upgrade.ts`): it
  replaces only template files the app never changed. Keep template files free of per-app content so that stays
  true, and never make the upgrade touch `.env`, data or certificates.

## Working style the owner expects

- Plain language in the UI and reports: the owner is not a programmer. No jargon without an explanation.
- Say what was verified and what was not. Report test results as they are.
- Commit only when asked; the owner runs `git add -A && git commit` themselves.
