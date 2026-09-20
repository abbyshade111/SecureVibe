# What the first session knew, for the sessions that came after

Written 20 September 2026 by the session that built SecureVibe's backbone on 17–18 September (the one whose
history iCloud ate and the bundle restored). The other sessions have the code and the backlog; what they did not
have is the owner's decisions and the reasons behind pieces they are now changing. Messages between sessions are
lost when a session is not running, so it lives here.

## What that session built, in the owner's chosen order

The owner picked this order on 17 September and asked for it to be worked through without further approval:
`CLAUDE.md` → plan → approve → build → verify → builds as durable jobs → evaluation harness with golden apps →
the "section 6" features (template upgrades, version diff, hand-off pack, build notifications, one-page report
landing, free onboarding example) → containerising generated code → OpenAI/Google providers. Every one of those
is now in `main`; the last three landed from other sessions after the iCloud incident. Before that list the same
session had added: save/resume of wizard answers, the Dashboard tab from the security log, "Save credits" (Sonnet
5, low effort, one fix round, budget split 55/30/15 so a $5 cap always covers a build), the human-checks wizard,
app previews with a one-click sign-in link, uploading your own app for a verify-only run, the red Delete button.

## Decisions the owner made, which still hold

- **Money.** "Please conserve credits." Never run a paid AI step unless the owner asks; every test uses the
  scripted provider. The owner once pasted an API key into chat: keys live only in `.env` and are never echoed.
- **Running builds.** Never restart SecureVibe while a build runs; only the owner stops the server (Ctrl-C) and
  we ask first. Durable worker builds exist so a restart is survivable, not so it is casual.
- **The owner's apps are theirs.** Salon Bookings `p_5c4fyqgk66`, SecureFit (was SecureApp) `p_anwzto2pth`,
  Pain in the Butt `p_enj4cx7ffl`, the self-assessment `p_lwph5z7zqd`, and the apps other people built since.
  Only `p_vozfygv6vt` "Salon Bookings (test)" is ours to break. Repair a record only to fix damage, and say so.
- **Pain in the Butt** (a friend's app): the assistant does the research itself (Claude's web-search tool), may
  suggest treatments and home remedies as long as sources are vetted and doubts about them are stated; records
  are kept until deleted; backups were explicitly not a concern; the allowed sites (medical bodies, journals,
  universities) came from a wizard question the owner asked for, `capabilities.aiAssistant.webSearchSites`;
  previews must not demand a password (hence the sign-in link); users need to be told where recovery codes are.
- **Any AI provider, keys in `.env`** — the owner chose both when asked.
- **Plain language everywhere**; the owner is not a programmer and reads every report.

## Why things are the shape they are

- **Plan → approve → build.** The plan is bound to the design hash (`api/plan.ts` `currentPlan`), the agent is
  told to build exactly the approved features and nothing else (`generator/brief.ts`), and plan coverage is
  computed from the route manifest, entities and test names — never from what the model said it did.
- **Follow-up questions and the second opinion** may only change answers on an allow-list, and only toward the
  safer side. Widening what the owner can say is fine; widening what the flow may change is not.
- **Durable builds.** `POST /projects/:id/runs` writes `job.json` and spawns `cli/build-worker.ts` detached;
  `worker.json` holds the pid, `events.jsonl` the progress, and the page tails the file when the server has no
  bus. `runIsLive()` (in-process or live worker) is the only liveness question to ask. The startup sweep skips
  live workers and non-run folders (it once crashed on the `cache` folder).
- **The evaluation harness** compares facts with a baseline: build status, per-step status, open findings by
  seriousness, ASVS/AISVS verified coverage (1-point tolerance), app-test counts, plan coverage; cost and time
  are notes, never failures. Baselines are AI-off so they are free and repeatable; `--ai` is for before a
  release. Results files carry each case's failed steps, failing tests and open findings so a failure is
  readable without a rebuild, and the test stage keeps its raw TAP in `stages/unit-tests.tap` for the same
  reason. In its first hour the harness found five template bugs that real owners would have hit: feature
  flags written kebab-case and read camelCase (API keys, AI actions, retention never switched on at runtime),
  `tools.ts` removed with the actions flag while the assistant still imported it, https apps with no
  certificate, generated tests sending text where an upload id belongs, and the built-in tests running against
  the app's deployment settings instead of loopback. That is the argument for keeping it green.
- **Template upgrades** replace only template files the app never changed (old provenance hash = current
  hash), add new files, remove unchanged dropped files, and keep every file with the owner's or Claude's
  changes, listing them. `.env`, data, certificates and packages are never written, except that new `.env` keys
  are appended with defaults. Keep template files free of per-app content or upgrades stop being safe.
- **Version diff** hides `.env` and the first-login file, compares binaries by hash, and confines paths to the
  version folders. Findings are matched across runs by fingerprint.
- **Scanner corrections that came out of the harness** (not to be undone as "false negatives"): SAST accepts a
  path helper named like `storedUploadPath(id)`, ignores token *usage counts* in logs, treats the assistant
  client's guarded `fetch` like the outbound client, and knows a destructured `{ row, fullKey }` is not a row;
  DAST reports a rate-limited probe as *not attempted*, never as "weak password accepted".

## Gotchas that cost time

- The Bash sandbox cannot signal or list processes it did not start: `kill -0` says "gone" for a live worker.
  Judge liveness from files (`worker.log`, `events.jsonl` growing, `run.json`) or from the Terminal.
- `grep` is aliased to `ugrep`, and `tests/security/ai.test.ts` contains NUL bytes: use `/usr/bin/grep -a`.
- Launchers in `.claude/launch.json` point at scripts in one session's scratchpad; every session must write
  its own scripts and entries, and never repoint another's.
- macOS `tmpdir()` is under `/var` → `/private/var`; Node's permission fence compares real paths, so the store
  resolves its home with `realpathSync`.
- Never keep this repository under an iCloud-synced folder (`~/Desktop`, `~/Documents`); eviction turns files
  into 0-byte placeholders and the first symptom is a module with no exports.
