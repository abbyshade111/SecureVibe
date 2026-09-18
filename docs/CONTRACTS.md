# SecureVibe — Implementation Contracts

This document fixes the identifiers, file layouts and interfaces that the independent parts of SecureVibe share.
It is authoritative where it is more specific than `DESIGN.md`. Every id listed here is referenced by data files,
code and tests; a build-time test (`server/tests/contracts.test.ts`) verifies that every ASVS/AISVS/SbD id referenced
anywhere exists in `data/frameworks/*.json`, and that every manifest control, probe and rule id referenced by the
knowledge base exists in code.

Conventions: ASVS ids look like `V6.2.1`; AISVS ids like `C2.1.3`; Appendix C ids like `AC.4.1`; SbD checklist ids
like `AS-01`; template controls `TPL-<AREA>-NN`; DAST probes `dast.<area>.<name>`; SAST rules `sast.<name>`; config
checks `config.<name>`; secrets rules `secrets.<name>`; dependency checks `deps.<name>`; patterns `PAT-<NAME>`;
security-contract rules `SC-NN`; security events `<area>.<name>`.

---

## 0. Repository layout and ownership

```
securevibe/
  shared/src/                       type contracts (DONE — do not change shapes without updating this doc)
  data/frameworks/                  asvs-5.0.0.json, aisvs-1.0.json (ids C*), aisvs-1.0-appendix-c.json, sbd-checklist-0.5.0.json (DONE)
  data/knowledge/                   applicability.json, sbd-rules.json, patterns.json, remediation.json, requirements-plain.json,
                                    wizard-copy.json, examples.json, injection-patterns.json, common-passwords.txt, glossary.json
  templates/secure-web-app/         the generated-app baseline (+ securevibe.manifest.json, package-lock.json)
  server/src/
    main.ts                         entry: config, startup token, open browser, listen 127.0.0.1
    config.ts                       SecureVibe settings (env + settings.json), paths (SECUREVIBE_HOME)
    app.ts                          express app factory (used by main and tests)
    security/                       local posture: token auth, host/origin allow-list, csrf, headers, rate limit, error model
    api/                            routes (projects, wizard, design, runs, artifacts, findings, attestations, status, examples, settings)
    store/                          project persistence + workspace layout + atomic writes + path confinement
    frameworks/                     loaders, id validation, applicability engine, plain-language lookup
    design/                         SbD engine (requirements, architecture, patterns, checklist, triage, threat model, ADRs, contract, build spec, summary)
    llm/                            providers (anthropic, null, scripted), prompt library (hash-pinned), structured outputs, agent loop, review, fix, quick-infer, peer-review, threat-model, budgets, audit log, redaction, screening
    generator/                      scaffold (template copy + toggles + secrets + admin bootstrap), CRUD expander, brief builder, provenance
    scanners/                       sast (TS AST rules), lint (eslint), secrets, deps (+sbom), config, dast (harness + probes), tests runner, external, normalize/dedupe/priority
    compliance/                     evidence collection, requirement evaluation, sbd evaluation, traceability, summaries, recommendations
    reports/                        overview, compliance, security, design doc, going-online checklist, sarif, html/md renderers, glossary
    pipeline/                       stage runner, progress bus (SSE), process sandbox (spawn/kill/permissions), run persistence, fix loop, cost estimate
    cli/                            self-assess.ts, verify.ts, smoke-api.ts, doctor.ts
  server/tests/                     vitest tests (unit + integration; scripted LLM scenarios; contracts test)
  web/src/                          React app
  self-assessment/profile.json      SecureVibe's own design profile
  artifacts/self-assessment/        SecureVibe's own reports (committed)
  docs/                             DESIGN.md, CONTRACTS.md, ARCHITECTURE.md, THREAT-MODEL.md, INCIDENT-RESPONSE.md, AI-USAGE-POLICY.md, adr/
  workspace/                        (git-ignored) projects/<id>/{project.json,design/,app/,app-v<N>/,pipeline/<runId>/,reports/,attestations.json}
```

Workspace root is `SECUREVIBE_HOME` (default `<repo>/workspace`). `llm-audit.jsonl` and `settings.json` live at the root.

---

## 1. Generated application template (`templates/secure-web-app`)

### 1.1 Runtime and dependencies (locked)

* Runs with **no build step**: `node --experimental-strip-types src/server.ts` (Node ≥ 22.13; tested on 26). Code uses
  erasable TypeScript syntax only (no `enum`, `namespace`, parameter properties, `import =`), explicit `.ts` extensions
  in relative imports, `import type` for types. `tsconfig.json`: `"module":"nodenext"`, `"allowImportingTsExtensions":true`,
  `"erasableSyntaxOnly":true`, `"verbatimModuleSyntax":true`, `"noEmit":true`, `"strict":true`, `"types":["node"]`.
* `package.json` (not editable by the agent) — dependencies: `express@^5.2`, `helmet@^8.3`, `ejs@^6`, `zod@^4.1`,
  `pino@^10`, `busboy@^1.6` (uploads feature), `@anthropic-ai/sdk@^0.126` (ai feature). devDependencies:
  `typescript@^5.9`, `@types/express@^5`, `@types/node@^22`, `@types/busboy@^1`, `@types/ejs@^3`.
  `package-lock.json` is shipped and tested; unused feature packages stay installed (harmless) so the lockfile never changes.
* Scripts: `start` (node --experimental-strip-types src/server.ts), `setup` (gen-secrets + migrate + bootstrap-admin),
  `test` (`node --experimental-strip-types --test tests/`), `typecheck` (tsc -p tsconfig.json), `docs:build`,
  `audit:verify`, `rotate-field-key`, `routes:export`, `gen-cert` (selfsigned TLS mode; uses `openssl` if present).
* `.npmrc`: `ignore-scripts=true`, `fund=false`, `audit=false`.
* Engines: `"node": ">=22.13.0"`. `scripts/preflight.mjs` runs before `start` and prints a friendly message on older Node.

### 1.2 Layout

```
src/server.ts            listen (127.0.0.1 unless BIND_LAN=1), timeouts (headers 10s, request 30s, keepAlive 5s), graceful shutdown,
                         test-mode ready line, TLS_MODE handling
src/app.ts               app factory: query parser 'simple', trust proxy hops, helmet+CSP nonce, body limits, static, session, csrf,
                         rate limits, request id + logger, route registry mount, 404/error handlers
src/config.ts            zod-validated env (§1.3); refuses weak/placeholder secrets; exports typed `config`
src/db/index.ts          node:sqlite wrapper: openDb(), q(sql, params), run(), get(), all(), withTransaction(fn); pragmas; 0600
src/db/migrate.ts        migrations runner (src/db/migrations/NNN_name.sql, applied in order, recorded in _migrations)
src/db/field-crypto.ts   encryptField/decryptField (AES-256-GCM, v<keyId>:iv:tag:ct, AAD table.column.rowId), key registry, rotate
src/security/routes.ts   route registry (§1.4)
src/security/session.ts  session store + middleware (§1.6)
src/security/csrf.ts     synchronizer token + Origin/Sec-Fetch-Site check
src/security/headers.ts  CSP policy builder (exact policy in §1.5), nonce per request, cache-control, clear-site-data
src/security/authz.ts    requireAuth, requireRole, requireOwner(entity, ownerField), forbid()
src/security/password.ts policy (§1.7), hash/verify (argon2id via crypto.argon2 when available, else scrypt; PHC strings)
src/security/totp.ts     RFC 6238 TOTP over node:crypto HMAC-SHA1, recovery codes
src/security/rate-limit.ts  presets (§1.8) keyed by client ip (via config) and/or account
src/security/validate.ts zod helpers: validateBody/Query/Params (strict), reject arrays for scalars
src/security/redirect.ts safeRedirect(res, target, allowList)
src/security/events.ts   security event catalog + emit() (§1.9)
src/security/audit.ts    append-only hash-chained audit table, verifyChain()
src/lib/logger.ts        pino JSON logger, UTC ts, reqId, redaction paths, hashed session id prefix
src/lib/http-client.ts   outboundFetch(url, init) with OUTBOUND_ALLOWED_HOSTS allow-list, redirect:'manual', 10s timeout, 1MB cap, breaker
src/lib/mailer.ts        (email) file mailer in dev (data/outbox/*.eml), SMTP via env; header sanitization
src/lib/scheduler.ts     (scheduler) registry-declared jobs, jobs table with lock_until, overlap protection
src/lib/dto.ts           pick()/omit() helpers; every entity module exports toPublicDto/toOwnerDto/toAdminDto
src/features/index.ts    registers feature modules in order: auth, account, admin, [_example], [uploads], [ai], [apikeys], <generated…>
src/features/auth/       register (per registration mode), login (+MFA step), logout, forgot/reset, change password
src/features/account/    profile, sessions list/revoke, MFA enrol/disable (re-auth), data export/delete (retention)
src/features/admin/      user management (create/invite/disable/delete/reset MFA/revoke sessions), audit log viewer, AI usage + kill switch
src/features/_example/   reference "notes" feature: registry routes, strict schemas, owner checks, DTOs, quota, 2-step flow, transaction
src/features/uploads/    (uploads) §1.10
src/features/ai/         (ai) §1.11
src/features/apikeys/    (public-api) API keys for /api/v1 (§1.12)
src/features/payments/   (payments) placeholder checkout page + provider setup guide (never card data)
src/views/               layouts/base.ejs (nonce helper, logout form on authenticated pages), partials, feature views
public/                  css/app.css, js/app.js (no inline scripts; no third-party CDN)
tests/                   node:test suites (§1.13) — tests/security/** are protected paths
docs/                    generated by docs:build (§1.14) + SECURITY.md, incident-response.md, data-retention.md, deployment.md, adr/
scripts/                 setup.ts, gen-secrets.ts, bootstrap-admin.ts, routes-export.ts, docs-build.ts, audit-verify.ts, rotate-field-key.ts, preflight.mjs
securevibe.manifest.json §1.15
securevibe.provenance.json  written by SecureVibe after generation (read-only to the agent)
routes.manifest.json     written by `routes:export` (and by the agent — validated against the live router by DAST)
.env.example, .env (written by SecureVibe scaffold via gen-secrets), .gitignore, README.md, FIRST-LOGIN.txt (one-time admin password)
```

### 1.3 Environment (config.ts)

| Variable | Default | Notes |
|---|---|---|
| `NODE_ENV` | `production` | `test` enables test mode only together with `SECUREVIBE_TEST_MODE=1` |
| `PORT` | `3000` | `0` = ephemeral (ready line reports the actual port) |
| `BIND_LAN` | `0` | `1` binds 0.0.0.0 (local-network deployments) |
| `TLS_MODE` | `off` | `off` \| `selfsigned` (uses `certs/`) \| `proxy` (behind TLS reverse proxy; sets Secure cookies + HSTS) |
| `TRUST_PROXY_HOPS` | `0` | `app.set('trust proxy', n)` |
| `DATA_DIR` | `./data` | SQLite db, uploads, outbox; created 0700 |
| `SESSION_SECRET` | — | ≥ 32 bytes base64; used to HMAC session ids at rest |
| `FIELD_KEYS` | — | `1:<base64 32 bytes>[,2:...]`; `ACTIVE_FIELD_KEY` selects the id |
| `TOKEN_HMAC_KEY` | — | ≥ 32 bytes; reset tokens / API keys hashing |
| `SESSION_IDLE_MINUTES` / `SESSION_ABSOLUTE_HOURS` / `SESSION_MAX_CONCURRENT` | 30 / 12 / 5 (L2: 15 / 8 / 5) | documented in docs/sessions.md |
| `ADMIN_MFA_REQUIRED` | `1` | admins must enrol TOTP on first login |
| `USER_MFA_AVAILABLE` | `1` | every user may enrol TOTP |
| `RATE_LIMIT_*` | §1.8 | overrides |
| `OUTBOUND_ALLOWED_HOSTS` | `` | comma-separated `host[:port]`; empty = deny all |
| `UPLOAD_MAX_BYTES` / `UPLOAD_ALLOWED_TYPES` / `UPLOAD_USER_QUOTA_BYTES` | 10485760 / `image/png,image/jpeg,image/gif,image/webp,application/pdf` / 209715200 | |
| `AI_ENABLED` / `AI_MODEL` / `AI_MAX_INPUT_CHARS` / `AI_MAX_OUTPUT_TOKENS` / `AI_USER_DAILY_TOKENS` / `AI_MODERATION` | `1` / `claude-opus-5` / 8000 / 1024 / 200000 / `0` | `ANTHROPIC_API_KEY` from env only, never logged |
| `EXAMPLE_FEATURE` | `0` | `1` mounts src/features/_example (flagged by config scanner in production) |
| `LOG_LEVEL` / `LOG_FILE` / `AUDIT_RETENTION_DAYS` | `info` / `DATA_DIR/app.log` / 400 | |
| `RETENTION_MONTHS` | unset | when set, retention job deletes/pseudonymises per docs/data-retention.md |
| `SECUREVIBE_TEST_MODE` | unset | `1` + `NODE_ENV=test` enables §1.16; refused in production |

Config validation fails fast with a plain-language message naming the variable. `SESSION_SECRET`, `FIELD_KEYS`,
`TOKEN_HMAC_KEY` must not equal the `.env.example` placeholders and must decode to ≥ 32 bytes.

### 1.4 Route registry (`src/security/routes.ts`)

```ts
export type Auth = 'public' | 'user' | `role:${string}`;
export interface RouteSpec<P = unknown, Q = unknown, B = unknown> {
  method: 'GET'|'POST'|'PUT'|'PATCH'|'DELETE';
  path: string;                       // express path
  auth: Auth;                         // deny-by-default: no route without an explicit auth value
  roles?: string[];                   // additional allowed roles when auth is 'user' (admin always allowed)
  owner?: { entity: string; param: string; ownerField?: string };  // requireOwner: loads row by :param and checks ownerField === user.id (admins bypass)
  schema?: { params?: ZodType<P>; query?: ZodType<Q>; body?: ZodType<B> };  // strict objects; body required for POST/PUT/PATCH
  csrf?: boolean;                     // default true for state-changing methods with session auth; false for API-key routes
  rateLimit?: RateLimitPreset;        // default 'general'
  idempotent?: boolean;               // when true on a JSON API mutation, Idempotency-Key header is honoured (stored response replay)
  summary?: string;                   // for docs/api.md + openapi.json
  entity?: string;                    // entity name (for docs + DAST IDOR probes)
  kind?: 'page' | 'api';              // pages render EJS; api returns JSON. Default from path prefix (/api → api)
}
export function defineRoute(router: Router, spec: RouteSpec, handler: (req, res) => Promise<void> | void): void;
export function listRoutes(): RouteSpec[];      // used by routes:export, docs:build, test mode endpoint
export function assertAllRoutesRegistered(app): void;  // startup: throws if app.router has a route not created via defineRoute
```

Handlers receive `req.valid = { params, query, body }` (validated), `req.user` (or undefined), `req.session`,
`res.locals.nonce`, `res.locals.csrfToken`. Validation failures → 400 `{error:{code:'validation_error', message, fields}}`
(API) or re-render with errors (pages). Unknown fields → 400. Arrays where scalars expected → 400.

`routes.manifest.json` (written by `routes:export`, also produced by the generation agent for generated routes):
`[{ method, path, auth, roles, owner, entity, kind, csrf }]`.

### 1.5 Headers

CSP (exact, per request nonce `{n}`):
`default-src 'self'; script-src 'nonce-{n}' 'strict-dynamic'; style-src 'self' 'nonce-{n}'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests` (last directive only in TLS modes).
Also: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`,
`Permissions-Policy: camera=(), microphone=(), geolocation=()`, `Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`. TLS modes add
`Strict-Transport-Security: max-age=31536000; includeSubDomains`. No CORS middleware; `Origin` is never reflected.
Authenticated responses: `Cache-Control: no-store, private`. Logout: `Clear-Site-Data: "cookies", "storage"`.
Every response with a body has `Content-Type` with `charset=utf-8`. `TRACE` → 405. `/healthz` → `{"status":"ok"}` only;
`/readyz` → loopback-only unless `BIND_LAN`, returns `{"status":"ready"}` or 503.

### 1.6 Sessions

Cookie name `sid` (`__Host-sid` in TLS modes) with `HttpOnly; SameSite=Strict; Path=/` (+ `Secure` in TLS modes).
Session id = 32 random bytes base64url; stored as `HMAC-SHA256(SESSION_SECRET, id)` in `sessions(id_hash, user_id,
created_at, last_seen_at, expires_at, ip, ua_hash, mfa_verified, revoked_at)`. Rolling idle timeout + absolute lifetime
from config. Regenerated on login and on MFA verification (old id revoked). Max concurrent sessions per user (oldest
revoked). `revokeAllForUser(userId, exceptCurrent?)` called on disable/delete/password change (when "log out everywhere"
chosen)/admin action. `/account/sessions` lists (created, last seen, ip, current) and revokes. Sensitive account changes
(email, MFA settings) require `reauth` within 5 minutes (password + TOTP when enrolled).

### 1.7 Password policy (`src/security/password.ts`)

`MIN_LENGTH = 12`, `MAX_LENGTH = 256`, no composition rules, exact verification (no trim/normalisation),
common-password check against `data/common-passwords.txt` (top 100k from SecureVibe's knowledge base, lowercase
exact match) and context words (app name, user email local-part, user name; case-insensitive substring ≥ 4 chars).
Hash: PHC string. argon2id `m=65536,t=3,p=4` via `crypto.argon2` when present; otherwise scrypt `N=131072,r=8,p=1,
keylen=64`; verify supports both; startup logs which algorithm is active and refuses to start if a stored hash uses an
algorithm unavailable at runtime. Password reset: 16-byte token (base64url) sent by mailer (or written to outbox),
stored as `HMAC-SHA256(TOKEN_HMAC_KEY, token)`, 15-minute expiry, single use; response identical whether or not the
account exists; TOTP still required after reset when enrolled. Login: constant-time dummy verification for unknown users.
Admin bootstrap (`scripts/bootstrap-admin.ts`): random 16-byte password shown once (FIRST-LOGIN.txt), `must_change_password=1`,
expires in 24h if unused. No default accounts exist otherwise.

### 1.8 Rate limits (`src/security/rate-limit.ts`)

| Preset | Limit | Key |
|---|---|---|
| `general` | 300 / min | ip |
| `login` | 5 / 15 min per account + 20 / 15 min per ip, exponential backoff, temporary soft lock (never permanent) | account+ip |
| `mfa` | 5 / 15 min | account |
| `registration` | 3 / hour | ip |
| `reset` | 3 / hour per account, 10 / hour per ip | account+ip |
| `ai` | 20 / hour + daily token budget | user |
| `uploads` | 20 / hour | user |
| `api-key` | 120 / min | key |

429 responses carry `Retry-After`. Hits emit `ratelimit.hit`. In test mode `general` is raised to 100 000 / min; the
others keep their values (the harness probes them last).

### 1.9 Security events (`src/security/events.ts`) — catalog

`auth.login.success{factor:'password'|'password+totp'}`, `auth.login.failure{reason}`, `auth.logout`,
`auth.password.changed`, `auth.password.reset.requested`, `auth.password.reset.completed`, `auth.mfa.enrolled`,
`auth.mfa.disabled`, `auth.mfa.failure`, `auth.reauth.success`, `auth.reauth.failure`, `auth.lockout`,
`authz.denied{route,userId,resourceId?}`, `session.revoked{count,reason}`, `validation.rejected{route,field}`,
`csrf.rejected{route}`, `ratelimit.hit{bucket}`, `upload.rejected{reason}`, `upload.stored`, `download.denied`,
`admin.user.created|disabled|deleted|mfa_reset|sessions_revoked`, `data.exported`, `data.deleted`,
`ai.request{model,provider,operation,inputTokens,outputTokens,promptHash,responseHash}`, `ai.input.flagged{rule}`,
`ai.input.rejected{reason}`, `ai.output.rejected{reason}`, `ai.moderation.decision`, `ai.budget.exceeded`,
`ai.killswitch.toggled`, `outbound.blocked{host}`, `outbound.failure{host}`, `breaker.open{host}`, `error.unhandled{reqId}`,
`config.startup{algorithm,tlsMode}`.
Each event: `{ts (UTC ISO), event, reqId, userId?, ip, route?, outcome:'success'|'failure'|'blocked', ...fields}`
written via pino (JSON lines) AND to the `audit_log` table (hash chain: `prev_hash`, `hash = sha256(prev_hash + canonical row)`).
Redaction paths: `password*`, `*token*`, `authorization`, `cookie`, `set-cookie`, `totp*`, `*secret*`, `*apiKey*`,
`*api_key*`, field values of entity fields marked `sensitive`. Session ids appear only as first 8 chars of their hash.

### 1.10 Uploads feature

`busboy` streaming with `limits {fileSize: UPLOAD_MAX_BYTES, files: 1, fields: 20}`; abort with 413 when exceeded;
sniff first 16 bytes against a bundled magic table; require sniffed type ∈ allow-list AND extension ∈ type's extensions
AND declared `Content-Type` consistent (else 415); never svg/html/xml/zip; store as `DATA_DIR/uploads/<uuid>` mode 0600
with DB row `{id, owner_id, original_name (sanitised, ≤ 120 chars), mime, size, sha256, created_at}`; per-user quota
(count + bytes) checked in a transaction. Download route: owner/admin check via registry `owner`, `Content-Type` from DB,
`Content-Disposition: attachment; filename="<ascii>"; filename*=UTF-8''<pct>`, `X-Content-Type-Options: nosniff`,
`Content-Security-Policy: sandbox`, `Cache-Control: private, no-store`. `docs/uploads.md` generated from config.

### 1.11 AI feature (`src/features/ai/`)

Pipeline per request: (1) normalise NFKC, strip Unicode Cc/Cf/Co/Cs except `\n\t`; reject if any control chars remain
or input contains reserved sequences (`<|`, `|>`, `[INST]`, `<<SYS>>`) after escaping them as literals; reject base64/hex
runs > 200 chars; reject length > `AI_MAX_INPUT_CHARS` with 422 (never truncate); (2) screen with
`data/knowledge/injection-patterns.json` (high-precision list → block + `ai.input.rejected`; medium list → `ai.input.flagged`
and continue); (3) assemble context: system prompt (hash-pinned constant) with instruction hierarchy; app data fetched
only through repository functions scoped to `req.user` (`dataItCanSee`), wrapped in `<untrusted_data>` blocks, screened
with the same ruleset; conversation history (when `storesHistory`) from `ai_conversations` scoped to user, resettable
(`POST /ai/reset`); (4) call Anthropic SDK with `max_tokens = AI_MAX_OUTPUT_TOKENS`, structured output
`{ answer: string(≤ 4000), refused: boolean, reason?: string }`, `stop_reason` checked (`refusal` → fixed fallback message);
(5) output: schema-validate (reject → fallback), n-gram overlap check vs system prompt (≥ 12 consecutive tokens → block,
`ai.output.rejected{reason:'system-prompt-disclosure'}`), post-inference filter removes any id/email of records the user
may not access, render as text (EJS escaped, no markdown-to-HTML, no auto-link); (6) log `ai.request` + insert into
`ai_interactions(id, user_id, session_hash, model, provider, operation, input_tokens, output_tokens, prompt_hash,
response_hash, injection_flagged, filter_decision, created_at)`; per-user/session/endpoint counters in `ai_usage`;
daily budget → 429 `ai.budget.exceeded`. Kill switch: `AI_ENABLED=0` or admin runtime toggle (`settings.ai_enabled`)
checked per request → 503 with a plain message; toggles logged. When `aiModeration`: a separate classification call
(`{categories:{violence,self_harm,hate,sexual}: 0-1}`) on input and output, thresholds in config, decisions logged.
`aiActions`: tools are a fixed allow-list defined in `src/features/ai/tools.ts` (each with zod input/output schemas);
mutating tools return a proposal that the user must confirm in the UI (`POST /ai/confirm/:proposalId`, CSRF) before the
app executes it through the normal repository functions with `req.user` authorization — the model never executes anything.
`docs/ai.md` generated (model inventory, data access, limits).

### 1.12 API keys feature (`src/features/apikeys/`)

Format `sk_<8 char prefix>_<32 bytes base64url>`; stored `{prefix, hash = HMAC-SHA256(TOKEN_HMAC_KEY, key), user_id,
scopes[], created_at, last_used_at, revoked_at}`; sent only as `Authorization: Bearer`; query-string keys → 400;
scoped to routes tagged `kind:'api'` with `auth:'user'`; per-key rate limit; admin/user UI to create/revoke. Not a session.

### 1.13 Tests (`tests/`)

`node:test` + `fetch` against the app started in-process on an ephemeral port with a throw-away `DATA_DIR`. Test names
must contain the requirement id they evidence, e.g. `test('V6.2.1 rejects passwords shorter than 12 characters', …)`.
Files: `tests/security/headers.test.ts`, `csrf.test.ts`, `session.test.ts`, `password.test.ts`, `mfa.test.ts`,
`authz.test.ts`, `validation.test.ts`, `errors.test.ts`, `logging.test.ts`, `crypto.test.ts`, `rate-limit.test.ts`,
`uploads.test.ts`, `ai.test.ts`, `apikeys.test.ts`, `outbound.test.ts`, `db.test.ts`, `dto.test.ts`, `redirect.test.ts`;
`tests/features/<generated>.test.ts` (written by the generator). The runner emits TAP (`--test-reporter=tap`) which
SecureVibe parses into `{name, ok, file}`.

### 1.14 Generated docs (`docs:build`)

| File | Source of truth | Credits |
|---|---|---|
| `docs/authorization.md` | route registry | V8.1.1, V8.1.2 |
| `docs/validation.md` | route schemas (zod → JSON schema) | V2.1.1, V2.1.3 |
| `docs/sessions.md` | session constants | V7.1.1, V7.1.2 |
| `docs/SECURITY.md` (anti-automation, contact, disclosure) | rate-limit presets + profile owner | V6.1.1, V6.1.3, MT-06 (partial) |
| `docs/crypto.md` | `crypto-inventory.json` | V11.1.1, V11.1.2 |
| `docs/logging.md` | event catalog + logger config | V16.1.1, V16.2.3 |
| `docs/communications.md` | `OUTBOUND_ALLOWED_HOSTS` + http-client | V13.1.1 |
| `docs/uploads.md` | upload config | V5.1.1 |
| `docs/data-protection.md` | profile data classification + entity `sensitive` fields + retention | V14.1.1, V14.1.2, DM-01, DM-05 |
| `docs/dependencies.md` | package-lock + remediation SLA table (critical 7d, high 30d, medium 90d) | V15.1.1, V15.1.2 |
| `docs/api.md` + `docs/openapi.json` | route registry | AS-05, MT-05 |
| `docs/ai.md` | AI config + tools | C3.1.1, C6.2.1 (partial) |
| `docs/deployment.md`, `docs/incident-response.md`, `docs/data-retention.md`, `docs/adr/*.md` | design artifacts | MT-06, DM-05, ADRs |

The manifest check `doc-generated` regenerates the doc in memory and compares hashes. SecureVibe itself re-runs
`routes-export` and `docs:build` (`refreshDerivedFiles`) after the CRUD expander, after generation and after every fix
round, and records the fresh `docs/**` hashes in provenance (the agent can never write `docs/**`), so the docs always
describe the code being assessed; the fix loop's protected-file regression check ignores `docs/**` for that reason.

### 1.15 Manifest (`securevibe.manifest.json`) — control inventory

Fields per control follow `TemplateControlSchema`. Every mapping carries `proves`. `file-contains` may only appear
alongside a `test`/`dast`/`ast`/`config-value`/`doc-generated` check. Feature ids: `auth`, `admin-mfa`, `user-mfa`,
`uploads`, `ai`, `ai-actions`, `ai-moderation`, `ai-history`, `email`, `scheduler`, `public-api`, `payments`,
`field-encryption`, `retention`, `external-apis`, `example`.

| Control | Title | Requires | Proves (ids) | Checks |
|---|---|---|---|---|
| TPL-HEADERS-01 | Nonce-based CSP with the exact §1.5 policy | — | V3.4.3, V3.4.6 | dast.headers.csp, ast.helmet-csp-configured, test "V3.4.3" |
| TPL-HEADERS-02 | nosniff, Referrer-Policy, Permissions-Policy, COOP/CORP | — | V3.4.4, V3.4.5 | dast.headers.nosniff, dast.headers.referrer-policy |
| TPL-HEADERS-03 | HSTS ≥ 1 year (TLS modes) | tlsModes selfsigned/proxy | V3.4.1 | dast.headers.hsts |
| TPL-HEADERS-04 | Content-Type with charset on every response | — | V4.1.1 | dast.headers.content-type-charset |
| TPL-HEADERS-05 | No CORS; Origin never reflected | — | V3.4.2 | dast.cors.origin-not-reflected |
| TPL-CACHE-01 | no-store on authenticated responses | auth | V14.3.2 | dast.cache.no-store-authenticated |
| TPL-COOKIE-01 | Session cookie HttpOnly + SameSite=Strict; token only in cookie | auth | V3.3.2, V3.3.4 | dast.cookie.session-attributes |
| TPL-COOKIE-02 | Secure + __Host- prefix (TLS modes) | auth; tlsModes selfsigned/proxy | V3.3.1, V3.3.3 | dast.cookie.secure-host-prefix |
| TPL-TLS-01 | TLS 1.2+ only, modern ciphers (selfsigned mode) | tlsModes selfsigned | V12.1.1, V12.1.2 | dast.tls.min-version |
| TPL-CSRF-01 | Synchronizer token + Origin/Sec-Fetch-Site on state-changing routes; no GET mutations | auth | V3.5.1, V3.5.3 | dast.csrf.missing-token-rejected, dast.csrf.cross-origin-rejected, dast.csrf.get-does-not-mutate, test "V3.5.1" |
| TPL-CLEAR-01 | Clear-Site-Data on logout | auth | V14.3.1 | dast.session.logout-clear-site-data |
| TPL-STATIC-01 | dotfiles denied, no directory listing, no .git/.env served | — | V13.4.1, V13.4.3 | dast.leak.dotfiles, dast.leak.directory-listing |
| TPL-METHOD-01 | TRACE not supported | — | V13.4.4 | dast.leak.trace |
| TPL-HEALTH-01 | Health endpoints minimal; readiness loopback-only | — | V13.4.5 | dast.leak.health-minimal |
| TPL-ERRORS-01 | Generic error model, no stack/SQL, correct status, fail-closed | — | V16.5.1, V16.5.3 | dast.errors.no-stack-trace, dast.errors.404-generic, dast.errors.500-generic, test "V16.5.1" |
| TPL-BODY-01 | Body limits, simple query parser, parameter-pollution and prototype-pollution rejection | — | V15.3.6, V15.3.7 | dast.input.oversized-body, dast.input.duplicate-param, dast.input.proto-pollution |
| TPL-VALIDATION-01 | Registry-enforced strict zod schemas server-side; unknown fields rejected; type-strict | — | V2.2.1, V2.2.2, V15.3.3, V15.3.5 | dast.input.unknown-field, dast.input.type-confusion, ast.routes-have-schemas, test "V2.2.1" |
| TPL-VALIDATION-02 | docs/validation.md from schemas | — | V2.1.1 (doc), V2.1.3 (doc) | doc-generated docs/validation.md |
| TPL-DTO-01 | Serializers; raw rows never returned; field-level shaping | — | V15.3.1, V8.2.3 | sast-clean [sast.res-raw-db-row], test "V15.3.1" |
| TPL-AUTHZ-01 | Deny-by-default registry; anonymous and wrong role denied server-side | auth | V8.2.1, V8.3.1 | dast.authz.anonymous-denied, dast.authz.wrong-role-denied, ast.all-routes-registered, test "V8.2.1" |
| TPL-AUTHZ-02 | Ownership enforced for owner-scoped entities (IDOR) | auth | V8.2.2 | dast.authz.non-owner-denied, test "V8.2.2" |
| TPL-AUTHZ-03 | docs/authorization.md from registry | auth | V8.1.1 (doc), V8.1.2 (doc) | doc-generated docs/authorization.md |
| TPL-AUTH-01 | Password policy (§1.7) | auth | V6.2.1, V6.2.4, V6.2.5, V6.2.8, V6.2.9, V6.2.11, V6.1.2 (doc) | test "V6.2.1", "V6.2.4", "V6.2.5", "V6.2.8", "V6.2.9", "V6.2.11", dast.auth.weak-password-rejected |
| TPL-AUTH-02 | Change password requires current password | auth | V6.2.2, V6.2.3 | test "V6.2.3" |
| TPL-AUTH-03 | type=password fields, paste allowed | auth | V6.2.6, V6.2.7 | dast.auth.password-field-type |
| TPL-AUTH-04 | KDF parameters (argon2id/scrypt) | auth | V11.4.2, V11.4.4 | test "V11.4.2" |
| TPL-AUTH-05 | Login anti-automation: per-account+ip limits, backoff, soft lock, uniform responses, dummy hash | auth | V6.3.1, V2.4.1 (partial) | dast.auth.login-rate-limited, dast.auth.uniform-unknown-user, test "V6.3.1" |
| TPL-AUTH-06 | No default accounts; bootstrap admin random one-time password, must change, 24h expiry | auth | V6.3.2, V6.4.1 | test "V6.3.2", "V6.4.1", config.no-default-admin |
| TPL-AUTH-07 | No password hints or secret questions | auth | V6.4.2 | sast-clean [sast.secret-question-field], test "V6.4.2" |
| TPL-AUTH-08 | Password reset: CSPRNG 128-bit token hashed at rest, 15 min, single use, uniform response, MFA still required | auth | V6.4.3, V11.5.1, V6.5.1 (partial) | test "V6.4.3", "V11.5.1", dast.auth.reset-uniform-response |
| TPL-AUTH-09 | docs/SECURITY.md anti-automation section from presets | auth | V6.1.1 (doc), V6.1.3 (doc) | doc-generated docs/SECURITY.md |
| TPL-AUTH-10 | No forced password rotation | auth | V6.2.10 | test "V6.2.10" |
| TPL-MFA-01 | TOTP RFC 6238, CSPRNG 20-byte seed stored encrypted, 30s step ±1, replay prevention | admin-mfa | V6.5.1, V6.5.3, V6.5.5 | test "V6.5.1", "V6.5.3", "V6.5.5" |
| TPL-MFA-02 | Recovery codes: 10 × 10 base32 chars, hashed, single-use | admin-mfa | V6.5.2, V6.5.4 | test "V6.5.2", "V6.5.4" |
| TPL-MFA-03 | MFA verification rate limited | admin-mfa | V6.6.3 | dast.auth.mfa-rate-limited |
| TPL-MFA-04 | TOTP enforced for admins; available to all users (L2) | admin-mfa | V6.3.3 (partial), V6.4.4 (partial: admin reset with logged reason) | test "V6.3.3", dast.auth.admin-mfa-enforced |
| TPL-SESSION-01 | 256-bit CSPRNG reference sessions, verified server-side, stored hashed | auth | V7.2.1, V7.2.2, V7.2.3 | test "V7.2.3", dast.session.id-format |
| TPL-SESSION-02 | New session id on login; old id invalid | auth | V7.2.4 | dast.session.rotated-on-login |
| TPL-SESSION-03 | Idle + absolute timeouts from config; documented | auth | V7.3.1, V7.3.2, V7.1.1 (doc) | test "V7.3.1", "V7.3.2", config.session-policy, doc-generated docs/sessions.md |
| TPL-SESSION-04 | Logout invalidates server-side | auth | V7.4.1 | dast.session.reuse-after-logout-denied |
| TPL-SESSION-05 | Disable/delete terminates all sessions | auth | V7.4.2 | test "V7.4.2" |
| TPL-SESSION-06 | "Log out everywhere" on factor change; admin revoke | auth | V7.4.3, V7.4.5 | test "V7.4.3", "V7.4.5" |
| TPL-SESSION-07 | Logout visible on every authenticated page | auth | V7.4.4 | dast.session.logout-visible |
| TPL-SESSION-08 | Re-authentication before email/MFA changes; sessions list/revoke | auth | V7.5.1, V7.5.2 | test "V7.5.1", "V7.5.2" |
| TPL-SESSION-09 | Concurrent session cap | auth | V7.1.2 (doc + enforced) | test "V7.1.2" |
| TPL-DB-01 | Parameterised queries only, through the db wrapper | — | V1.2.4 | sast-clean [sast.sql-string-concat, sast.db-raw-outside-wrapper], ast.db-wrapper-only |
| TPL-DB-02 | Pragmas (WAL, foreign_keys, busy_timeout, secure_delete), 0600 files, transactions helper, LIMIT on lists | — | V2.3.3, V16.4.2 (partial) | test "V2.3.3", test "V16.4.2" |
| TPL-CRYPTO-01 | Field encryption AES-256-GCM, versioned keys, AAD, rotation | field-encryption | V11.3.1, V11.3.2, V11.3.3, V11.2.2, V11.2.3 | test "V11.3.2", "V11.3.3", "V11.2.2" |
| TPL-CRYPTO-02 | Only node:crypto primitives; no MD5/SHA-1 in security contexts | — | V11.2.1, V11.4.1 | sast-clean [sast.weak-hash-security-context, sast.crypto-createcipher, sast.math-random-security], ast.node-crypto-only |
| TPL-CRYPTO-03 | crypto-inventory.json → docs/crypto.md | — | V11.1.1 (doc), V11.1.2 (doc) | doc-generated docs/crypto.md |
| TPL-SECRETS-01 | Secrets from env only; validated strength; placeholders refused; gen-secrets | — | V13.2.3, V13.3.2 (partial) | config.secrets-strength, test "V13.2.3" |
| TPL-LOG-01 | Structured JSON logs with UTC ts, reqId, userId, route, outcome | — | V16.2.1, V16.2.2, V16.2.4 | test "V16.2.1" |
| TPL-LOG-02 | Redaction; hashed session ids; no secrets in logs | — | V16.2.5 | test "V16.2.5", sast-clean [sast.log-sensitive-field] |
| TPL-LOG-03 | Security events for auth, authz denials, validation/anti-automation bypass attempts, unexpected errors | — | V16.3.1, V16.3.2, V16.3.3, V16.3.4 | test "V16.3.1", dast.log.login-failure-logged, dast.log.authz-denial-logged, dast.log.validation-rejected-logged |
| TPL-LOG-04 | Log injection prevented (JSON encoding) | — | V16.4.1 | test "V16.4.1" |
| TPL-LOG-05 | Append-only hash-chained audit table, verify command, retention setting, pseudonymisation on delete | — | V16.4.2 (partial), MT-07 (partial), MT-01 | test "V16.4.2 audit chain", test "MT-07" |
| TPL-LOG-06 | docs/logging.md from catalog | — | V16.1.1 (doc), V16.2.3 (doc) | doc-generated docs/logging.md |
| TPL-RATE-01 | Anti-automation on registration, reset, AI, uploads, general | auth | V2.4.1 | dast.rate.registration-limited, dast.rate.reset-limited, test "V2.4.1" |
| TPL-PROXY-01 | Client IP from configured proxy hops only; XFF ignored by default | — | V4.1.3, V15.3.4 | dast.rate.xff-spoof-ignored, config.trust-proxy-hops |
| TPL-OUTBOUND-01 | Outbound allow-list, manual redirects, timeouts, cert validation, breaker | external-apis \| ai \| email | V1.3.6, V13.2.4, V13.2.5, V15.3.2, V12.3.2, V16.5.2 | sast-clean [sast.fetch-outside-http-client, sast.tls-reject-unauthorized-false], test "V13.2.4", "V15.3.2", "V16.5.2" |
| TPL-OUTBOUND-02 | docs/communications.md | external-apis \| ai \| email | V13.1.1 (doc) | doc-generated docs/communications.md |
| TPL-REDIRECT-01 | Redirects only to allow-listed local paths | — | V3.7.2, V1.2.2 (partial) | dast.redirect.open-redirect-blocked, test "V3.7.2" |
| TPL-VIEWS-01 | EJS auto-escaping; no unescaped user data; no inline scripts; nonce | — | V1.2.1, V1.1.2, V3.2.2 | sast-clean [sast.ejs-unescaped-output, sast.inline-script-in-view], dast.xss.reflected-smoke |
| TPL-VIEWS-02 | No eval / Function / vm | — | V1.3.2 | sast-clean [sast.eval-usage, sast.new-function, sast.vm-module] |
| TPL-UPLOAD-01 | Streaming size cap, abort at limit | uploads | V5.2.1 | dast.upload.oversize-413, test "V5.2.1" |
| TPL-UPLOAD-02 | Magic-byte + extension + declared type allow-list; svg/html/xml/zip refused | uploads | V5.2.2, V1.3.4 | dast.upload.type-mismatch-415, dast.upload.svg-refused, test "V5.2.2" |
| TPL-UPLOAD-03 | Random names, outside web root, 0600, never user paths | uploads | V5.3.1, V5.3.2 | test "V5.3.2", dast.upload.not-served-from-public |
| TPL-UPLOAD-04 | Download headers (attachment, RFC 6266, nosniff, sandbox), type from DB | uploads | V5.4.1, V5.4.2, V3.2.1 | dast.upload.download-headers, test "V5.4.2" |
| TPL-UPLOAD-05 | Ownership on download; per-user quota | uploads | V8.2.2 (partial), V2.3.2 (partial) | dast.upload.non-owner-denied, test "V2.3.2 upload quota" |
| TPL-UPLOAD-06 | docs/uploads.md | uploads | V5.1.1 (doc) | doc-generated docs/uploads.md |
| TPL-AI-01 | Input normalisation, control-char/allow-list, reserved-token escaping | ai | C2.1.1, C2.1.5, C2.1.7 | test "C2.1.1", "C2.1.5", "C2.1.7", dast.ai.control-chars-rejected |
| TPL-AI-02 | Encoding smuggling and length rejection (422, no truncation) | ai | C2.1.2, C2.1.4 | test "C2.1.2", "C2.1.4", dast.ai.oversized-input-422 |
| TPL-AI-03 | Injection ruleset: block + event | ai | C2.1.3, C12.2.1 | test "C2.1.3", dast.ai.injection-blocked-and-logged |
| TPL-AI-04 | Instruction hierarchy; untrusted data wrapping; user-scoped data access | ai | C2.1.6, C5.2.1, C5.2.4 (partial), C9.5.3 | test "C2.1.6", "C5.2.1", ast.ai-context-user-scoped |
| TPL-AI-05 | Output schema + length bound + fallback; system-prompt disclosure filter; no outbound from output; text-only render | ai | C7.1.1, C7.1.2, C7.3.2, C7.3.3 | test "C7.1.1", "C7.1.2", "C7.3.2", sast-clean [sast.ai-output-rendered-unescaped], dast.ai.output-escaped |
| TPL-AI-06 | Interaction logging schema; per user/session/endpoint token attribution; budget | ai | C12.1.1, C12.1.2, C12.1.3, C12.2.5, C9.1.2, C11.2.2 | test "C12.1.1", "C12.1.3", "C12.2.5", "C9.1.2" |
| TPL-AI-07 | Kill switch (env + admin runtime toggle), logged | ai | C9.6.1, C12.4.3 | test "C9.6.1", dast.ai.killswitch-503 |
| TPL-AI-08 | API key never in model context; model pinned + inventory doc | ai | C9.5.4, C3.1.1, C6.1.2 | sast-clean [sast.ai-api-key-in-prompt], doc-generated docs/ai.md |
| TPL-AI-09 | Conversation memory scoped to user and resettable | ai-history | C8.1.3, C8.3.2 | test "C8.3.2" |
| TPL-AI-10 | Content moderation classifier on input and output | ai-moderation | C2.2.1, C7.3.1 | test "C2.2.1", "C7.3.1" |
| TPL-AI-ACTIONS-01 | Allow-listed schema-validated tools; human confirmation for mutations; authorization by app logic | ai-actions | C9.2.1, C9.3.2, C9.3.7, C9.5.1 | test "C9.2.1", "C9.3.2", dast.ai.action-requires-confirmation |
| TPL-EMAIL-01 | Mail header sanitisation; templates from disk only | email | V1.3.11 | test "V1.3.11" |
| TPL-SCHED-01 | Registry-declared jobs, lock, no user input in schedules | scheduler | V15.2.2 (partial), RR-01 | test "V15.2.2 scheduler" |
| TPL-APIKEY-01 | API keys §1.12 | public-api | V14.2.1, V8.2.1 (partial), V11.5.1 | dast.apikey.query-string-rejected, test "V14.2.1" |
| TPL-EXAMPLE-01 | Example feature disabled in production | — | V15.2.3 | config.example-feature-disabled |
| TPL-DEPS-01 | Lockfile, ignore-scripts, remediation SLA doc, SBOM | — | V15.1.1 (doc), V15.1.2, V15.2.1 (partial) | config.lockfile-present, config.ignore-scripts, doc-generated docs/dependencies.md, deps.sbom-generated |
| TPL-DATA-01 | Data classification doc with per-class controls and retention; retention job | — (retention for job) | V14.1.1 (doc), V14.1.2 (doc), V14.2.4 (partial), DM-01, DM-05 | doc-generated docs/data-protection.md, test "DM-05 retention job" (retention) |
| TPL-DATA-02 | No sensitive data in URLs; sensitive fields redacted | — | V14.2.1, V14.2.4 (partial) | sast-clean [sast.sensitive-in-get-param], test "V14.2.1" |
| TPL-RESILIENCE-01 | Request/header/keep-alive timeouts, health + readiness, graceful shutdown | — | RR-06, V15.2.2 (partial) | test "RR-06", dast.health.readyz |
| TPL-IDEMPOTENCY-01 | Idempotency-Key on JSON API mutations; unique constraints | — | RR-05, DM-03 | test "RR-05", dast.api.idempotency-key |
| TPL-CONTRACT-01 | docs/api.md + openapi.json from registry | — | AS-05, MT-05 | doc-generated docs/openapi.json |
| TPL-IR-01 | Incident response plan + security contact + deployment guide | — | MT-06 (partial), AC-06 (partial) | file-exists docs/incident-response.md, doc-generated docs/SECURITY.md |
| TPL-THEME-01 | Chosen theme changes colour only, from a closed list, and keeps WCAG AA contrast in light and dark | — | UX-01, AS-07 (partial: APP_THEME refused when unknown) | test "UX-01", test "AS-07 unknown theme" |
| TPL-TESTS-01 | Security test suite present and passing | — | MT-03, MT-04 | test "security suite" (meta: ≥ 1 test per file in tests/security) |
| TPL-TRUSTZONES-01 | Loopback bind by default; LAN/internet require explicit config; egress allow-list | — | AS-01, AC-01 (partial: loopback) | config.bind-loopback-default, test "AS-01" |

`protectedPaths` (agent may not write/delete): `src/app.ts`, `src/server.ts`, `src/config.ts`, `src/db/index.ts`,
`src/db/migrate.ts`, `src/db/field-crypto.ts`, `src/security/**`, `src/lib/**`, `src/features/auth/**`,
`src/features/account/**`, `src/features/admin/**`, `src/features/uploads/**`, `src/features/ai/**` (except
`src/features/ai/prompt.ts` and `tools.ts` which the agent may edit), `src/features/apikeys/**`, `src/views/layouts/**`,
`src/features/scheduler/**`, `src/features/payments/**`, `src/features/_example/**`,
`tests/security/**`, `securevibe.manifest.json`, `securevibe.provenance.json`, `package.json`, `package-lock.json`,
`.npmrc`, `tsconfig.json`, `.gitignore`, `.env*`, `scripts/**`, `docs/**` (regenerated), `public/js/app.js`.
`writablePaths`: `src/features/<generated>/**`, `src/features/index.ts` (registration list only; validated),
`src/views/<generated>/**`, `src/db/migrations/1??_*.sql` (numbers ≥ 100), `tests/features/**`, `public/css/**`,
`public/js/features/**`, `routes.manifest.json`, `README.md` (append-only section).
`allowedImports`: `express`, `zod`, `ejs`, `pino`, `node:*`, and the template's own modules; everything else → the agent
must not import it (SAST rule `sast.disallowed-import` + typecheck).

### 1.16 Test-bootstrap mode (DAST contract)

Enabled only with `NODE_ENV=test` **and** `SECUREVIBE_TEST_MODE=1` (config refuses it in production; the config
scanner flags `SECUREVIBE_TEST_MODE` in `.env`). Effects:
* Seeds users on startup (idempotent): `admin@test.local` (role admin, MFA enrolled with seed from
  `SECUREVIBE_TEST_TOTP_SEED` base32), `staff@test.local` (first non-admin role), `member@test.local`, `member2@test.local`
  (last role); all with password `SECUREVIBE_TEST_PASSWORD` (≥ 16 chars, provided by the harness).
* Seeds one record per entity owned by `member@test.local` (from the CRUD expander's `seed()` hook).
* `GET /__securevibe/routes` → `{ routes: (RouteSpec serialisable fields + bodySchema: JSON Schema | null)[], roles: string[], entities: [{name, ownerField, sample: {id}}] }`.
* `GET /__securevibe/events?since=<ISO>` → last 500 security events (for log-evidence probes).
* `POST /__securevibe/reset-rate-limits` → clears limiter state (used between probe groups).
* Prints exactly one line to stdout when listening: `{"securevibe":"listening","port":<n>,"pid":<pid>,"tlsMode":"off"}`.
* `general` rate limit raised to 100 000/min; `login`, `mfa`, `registration`, `reset`, `ai`, `uploads` unchanged.
These endpoints do not exist outside test mode (404) — a DAST probe (`dast.leak.test-endpoints-absent`) verifies this in
a second, production-mode start.

---

## 2. DAST probes (`server/src/scanners/dast/probes/*.ts`)

Harness: spawn app with `PORT=0`, `NODE_ENV=test`, `SECUREVIBE_TEST_MODE=1`, generated secrets, throw-away `DATA_DIR`,
under the Node permission model (§9.3); wait for the ready line (≤ 30 s); fetch `/__securevibe/routes`; log in each seeded
user with a cookie jar (handling the TOTP step for admin); run probe groups in order: headers → leak → errors → input →
csrf → session → authz (every non-public route: anonymous, wrong role, non-owner) → uploads → ai → redirect → xss → log
→ rate (last, with resets between) → then restart in production mode for `dast.leak.test-endpoints-absent`,
`dast.health.readyz`, cookie/HSTS checks in `proxy` mode with `TRUST_PROXY_HOPS=1` and `X-Forwarded-Proto: https`.
Kill the process group afterwards. Each probe returns `{ id, passed: boolean | null (not attempted), expected, observed,
requestExcerpt, responseExcerpt, requirementIds, findingOnFail: Partial<Finding> }`. A probe that could not run records
`passed: null` with a reason — never `true`.

Probe ids (all listed in §1.15 plus): `dast.leak.test-endpoints-absent`, `dast.health.healthz`, `dast.api.json-content-type`,
`dast.authz.unregistered-route` (a live route absent from `routes.manifest.json` → High finding `unknown authorization policy`),
`dast.session.cookie-not-in-url`, `dast.xss.stored-smoke` (creates a record with a payload as `member`, reads it back
as `member`, asserts escaped), `dast.input.sql-smoke` (`'` and `" OR 1=1--` in every string param → never 500),
`dast.input.path-traversal-smoke` (`../` in path params → 400/404), `dast.errors.method-not-allowed`,
`dast.ai.prompt-not-in-response` (asks the assistant to repeat its instructions; asserts overlap filter), `dast.upload.quota-enforced`.

---

## 3. SAST rules (`server/src/scanners/sast/rules/*.ts`)

Each rule: `{ id, title, severity, confidence, cwe[], asvs[], aisvs[], description, impact, remediation (from
data/knowledge/remediation.json), appliesTo: ['ts','ejs','react'] }`. Implementation uses the TypeScript compiler API
(`ts.createSourceFile`) for `.ts/.tsx` and a tokenizer for `.ejs`. Rules (severity):

`sast.eval-usage` (high), `sast.new-function` (high), `sast.vm-module` (high), `sast.child-process-exec` (high),
`sast.child-process-user-input` (critical), `sast.sql-string-concat` (critical), `sast.db-raw-outside-wrapper` (medium),
`sast.ejs-unescaped-output` (high: `<%-` with any expression that is not `nonce`/`csrfToken`/a `safeHtml(...)` call),
`sast.inline-script-in-view` (medium: `<script>` without `nonce="<%= nonce %>"`), `sast.inline-event-handler` (medium),
`sast.innerhtml-assignment` (high), `sast.document-write` (medium), `sast.dangerously-set-inner-html` (high, react),
`sast.href-from-data` (medium, react/js: `href={...}` from state without protocol check), `sast.postmessage-no-origin-check` (medium),
`sast.weak-hash-security-context` (medium: md5/sha1 with names like token/password/session), `sast.math-random-security` (high),
`sast.crypto-createcipher` (high), `sast.hardcoded-secret` (critical), `sast.tls-reject-unauthorized-false` (critical),
`sast.cors-wildcard-credentials` (high), `sast.cors-any-origin` (medium), `sast.cookie-missing-httponly` (medium),
`sast.cookie-missing-samesite` (low), `sast.helmet-disabled-csp` (high), `sast.unsafe-regex` (medium: nested quantifiers),
`sast.regex-from-user-input` (medium), `sast.path-join-user-input` (high), `sast.fs-user-path` (high),
`sast.open-redirect` (high: `res.redirect(req.*)`), `sast.res-raw-db-row` (medium: `res.json(row)`/`res.render` with a raw
db result variable), `sast.req-body-unvalidated` (medium: handler uses `req.body` outside `defineRoute` with schema),
`sast.route-outside-registry` (high: `app.get(`/`router.post(` etc. not via `defineRoute`), `sast.missing-authz-declaration`
(high: `defineRoute` without `auth`), `sast.fetch-outside-http-client` (medium), `sast.http-request-outside-client` (medium),
`sast.mailer-header-user-input` (high), `sast.object-assign-user-input` (medium: mass assignment), `sast.proto-pollution-merge` (medium),
`sast.log-sensitive-field` (medium), `sast.console-log` (low), `sast.default-secret-fallback` (high: `process.env.X || 'literal'`),
`sast.express-static-dotfiles-allow` (medium), `sast.trust-proxy-true` (medium), `sast.multiple-writes-no-transaction` (low),
`sast.timing-unsafe-compare` (medium: `===` on token/secret/hash), `sast.jwt-none-alg` (critical), `sast.secret-question-field` (medium),
`sast.password-composition-rule` (low), `sast.xml-external-entities` (high), `sast.deserialize-untrusted` (critical),
`sast.ai-output-rendered-unescaped` (high), `sast.ai-api-key-in-prompt` (critical), `sast.disallowed-import` (medium),
`sast.sensitive-in-get-param` (medium), `sast.protected-file-modified` (high: hash mismatch vs provenance),
`sast.todo-security` (info: `TODO`/`FIXME` mentioning auth/security). Findings carry `introducedBy` from provenance.

Named AST checks for manifests (`server/src/scanners/ast-checks.ts`): `helmet-csp-configured`, `routes-have-schemas`,
`all-routes-registered`, `db-wrapper-only`, `node-crypto-only`, `ai-context-user-scoped`. `routes-have-schemas`
accepts a POST/PUT/PATCH route without `schema.body` only when `src/security/routes.ts` validates a missing body
against `EMPTY = z.strictObject({})` (so such a route accepts no fields beyond the CSRF token).

ESLint runs `eslint-plugin-security` (recommended, with `detect-object-injection`, `detect-non-literal-fs-filename`
and `detect-non-literal-regexp` off because they flag nearly every line of typed code) via SecureVibe's own node_modules
against the app dir, ignoring `tests/**`, `**/*.test.*` and `scripts/**`; findings are de-duplicated against SAST by fingerprint (SAST wins).

---

## 4. Config checks (`config.*`), secrets (`secrets.*`), dependencies (`deps.*`)

Config: `config.env-example-present`, `config.gitignore-covers-env`, `config.secrets-strength` (values in `.env` decode
to ≥ 32 bytes and ≠ placeholders), `config.no-default-admin` (no `ADMIN_PASSWORD`-style vars; FIRST-LOGIN.txt marked
used or absent), `config.node-engine-pinned`, `config.lockfile-present`, `config.ignore-scripts`, `config.no-debug-flags`
(`NODE_ENV` not development, no `--inspect`), `config.example-feature-disabled`, `config.test-mode-not-in-env`,
`config.tls-mode-consistent` (proxy mode ⇒ `TRUST_PROXY_HOPS ≥ 1`; selfsigned ⇒ certs present), `config.trust-proxy-hops`,
`config.session-policy`, `config.protected-files-unchanged`, `config.provenance-present`, `config.bind-loopback-default`,
`config.security-md-present`, `config.readme-run-instructions`, `config.package-json-unmodified`.

Secrets: `secrets.anthropic-key` (`sk-ant-`), `secrets.aws-access-key`, `secrets.aws-secret-key`, `secrets.github-token`,
`secrets.slack-token`, `secrets.stripe-key`, `secrets.google-api-key`, `secrets.private-key-block`, `secrets.jwt`,
`secrets.high-entropy-assignment` (≥ 32 chars, Shannon entropy ≥ 4.0, assigned to secret-like names),
`secrets.password-assignment`, `secrets.connection-string-password`, `secrets.env-file-committed` (a `.env` next to a
`.git`). Scans everything except `node_modules`, `data`, `dist`, `.git`, `*.lock`, images; `.env` itself is scanned only
for placeholders (it is expected to contain generated secrets — reported as info with the file mode check).

Deps: `deps.vulnerability` (one per advisory from `npm audit --json`, any exit code; non-JSON → coverage `skipped`),
`deps.lockfile-missing`, `deps.install-scripts-present` (lockfile packages with `hasInstallScript`),
`deps.deprecated-package`, `deps.license-copyleft` (info), `deps.sbom-generated` (CycloneDX via `@cyclonedx/cyclonedx-npm`
or built-in fallback from package-lock). Offline: `npm audit` failure → coverage row `deps: skipped (offline)`, cached
result reused with `vulnDbAsOf` when the lockfile hash matches.

---

## 5. Patterns (`data/knowledge/patterns.json`)

`PAT-TRUST-ZONES` (always; AS-01), `PAT-DENY-BY-DEFAULT-ROUTES` (auth; AC-03), `PAT-LEAST-PRIVILEGE-ROLES` (auth; AC-03),
`PAT-SECURE-DEFAULT-HEADERS` (always), `PAT-CONTRACT-FIRST-VALIDATION` (always; AS-05), `PAT-FAIL-SECURE-ERRORS`
(always; RR-01), `PAT-OBSERVABILITY-EVENTS` (always; MT-01), `PAT-AUDIT-CHAIN` (always; MT-07), `PAT-IDEMPOTENT-MUTATIONS`
(always; RR-05, DM-03), `PAT-TIMEOUTS-HEALTH` (always; RR-06), `PAT-RATE-LIMITS` (always; RR-07), `PAT-SECRETS-FROM-ENV`
(always; AC-05), `PAT-DATA-CLASSIFICATION` (personal-data; DM-01), `PAT-FIELD-ENCRYPTION` (sensitive-data; DM-02),
`PAT-RETENTION` (personal-data; DM-05), `PAT-ADMIN-MFA` (auth; AC-02), `PAT-USER-MFA` (level2), `PAT-EGRESS-ALLOWLIST`
(external-apis/ai/email; AS-01), `PAT-UPLOAD-QUARANTINE` (uploads), `PAT-AI-GUARDRAILS` (ai), `PAT-AI-HUMAN-APPROVAL`
(ai-actions), `PAT-SBOM-PINNED-DEPS` (always; RR-01), `PAT-IR-PLAN` (always; MT-06), `PAT-TLS-PROXY` (internet/lan; AC-01, DM-02),
`PAT-API-KEYS` (public-api), `PAT-PROVIDER-HOSTED-PAYMENTS` (payments; AC-06), `PAT-SCHEDULED-JOBS-LOCKED` (scheduler; RR-03).

## 6. Security contract rules (`SC-*`, generated into `design/security-contract.md`)

SC-01 register every route with `defineRoute` and an explicit `auth`; SC-02 strict zod schemas for params/query/body;
SC-03 all DB access through `db.ts` helpers with parameters; SC-04 return DTOs, never raw rows; SC-05 owner checks via
registry `owner` for owner-scoped entities; SC-06 EJS `<%= %>` only for data; no inline scripts; scripts in
`public/js/features/` with nonce tag from layout; SC-07 no `eval`/`Function`/`child_process`/`vm`; SC-08 no new
dependencies; only `allowedImports`; SC-09 secrets/config only via `config`; SC-10 use `logger`/`events.emit`, never
`console.log`, never log sensitive fields; SC-11 outbound HTTP only via `http-client`; SC-12 uploads only via uploads
module; SC-13 AI only via ai module; SC-14 redirects only via `safeRedirect`; SC-15 multi-row writes in `withTransaction`;
SC-16 migrations numbered ≥ 100, additive, with `LIMIT` on list queries; SC-17 write `tests/features/<name>.test.ts`
with at least: anonymous denied, wrong role denied, validation rejects bad input, owner check; SC-18 emit
`routes.manifest.json` entries for every route; SC-19 sensitive entity fields use `encryptField`; SC-20 never touch
protected paths; SC-21 erasable TS syntax + `.ts` import extensions; SC-22 no sensitive data in GET params or URLs;
SC-23 per-user quotas for user-created records (as in `_example`); SC-24 sequential multi-step flows keep server-side
state; SC-25 generated code files start with the provenance header comment `// Generated by SecureVibe (AI-generated) — run <runId>`.

## 7. SbD checklist rules (`data/knowledge/sbd-rules.json`)

`severityIfNo` as in `data/frameworks/sbd-checklist-0.5.0.json` (businessImpact `high` raises `low→medium`, `medium→high`).
Outcomes (first matching `when` wins); "deploymentTimeStatus" is the status assuming internet deployment:

| Id | Outcome |
|---|---|
| AS-01 (C) | always **yes**: trust zones browser(untrusted) / app(trusted, loopback) / data(trusted, file perms) / vendor(external via egress allow-list); evidence TPL-TRUSTZONES-01, architecture. Deployment: yes if behind a TLS proxy (deferred note). |
| AS-02 | always **n-a**: single service, no discovery. |
| AS-03 | always **yes**: single service owns its data; feature modules; evidence architecture. |
| AS-04 | always **n-a**: no service chains. |
| AS-05 | always **yes**: route registry + openapi.json; evidence TPL-CONTRACT-01. |
| AS-06 | always **n-a**: no message bus. |
| AS-07 | always **yes** (partial wording): startup fails fast on missing config; no autoscaling (n-a part noted). |
| AS-08 | always **n-a**: no legacy integration. |
| DM-01 | personal-data → **yes** (docs/data-protection.md, owner named) ; otherwise **yes** with "only business/internal data". |
| DM-02 (C) | sensitive-data or personal-data → **yes** when field-encryption on (in transit: loopback n-a note; at rest: AES-GCM with rotation command; key on same host — limitation noted); local-only without personal data → **n-a** (in transit loopback; at rest no sensitive fields). local-network → **no (high)** unless TLS mode selfsigned/proxy — action "enable TLS". internet-later → deferred: **no (high)** with mitigationPlan "deploy behind TLS proxy (docs/deployment.md)". |
| DM-03 | always **yes**: idempotent handlers + Idempotency-Key + unique constraints (TPL-IDEMPOTENCY-01). |
| DM-04 | always **n-a**: single database; local ACID transactions. |
| DM-05 | personal-data → **yes** when retention configured (retention months or keep-until-deleted with delete endpoints + docs/data-retention.md); else **yes** (minimal data). |
| DM-06 | always **n-a**: strongly consistent single DB. |
| UX-01 | SecureVibe's own requirement, not an external one: a look the owner chooses may change colour only, and every theme keeps the WCAG 2.2 AA contrast ratios (4.5:1 for text, 3:1 for the edge of a form field) in its light and its dark version. Checked by `tests/security/theme.test.ts` straight from the stylesheet. |
| RR-01 | always **yes**: safe error model; retries with backoff in http-client. |
| RR-02 | external-apis/ai/email → **yes** (circuit breaker + degraded mode in http-client); else **n-a**. |
| RR-03 | scheduler → **yes** (jobs table, lock, at-least-once documented); else **n-a**. |
| RR-04 | always **n-a**: no shared integration layer. |
| RR-05 | always **yes**: Idempotency-Key + optimistic concurrency (`updated_at` check) in the example/expanded CRUD. |
| RR-06 (C) | always **yes**: timeouts on server + outbound; /healthz /readyz; failover **n-a** locally (deployment note: multi-AZ deferred). |
| RR-07 | always **yes** (rate limits at the edge = the app); quotas per user; autoscaling n-a note. |
| RR-08 | always **n-a** (no CDN/caching layer; performance guardrails = body limits, LIMIT queries — noted). |
| AC-01 (C) | local-only → **n-a** (loopback only, no network path) with deploymentTimeStatus `no` + plan; local-network → **no (high)** unless TLS mode; internet-later → **no (high)** with mitigationPlan "TLS proxy before exposure". |
| AC-02 (C) | auth → **no (medium)**: local accounts, admin MFA enforced (partial), short-lived sessions; mitigationPlan "adopt OIDC/central IdP if the organisation has one" owner:developer dueBy:"before multi-team use"; no-auth → **n-a** (single user, no accounts) with note. |
| AC-03 | auth → **yes** (RBAC via registry, least privilege); no-auth → **n-a**. |
| AC-04 | always **n-a** (no gateway/mesh; authorization centralised in the route registry — noted as compensating). |
| AC-05 | always **no (medium)** for local apps: secrets in `.env` with strict permissions, generated strong, never in code/logs (TPL-SECRETS-01) but no secret manager; action "move secrets to a secret manager when deploying". internet-later → same with mitigationPlan. |
| AC-06 | personal-data → **yes** (regulatory hints doc: GDPR/CCPA/HIPAA depending on region + data classes; evidence docs/data-protection.md); else **n-a**. |
| AC-07 | always **n-a** (no CI/CD or third-party tooling) with note recommending least privilege when added. |
| MT-01 | always **yes** (structured logs, reqId, admin actions logged — TPL-LOG-01/03). "Centralised" n-a note for local. |
| MT-02 | always **no (low)**: no dashboards/SLOs; action "add monitoring when deployed". |
| MT-03 | always **yes** (ASVS-aligned tests + negative tests from threat model — TPL-TESTS-01). |
| MT-04 | always **yes** (authz denials, rate limits, CSRF verifiable in tests/DAST). |
| MT-05 | always **yes** (openapi.json, ADRs, docs). |
| MT-06 (C) | **no (medium)** unless attested (owner recorded a rehearsal date) → then **yes** with manual evidence; plan exists (docs/incident-response.md); action "read and rehearse the plan". |
| MT-07 (C) | always **yes** when audit chain + AUDIT_RETENTION_DAYS ≥ 365 (TPL-LOG-05); note "tamper-evident locally; ship logs to a separate system when deployed" (deploymentTimeStatus `no` until shipped). |

Escalation: exactly `criticalNo.length > 0 || score >= 6 || triggers.some(t => t.triggered)`. Since critical AC-02
(auth apps) / AC-05 are `no`, most apps escalate; `escalationHandling` = "Escalation required — satisfied by: generated
STRIDE threat model + owner acknowledgment on <date> (no independent AppSec review was performed)". The UI never shows
the score or the word "escalate"; it shows "Extra care level" with what was done.

## 8. Applicability rules (`data/knowledge/applicability.json`)

ASVS: `V10` never (`oauth`) "No OAuth/OIDC: the app uses local accounts"; `V17` never; `V9` `jwt` (never in v1: "opaque
API keys are not self-contained tokens"); `V5` `uploads`; `V3.7.1` always; `V4.3` never (no GraphQL); `V4.4` never (no
WebSockets); `V1.2.6-1.2.8`, `V1.3.8`, `V1.3.9`, `V1.3.10`, `V1.4.*`, `V1.5.1` never (no LDAP/XPath/LaTeX/JNDI/memcache/
format strings/unmanaged memory/XML) with reasons; `V1.3.11` `email`; `V1.3.1`, `V1.3.5` never (no WYSIWYG/markdown
rendering) unless `ai` (then applicable, satisfied by text-only rendering); `V6.6.1-6.6.2`, `V6.8.*`, `V7.1.3`, `V7.6.*`
never (no out-of-band/IdP/federation); `V6.5.*`, `V6.6.3` `auth` (MFA present); `V6.*`, `V7.*` `auth`; `V8.4.1` never
(single tenant); `V3.5.4`, `V3.5.5` never; `V12.1.x`, `V12.2.x`, `V3.3.1`, `V3.3.3`, `V3.4.1` `tls` — when `tlsMode=off`
(local-only) → not-applicable "loopback-only deployment, no TLS" with deploymentNote; `V12.3.*` `external-apis|ai|email`
(V12.3.1/12.3.3/12.3.4 partially n-a: SQLite is a file); `V13.2.1`, `V13.2.2` never (no backend components) except
`external-apis`; `V16.4.3` deployment-time; `V15.4` (no reqs L1/L2); `V4.1.2` `tls`; `V4.2.1` deployment-time.
`manualOnly`: V2.3.1, V2.3.4, V6.2.12, V6.3.4, V6.4.4, V11.1.1, V11.1.2, V13.3.1, V14.2.2, V14.2.3, V15.1.3, V16.4.3,
V5.4.3, V12.2.2, C7.2.1, C7.2.2, C11.1.1, C11.1.2, C11.1.3, C11.1.4, C11.3.1, C12.2.2, C12.2.3, AC.4.1, AC.6.3, AC.1.4.
Verification classes: docs in §1.14 → `doc-generated`; requirements only covered by SAST absence → `scanner-clean`
(V1.2.1-1.2.5, V1.3.2, V1.3.6, V15.3.6); tests/probes → `automatable`; others → `ai-assistable`.

AISVS (only when `ai`, or self-assessment): `C1` never (no training); `C3.1.1`, `C3.2.1` (ai: model behavioural tests =
tests/security/ai.test.ts), rest of `C3` never (vendor-hosted model); `C4` never (hosted provider infrastructure);
`C5.1` L3 only; `C5.2.2`, `C5.2.3` `rag` (never); `C5.2.5` `ai-actions`; `C5.3` never (single tenant); `C6.1.1`, `C6.1.3`,
`C6.1.4`, `C6.2.2`, `C6.2.3` never (no model artifacts imported) — `C6.1.2`, `C6.2.1` applicable (pinned vendor model,
docs/ai.md); `C7.4` `rag` (never); `C8` `ai-history` (C8.1.1, C8.1.2, C8.2.x never: no vector store); `C9.1`, `C9.6`
always with ai; `C9.2`, `C9.3`, `C9.5` `ai-actions` (C9.5.3, C9.5.4 always with ai); `C9.4` never (single agent);
`C10` never (`mcp`); `C11.2.1`, `C11.2.2`, `C11.3.2` applicable; `C11.4` `ai-moderation`; `C12.1.4` `rag`; `C12.3`, `C12.5`
never (vendor-hosted); `C12.4` `ai-actions`. For SecureVibe's self-assessment `canTakeActions=true` so `C9.2/9.3/9.5` apply.

Appendix C (always evaluated for the build process): AC.1.1 (documented workflow: docs/AI-USAGE-POLICY.md generated for
the user), AC.2.1 (SecureVibe threat model), AC.3.1-AC.3.5, AC.4.1 (**fail** unless human review recorded), AC.4.2,
AC.4.3, AC.4.4 (elevated review of security files: human review pack), AC.5.1, AC.7.1, AC.7.2, AC.8.1, AC.10.1, AC.10.2,
AC.11.1-AC.11.3, AC.14.1; AC.6, AC.9, AC.12, AC.13 not-applicable (no CI/CD pipeline / fork PRs) with reasons.

## 9. Server interfaces

### 9.1 LLM

```ts
interface LlmProvider {
  readonly name: 'anthropic' | 'null' | 'scripted';
  readonly model: string;
  structured<T>(req: StructuredRequest<T>): Promise<StructuredResult<T>>;   // messages.parse + zod (strict), cache_control on system, stop_reason handled
  agentRun(req: AgentRunRequest): Promise<AgentRunResult>;                  // manual streaming loop with client tools (see below)
}
interface StructuredRequest<T> { purpose: LlmPurpose; system: SystemBlock[]; user: string; schema: ZodType<T>; effort: Effort; maxTokens: number; correlationId: string; projectId: string; runId?: string; }
interface StructuredResult<T> { ok: true; data: T; usage: UsageDelta; servedModel: string } | { ok: false; reason: 'refusal'|'max_tokens'|'invalid_output'|'budget'|'error'; category?: string; message: string; usage: UsageDelta }
type LlmPurpose = 'quick-infer'|'peer-review'|'threat-model'|'generate'|'fix'|'ai-review'|'classify'|'summarize';
interface AgentRunRequest { purpose: 'generate'|'fix'; system: SystemBlock[]; user: string; tools: AgentTool[]; budget: Budget; correlationId: string; onEvent(e: AgentEvent): void; abort: AbortSignal }
interface AgentTool { name: 'list_files'|'read_file'|'write_file'|'delete_file'|'run_checks'|'done'; description: string; inputSchema: ZodType; run(input): Promise<ToolResult> }  // run_checks input: { check: 'typecheck'|'lint'|'test' } only
interface Budget { maxIterations: number; maxUsd: number; maxWallClockMs: number; maxOutputTokens: number }
```
Every call appends to `llm-audit.jsonl`: `{ts, correlationId, projectId, runId, purpose, provider, requestedModel,
servedModel, stopReason, stopCategory, fallbackUsed, inputTokens, outputTokens, cacheRead, cacheWrite, costUsd,
promptHash, responseHash, injectionFlags, pathDenials, budgetStop}` and (when `storeFullPrompts`) the redacted
prompt/response to `pipeline/<runId>/llm/<correlationId>.json`. Anthropic provider: `claude-opus-5` default, adaptive
thinking, `output_config.effort`, `betas: ['server-side-fallback-2026-07-01']`, `fallbacks: 'default'`, streaming for
agent runs, `max_tokens` 32000 (structured) / 64000 (agent), typed error chain. Null provider returns
`{ok:false, reason:'error', message:'AI is not configured (preview mode)'}`. Scripted provider replays
`server/tests/fixtures/llm/<scenario>.json` (array of SDK-shaped messages incl. `stop_reason`, `usage`, tool_use blocks).

### 9.2 Scanners

```ts
interface ScanContext { appDir: string; projectDir: string; runId: string; buildSpec: BuildSpec; manifest: TemplateManifest; provenance?: Provenance; ignore: string[]; knowledge: Knowledge; log(msg: string): void; abort: AbortSignal }
interface ScanResult { findings: Finding[]; evidence: Evidence[]; coverage: ToolCoverage; details?: unknown; status: 'passed'|'failed'|'warning'|'skipped'; summary: string }
type Scanner = (ctx: ScanContext) => Promise<ScanResult>;   // sast, lint, secrets, deps, config, tests, dast, external
```
`normalize.ts`: `finalize(findings, ctx)` → dedupe by fingerprint, apply `remediation.json`, compute
`severityAdjusted`/`priority`/`exploitability` (deployment context: local-only downgrades network-exposure findings one
step and records `adjustmentReason`), apply persisted `findingDecisions`, set `firstSeenRun/lastSeenRun`.

### 9.3 Process sandbox (`pipeline/process.ts`)

`spawnSandboxed({ cmd: 'node'|'npm', args, cwd, env: allowList, timeoutMs, maxOutputBytes, permission?: { read: string[], write: string[] } })`.
`node` → `process.execPath` with `--permission --allow-fs-read=<dirs> --allow-fs-write=<dirs>` (no child-process, no
worker, no addons); `npm` → `node <npm-cli.js>` resolved from `process.execPath` (fallback: `npm` on PATH, `shell:false`).
Detached process group; kill with `process.kill(-pid, 'SIGKILL')` on timeout/abort; pid file under `pipeline/<runId>/`;
sweep at startup. Env allow-list: `PATH`, `HOME`=`<projectDir>/home`, `TMPDIR`=`<projectDir>/tmp`, `NODE_ENV`, app
variables; never `ANTHROPIC_*`/`SECUREVIBE_*` of the parent. The report's methodology states: "Generated code runs
with the user's OS privileges under Node's permission model (file system restricted to the project folder); network
access is not restricted."

### 9.4 Compliance

```ts
evaluate(input: { design: DesignArtifacts; manifest: TemplateManifest; manifestResults: ManifestControlResult[]; findings: Finding[]; evidence: Evidence[]; testResults: TestResult[]; probeResults: ProbeResult[]; aiReview?: AiReviewResult; attestations: Attestation[]; humanReview?: HumanCodeReview; runMeta; previous?: ComplianceResult; knowledge }): ComplianceResult
```
Status algorithm per requirement (in order): out-of-level → not-applicable (rule) → if manual-only: attested/not-verified →
failing strong/medium evidence or open mapped finding (confidence ≥ medium) → `fail` (or `partial` if any strong pass) →
≥1 strong pass or ≥2 medium pass → `pass` → 1 medium pass → `partial` (rationale "single static check") → only weak:
ai-review (confidence ≥ medium, citation verified) → `ai-assessed`; design/doc → `documented`; manual → `attested` →
otherwise `not-verified` with reason. Tests assert: no `pass` from weak evidence; manual-only never `pass`.
A template control adds failing evidence only when one of its checks actually failed; a control left uncredited
because a check was skipped (feature off, test skipped) or because it has only supporting checks adds no evidence.
Test evidence matches a requirement when the test's own name (the last ` > ` segment) starts with the requirement id.
Manifest `config-value` checks read config evidence and the deps scanner's `deps.*` evidence.

### 9.5 Pipeline

`runPipeline(project, { mode, approval? | approvedBy?, spendingCapUsd, fixFindingIds? }, bus)`. Web builds pass
`approval` (from `POST /api/projects/:id/runs` with `approved: true` and the one-time `approvalCode` returned by
`GET /api/projects/:id/estimate`; see `server/src/api/approvals.ts`); it is recorded as `run.approvedBy`,
`run.approvedAt` and `run.approval`. CLI runs record no approval unless a named `approvedBy` is given. Persists `PipelineRun` after every
stage (atomic). Stage failure: `install` failed → continue with typecheck/tests/dast `skipped (dependencies missing)`;
`generate` refusal → run fails with `failure.options ['change-answers','retry']`; any stage crash → mark failed, still
run `compliance` + `reports` with `incomplete: true`. `verify-only` mode skips design-freeze/scaffold/generate/fix.
Fix loop: only when llm configured; candidates = open findings with priority P1/P2 (plus `fixFindingIds`), excluding
`ai-review` findings with confidence < high; after each round re-run typecheck→…→dast; `fixed` iff fingerprint gone AND
no new P1/P2 AND passing-test count not decreased AND protected hashes unchanged; else `fix-attempted`; diffs saved to
`pipeline/<runId>/fixes/<findingId>.patch`.
After the scan stages the runner normalizes findings once (`finalizeFindings`: dedupe, deployment-aware severity,
priority, saved accept/false-positive decisions, continuity with the previous run, stable `F-NNNN` ids) and notes
reviewed findings in each scan stage's summary and status. "Fix these" ids from a previous run are translated to
fingerprints. After the fix loop and before `compliance`, `finalizeProvenance` records the code-tree hash, framework
and tool versions, AI calls (correlation ids, served models, prompt-library hash) and human involvement. A recorded
human code review counts only while the hash of the protected files equals the one reviewed.
Appendix C run facts: audit-log and screening facts only when AI was available for the run; `AC.8.1` approval facts
are not produced for `verify-only` runs; protected-file verification only when the manifest has protected paths.
Informational findings never contradict a requirement; a failed probe whose finding is marked false positive is not
failing evidence.

Spending cap: the cap covers the whole build. Every AI step (generate, ai-review, each fix round) gets at most
`cap - spent so far`; a step with less than $0.50 left is not started and says so. Agent usage events carry the
step's running total and are added to what was spent before the step. Tool-layer security events (flagged reads,
denied paths) and every `ctx.log` message are written to the stage log. `verify-only` runs load
`securevibe.provenance.json` from the app folder; code (AST) checks in `compliance` still run after a cancel.

AI review: files are chosen with the scan's exclusions, security code first, and sent once per run as a cached
user-turn block; requirements go out 6/4/2/1 per call for review effort low/medium/high/xhigh+ (reasoning shares
the 32k answer room; structured calls are streamed); the review stops before a call that would likely cross its
limit (cost of the costliest call so far). Structured calls are streamed and parse the reply themselves, so a
malformed reply's cost is still recorded. `reviewedRequirementIds` lists only requirements whose call was used.

Reports: `ArtifactRef.path` is project-relative (`reports/<runId>/<file>`); older runs listing a bare file name are
resolved in their run's report folder. `GET /api/projects/:id/report-runs` lists runs with reports (newest first);
`/api/projects/:id/reports/:runId/:name` serves one run's report so relative links stay in that run; report HTML is
served with its own CSP (`default-src 'none'`, its `<style>` blocks by hash).

Extra scanners (optional, found on PATH): semgrep (`p/owasp-top-ten` + `p/typescript`, metrics off), gitleaks (a
generated config extending the default rules), trivy (vuln, secret, misconfig; downloads its database as needed),
osv-scanner (given the app's lockfiles; `scan source` form from v2). All get SecureVibe's ignore patterns; the secret
scanners also skip `.env`, `FIRST-LOGIN.txt`, `securevibe.provenance.json` and lockfiles (secrets by design or hashes).
Template test fixtures that hold deliberately weak passwords carry `// gitleaks:allow`.

Design page: while the design is derived and the AI second opinion runs, the summary page shows the three steps with
a progress bar. `POST /api/projects/:id/design/peer-review/skip` aborts a running second opinion (in-flight
controllers per project) and records `performedBy: 'skipped'` with "Skipped at your request"; the second opinion uses
`settings.reviewEffort`.

Apps: `POST /api/projects/:id/archive` sets `archivedAt` (hidden from the main list, nothing removed);
`POST /api/projects/:id/restore` clears it; `DELETE /api/projects/:id` removes the project folder and is refused (409)
while that app's build is running. The web list confirms deletion by typing the app's name.

AI switch: `settings.aiEnabled` (default true, "Use AI" in Settings) and `SECUREVIBE_AI=off` both force the null
provider (`llm/active-provider.ts`), checked on every request; `GET /api/status` reports `llm.switchedOff`
(`setting` | `environment`) when a key exists but AI is off.

Cost control: `settings.saveCredits` (default true) → `effectiveAiSettings()` (server/src/config.ts) uses
`claude-sonnet-5`, effort `low` and at most one fix round; the provider, the runner, the estimate and the CLIs all read
the effective settings. The spending cap (default $5) is shared by `stageBudgetUsd()` (pipeline/stage-helpers.ts):
generate may use what is left minus 45% of the cap, ai-review what is left minus 15% (when a fix round will run), fix
the rest. Agent conversations carry a moving prompt-cache breakpoint (`withConversationCache`, llm/anthropic.ts), and
the agent loop adds `WRAP_UP_NOTICE` once when 70% of a step's money or 80% of its turns are used.

Model access errors: an Anthropic "credit balance" error maps to `billing`; `auth` and `billing` failures set
`accountProblem`, and the AI review makes no further calls after one. Field encryption pins the AES-GCM tag length
(16 bytes) and rejects stored values with a different IV or tag length.

**Self-assessment** (`npm run self-assess [-- --no-ai] [--max-usd <n>] [--skip-tests]`): verify-only run over the repository with
`server/tests/**`, `web/tests/**` and `templates/**` excluded (the template is verified by building apps). It runs
SecureVibe's vitest suite first and imports the results as `unit-tests`; types are checked per workspace
(`*/tsconfig.json`); `dast` starts SecureVibe in-process (scratch workspace, resettable rate limiters) with the route
list read from its Express app, signs in with the startup token (`?t=`, CSRF from `/api/status`, cookie
`securevibe_session`), and records generated-app-only probes as not attempted with a reason. Reviewed rule-level
decisions with reasons come from `self-assessment/triage.json`. Reports are copied to `artifacts/self-assessment/`,
and one "SecureVibe self-assessment" project is reused. Recorded request paths redact credential-like query values.

### 9.6 Store

`workspace/projects/<id>/project.json` (Project), `design/` (design.json, design.md, security-contract.md, adr/*.md,
threat-model.md, diagram.mmd), `app/` (current generated app), `app-v<N>/` (previous versions), `pipeline/<runId>/`
(run.json, stages/*.log, llm/, fixes/, dast/), `reports/<runId>/` (overview.html, compliance-report.{html,md,json},
security-report.{html,md,json}, design.md, going-online.md, findings.sarif, sbom.cdx.json, provenance.json, app.zip).
Atomic writes (`tmp` + rename); every path resolved with `realpath` and checked against the workspace root
(case-folded prefix, NUL/UNC rejected).

## 10. Web pages

`/` Home (projects, preflight card, "Preview without AI" banner + how to add a key, examples gallery, "About 10 minutes");
`/projects/:id/wizard/<step>` (steps §api WIZARD_STEPS; sub-screens one idea per screen; "Not sure" on every question;
autosave; progress bar; "Why we ask" + "What this changes" panels); `/projects/:id/summary` ("Here's what we'll build":
plain summary, consequences, assumptions to confirm, extra-care panel; collapsed "Technical details for your developer"
drawer with diagram, patterns, checklist, threat model, second-opinion decisions); `/projects/:id/build` (estimate +
spending cap + approval, live progress, per-stage failure UX with three actions, reconnect by run id);
`/projects/:id/results` (Can I use it? · Run your app checklist with copy buttons and first-login box · Top actions ·
Findings grouped: Fixed for you / Needs your decision / Needs a developer / Nothing to do · Reports · Attestation
questions · Human review pack · Rebuild banner); `/settings` (Advanced, with reset).


## Dashboard, human checks and app preview (added 2026-09-17)

* `GET /api/metrics?days=7|30|90` (server/src/api/metrics.ts): AI spending from `llm-audit.jsonl` (scripted test
  entries ignored), builds from saved runs, security events from `<home>/logs/security-events.jsonl` (written by
  `securityEventStream`, server/src/security/event-log.ts: every log entry with an `event` name, safe fields only, 0600,
  rotated at 5 MB), open findings from each non-archived app's latest run. Web: `/dashboard`.
* Human checks: `GET /api/projects/:id/verification` (manual-verification items of the latest run joined with the
  requirement and the current answer, plus the code-review scope), `POST /api/projects/:id/reports/refresh`
  (re-evaluates compliance from `pipeline/<run>/compliance-inputs.json`, saved by the compliance stage, with the
  current attestations and human review, and re-renders the reports; nothing is re-run). Review scope:
  `reviewScope()` (server/src/verification) — the manifest's protectedPaths, or `SECUREVIBE_REVIEW_GLOBS` for the
  self-assessment project. A "not sure" attestation adds no evidence (the requirement stays unverified). Web:
  `/projects/:id/verify?step=start|code|owner|developer|specialist|finish`.
* App preview: `GET|POST|DELETE /api/projects/:id/preview` (server/src/preview). Fresh data dir and secrets per start
  under `<project>/tmp/preview-*`, sandboxed, `SMTP_URL`/`OUTBOUND_ALLOWED_HOSTS`/`ANTHROPIC_API_KEY` emptied,
  `AI_ENABLED=0`, `ADMIN_MFA_REQUIRED=0`, a `preview-admin@example.com` account with a one-time password; stops after
  an hour, on rebuild, delete and exit; leftovers are swept at startup. Served as `http://localhost:<port>`: SecureVibe
  sessions only count on 127.0.0.1 (`SESSION_HOSTNAME`), and `/auth/token` or a page on another host redirects there.
* Build approval: `GET /estimate` returns a one-time `approvalCode`; `POST /runs` requires it (server/src/api/approvals.ts).
* Uploaded apps (`project.origin.kind === 'uploaded'`, created with `POST /projects` `{ uploaded: { aiAssisted } }`):
  `POST /projects/:id/upload/begin`, `PUT /projects/:id/upload/file?path=` (raw `application/octet-stream`, ≤ 2 MB,
  own rate limit), `POST /projects/:id/upload/finish` (staging → app/, previous app kept as app-vN), `.../cancel`
  (server/src/api/uploads.ts). Dependencies, build output, `.env*` (except examples), keys and databases are skipped.
  Runs are always `verify-only` with `skipStages` (install, typecheck, unit-tests, dast: uploaded code is never run),
  `manifestOverride: uploadedManifest()`, and `excludedChecks` (template-only SAST/config checks, dropped in
  `absorbScanResult`). Appendix C applies only when `aiAssisted`. No preview, fixes or run instructions. Code-review
  scope: `UPLOADED_REVIEW_GLOBS`. Web: Home "Check an app you already have" → `/projects/:id/upload` → wizard → summary
  ("Check my app").

## Plan → approve → implement → verify (added 2026-09-17)

A full build that writes with AI needs an approved plan for the current design (`project.buildPlan`, shared
`BuildPlanSchema`; `designHash` must equal `design.profileHash`). `POST /projects/:id/plan` runs the `plan` flow
(`server/src/llm/flows/plan.ts`, scripted fixture `tests/fixtures/llm/plan.json`); `POST /projects/:id/plan/approve`
records `wanted` per feature and `approvedAt`. `POST /projects/:id/runs` refuses a full AI build without one and passes
it as `RunPipelineOptions.plan`; `buildGenerationBrief(design, manifest, plan)` appends the approved features as the
agent's ordered to-do list. After the core stages, `planCoverage()` (`server/src/pipeline/plan-coverage.ts`) scores
each feature `built | partly | not-built | left-out` from `routes.manifest.json` (pages, entities) and the unit-test
names, into `run.planCoverage`; the Results page shows it. Builds without AI, check-only runs, fix rounds and uploaded
apps need no plan.

## Durable builds (added 2026-09-17)

`POST /projects/:id/runs` no longer executes the pipeline in the server: it creates the run record (`prepareRun`,
status `running`, app `building`), writes `pipeline/<run>/job.json` (`BuildJob`) and spawns
`server/src/cli/build-worker.ts <projectId> <runId>` detached in its own session (`spawnBuildWorker`,
`pipeline/job.ts`), recording the pid in `worker.json` and its output in `worker.log`. The worker runs
`startRun({ existingRun })` with a `RunBusRegistry` whose sink appends each event to `events.jsonl`; the server's
`GET /runs/:id/events` streams the in-process bus when it has one, otherwise tails that file until the run record
is no longer `running`. `POST /runs/:id/cancel` aborts an in-process run or sends the worker SIGTERM. `runIsLive()`
(in-process or live worker) replaces `isRunActive()` for API checks; `markInterruptedRunsAtStartup` and the pid
sweep skip runs whose worker is alive, so a SecureVibe restart no longer ends a build. If a worker cannot be spawned
the route falls back to running in-process.

## Evaluation harness (added 2026-09-17)

`npm run eval` (`server/src/cli/eval.ts`) builds every golden app in `evals/golden/*.json` — saved wizard answers,
one file per app — in a scratch workspace, runs all checks, and turns each run into `EvalMetrics`
(`server/src/eval/metrics.ts`): status, stage results, open findings by severity, ASVS/AISVS verified coverage,
app-test counts, cost, plan coverage. `compareMetrics(baseline, current)` sorts differences into regressions (build
no longer succeeds, a step now fails, more open critical/high/medium findings, verified coverage down by more than
`PASS_PERCENT_TOLERANCE`, more failing ASVS/AISVS requirements, fewer passing app tests, planned features no longer
built), improvements, and notes (low/info counts, cost, time). Baselines live in `evals/baselines/<case>.<ai|no-ai>.json`
and are written only with `--update`; each run's full record goes to `evals/results/` (git-ignored). Without
`--ai` the build is template-only and free (nightly); with `--ai` Claude writes the features (before a release,
`--max-usd` per app). Exit code 1 on any regression or unfinished build.

## Template upgrades (added 2026-09-18)

Every scaffold records `templateHash` (a hash of the template's files, `generator/template-hash.ts`) in the app's
`securevibe.provenance.json`. `GET /projects` and `GET /projects/:id` add `templateOutdated` (computed, never
stored) when that hash differs from the current template; apps built before the hash existed count as outdated.
`POST /projects/:id/upgrade` (`generator/upgrade.ts`) stages the current template for the app's design
(`stageTemplate`, the first half of `scaffoldApp`), then for every file compares the old template's hash (from the
provenance), the app's current hash and the new template's: unchanged template files are replaced, files the
template gained are added, unchanged files the template dropped are removed, and files carrying the owner's or
Claude's changes are kept and listed (`kept`). `.env`, data, certificates and packages are never written except
that new `.env` keys are appended with their defaults and a changed lockfile refreshes `node_modules` from the
template's tested set. The provenance is rewritten (new hashes, new `templateHash`), the result is stored as
`project.lastUpgrade`, and the web app then starts a free `verify-only` re-check. Uploaded apps cannot be upgraded.

## Version diff (added 2026-09-18)

`GET /projects/:id/versions` lists the current app and every archived `app-v<N>/` (`versions/index.ts`), each
with the run that built it (the current app's `project.lastRunId`; an archive's provenance `runId`) and when.
`GET /projects/:id/diff?from=<v>&to=<v>` (defaults: the newest archive → current) lists files that differ —
added / removed / changed, the origin from the newer version's provenance, line counts for text files — and, when
both versions have a run, how the checks moved: open findings resolved / new / still open (matched by
fingerprint), ASVS/AISVS verified coverage and app-test counts. `GET /projects/:id/diff/file?path=` returns one
unified diff (`versions/line-diff.ts`, LCS with 3 lines of context, first 4000 lines). `.env` and
`FIRST-LOGIN.txt` are reported as changed but never shown; binary and very large files are compared by hash only;
`node_modules`, data, `package-lock.json` and the provenance file are ignored. Paths are confined to the version's
folder. The results page shows the comparison for any app with at least one archived version.

## Hand-off pack (added 2026-09-18)

`GET /projects/:id/artifacts/handoff.zip` (`?run=` selects a run; default the latest) streams a zip built on
demand: `HANDOFF.md` (`reports/handoff.ts`: what the app is, how to run it, how the checks came out, open
problems with who can fix them, the human checks answered, what must happen before wider use, where files came
from, the pack's contents), `app/` (the same exclusions as `app.zip`: no `.env`, data, packages or first-login
file; `.env.example` included), `reports/` (that run's report folder) and `human-checks.json` (attestations and
the human code review). Uploaded apps get no pack. The results page offers both zips above the reports table.

## Build-finished notifications (added 2026-09-18)

`settings.notifyOnFinish` (default true; Settings → "Tell me when a build finishes"). When a run ends, the process
that ran it (the build worker, or the server for the in-process fallback) calls `notifyRunFinished`
(`server/src/notify.ts`), which shows one system notification through the platform's own tool — macOS `osascript
display notification`, Linux `notify-send`; nothing on other platforms — with a plain-language line from
`finishMessage` (verdict, count of serious open problems, or why it stopped). Failures to notify are swallowed.
The Build page additionally offers a browser notification (Web Notifications API, permission requested only on
click) that fires when the run ends while the tab is hidden.

## Free onboarding example and the one-page landing (added 2026-09-18)

`data/knowledge/examples.json` may mark an example `free: true` (the "Habit log" example, the golden
`evals/golden/habit-tracker.json` profile): small enough to build without AI in minutes. `POST /projects/:id/runs`
accepts `withoutAi` with `mode: 'full'` as well as `verify-only`: the worker uses the null provider, the scaffold
writes the starter app from the answers (pages for every record, no AI-written features), every check and report
runs, and no plan approval is needed. The Build page offers "Build without AI (free)" for any unbuilt app when a key
is configured (in preview mode every build is already without AI) and "Check again without AI (free)" for built
ones. The results page leads the Reports section with the one-page summary: verdict, headline, "can I use it", the
first three top actions, and buttons to open `overview.html` or save it as PDF.

## Network fence for generated code (added 2026-09-18)

Every `node` process SecureVibe starts for a generated app (tests, the runtime scan, the preview, the scaffold's
scripts) runs behind an operating-system network fence in addition to Node's permission model
(`pipeline/net-fence.ts`, applied in `spawnSandboxed`): macOS `sandbox-exec` with a Seatbelt profile that denies
all networking except loopback and unix sockets; Linux `unshare -rn` with only `lo` up. The fence is probed once
per process (a tiny node run behind it must succeed) and, when present, the run's `sandboxMode` and the provenance
`sandbox` record read `node-permission-model+loopback-only`; when absent the reports say network access was not
restricted. `PermissionSpec.network: 'any'`, or a non-empty `OUTBOUND_ALLOWED_HOSTS` in the child's environment,
skips the fence for an app that genuinely has to reach outside hosts (previews clear that variable, so previews are
fenced). `npm` and external scanners are never fenced.

## OpenAI and Google providers (added 2026-09-18)

`settings.aiService` ('anthropic' default, 'openai', 'google'; Settings → "Which AI service builds use") picks the
provider; the service needs a key (`OPENAI_API_KEY`, `GOOGLE_API_KEY`, written by Settings → "Your AI service"),
otherwise the null provider (preview mode) applies. `llm/openai.ts` talks to the Responses API and `llm/google.ts`
to Gemini `generateContent`, both over plain HTTPS through `llm/rest.ts` (timeout, abort, status → `LlmError`
kind, strict JSON schemas). Both implement `structured()` (strict schema output, refusal and truncation checked
before parsing) and `agentRun()` through the shared agent loop (function tools with strict input schemas, the
model's own output replayed statelessly; Gemini function calls get SecureVibe-made ids). `effectiveAiSettings`
maps the model to the chosen service (`modelForService`; Save credits uses `gpt-5-mini` / `gemini-2.5-flash`).
Rates for these models are in `MODEL_RATES`; the spending cap applies as for Anthropic. Provenance and the audit log
record the provider name. Not available for these services: Anthropic's server-side fallback and web search.

## Generated apps on OpenAI or Google (added 2026-09-18)

The template's assistant runs on Anthropic, OpenAI or Google (`src/features/ai/providers.ts`): `AI_PROVIDER`
(empty = whichever key is present, Anthropic first; `openai`; `google`; `mock` for tests) with `OPENAI_API_KEY`
or `GOOGLE_API_KEY`, and an `AI_MODEL` of that service. Both go through the app's guarded fetch (outbound
allow-list, timeout) and use the same strict JSON answer and moderation schemas, so every guard-rail in
`features/ai/index.ts` applies unchanged; web search stays Anthropic-only. The scaffold writes `AI_PROVIDER` from
`settings.aiService`, the matching host into `OUTBOUND_ALLOWED_HOSTS`, and switches `AI_WEB_SEARCH` off for the
other services. The app never receives SecureVibe's key: the owner adds their own to the app's `.env`.

## Which AI service does which step (added 2026-09-18)

`settings.aiService` is the default service; `settings.aiServiceFor` overrides it per step group —
`write` (generate, fix), `review` (ai-review) and `questions` (quick-infer, peer-review, refine, plan,
threat-model, classify, summarize) — each `'default'` or a service id (`server/src/config.ts`: `STEP_GROUP`,
`stepGroupFor`, `serviceForPurpose`, `effectiveAiSettings(settings, purpose)`, which also resolves the model to
one belonging to that step's service and applies Save credits). `providerFactory(config)` returns
`ProviderFor = (purpose?) => LlmProvider`: `ApiDeps.getProvider` and `PipelineCtx.providerFor` are that function,
so each route and each stage asks for the provider of its own step (a step whose service has no key falls back to
preview mode for that step alone). The pre-build estimate is priced at the writing step's service; the compliance
stage's "was any of this assessed by AI" reads the review step's provider; the provenance `llm.provider` lists
every service that could have run and `requestedModel` is the writing model. Settings → "Which AI service does
what" sets all three groups (the web app always sends the complete object) and points out when the review runs on
a service that did not write the code — an independent check.

## Evidence that names its requirements, and fixing any finding (added 2026-09-18)

`Evidence.requirementIds` (shared/src/compliance.ts) lets a checker say which requirements its result speaks to,
instead of the id having to appear in `ref`. The configuration scanner fills it from each check's `asvs`/`aisvs`
mapping, so the 19 checks that run on every build now credit the requirements they verify (`extraEvidenceFor` in
`compliance/evidence.ts` matches on either). Tiers are unchanged — configuration evidence stays `medium`, so a
requirement reaches `pass` only with a second independent medium check or a strong one, and a failing check now
fails the requirement instead of leaving it silently unverified. On the golden apps this clears six checks the
owner used to be asked to confirm by hand (V6.1.1, V6.3.2, V6.4.1, V11.2.3, V15.1.2, V15.2.1).

The results page can send any open finding to the AI, not just the ones marked as SecureVibe's to fix: each open
finding has a tick box, with "Fix the ticked problems" and "Fix all N" above the list (the Build page then shows the
estimate and asks for approval as for any build, and `fixFindingIds` goes to the fix loop, which accepts explicitly
requested findings whatever their `whoCanFix`). The group heading reads "Usually needs a developer", because the AI
may still fix it.

## Documentation checks and the documents a human check names (added 2026-09-18)

`scanners/config/docs-checks.ts` adds seven `docs.*` checks to the `config` stage (`ALL_CONFIG_CHECKS` =
configuration + documentation): each generated document must exist, carry content, and still match the app —
validation.md covers every record type, sessions.md states the app's own session times, communications.md lists
exactly the hosts the app may contact, data-protection.md covers the kinds of information and how long they are
kept, logging.md says where the log lives and for how long, dependencies.md gives update deadlines, SECURITY.md
describes the sign-in limits, the banned password words and the administrator's second step. They are `low`
severity (misleading documentation, not an exploit) and, through `requirementIds`, credit V2.1.1, V2.1.3, V6.1.1,
V6.1.2, V6.1.3, V7.1.1, V7.1.2, V13.1.1, V14.1.1, V14.1.2, V15.1.1 and V16.1.1. Whether the wording is right for
the business is still a person's judgement; what a machine can settle (is it there, does it match the app) it now
settles.

`verification/documents.ts` finds the files a manual check names in its own question and steps, resolves each
against the app, the project folder and the SecureVibe folder in that order, and returns them on every
`VerificationItem` as `documents[{ path, where, openable }]`. `GET /projects/:id/document?path=…` serves one
(`.md`/`.json` only, ≤512 KB, path-confined); `.env` and `FIRST-LOGIN.txt` are listed with `openable: false` and
never served, whatever a check's wording says. The human-checks wizard shows a "Read docs/x.md" button per
document and opens it in place.
