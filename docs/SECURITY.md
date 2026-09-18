# SecureVibe — Security policy

SecureVibe is a local tool: it runs on one person's computer and listens on `127.0.0.1` only. This page says how it
protects itself, how to report a problem, and where its own security evidence lives.

## Reporting a vulnerability

* Tell the maintainer of your copy of SecureVibe privately (not in a public issue), with the steps to reproduce, the
  version (`package.json`) and, if you have one, the run id from the affected report.
* Never include an API key, a startup link or a generated app's `.env` in a report. If one was exposed, follow
  [INCIDENT-RESPONSE.md](INCIDENT-RESPONSE.md) first: revoke the key, then report.
* Target response times: acknowledge within 3 working days; fix critical issues within 7 days, high within 30 days,
  medium within 90 days (the same remediation windows SecureVibe applies to the apps it builds).

## Protections against automated abuse

SecureVibe has no user accounts, so there is no password sign-in to guess. Instead:

| Control | Setting | Where |
|---|---|---|
| Startup token | 256-bit random value, printed only in the terminal, compared in constant time, exchanged for an `HttpOnly; SameSite=Strict` session cookie | `server/src/security/token.ts` |
| Request rate limit | 600 requests per minute per client on every route | `server/src/app.ts` |
| Host and Origin checks | Requests must name `127.0.0.1`, `localhost` or `[::1]` on SecureVibe's port; cross-site requests are refused | `server/src/security/middleware.ts` |
| CSRF token | Required on every state-changing API call, together with the Origin/`Sec-Fetch-Site` check | `server/src/security/middleware.ts` |
| Request limits | JSON bodies up to 1 MB, 30-second request timeout, 10-second header timeout | `server/src/app.ts`, `server/src/main.ts` |
| AI spending cap | Every build stops before the cost limit you approve | `server/src/pipeline/stages/generate.ts`, `server/src/pipeline/fix-loop.ts` |
| Build approval | Showing the estimate issues a one-time approval code (1 hour; bound to the session, app and design). A build starts only with that code, and the run records who approved, when, the estimate shown and the spending limit | `server/src/api/approvals.ts`, `server/src/api/runs.ts` |
| Security event log | Refused requests are logged at the default level with a stable event name (`auth.denied`, `auth.token_rejected`, `csrf.rejected`, `origin.blocked`, `access.denied`, `rate_limit.exceeded`, `validation.rejected`, `build.approval_refused`); sign-ins and approvals as `auth.token_accepted` and `build.approved`. Tokens, cookies and approval codes are never logged | `server/src/security/errors.ts`, `server/src/app.ts` |

## Where the evidence is

* SecureVibe's own compliance and security reports: `artifacts/self-assessment/` (`npm run self-assess`).
* Threat model: [THREAT-MODEL.md](THREAT-MODEL.md). Architecture and trust boundaries: [ARCHITECTURE.md](ARCHITECTURE.md).
* How AI is used and controlled: [AI-USAGE-POLICY.md](AI-USAGE-POLICY.md).
* Reviewed scanner decisions for SecureVibe's own code (accepted risks and false positives, each with its reason):
  `self-assessment/triage.json`.
