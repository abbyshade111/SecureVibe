# Your app

This folder contains a complete web application built on a hardened starting point. It runs on your own computer
with nothing but Node.js: no build step, no cloud account, no extra services.

## Run it in three steps

1. Install the dependencies (once):

   ```
   npm install
   ```

2. Create the secrets, the database and the first administrator account (once):

   ```
   npm run setup
   ```

   This writes a `.env` file with strong random secrets and prints a one-time password for the first administrator.
   The same password is saved in `FIRST-LOGIN.txt`. Use it once, then choose your own; the file can be deleted
   afterwards. The one-time password stops working after 24 hours if unused (run `npm run setup` again to get a
   new one).

3. Start the app:

   ```
   npm start
   ```

   Open the address it prints (normally `http://127.0.0.1:3000/`) and sign in. As an administrator you will be
   asked to set up one-time codes with an authenticator app on your phone before you can continue.

You need Node.js 22.13 or newer. `npm start` checks this and tells you what to do if your version is too old.

## What is in the box

| Folder / file | What it is |
|---|---|
| `src/server.ts`, `src/app.ts` | Starts the web server and wires up every protection (headers, sessions, cross-site request checks, rate limits, logging). |
| `src/config.ts` | Reads `.env`. Refuses to start with missing or placeholder secrets. |
| `src/security/` | Sign-in, sessions, password rules, one-time codes, permission checks, input validation, safe redirects, the security event log. |
| `src/features/` | The app's features. `auth`, `account` and `admin` are always present; optional features (uploads, AI assistant, API keys, payments) are switched on in `securevibe.features.json`. |
| `src/features/_example/` | A reference "notes" feature that shows how every feature is written. Only mounted with `EXAMPLE_FEATURE=1`. |
| `src/views/` | The pages (EJS templates; every value is escaped). |
| `public/` | Stylesheet and the small script the pages use. |
| `src/db/` | The SQLite database wrapper, migrations and field encryption. |
| `tests/` | Automated security checks (`npm test`). |
| `docs/` | Generated documentation: who may do what, what is logged, how data is protected, how to deploy, what to do in an incident. |
| `data/` | Created at first start: the database, uploads, the log and outgoing mail (owner-only permissions). |

## Useful commands

| Command | What it does |
|---|---|
| `npm start` | Runs the app. |
| `npm run setup` | Generates secrets, creates the database and the first administrator. Safe to run again: it never overwrites existing secrets. |
| `npm test` | Runs the security test suite. |
| `npm run typecheck` | Checks the code for type errors. |
| `npm run docs:build` | Regenerates the `docs/` folder from the code and configuration. |
| `npm run audit:verify` | Confirms that the security event log has not been tampered with. |
| `npm run rotate-field-key` | Re-encrypts protected fields with the newest key in `FIELD_KEYS`. |
| `npm run routes:export` | Writes `routes.manifest.json`, the list of every page and API route with who may use it. |
| `npm run gen-cert` | Creates a self-signed certificate for `TLS_MODE=selfsigned` (needs `openssl`). |

## Where things are kept

* `.env` holds the secrets. Never share it, never commit it. `.env.example` shows every setting with an explanation.
* `data/` holds the database and everything users upload. Back this folder up; keep it private.
* `data/app.log` is the application log (JSON lines). Security events also go to the tamper-evident `audit_log`
  table in the database (`npm run audit:verify`).
* Password reset and invitation emails are written to `data/outbox/` as `.eml` files unless `SMTP_URL` is set.

## Making it reachable from other devices

By default only this computer can reach the app. Read `docs/deployment.md` before changing `BIND_LAN` or
`TLS_MODE`: it explains the safe way to share the app on a local network or put it on the internet.

## If something goes wrong

* The app will not start: read the message. It names the setting that is missing or unsafe.
* You are locked out: sign-in locks are temporary (minutes, never permanent). Wait and try again.
* Lost your phone (one-time codes): use a recovery code, or ask another administrator to remove one-time codes from
  your account.
* You suspect a break-in: follow `docs/incident-response.md`.
