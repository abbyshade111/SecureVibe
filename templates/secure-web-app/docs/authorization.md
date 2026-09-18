# Who can do what

Every page and every API call in this app is checked against a single list before it runs — there is no page that is reachable just because no link points away from it. The rule is *deny by default*: a route only works for the people named here. Administrators can always do what a named role can do.

## Routes

| Route | Who may use it | Ownership check | What it does |
| --- | --- | --- | --- |
| GET `/healthz` | Anyone (no sign-in required) | — | Liveness check |
| GET `/readyz` | Anyone (no sign-in required) | — | Readiness check (loopback only) |
| GET `/` | Anyone (no sign-in required) | — | Home page |
| GET `/login` | Anyone (no sign-in required) | — | Sign-in form |
| POST `/login` | Anyone (no sign-in required) | — | Sign in with email and password |
| GET `/login/mfa` | Anyone (no sign-in required) | — | One-time code step of sign-in |
| POST `/login/mfa` | Anyone (no sign-in required) | — | Verify the one-time code |
| POST `/logout` | Anyone (no sign-in required) | — | Sign out |
| GET `/register/invite/:token` | Anyone (no sign-in required) | — | Accept an invitation |
| POST `/register/invite/:token` | Anyone (no sign-in required) | — | Set the password for an invited account |
| GET `/forgot-password` | Anyone (no sign-in required) | — | Request a password reset |
| POST `/forgot-password` | Anyone (no sign-in required) | — | Send a password reset link |
| GET `/reset-password/:token` | Anyone (no sign-in required) | — | Reset password form |
| POST `/reset-password/:token` | Anyone (no sign-in required) | — | Set a new password with a reset link |
| GET `/account/password` | Any signed-in user | — | Change password form |
| POST `/account/password` | Any signed-in user | — | Change password (current password required) |
| GET `/account` | Any signed-in user | — | Your account |
| GET `/account/profile` | Any signed-in user | — | Edit your name |
| POST `/account/profile` | Any signed-in user | — | Update your name |
| GET `/account/email` | Any signed-in user | — | Change your email address |
| POST `/account/email` | Any signed-in user | — | Change your email address (password confirmation required) |
| GET `/account/sessions` | Any signed-in user | — | Devices signed in to your account |
| POST `/account/sessions/:id/revoke` | Any signed-in user | — | Sign out one device |
| POST `/account/sessions/revoke-others` | Any signed-in user | — | Sign out everywhere else |
| GET `/account/reauth` | Any signed-in user | — | Confirm your password before a sensitive change |
| POST `/account/reauth` | Any signed-in user | — | Confirm your password (and code) |
| GET `/account/mfa/enrol` | Any signed-in user | — | Set up one-time codes (password confirmation required) |
| POST `/account/mfa/confirm` | Any signed-in user | — | Confirm the one-time code setup |
| POST `/account/mfa/disable` | Any signed-in user | — | Turn off one-time codes (password confirmation required) |
| GET `/account/export` | Any signed-in user | — | Download a copy of your data (JSON) |
| GET `/account/delete` | Any signed-in user | — | Delete your account (confirmation page) |
| POST `/account/delete` | Any signed-in user | — | Delete your account and data (password required) |
| GET `/admin` | Role `admin` (or an administrator) | — | Administration overview |
| GET `/admin/users` | Role `admin` (or an administrator) | — | List accounts |
| GET `/admin/users/new` | Role `admin` (or an administrator) | — | Create an account form |
| POST `/admin/users` | Role `admin` (or an administrator) | — | Create an account and an invitation link |
| GET `/admin/users/:id` | Role `admin` (or an administrator) | — | Account details |
| POST `/admin/users/:id/disable` | Role `admin` (or an administrator) | — | Disable an account and sign it out everywhere |
| POST `/admin/users/:id/enable` | Role `admin` (or an administrator) | — | Re-enable an account |
| POST `/admin/users/:id/delete` | Role `admin` (or an administrator) | — | Delete an account and its data |
| POST `/admin/users/:id/mfa-reset` | Role `admin` (or an administrator) | — | Remove one-time codes from an account (reason required) |
| POST `/admin/users/:id/sessions/revoke` | Role `admin` (or an administrator) | — | Sign an account out everywhere |
| POST `/admin/users/:id/role` | Role `admin` (or an administrator) | — | Change the role of an account |
| POST `/admin/users/:id/invite` | Role `admin` (or an administrator) | — | Send a new invitation link |
| GET `/admin/audit` | Role `admin` (or an administrator) | — | Security event log |
| GET `/admin/audit/verify` | Role `admin` (or an administrator) | — | Check the event log has not been tampered with |
| GET `/admin/settings` | Role `admin` (or an administrator) | — | Runtime settings |
| POST `/admin/ai/kill-switch` | Role `admin` (or an administrator) | — | Switch the AI assistant on or off |

## How this is enforced

- Every route is registered with an explicit rule (`public`, `user`, or `role:<name>`) — the app refuses to start if any route was added without one.
- A route with an ownership check loads the record first and compares it to the signed-in user before running the handler; a non-owner sees the same "not found" response as a record that does not exist, so the app never reveals that something exists that the visitor may not see.
- Every refusal is written to the security event log as `authz.denied` (see docs/logging.md).

---

*This file is generated by `npm run docs:build` from the app’s own code and configuration. Do not edit it by hand — change the code or configuration and run `npm run docs:build` again.*
