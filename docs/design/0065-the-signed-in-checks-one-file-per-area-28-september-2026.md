# The signed-in checks, one file per area (28 September 2026)

Everything `sv` asks of the running app as a signed-in user was one file, `crates/sv-check/src/signed_in.rs`,
15,463 lines long by 28 September. A session changing one check read all of it, and every session's change to
any check landed in the same file, which is where that week's merge conflicts were (item 13 of the review of
27 September). It is now a folder, `crates/sv-check/src/signed_in/`, with one file per area:

| File | What it holds |
|---|---|
| `mod.rs` | What every check shares: sessions and cookies, anti-forgery tokens, requests filled from the manifest's templates, signing in and up, and `run_with`, which calls each area in turn. Its tests are the ones that exercise several areas at once. |
| `rules.rs` | Every rule a signed-in check can raise, with its requirements, impact, and fix. |
| `signin.rs` | Wrong-password limits (V6.3.1), `X-Forwarded-For`, default accounts, a password in an address, signing out. |
| `sessions.rs` | Session cookies, ids, and timeouts; invented sessions; private pages and their caching; `Clear-Site-Data`; the fields a record gives back; a private WebSocket's session and origin. |
| `passwords.rs` | The password rules at sign-up, the password field, changing a password, hints, deleting an account. |
| `reset.rs` | A forgotten-password reset, followed through its email. |
| `codes.rs` | Signing in with an emailed code, and finding a code in an email, which all three email flows use. |
| `activation.rs` | The activation code emailed at sign-up. |
| `totp.rs` | Two-factor codes from an authenticator app. |
| `admin.rs` | The admin page and admin actions, a role given at sign-up, records that belong to someone else. |
| `forgery.rs` | Cross-site request forgery, `Origin: null`, forms another site can send without asking first. |
| `flows.rs` | The steps of a multi-step flow, taken out of order. |
| `uploads.rs` | Uploads and downloads. |
| `fake_app.rs` | The scripted app every test drives, with each flaw switchable (tests only). |

The same list is at the top of `mod.rs`, where a person changing a check will look first. A new check goes
in its area's file with its tests beside it; a rule goes in `rules.rs`; something two areas share stays in
`mod.rs`.

**How it was moved.** The file was frozen from the first step's claim until this section was written: no
other change touched it, so the several sessions moving it spent no time on merge conflicts. Each move was
a move and nothing else, and each pull request showed it three ways:

- The old file's lines equal the new files' lines, compared as lists with whitespace and `pub(super)` set
  aside. The only new lines are `mod` and `use` lines and each test module's opening and closing lines.
- The same 233 test names before and after every step.
- Each check was made to return at once, and the tests that went red were counted. A check whose own
  tests did not go red is guarded only by the tests that exercise several areas at once. Before the split
  that was already so, but it could not be seen. There are seven: `forgery_check` (V3.5.1),
  `session_checks` (V3.3.2, V3.3.4, V7.2.4), `session_id_check` (V7.2.3), `default_account_check`
  (V6.3.2), `password_in_url_check` (V14.2.1), `sign_out_on_get_check` (V3.5.3), and `plant_log_markers`.
  The multi-step flow check is the opposite case: its own tests catch it, and no test that exercises
  several areas does.

**Two things outside the folder had to follow it.** `tools/coverage.py` read only the files directly in each
crate's `src`, so moving the rules down a folder made it lose every signed-in check (the coverage test
caught this). It now reads subfolders too, and leaves out a file that is a test module of its own. And
`tools/pwned_passwords.py`, which reads the breached password the sign-up check tries, still pointed at
`signed_in.rs` and looked for a line beginning `const BREACHED`. It has no test, since it needs the
network, so nothing caught it: it would have failed the next time it was run. It now reads
`signed_in/passwords.rs`, and the part that reads the password was run to show it finds the same one the
evidence file records.
