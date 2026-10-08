# An admin who signs in with a code (4 October 2026)

On family-hub (3 October) the owner asked for an authenticator code to be required for admins. The admin checks
signed the seeded admin in with its password alone, so the admin never got past the code step, and V8.2.1 and
V8.3.1 were reported as not assessed with a reason that blamed securevibe.toml: "the page may not be where
securevibe.toml says". The page was where the file said (BACKLOG, "What the owner hit building family-hub", item 5).

**The admin gets a secret of its own.** When there is an admin, a `totp` entry and a `seed`, `sv` makes 20 random
bytes for the admin as it does for the two-factor account, and gives them to `seed` in base32 as
`SV_ADMIN_TOTP_SECRET` (`new_accounts` in `crates/sv-run/src/lib.rs`, `seed_env` in `docker.rs`). Held exactly as
`SV_TOTP_SECRET` is: made fresh for each run, handed only to the app's container, never written anywhere else.

**The admin's sign-in is finished with the code when the app asks for it** (`sign_in_admin`,
`crates/sv-check/src/signed_in/admin.rs`). The admin signs in with its password, then the first private page is
asked. Open, and the password was enough: no code is given, so an app that asks admins for nothing more is checked
exactly as before. Shut, and the code for this moment is worked out from the secret and given through `totp`, and the
private page asked again. Both admin checks (pages, and actions) use it. The second sign-in usually comes in the same
30-second step as the first, and most apps take a code once, so a refused code is tried once more, from a new sign-in,
after the next step begins. The code is never written into the run's steps.

**When the admin is not shown signed in, the reason says where its sign-in stopped**, not that the page is in the
wrong place: with no secret to work out a code from, that it most likely stopped at the authenticator-code step (and
the path); with a code the app refused, that it stopped at the code step and to check that `seed` enrolls the admin
with `SV_ADMIN_TOTP_SECRET`; with no `totp` entry, where the sign-in left the browser and what the private page
answered, and that a further step belongs in securevibe.toml as `totp`. Only an admin shown signed in, who still
cannot open the admin page, is told the page may not be where securevibe.toml says (or that the `seed` account is not
an admin). The admin-actions reason carries the same words.

**A failed `seed` no longer carries a secret into the report.** Its first line of output went into the reason word
for word, so a seed that printed its environment as it failed would have put the run's passwords and both
two-factor secrets in the report. They are now taken out of that line (`seed_failed`).

Tested against the fake app with the admin enrolled: signed in with the secret and both admin checks credited, the
second sign-in getting in with the next step's code; without the secret, the reason names the authenticator step;
with a code the app refuses, and with a code step the manifest does not name, the reasons say so and never blame the
page; an admin page open to everybody is still found. `the_admins_secret_never_reaches_the_report` looks for the
secret, in base32 of either case and in hex, in everything the signed-in run hands the report (every finding,
credit, reason and step, and the log markers), in a run that used it, one whose code was refused, and one without
it; it first shows the search finds a planted copy in each form. The seed tests, in `docker.rs`, show the secret is
given only when there is a two-factor step and is taken out of a failed seed's output, with the line first shown to
carry it. Test secrets are worked out at run time; no file holds one. Each guard broken in turn was caught: no code
given (three tests), the old reason (three), no second try (one), the secret written into a step (one, the leak test),
no redaction of seed output (one), the secret not given to `seed` (one), and no admin secret made (three).
