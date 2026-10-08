# Firebase rules and Supabase migrations are read (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.2; BACKLOG, item 10, its first two parts). An app built with Lovable,
Bolt, and the like often has no server of its own between the browser and the database: the browser talks to Firebase
or Supabase directly, and their rules are the whole of its access control. Nothing read them, so a test app with
`allow read, write: if true;` and a table with no row-level security drew no finding.

`crates/sv-check/src/hosted_rules.rs`, run with the configuration checks, finds three shapes, each high severity and
citing V8.2.2 (data reached only by who may reach it) and V8.2.1. Each only ever finds: a file without them may still let
one user reach another's data in a way a file cannot show, so a clean reading credits nothing.

- **`config.firebase-rules-open`.** In a `.rules` file that names `service cloud.firestore` or `service
  firebase.storage`, an `allow` with no condition, `if true`, or only the date Firebase's test mode writes
  (`request.time < timestamp.date(...)`, which lets everybody in until that day). In a `database.rules.json`, a
  `.read` or `.write` set to `true`. Comments are taken out first, so a rule written and commented out is not read.
- **`config.supabase-table-without-rls`.** A table a migration under `supabase/migrations/` creates in the `public`
  schema, for which no migration turns row-level security on (`enable` or `force`). A table in another schema
  (`auth`, a `private` one) is not reached by the browser's key and is left alone, and so is SQL outside the migrations
  folder: a Postgres app with its own server has no reason to use row-level security.
- **`config.supabase-policy-allows-all`.** A policy for `all`, `insert`, `update`, or `delete` whose `using` or `with
  check` is `(true)`, naming who it lets in (`anon`, `authenticated`). A policy that lets everybody read is left alone:
  a public list is often meant to be one.

Not done: a rule whose condition never mentions `request.auth` (a helper function defined elsewhere in the file can hold
it, and guessing would mean false alarms), and grants to `anon` as such: on a table with row-level security the policies
decide, and on one without it the table is already found. The other two parts of item 10, a secret key under a public
name and a line in the run's summary, are still open.

Tests: five in `hosted_rules.rs`, one of them through `config::check_dir`, the path `sv check` takes. Six guards broken
in turn, each caught: the check not called, test mode's date not counted, comments read as rules, row-level security
never seen, a public read policy counted, and tables in any schema counted.
