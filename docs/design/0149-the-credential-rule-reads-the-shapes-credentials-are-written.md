# The credential rule reads the shapes credentials are written in (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H3) found the credential-assignment rule in
`crates/sv-check/src/secrets.rs` reading only `name = "value"` and `name: "value"`. A password written as a JSON or
dict key (`"password": "…"`), with PHP's or Ruby's `=>`, with Go's `:=`, in a typed declaration
(`const apiKey: string = "…"`, `var dbPassword string = "…"`), as unquoted YAML, or as the default given to a setting
read from the environment (`os.getenv("DB_PASSWORD", "…")`, `process.env.JWT_SECRET || "…"`) was reported by nothing.
The last is how AI-built apps most often leave a secret in the code: the setting is read properly, and a working value
is written beside it in case it is missing.

The rule now reads each of those shapes, as separate patterns that each say which part is the name and which the
value, so a typed declaration's type word is never taken for the name and one value read under two names is reported
once. Unquoted values are read only in YAML, `.properties`, `.ini`, `.cfg`, and `.conf` files; in code the same shape
is a call. Passed over in those files: a reference (`${DB_PASSWORD}`), a YAML anchor, alias, or tag
(`!secret db_password`), and a value SOPS keeps encrypted (`ENC[…]`). The text `sv` passes on, such as a failing
test's last lines, has a value cut in all the same shapes.

What it cost, measured. Reading JSON and dict keys brought in every message catalog and schema whose key holds
"token" or "password": with the new shapes alone, 90 false alarms in v1's `node_modules` (TypeScript's "Unexpected
token…" in thirteen languages, CycloneDX's "A secret word, phrase…") and 17 in this repository and v1's code. So what
only the new shapes find is judged once more: text with a space or a letter outside ASCII, a relative path, or an
identifier in lower case (`config.workflow-fork-secrets`) is not a credential. Two shapes skip that judgment. The one
read before keeps its old judgment exactly, so nothing found before is lost (a first version widened that shape and
lost a real assignment inside a JSON string, in v1's self-assessment report). A default given to a setting whose
name says "secret" is that secret whatever it reads like, and `dev-session-secret-for-local` is how such a default is
usually written. The cost, stated: a passphrase with spaces written as a JSON value is still not found.

Against `main` with the other session's sentence change (the entry above), on this repository, its sample apps, and
v1's code, templates, reports, and `node_modules`, nothing reported before was lost, and the new findings were
v1's planted `process.env.SESSION_SECRET || '…'` fixture, two test-password constants in `sv`'s own tests, a
breached-password sample in `data/`, and a test constant in `mcp.rs`; `node_modules` read 11 before and 11 after.
Twenty-four guards broken in turn, each caught: each shape turned off, the quoted names and new operators, the
unquoted reading in every file and in none, YAML's leading characters, the SOPS guard, one name kept per value, a
value reported twice, both redaction changes, each part of the second judgment, that judgment applied to the old
shape or to none, the old shape dropped, and the environment defaults judged as text.
