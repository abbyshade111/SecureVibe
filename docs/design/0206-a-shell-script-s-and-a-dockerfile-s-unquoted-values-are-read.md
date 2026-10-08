# A shell script's and a Dockerfile's unquoted values are read; a JSON passphrase is still not (5 October 2026)

The two parts of H3 left open on 4 October ("The credential rule reads the shapes credentials are written in").

- **Shell scripts and Dockerfiles.** The credential rule read values without quotes only in YAML, `.properties`,
  `.ini`, `.cfg`, and `.conf` files, so `export API_KEY=…` in `deploy.sh` and `ENV DB_PASSWORD …` in a Dockerfile were
  found only when a vendor's own rule knew the key. Now a `.sh`, `.bash`, `.zsh`, or `.ksh` file is read for
  `NAME=value`, with `export`, `readonly`, `local`, or `declare` before it, and before a command
  (`DB_PASSWORD=… ./migrate`); and a `Dockerfile`, `Containerfile`, `Dockerfile.*`, or `*.dockerfile` for `ENV` and
  `ARG`, with `=` or a space, in either case. Everything after the name is judged as every other shape is: the name
  must say it holds a credential, and a value that is wholly another variable or a command's output (`$X`, `${X}`,
  `$(…)`) is a reference. A quoted value is left to the quoted shapes, so it is reported once. Only the first name on
  a Dockerfile `ENV` line is read.
- **A passphrase with spaces as a JSON value: measured, and left as it was.** Across this repository, its
  `node_modules`, and v1's code, 201 values with a space sit under a name holding "secret", "password", "token", or
  the like, and not one is a passphrase. Even the narrowest reading considered, three or more lowercase words, takes in
  11 of them, every one a message or test text ("please hide me", "will be redacted", "only the owner should see this
  line"), and a real passphrase looks exactly like them. Nothing here tells the two apart, so the rule still passes
  over such a value, and says why in `reads_as_text_or_a_name`.

How it is held: ten new cases in `a_credential_is_found_in_every_shape_it_is_commonly_written_in`, each found
exactly once, quoted ones included, and eight in `the_new_shapes_pass_over_what_is_not_a_credential_in_the_clear`
(`crates/sv-check/src/secrets.rs`). Ten guards were undone in turn and each was caught; three that carried no weight
(refusing `$`, a backtick, and a parenthesis in the value, which the reference check already passes over) were taken
out. On the twelve shell scripts and Dockerfiles in this repository, its `node_modules`, and v1's code, nothing new is
reported.
