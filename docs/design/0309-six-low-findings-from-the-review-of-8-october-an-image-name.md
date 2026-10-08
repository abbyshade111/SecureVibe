# Six low findings from the review of 8 October: an image name held to Docker's grammar, a zeroed passphrase, a random DNS id, a private bundle folder, a content security policy, and SHA-256 (8 October 2026)


The rest of item 6 of "From the review of 8 October 2026: the medium and low findings" (`docs/backlog/0188-…`), after
two other sessions took its first seven parts. Six small fixes in one pull request, each with a test, and a done note
for a seventh that was done already.

- **`image` held to Docker's reference grammar** before it reaches a command line (`sv_run::image_reference`,
  `CannotRun::BadImage`). `sv run` passed `image` from `[stack.run]` to `docker run` as the argument where the image
  goes; a value beginning with a dash (`--privileged`) is an option there, and a value with a space is nothing Docker
  finds, so either came back as Docker's own words or not at all. The grammar is Docker's (`distribution/reference`):
  an optional registry with a port or a bracketed IPv6 address, lower-case path components joined by `.`, `_`, `__`,
  or dashes, a tag of up to 128 characters, a digest of an algorithm and at least 32 hexadecimal digits, 255 characters
  in all. A value that is not a name is refused with its reason in plain words, and the run is reported as not
  assessed, as every other refusal is.
- **The typed passphrase is zeroed** once used (`sv-cli/src/review.rs`, `zeroize::Zeroizing`), the one kept for a new
  key included, so it does not stay in freed memory for the rest of the run. Not done: the line buffer the terminal
  was read through keeps its own copy until it is reused.
- **The DNS transaction id is drawn from the operating system's randomness** (`live_tls::query_id`) rather than
  formed from the process id, which `ps` shows anyone on the computer; a forged answer carrying the predictable id
  would have been taken for the resolver's. The standard library's hasher seed is the source, so no dependency.
- **The bundle's report is written into a private folder** (`adapters::PrivateFolder`: this user alone, a name
  nobody can guess, removed with everything in it when dropped) rather than a folder in the system's temporary
  folder named by the process id and the time, which anyone on the computer could make first and read. Recorded on
  ADR-017, since it is a write outside the app's folder no document named.
- **A Content-Security-Policy `meta` tag on `report.html` and the dashboard** (`html::CSP_META`): nothing may load,
  no script may run, the inline style is the one style, and the page can neither be framed nor submit a form. A
  report is a file somebody hands on; a browser that honors the policy refuses a script edited into it.
- **The install volume's name is a SHA-256** (its first 128 bits) over the ecosystem, the image, and the dependency
  files, in place of two FNV-1a passes: a checksum, not a hash, which a dependency file could be written to collide
  with so that another app's packages were served.
- **The no-sidecar fallback** already goes through `prepared` since the hardening was put in one place (`d77f82dc`,
  8 October): a done note, no build.

**Breaks.** Each failed the test named: the image check skipped (`image_reference`'s refusal test, and the run-plan
test that a dashed image is refused); the id formed from the process id again (`live_tls/id_tests.rs`); the policy tag
left off either page (`sv-report/tests/csp.rs` for the dashboard, `sv-cli/tests/csp.rs` for the written report); the hash put back to FNV (the volume-name test's new length and
prefix check, and the known-answer test); the private folder not removed (`sv-cli/tests/bundle_private.rs`, which holds only that nothing is left
behind; that the folder is this user's alone and unguessable is `PrivateFolder`'s own tests' to hold, in
`adapters.rs`).
