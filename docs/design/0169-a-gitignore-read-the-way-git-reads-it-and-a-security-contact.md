# A .gitignore read the way git reads it, and a security contact however it is spelled (5 October 2026)

H23 of the deep review: the check that `.gitignore` leaves out `.env` (V13.3.1) compared whole lines against a short
list, so `/.env` failed and `.env` followed by `!.env` passed. The check for a way to report a security problem knew
four exact paths.

- **`.gitignore` is read the way git reads it** (`gitignore_ignores`): blank lines and comments skipped, the last
  pattern that matches decides, `!` brings a file back, a pattern with a `/` in it is anchored to the root, and
  `*`, `?`, `**`, `[...]`, and `\` mean what they mean to git. So `/.env` and `*\n!.gitignore` pass, and `.env` then
  `!.env`, or `*` then `!*.env`, fail.
- **One answer changed the other way.** `.env.*` alone used to count as leaving out `.env`. Git does not apply it
  to `.env`, which has no dot after `env`, so an app whose `.gitignore` says only that now gets the finding. The
  finding's own fix has always said to add both `.env` and `.env.*`.
- **A security contact is found however it is spelled** (`has_security_contact`): a `SECURITY` file, as `.md`,
  `.txt`, `.rst`, `.adoc`, or with no extension, in any capitalization, at the root, in `.github/`, or in `docs/`; and
  a `security.txt` where a site serves it from (RFC 9116's `.well-known/`, also under `public/` or `static/`, and at
  the root). A folder called `SECURITY`, or a `security.txt` among the app's sources, is not one.

How it is held: `a_gitignore_is_read_the_way_git_reads_it`, with twenty cases each checked against what git does,
`a_wildcard_env_entry_counts`, now with `.env.*` alone as a failure, and
`a_security_contact_is_found_however_it_is_spelled_and_wherever_a_site_serves_it` (`crates/sv-check/src/config.rs`).
Five guards were undone in turn and each was caught; a sixth, skipping patterns that end in `/`, was found to change
nothing, since such a pattern never matches a file, and was taken out.
