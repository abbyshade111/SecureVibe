# The password and implicit grants, read from a sign-in server's code (29 September 2026)

V10.4.4 says the password grant and the implicit grant must no longer be used. `probe.retired-grants-offered`
reads the settings a running app publishes; `config.retired-grant-enabled` (`crates/sv-check/src/grants.rs`)
reads the switches themselves, in the four sign-in server libraries whose source was read this day to learn
each one's names: django-oauth-toolkit 3.4.1 (`GRANT_PASSWORD`, `GRANT_IMPLICIT`, and an
`authorization_grant_type` of `password` or `implicit` in a fixture), Doorkeeper 5.9.9 (`grant_flows` naming
`password` or `implicit`), fosite 0.49.0 (the compose factories for each grant, and `ComposeAllEnabled`,
which turns on both), and node-oauth2-server 5.3.0 (a client whose `grants` holds `password`; its implicit
response type throws "Not implemented", so there is nothing to find). league's oauth2-server is left out: its
source is fetched from GitHub's archive downloads, which this session's network refuses, and a name recalled
rather than read is not written down as one.

A file is read for a library only when the library is among the app's packages or the file names it, so a
client of someone else's server that lists `grants`, or an app's own method called `grant_flows`, is not its
sign-in server. Lines that are only comments are left out, since Doorkeeper's generated settings file shows
`grant_flows` in one. It is only ever a finding: settings kept in a database, and libraries not listed, are
not seen, and a line that names a grant to refuse it is read as switching it on, which is why its confidence
is medium.
