# Old TLS versions on the live site (3 October 2026)

`sv probe` now makes one handshake offering only TLS 1.0 and 1.1 (V12.1.1, level 1). Both versions were retired in
2021. One handshake asks about both: a site that completes it accepts at least one of them.

- **Still at most four requests.** It is asked only when the certificate passed, the same run in which the stapling
  question (V12.1.4) may be asked and the unverified retry is not. A run is then HTTPS, the stapling question when
  the certificate names an OCSP responder, this handshake, and plain HTTP: four, the cap `CLAUDE.md` states, with no
  slack left. The backlog item said this would need the cap raised; it did not.
- **Only a certificate this machine trusts.** With verification on, a certificate problem fails the handshake too,
  and must never read as the site refusing old TLS.
- **Only the site's own words count as a refusal.** Measured on 3 October 2026 with three builds of curl. A server
  that will not speak TLS 1.0 or 1.1 sends the `protocol version` alert, which curl prints as `alert protocol
  version` through LibreSSL and OpenSSL alike (github.com, www.digicert.com), and LibreSSL prints `wrong ssl version`
  when a server answers with a version it was not offered. Everything else is not an answer: OpenSSL 3 at its
  default security level will not offer the old versions at all and fails on its own side (`legacy sigalg
  disallowed`, `no protocols available`), and a server reset the connection in one case. A check that read those as
  refusals would credit every site probed from a modern Linux machine.
- **OpenSSL is told to offer them.** When `curl --version` names OpenSSL, the handshake adds `--ciphers
  DEFAULT@SECLEVEL=0`, with which curl 8.12.1 on OpenSSL 3.0.17, and Debian trixie's curl in a container, completed
  handshakes with badssl.com's TLS 1.0 and 1.1 servers. macOS's curl, on LibreSSL 3.3.6, offers them as it is and
  refuses that cipher list. Asking `curl --version` opens no connection.
- **Only ever a finding.** V12.1.1 asks two things: that only recent versions are enabled, and that the newest is
  the one preferred. curl reports no negotiated version a program can rely on: `%{json}` has none, and its verbose
  output differs by library (OpenSSL's printed `TLSv1.3` for a server that speaks only TLS 1.2). So a refusal is
  said in the report, with the site's words, and V12.1.1 is not credited. `tools/coverage.py` lists the rule in
  `RUST_FINDINGS_ONLY`.

Tried on 3 October 2026 with the built `sv probe`: github.com and www.digicert.com refused, through both curls.
badssl.com's TLS 1.0 server was found through LibreSSL's curl. Through OpenSSL's curl its ordinary HTTPS request
could not connect at all, so everything about it, V12.1.1 included, was reported as not assessed.
