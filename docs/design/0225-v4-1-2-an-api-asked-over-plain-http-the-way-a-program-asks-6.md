# V4.1.2: an API asked over plain HTTP the way a program asks (6 October 2026)

Left over from "`sv probe`: the questions only the live site can answer" (BACKLOG). The owner decided on 6 October
2026 that `sv probe` may make one more request for it (ADR-027, Later). V4.1.2 asks that only what people open in a
browser redirects plain HTTP to HTTPS. A program written with an `http://` address by mistake that is redirected sends
its request, token and all, unencrypted first, and then works anyway, so nobody finds out.

- **Asked only with `--api /path`**, the path of an address of the app's API on the same site, typed at the terminal
  like the address. `sv` never guesses an API path. Without it, V4.1.2 is not assessed, and the reason says how to ask.
- **One HEAD over plain HTTP**, on port 80 of the same host, held to the checked address like every other request,
  with `Accept: application/json` and this probe's own user agent (`Fetch::get_as_program`).
- **A redirect to HTTPS on this host is a finding**, `probe.api-redirected-to-https` (low). A refusal, any other
  answer, a redirect elsewhere (not followed), or no answer credits nothing, since one address is not every endpoint
  of the API. Each says what it got. It is listed in `RUST_FINDINGS_ONLY`.
- **Five requests with `--api`, four without**: the curl fetcher's cap follows the target. A path is refused unless
  it starts with a single `/`, has no `..`, no spaces, braces, backslashes, or `#`, and is at most 300 characters.

How it is held: four tests in `production.rs` (a redirect found; a refusal, another host, a redirect that stays on
plain HTTP, and no answer each credit nothing and say so; no `--api`, no extra request and the reason; what a path may
be), and `crates/sv-check/tests/probe_curl.rs`, which puts a stand-in `curl` first on the PATH to hold the header and
the cap of five as curl receives them. Twelve guards were undone in turn, and each was caught.
