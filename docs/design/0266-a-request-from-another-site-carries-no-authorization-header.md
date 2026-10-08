# A request from another site carries no `Authorization` header (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 2.1). Two of the signed-in checks send a request as a page on another site
would: `probe.cross-site-request-accepted` (V3.5.1), the create request with another site's Origin and no anti-forgery
token, and `probe.preflight-skipped` (V3.5.2), the same request in the three forms a browser sends without asking the app
first. Both were built from the signed-in session, which for an app signed in by a token carried
`Authorization: Bearer …`. No browser adds that header to a request another site makes. An API that keeps its token in
the page and checks no Origin, which another site cannot use at all, was reported high on both.

- **What is sent now.** The session's cookies, and never the `Authorization` header (`as_another_site_sends` in
  `crates/sv-check/src/signed_in/forgery.rs`).
- **A token and no cookie.** Neither request is sent: both requirements are not assessed, saying that a browser cannot
  carry this session from another site, and that whether the app also takes a cookie was not seen.
- **A token and a cookie.** Taken with the cookies alone is still a finding. Refused is not credited, since without the
  token a refusal may only mean the cookies sign nobody in; it is not assessed, saying so.
- **A cookie and no token.** Unchanged.
- **Not changed here.** The WebSocket handshake from another site (V4.4.2) still carries the session as the run holds
  it. A browser's WebSocket cannot send an `Authorization` header from any page, the app's own included, so an app that
  signs its socket in that way is not one a browser can reach from any page; that check is left as it was.

ADR-021, "Later, 7 October 2026: a request sent as another site carries no `Authorization` header". The fake app gained
`token_login_sets_cookie` (not a flaw: the token sign-in also sets the session cookie), and `forgery.rs` three tests: a
token-only API that takes any Origin in every form (no finding, no credit, both not assessed), the same with a cookie
beside the token (both still found), and that cookie with an app refusing other origins (refused, not credited).

Four guards broken in turn, each caught by its own test among the 388 signed-in tests:
- the `Authorization` header kept, the behavior before;
- a token-only session sent anyway, signing nobody in;
- the request from another site, refused without the token, credited;
- the requests sent without a preflight, refused without the token, credited.
