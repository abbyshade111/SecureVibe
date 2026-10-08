# An error answer is credited only when the app was made to give one (8 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 1.6; BACKLOG, item 3; ADR-056). `probe.error-detail-leak` asked the
running app for a page that does not exist, and when the answer carried no stack trace it credited V16.5.1 (errors
answered with a generic message) and V13.4.2 (debug mode off). It did so in 177 of about 190 trial builds that
started. Frameworks show their traces when the app's code fails, not when a page is missing, so a clean 404 showed
neither.

- **The app is made to fail, without changing anything.** Signed out, `sv` sends `{"sv-probe": `, which is not JSON,
  marked as JSON, to the health path, the root, and the routes securevibe.toml names that read a body: `signup`,
  `login`, and `owned`'s `create` (`bad_body_request` and `error_requests` in `crates/sv-check/src/probes.rs`;
  `body_routes` in `crates/sv-cli/src/main.rs`). A body that does not parse creates nothing. To a sign-in route it is
  one failed sign-in naming no account.
- **What is credited.** V16.5.1, only when at least one answer was an error the app produced (400, 422, or 500 to 599
  other than 501) and no answer, the missing page included, carried a trace. V13.4.2, only when one of them was a
  server error: Flask answers a body it cannot read with a plain 400 whether debug mode is on or off, and a debug page
  shows on a failure. The credit names each request and its status.
- **What is found.** A trace in any answer to the body: "An error answer shows how the app is built", naming each
  request and what it showed. Express's default error handler prints the stack of a body it cannot parse in
  development, which the missing page never showed.
- **What the report says otherwise.** No error drawn: "V16.5.1, V13.4.2" is a gap, naming the requests answered
  without one. Only refusals: "V13.4.2" is (`error_answer_gap`).

Most apps lose both credits from the missing page alone. Tests: `an_error_answer_is_credited_only_when_the_app_was_made_to_give_one`
and `a_bad_body_goes_to_each_route_that_reads_one_once` in `probes.rs`; `a_bad_body_goes_to_the_routes_the_manifest_names`
in `main.rs`; and `sv-run`'s trace-keeping test, whose control now needs an error answer. Six guards were broken in turn
and a test went red each time: a 404 counted as an error, debug mode credited from a 400, the missing page not held to
the rule, a trace in an error answer not found, the old credit from the missing page alone, and no routes taken from
the manifest.
