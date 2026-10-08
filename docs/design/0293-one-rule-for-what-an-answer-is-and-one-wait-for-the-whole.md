# One rule for what an answer is, and one wait for the whole run (8 October 2026)

Items 6 and 7 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026"). ADR-021's rule, that a crash's or a rate limiter's answer is never read as the app refusing, was written out in
seven places with three definitions; one of them read only a 429 as the limiter's and missed the 503 with
`Retry-After`, another counted that 503 as a crash. And three of the suites that ask the running app (sign-in through
the test provider, the app as an MCP server, the fetch) took the app's answers as they came, never waiting a limiter
out, where the anonymous and signed-in questions had `Patient` to do it. The sidecar the questions are sent through
lived a fixed 900 seconds set apart from the 300 seconds each suite could spend waiting, so a run that waited could
outlive it, and then every request read as "no answer" with nothing naming why.

Three changes:

- **`answer_of`** (`crates/sv-check/src/signed_in/mod.rs`) is the one rule: `Answered`, `Silent`, `Crashed`, or
  `Limited` with the seconds the app asks. The seven places read it; the two readings that changed are said in
  ADR-021's entry.
- **`Patient` around the three suites**, in the run's script, with one waiting budget (`MOST_WAITING`) shared by every
  suite of the run through `Patient::within` and `Patient::settle`, which says what the limiter and the crashes left
  exactly as the signed-in suites say it. The AI suite stays outside it, for the reason ADR-021's entry gives.
- **The sidecar's life is built from the same budget** (`SIDECAR_SECONDS = 600 + MOST_WAITING`, the same 900), and
  `probe` tells a lost sidecar from a silent app: the first request Docker answers with "No such container" or "is not
  running" is written down (`RunOutcome::sidecar_lost`), and the terminal and the report say that every question
  after it got no answer because nothing was there to send it.

Held by `one_rule_says_what_an_answer_is`, the two script tests named in ADR-021's entry, and
`a_lost_sidecar_is_told_from_a_silent_app`. With `Patient` taken off the MCP suite on purpose, the script's limiter
test failed; restored, all pass.
