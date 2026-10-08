# A delay counts only when every attempt past the limit shows it (5 October 2026)

H16 of the deep review: the password-guessing check (V6.3.1) and the emailed-code guessing check (V6.6.3) credit an
app that slows down past the limit the owner states. Each compared one time with one: the last attempt against the
first. Both times include the time `docker exec` takes to start the request in the test container, which varies
from one request to the next, so one slow start credited a limiter that was not there, and a slow first answer hid a
limiter that was (ADR-021, Later).

- **`slowing`** (`crates/sv-check/src/signed_in/signin.rs`) takes the quickest attempt within the limit as the
  baseline, since the container's time only ever adds, and counts a delay only when every attempt past the limit
  is four times as long and at least 900ms longer.
- **Two attempts past the limit**, so there are two to agree: each check makes the number allowed plus two, at
  most 26.
- **A request no limit slows, as a control.** The password check already fetches the sign-in page before each
  attempt; it is now timed, and a page as slow as the attempts beside it means the slowness was not the sign-in's.
- **When the times disagree, it is not assessed,** with the times, unless a different answer or a refusal settles
  it, as before. Neither a pass nor a finding rests on a timing the run cannot stand behind.
- **The fake app can answer chosen requests late** (`FakeApp::slow_ms`), in real time, the only wait in it not on
  its own clock, so the tests time what the checks time.

What is not done: the time is still measured from outside the container. Timing the request inside it would take the
container's own time out of the number altogether; it needs a change to how `sv-run` sends requests, and a
container to test it in.

How it is held: `a_delay_counts_only_when_every_attempt_past_the_limit_shows_it` and
`an_app_that_slows_every_attempt_past_the_limit_is_credited_and_one_slow_attempt_is_not` (`signin.rs`), and
`a_code_guessing_delay_counts_only_when_both_codes_past_the_limit_show_it` (`codes.rs`). Eight guards were undone in
turn: the quickest as the baseline, both attempts slow, the control, the page times passed to it, the not-assessed
outcome in each check, and the second attempt past the limit in each. Each was caught.
