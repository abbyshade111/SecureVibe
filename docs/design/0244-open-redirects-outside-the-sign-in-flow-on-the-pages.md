# Open redirects outside the sign-in flow, on the pages `redirects` names (7 October 2026)

Decided by the owner on 6 October 2026 (BACKLOG, the running-app review's item 8). `probe.open-redirect` gave an address
outside the app only to the sign-in and sign-out, since a redirect anywhere else is at an address only the app knows.
The owner chose a new optional field to name them.

- **`redirects = ["/go", …]`** under [stack.run.users]: the app's own pages that send the browser on to an address
  they are given (a "continue to" link, a language switch that returns where it came from). The spec says what to
  list.
- **`page_redirect_check`** (`crates/sv-check/src/signed_in/redirects.rs`) signs A in once, then asks each page with
  the same outside address as the sign-in check (`sv-redirect.invalid`, full and beginning with `//`) in the same
  nine return parameters, and reads each answer's `Location`. A page that sends the browser there is a finding,
  "A page of the app sends the browser to any address it is given", under the same rule (V3.7.2), medium, and only
  ever a finding: a page that sends the browser home says nothing about pages nobody named. A sign-in that fails
  says the pages were not asked. Nothing is asked when nothing is named.

How it is held: `a_page_named_in_redirects_that_goes_anywhere_is_found_and_one_that_stays_home_is_not`, against the fake
app's new `/go` (which follows `next` to its own pages, and anywhere with `go_anywhere`), with a page that stays home
and an app that names nothing as its controls; and `a_sign_in_that_fails_says_the_named_pages_were_not_asked`. Six
guards were undone in turn, each caught. A condition copied from the sign-in check (no asking when sign-in answers
with a token) was left out, since a session reached through a token works here too; the spec's line for the field
is documentation, not held by a test.
