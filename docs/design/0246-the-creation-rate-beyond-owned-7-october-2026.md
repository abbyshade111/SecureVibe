# The creation rate, beyond `owned` (7 October 2026)

Decided by the owner on 6 October 2026 (BACKLOG, the running-app review's V2.4.1 note). The burst check
(`crates/sv-check/src/signed_in/burst.rs`) held one action to the stated `[policy] requests-per-minute`: `owned`'s
create. V2.4.1 asks it of every function that creates something.

- **`creates = [{ path = "/comments", form = { text = "{marker}" } }, …]`** under [stack.run.users] names the app's
  other requests that each create a record. The spec says to put `{marker}` where a value must differ.
- **Each is burst on its own** (`burst_one`), after `owned`'s, by the same signed-in second user, with the same
  minute's pause before and after, and the same rules: all through is a finding naming the request, the first
  through and the last refused as a limit refuses is credit for that action alone, and anything else is said and not
  judged. With no `owned`, `creates` alone is asked; with neither, the report says what to list.

How it is held: `each_request_creates_names_is_held_to_the_stated_limit_on_its_own`, against the fake app's new
`/comments` (limited, or not, apart from notes), finding one unlimited action beside a limited one and crediting both
when both are limited; and `creates_alone_is_enough_and_neither_is_said`. The fourteen burst tests before it still
pass unchanged. Four guards were undone in turn, each caught.
