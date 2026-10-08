# The browser's storage check says what a clean look found (8 October 2026)

Backlog item 218, and the open question at the end of
`docs/design/0310-a-check-that-asked-says-what-it-found-8-october-2026.md`: which check fell silent against a real
app in CI, where the first version of the check guard stopped every debug build.

**What was found.** With Colima running, `sv report --run` on a copy of `examples/notes-with-users` wrote, on its
first run, "V10.1.1, V14.3.3 ... A check asked the app about this and returned without saying what it found
(`storage_check`)". `storage_check` (`crates/sv-check/src/browser_storage.rs`) signs in through the app's form in a
headless browser, opens the private page, and reads everything the page's scripts can read. The example keeps nothing
there, which is the right answer, and the check then wrote only a step ("kept 0 values") and returned: no finding, no
credit, no not-assessed entry. That is the path a correct app with `browser` set always takes, so every CI run that
started the example took it. The fake app had no browser at all, so in sv-check's own tests every browser check
stopped at "the browser could not be started" and said so, and the clean path was never reached. The check's own
unit test of the clean path asserted that nothing was said, as the archive test had before the guard.

**Why `asked!` and not `quiet!`.** Both of its rules are findings only (`tools/coverage.py`), so `quiet!` would have
been allowed. But a clean look is evidence of something: one private page, after one sign-in through the form,
held neither the password nor a sign-in token. Left unsaid, the report showed V10.1.1 and V14.3.3 as if nothing had
asked. So the check now says it, as not assessed, as `production.rs` does for a plain-HTTP answer that redirects:
"In a real browser: after signing in through the form on /login and opening /account, nothing the page's scripts can
read held a sign-in token or the password. One page after one sign-in does not show that the app never keeps either
anywhere, so this credits nothing." When one of the two is found and the other is not, the other is said on its own.
Storage that could not be read (IndexedDB, cookies) is named in the sentence. Nothing is credited, as before; what a
report concludes about the two requirements is unchanged (not assessed), and only the reason is now the check's own.
Kept under `asked!`, so the guard still holds its other paths.

**So the fake app catches it from now on.** `FakeApp` has a `browser` switch: a headless browser that signs in
through the form, opens every page where it was asked for, and finds nothing kept. It answers only a job that signs
in through a form (only `storage_check` sends one); the other two browser checks still see no browser, as before. A
new test, `crates/sv-check/src/signed_in/storage_check_tests.rs`, runs the whole suite with it and first asserts that
the browser really signed in and read the page, then that the check said what it found, in its own words.

Tests and what caught what. The fix switched off: three tests failed, each for its own reason (the new suite test,
stopped by the guard naming `storage_check` and both requirements; the clean-path unit test; the password test's new
assertion that the token, not found, is said apart). The fake browser switched off: the new test fails at its setup
assertion rather than passing on a browser that was never reached.

Not done: the guard still cannot see inside the 16 `quiet!` checks, and the fake browser answers one kind of job;
`browser::checks` and `browser::sign_out_check` against a working browser are still exercised only by their own
unit tests.
