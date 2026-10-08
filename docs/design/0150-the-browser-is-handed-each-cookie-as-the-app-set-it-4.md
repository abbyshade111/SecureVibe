# The browser is handed each cookie as the app set it (4 October 2026)

On family-hub (3 October) the real-browser checks (V7.4.4, V3.2.2, V14.3.1) said the browser "was not really signed
in". The app's session cookie was `__Host-fh_session`, marked `Secure`; the driver handed the browser each cookie by
name and value alone and never read the browser's answer, and a browser refuses a `__Host-` cookie that is not
`Secure`. The AI coding tool's way round it was `FAMILY_HUB_INSECURE_COOKIES=1` in the start command, so the checks
then passed against a copy of the app with weaker cookies than the real one (BACKLOG, "What the owner hit building
family-hub", item 3).

**Each cookie carries its attributes.** The signed-in checks keep, beside each cookie, the `Secure`, `HttpOnly`,
`Path`, and `SameSite` the app set it with (`Session::browser_cookies`), and the browser is handed them
(`browser::BrowserCookie`). As the owner decided, a name starting `__Secure-` or `__Host-` (in any case, as browsers
match it) is always handed over `Secure`, and a `__Host-` one with the path `/`. `Domain` is never carried: the
browser reaches the app at `localhost`. A cookie with no `Path` gets `/`, as before; a browser would use the folder of
the address that set it, so this can be a little kinder than a browser. Carrying `HttpOnly` also means a page's own
scripts can no longer read a session cookie the app keeps from them, as in a real browser.

**The browser's answer is read, and a refusal is said by name.** Cookies are now set by an action of the job, never
before it, so every cookie handed over has an answer: `{"refused": [{"name", "why"}]}`, from DevTools' error (or an
older browser's `success: false`). When the private pages then do not open, the not-assessed reason ends "Handed the
first user's cookies, the browser refused the cookie `__Host-sid` (Sanitizing cookie failed), which may be why"; the
sign-out check (V14.3.1) says the same. When they open anyway, the step says which cookie was refused.

**A start command that looks like it weakens the app is warned about, not refused** (`sv_run::weakening_named_in`).
Each environment variable or flag in the start command is split into words at `_`, `-`, and `.`, and listed when a
word is `insecure`; or a word is `disable`, `disabled`, `skip`, `bypass`, or `no` and another names security (`auth`,
`csrf`, `xsrf`, `secure`, `security`, `ssl`, `tls`, `https`, `hsts`, `csp`, `verify`, `captcha`, `mfa`, `2fa`,
`totp`, `ratelimit`, with `rate_limit` counting); or a word names security and the value is `0`, `false`, `no`, or
`off`. Nothing else: `NEXT_TELEMETRY_DISABLED`, `--no-cache-dir`, and `DEBUG=1` are not listed. It is said on the
terminal before the run and at the end of the report's note about the run; a value is shown only when it is a short
on-or-off word, so a key set beside it is never printed.

**Tested.** With sv's own Chromium (`chromedp/headless-shell:151.0.7922.109`) through the real driver, an app that
opens its private page only for `__Host-sid` signs the browser in, a 5,000-byte cookie is refused and named, the
browser sends back only the cookie it kept, and `HttpOnly` hides it from the page; handed over as before, the same
Chromium refused `__Host-sid` with "Sanitizing cookie failed", as Chrome 154 did on the owner's Mac. End to end
(`crates/sv-cli/tests/host_cookie.rs`), `examples/notes-with-users` changed to a `Secure` `__Host-sid` cookie, an
oversized second cookie, and `FAMILY_HUB_INSECURE_COOKIES=1` in its start command: `sv report --run` signs the
browser in, names the refused cookie, and warns in the terminal and the report. With the old driver, the same app
reproduced family-hub's "not really signed in" and now named `__Host-sid` as refused. Eight guards broken in turn:
the driver dropping the attributes (two tests, the real-browser one and the end-to-end one), no `Secure` for prefixed
names (two: a unit test and the real-browser one), the driver not reading the answer (two), the check ignoring
refusals (two: a unit test and the end-to-end one), the report note left out (one, end to end), and each of two
warning rules dropped (one or two). Not parsing `Secure` was at first caught by nothing, since every `Secure` cookie
in the tests also had a prefix; a plain `Secure` cookie was added to the unit test, which then caught it.
