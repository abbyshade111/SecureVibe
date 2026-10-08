# Log markers an app that keeps personal data out of its log still writes (4 October 2026)

On family-hub (3 October) V16.3.1, V16.3.2, V16.2.1, V16.2.2, and V16.2.4 were all not assessed. The owner had
decided never to log email addresses and to strip what follows `?` from logged addresses, and `sv` found its sign-ins
only by the test accounts' email addresses and its refused request only by a marker after `?`. The app logged JSON
lines with the path, a user id, and an event name, which is the log `sv`'s own design prompt asks for (BACKLOG,
"What the owner hit building family-hub", item 4). The owner's decision: markers that are not personal data, in the
address's path, and a not-assessed message that names privacy rules as a likely reason.

**The sign-ins are tied to the log by when, not by who** (`plant_log_markers` in
`crates/sv-check/src/signed_in/signin.rs`; `crates/sv-check/src/logs.rs`). Nothing in a sign-in request can carry a
path marker without changing what it means: a sign-in to `/login/sv-log-…` is a request for a page that does not
exist. So each of the two sign-ins (the refused one, for an account that does not exist, and the accepted one, by an
account used for nothing else) is bracketed instead: just before it `sv` asks for `/sv-log-before-…`, and just after
it `/sv-log-after-…`. Those are requests for pages nobody has, a 404 that means nothing to the app and carries
nothing personal. A line written between the two was written while that one sign-in was handled, and if it names a
sign-in event (`login_failed`, `user.signin`, `Authentication failed`) it is the record of it. The sign-in's own
address is taken out of each line first, so an access-log line `POST /login 401` is not counted as an event because
its path says "login". The refused sign-in's line must also say it failed; the accepted one's must not, and its
window is planted only once the private page opened with its session, so an app that logs `"event":"login"` with
`"ok":false` is not credited with a success. That last check also now applies to finding the accepted sign-in by
name: before, a sign-in that got any answer counted.

A line found this way never stands for *who*: it is tied to the request by when it was written, and an app that keeps
emails out of its log records who by a user id, which an account that does not exist has none of. So V16.2.1 is not
assessed from such a line, saying why; V16.2.2 (the timestamp's zone) and V16.2.4 (the line's format) do not depend
on who and are read from it as before. The bracketing assumes the app writes its lines in the order it handles
requests, which holds for an app writing to one stream or flushing each line, as logging libraries do. An app writing
its events and its requests to different streams with block buffering could put a line in the wrong window; the
failed/not-failed wording and the narrowness of each window (two or three requests) make a false credit from that
unlikely, not impossible, and this is said in `logs.rs`.

**The refused request is asked twice.** First as before, the private page itself with the marker after `?`, so the
request means exactly what it did and an app that logs query strings is read as before. Then with the marker as the
last part of the path under the private page (`/account/sv-log-denied-…`), which an app that strips query strings
still logs. That address is not the private page, so its answer counts as an authorization refusal only when it is
the same refusal the private page got (the same status), and not a 404: an app that guards everything under
`/account` sends both to the sign-in page alike, while one that answers "no such page" was never asked an
authorization question, and neither was one that hides private pages behind a 404, where the two cannot be told
apart. In those cases only the marker after `?` is planted. Reading the status also now splits at commas, so compact
JSON (`{"status":302,"path":…}`) is read; it was split at whitespace only.

The email addresses and the `?` marker are still planted and still read first, so an app that does log them is
assessed exactly as before, and a line found by the account's name still speaks to who. When nothing is found, the
message now names two likely reasons, neither a finding: the app logs to a file or a service, or its privacy rules
keep email addresses and query strings out of its log and it logs neither request paths nor a sign-in event. No
`securevibe.toml` setting was added; one naming the log's user-id field can follow.

Tested in `logs.rs` with a reduced copy of the family-hub log and in `signin.rs` end to end: the suite run against
the fake app with a privacy-minded log (JSON, path only, user ids, no `@` and no `?` anywhere, asserted before
anything is read), an app that answers 404 under the private page, one that hides the private page itself behind a
404, an app that logs emails and full addresses, and a sign-up that does not work. Nine guards were broken in turn,
and each was caught by the test written for it: not taking the sign-in's address out of the line, not requiring the
failed wording, reading the whole log instead of the window, planting the path marker whatever it was answered,
planting it after a 404, bracketing an accepted sign-in that did not work, crediting who from a line found by the
window, reading status at whitespace only, and a message that does not name privacy (two tests). The 404 guard was
at first caught by nothing; the hidden-page fixture was added for it.
