# What the owner hit building family-hub (3 October 2026) and my-first-app (4 October 2026), never reported

**Status:** done, as its markers read on 8 October 2026

Found on 4 October 2026 by the cato-pipeline session while updating `docs/paper` (the usability analysis,
`figure-usability.html`), from the two builds' transcripts on the owner's Mac. Each item says what happened, the
cause in `sv` at `main` 6d4ce3f, and how it was confirmed: *Reproduced* (run here), *Read* (from the code), or
*Plausible*. Items already in this backlog got a dated note on their entry instead: the "install `sv`" step
(under "Packaging `sv`"), the build folder `sv` cannot leave (the walk-through's item 2), Bandit reading
`vendor/` (S7), the Django rule and a regular-expression rule (the measured false-alarm entry), the
`.DS_Store` gap (H22). The SQL false alarms are A1's, and the 7 of 25 reviews a newer `sv` did not recognize
are R3's. **Each item can be claimed on its own.**
1. **The starter file's example start command listens where `sv` cannot reach it.** family-hub, 3 October: the
   first `sv report --run` waited 60 seconds and said "The app started but never answered on its health path
   within 60s. Its last output was: WARNING: This is a development server...". The AI tool had followed the
   starter file's own example, `start = ""  # e.g. "uvicorn app:app --host 127.0.0.1 --port $PORT"`
   (`crates/sv-manifest/src/spec.rs`, line 25). Inside its container, an app that listens on 127.0.0.1 answers
   only itself, and `sv` asks from a second container on the fenced network (`crates/sv-run/src/docker.rs`, line
   8). The AI tool found this by reading `sv`'s source, changed the command to `--host 0.0.0.0`, and the next run
   worked. The message (`crates/sv-run/src/lib.rs`, lines 81 to 94) gives no hint; it already has a special case
   for a read-only file system. *Read*, and the transcript. Fix: the example says `--host 0.0.0.0`, with a comment
   on why; the "never answered" message says that an app listening on 127.0.0.1 or `localhost` cannot be reached;
   and `sv` could warn before waiting when the start command itself names 127.0.0.1 or `localhost`.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-1-host`.
   **Done the same day** (DESIGN, "An app listening on 127.0.0.1 is named as the likely cause"): the example says
   `--host 0.0.0.0` and why; "never answered" says an app listening on 127.0.0.1 or `localhost` cannot be reached,
   and names the address as the likely cause when the start command names it; and `sv` warns before waiting when it
   does, then starts the app anyway. Tested with a real container on 127.0.0.1 (shown to be up by answering itself)
   and a control on 0.0.0.0; each of five guards broken on its own was caught, the warning and the message's naming
   only by the container test.
   **Part status:** done, 4 October 2026
2. **Two runs at once write the same report folder, and the one that finishes last wins, even when it failed.**
   family-hub, 3 October: the AI tool and the owner each ran `sv report --run --tools` on the app, at about the
   same time. The AI tool's run succeeded at 14:55 (Eastern); the owner's finished two minutes later with the
   "never answered" failure and replaced the good report with the failed one. The AI tool guessed the owner's run
   had started before it fixed the start command (item 1); the transcript does not show when it started, so why
   it failed is not established. `sv report` writes to `<app>/securevibe-report` unless told otherwise
   (`crates/sv-cli/src/main.rs`, line 3962) and replaces each file (`write_report_files`, line 2400, called at
   3982), with nothing to say another run holds the folder or that a newer report is there. *Read*, and the
   transcript. Related: S6 and S10 (two runs at once share tool reports and container names). Fix: a lock in the
   report folder while a run is writing it (refuse, saying which run holds it), and record in `report.json` when
   the run started and a hash of the `securevibe.toml` it read, so a report older than the one it replaces says
   so rather than replacing it quietly.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-2-report-lock`.
   **Done the same day** (DESIGN, "One run at a time in a report folder"): `sv report` and the MCP server take a
   lock in the report folder before the run, and a second run refuses at once, naming the first (command,
   process, start time). The lock is the operating system's, let go when a run ends however it ends, so a run
   killed outright does not block the next, which says it stopped before it finished. `report.json` records
   when its run started and the SHA-256 of the `securevibe.toml` it read; a run does not replace a report from
   a run that started later, and a file changed during the run is said. Tested with real processes of the real
   binary (a `--run` kept going by a sleeping test command, a second run beside it, `kill -9`); breaking each
   guard was caught, and testing found a second run calling the folder someone else's while the first wrote its
   marker, and Ctrl-C leaving the newly made folder behind, both fixed. S6 and S10 are unchanged.
   **Part status:** done, 4 October 2026
3. **The real-browser checks cannot sign in to an app whose cookies use the `__Host-` prefix, so the AI tool
   weakened the app's cookies for the run.** family-hub, 3 October: the browser checks (V7.4.4, V3.2.2, V14.3.1)
   said "the private pages did not open in the browser with the first user's cookies, though they opened for the
   plain requests, so the browser was not really signed in". family-hub names its cookies `__Host-fh_session` and
   the like, marked `Secure`. The browser driver hands each cookie to the browser by name and value only, with no
   `secure` (`crates/sv-run/assets/browser-driver.mjs`, lines 78 to 79 and 192 to 193; `browser.rs`, line 287),
   and does not look at the browser's answer. A browser refuses a `__Host-` cookie that is not `Secure`.
   *Reproduced* on Chrome 154 on this Mac (headless, through the same DevTools call): `__Host-fh_session` set as
   the driver sets it was refused ("Sanitizing cookie failed"); with `secure: true` it was kept on
   `http://localhost`; a plain name was kept either way. Not tried on the Chromium in `sv`'s browser image. The AI
   tool's own explanation, that the browser drops `Secure` cookies over plain HTTP, is not what the code shows:
   the browser reaches the app at `http://localhost`, which browsers treat as secure (`docker.rs`, line 386). Its
   workaround was `FAMILY_HUB_INSECURE_COOKIES=1` in `sv`'s start command, which also drops the prefix: the
   browser checks then passed, against a copy of the app whose cookies are weaker than the real one. Fix: carry
   each cookie's attributes from the sign-in answer (at least `Secure`, and `Secure` for any `__Host-` or
   `__Secure-` name), check the browser's answer to each cookie, and when one is refused say that, by name.
   **The owner's decision, 4 October 2026:** fix the cookie handling as above, and also warn in the report when the start command looks like it weakens the app for the run (an environment variable naming `INSECURE`, `DISABLE_`, or the like): a warning, not a refusal.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-3-cookies`.
   **Done the same day** (DESIGN, "The browser is handed each cookie as the app set it"): each cookie reaches the
   browser with the `Secure`, `HttpOnly`, `Path`, and `SameSite` the app set (`Secure` always for a `__Host-` or
   `__Secure-` name, and path `/` for `__Host-`); the browser's answer to each is read, and a refused cookie is
   named in the not-assessed reason, or in the step when the pages opened anyway. A start command with a setting
   that looks like it weakens the app (`INSECURE`; `DISABLE`, `SKIP`, `BYPASS`, or `NO` beside a security word;
   a security word set to 0, false, no, or off) is warned about on the terminal and in the report's note about the
   run, and the run goes on. Tested in sv's own Chromium 151, which refused `__Host-sid` handed over the old way
   ("Sanitizing cookie failed"), and end to end with a `__Host-` copy of `examples/notes-with-users` started with
   `FAMILY_HUB_INSECURE_COOKIES=1`. Each of eight guards broken was caught; parsing `Secure` was caught by nothing
   at first, until a test cookie with `Secure` and no prefix was added.
   **Part status:** done, 4 October 2026
4. **The log checks need the test account's email address in the log, and an app that keeps personal data out of
   its log cannot be checked.** family-hub, 3 October: V16.3.1, V16.3.2, V16.2.1, V16.2.2, and V16.2.4 were not
   assessed ("Neither sign-in was named in the app's output", and "no such line was found"). The owner's
   decisions, in `security-notes.md`, were never to log email addresses (V16.1.1) and to strip what follows `?`
   from logged addresses (V14.1.2). `sv` finds its sign-ins in the log by the test account's email
   (`crates/sv-check/src/signed_in/signin.rs`, lines 388 and 395 to 401), and its refused request by a marker
   after `?` (lines 404 to 416); `crates/sv-check/src/logs.rs` (lines 137 and 162) then reports not assessed.
   The app logged JSON lines with a user id and an event name, which `sv` cannot tie to its test account. The
   not-assessed message names a log file or a service as the likely reason, not privacy. Note that `sv`'s own
   design prompt 6 ("never passwords or personal data") asks for exactly the log that blinds this check. *Read*,
   and the transcript. Fix: plant markers an app may log without personal data (a marker in the path's last part
   rather than after `?`, a `User-Agent` or request-id header), and say in the message that an app keeping emails
   and query strings out of its log ends up here.
   **The owner's decision, 4 October 2026:** plant markers that are not personal data (in the address's path, not after `?`), and make the not-assessed message name an app's privacy rules as a likely reason. A `securevibe.toml` setting naming the log's user-id field can follow later.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-4-log-markers`.
   **Done the same day** (DESIGN, "Log markers an app that keeps personal data out of its log still writes"):
   each of the two sign-ins is bracketed by requests for pages nobody has (`/sv-log-before-…`, `/sv-log-after-…`),
   and a sign-in event written between them (`login_failed`, with the sign-in's own address taken out first) is
   its record, so no personal data is needed; the refused request is also asked with the marker as the last part
   of the path under the private page, counted only when the app refused it exactly as it refused the page and not
   with a 404. Emails and the `?` marker are still read first. A line found by the window is not credited with
   *who* (V16.2.1 not assessed, saying why). The not-assessed message names privacy rules (no emails, no query
   strings in the log) as a likely reason. Tested against the fake app writing a family-hub-style log (JSON, path,
   user id, no `@` or `?`, asserted): V16.3.1, V16.3.2, V16.2.2, and V16.2.4 are now assessed. Each of nine guards
   broken on its own was caught by its own test; the 404 guard was caught by nothing until a fixture was added.
   No `securevibe.toml` setting.
   **Part status:** done, 4 October 2026
5. **The admin checks sign the admin in with a password alone, so they say nothing about an app that requires an
   authenticator for admins.** family-hub, 3 October: the owner asked for an authenticator code to be required for
   admins. The AI tool warned beforehand that the seeded admin "has no authenticator app, because `sv` signs it in
   with a password alone", and the run reported V8.2.1 and V8.3.1 as not assessed: "The admin account did not open
   /family either, so the ordinary user being refused says nothing: the page may not be where securevibe.toml
   says" (`crates/sv-check/src/signed_in/admin.rs`, lines 50 to 57). The page was where the file said. `sign_in`
   sends only the `login` form (`crates/sv-check/src/signed_in/mod.rs`, lines 578 to 627); the `totp` step is
   used only for one extra account made for the two-factor checks (`SV_USER_TOTP`; `spec.rs`, lines 129 to 133).
   `sv`'s design prompt 7 recommends "two-factor sign-in for admins". *Read*, and the transcript. Fix: give the
   seeded admin a secret too when `totp` is set (`SV_ADMIN_TOTP_SECRET`) and finish its sign-in with the code; and
   when the admin's sign-in ends on the `totp` path, or any page other than the private one, say that rather than
   suggest the page is in the wrong place.
   **The owner's decision, 4 October 2026:** yes, `sv` may read a test admin's authenticator secret from `SV_ADMIN_TOTP_SECRET`, held like `SV_USER_TOTP` and never shown in a report; and fix the message either way.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-5-admin-totp`.
   **Done the same day** (DESIGN, "An admin who signs in with a code"): when there is an admin, a `totp` entry
   and a `seed`, `seed` is given `SV_ADMIN_TOTP_SECRET`, made fresh for each run like `SV_TOTP_SECRET`; when the
   admin's password alone does not open the private page, both admin checks give the code worked out from it
   (once more after the next 30-second step if the app refuses a code already used). When the admin is still not
   shown signed in, the reason says where its sign-in stopped (the authenticator step, a refused code, or a step
   the manifest does not name) and no longer blames the page. A failed `seed`'s output no longer carries the
   run's passwords or secrets into the report. Tested against the fake app with the admin enrolled, with, without,
   and with the wrong secret, and a leak test over everything the run hands the report; each guard broken in turn
   was caught (no code, the old reason, no second try, the secret in a step, no redaction, the secret not given
   to `seed`, no secret made).
   **Part status:** done, 4 October 2026
6. **A test-name warning that says it does not take the credit away does take it away.** family-hub, 3 October:
   V6.3.3 and V2.3.2, each backed by passing tests and by the owner's own check by hand, and V8.3.1, backed by the
   owner's answer, read "needs attention" because of `tests.name-does-not-match-requirement`: a test named for the
   requirement shares no words with it. That finding is information, low confidence, and its own text says "about
   a third of these are honest tests written in different words, which is why this does not take the credit away"
   (`crates/sv-check/src/suite.rs`, lines 456 to 489). But any finding at all makes a requirement "needs
   attention" (`crates/sv-report/src/lib.rs`, lines 1032 to 1033). *Read*, and the transcript. The AI tool
   proposed recording the three as false alarms rather than renaming tests to suit the word match, and the owner
   signed them, seven test-name entries in all, with the rest. That made it worse: a requirement with a finding set
   aside as a false alarm can never be "checked" by another check (`lib.rs`, lines 1027 to 1036), so in the last
   report of the day V10.5.2 and V10.1.2, each with a passing test named for it, read "not verified", and V6.3.3
   and V2.3.2 rested on the owner's word by hand rather than on their tests. Following the warning's own advice
   cost the credit it says it leaves alone. *Read*, and family-hub's `report.json` of 3 October. Fix: show this
   finding (and any information-only one) beside the credit rather than over it, and let a person's "these do
   match" on it leave the test's credit standing; or, if it is meant to override, say so in its text.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-6-test-name-credit`.
   **Done the same day** (DESIGN, "A finding that says it leaves the credit alone does"): `Finding::withholds_credit`
   is false only for a rule listed in `INFORMATION_ONLY` (today the test-name rule alone) at `info` severity with
   nothing merged into it. Such a finding is shown beside the requirement's status ("also noted, for information,
   and not counted against it") instead of deciding it, and setting it aside as a false alarm leaves the test's
   credit standing; every other finding, a tool's at `info` included, still makes its requirement need attention.
   Tested with three report tests (beside the credit, the real-finding control in four forms, and the false-alarm
   review) and an assertion in the suite's own test; seven guards broken in turn, each caught, and letting no
   finding withhold credit turned twelve tests red.
   **Part status:** done, 4 October 2026
7. **Two false alarms of `sv`'s own rules, one of which ended with working code removed.** family-hub,
   3 October. (The third kind the owner met, SQL "built by joining text" from fixed text, is A1.)
   - `secrets.credential-assignment` rated an error message high: `WRONG_PASSWORD = "Your current password isn't
     right."` in `familyhub/views/account.py`, with the advice to "change the credential". The rule takes any
     name containing `password` assigned 8 to 200 characters of quoted text with enough variety of characters
     (`crates/sv-check/src/secrets.rs`, lines 211 to 241 and 326 to 357), and a sentence passes that test.
   - `ast.open-redirect` flagged `redirect(destination)` in `familyhub/signin.py`, where `destination` was a
     parameter that every caller filled with `url_for("home.index")`. The finding said "possible" and to read the
     code first; the AI tool still offered to remove the parameter "which ... clears the finding", and the owner
     agreed. The removal was harmless here, but it is code changed to quiet a rule. The "Three false alarms on
     code that does the safe thing" entry's item 3 is the checked-destination form of the same rule.
   *Reproduced* both, on a three-file scratch app with `sv check` built at 3f1f2b5 (the family-hub build); the
   credential and redirect rules are unchanged between 3f1f2b5 and 6d4ce3f. Fix: for the credential rule, leave
   out a value with spaces between ordinary words that ends in a period or question mark, or at least rate it
   low with "this reads like a sentence"; for the redirect rule, when the value is a parameter, look at the
   function's callers in the same app and stay quiet when every one passes the app's own route.
   **The owner's decision, 4 October 2026:** the credential rule keeps reporting a value that reads like a sentence, at low severity with "this reads like a sentence", rather than leaving it out (a real passphrase can be a sentence). The redirect half is left to whoever takes A1, its root cause, so two sessions do not change one rule; only the credential half is claimed here.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-7-sentence-credential`.
   **Done the same day**, the credential half (DESIGN, "A credential name over a sentence is reported low, and
   says so"): a value of three or more ordinary words, one space apart, ending in `.`, `?`, or `!` is still
   reported, at `low` severity and "possible", with "this reads like a sentence" in its title, description, and
   advice; everything else keeps `high`. The value now runs to the quote that opened it (an apostrophe used to cut
   the family-hub line to `Your current password isn`). Redaction is unchanged. Tested with four tests: six
   messages reported low, eleven passphrase, key, and token controls each shown still `high`, a table of what is
   a sentence, and quote pairing; nine guards broken in turn, each caught, one only after a control was added.
   Found: with `--tools`, Bandit's B105 on the same line now wins the merge and the sentence note is lost (not
   changed; it is the merge's rule for all findings). The redirect half is A1's, untouched.
   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-7-sentence-credential`: the Bandit merge follow-up above.
   **Done the same day** (DESIGN, the same section, "The merge keeps `sv`'s words"): `merge_same_place` keeps the
   most severe finding's words, then `sv`'s own rule's over a tool's, then the surer. It keeps that finding's own
   confidence, carries the redacted value, and says in one line how `sv`'s own rules rated the line when a more
   severe tool finding is kept. It never copies a tool's text, which can quote the value (S8). A review naming a
   merged-in rule still counts. The family-hub line under `--tools` now reads "reads like a sentence", with
   Bandit in "also reported by", shown with a stand-in and with the real Bandit 1.9.4. Ten guards broken in turn,
   each caught. Changed: at the same severity a less sure `sv` finding is now kept over a tool's.
   **The redirect half claimed on 5 October 2026 by session securevibe-e10**, at the owner's asking, in branch
   `claude/a1-redirect-callers`: when the destination is a parameter of the enclosing function, look at that
   function's calls across the app's Python, and when every one passes the app's own route (`url_for(...)`) or a
   path on this site, keep the finding and say so, naming each call, as the owner decided for a destination a
   function checked (item 3 of "Three false alarms on code that does the safe thing"). Not made quiet.
   **Done the same day** (DESIGN, "A redirect to a parameter every caller fills with the app's own route says
   so"): the finding stays, and when every use of the function's name across the app's Python is a call, its
   definition, or an import, and every call passes or leaves to a default what the rule counts as safe on its own,
   it names each call and says removing the parameter only to clear the finding is not a fix. Python only. Ten
   guards broken in turn, each caught.
   **Part status:** done, 5 October 2026
8. **`sv run --slow` waits out the idle timeout and then reuses the session it let expire.** family-hub,
   3 October: after the 31-minute wait (which did credit V7.3.1), the run's later steps went wrong: "A signed out
   (400)", record creation and the real-browser checks failed, where the normal run minutes before had passed
   them. The AI tool reproduced the app's answers and concluded the run had reused a session from before the
   wait. The code agrees: A's main session is made first (`crates/sv-check/src/signed_in/mod.rs`, line 1156); the
   timeout checks then wait with sessions of their own (lines 1211 to 1223, whose comment says "nothing below is
   using them"); and every step after, from the owned records (line 1228) to the browser and the admin checks,
   uses A's main session, which sat idle through the whole wait. *Read*, and the transcript. Fix: sign A in
   again after the wait (or run the waiting checks last), and test it with the fake app's idle limit shorter than
   the wait.

   **Claimed on 4 October 2026 by the cato-pipeline session**, at the owner's asking, in branch
   `claude/build-item-8-slow-session`.
   **Done the same day** (DESIGN, "A fresh sign-in after the `--slow` wait"): when the timeout check has waited,
   A signs in again through the sign-in page (so a form token comes with the new session) and is shown opening
   the private page before any later check uses the session; when that fails the run stops and says why, as it
   does when the first sign-in fails. The timeout check keeps the two sessions of its own it always had. Tested on
   the fake app's clock with sessions that end after 15 idle minutes: a correct app earns every credit with
   `--slow` that it earns without, seeded and through sign-up, and sign-ins refused during the wait leave the rest
   not assessed with the reason. With the fresh sign-in turned off, both tests failed: six credits lost, and the
   sign-out credited with a dead session. No test caught it before.
   **Part status:** done, 4 October 2026
