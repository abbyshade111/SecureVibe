# Prompts to give your AI coding tool before it writes any code

These are the design-time companions of the [prompt library](../PROMPTS.md). Each one asks your AI coding tool to
**decide something with you, write it down, and only then build it**: who may do what, the limits on abuse, what the
app logs, how sign-in works. They come from the OWASP Secure by Design checklist (version 0.5.0, a draft of August
2025), which `sv` loads alongside the ASVS. The same prompts, with the checks behind them, are in
`data/design-prompts.json`.

**What "helps you answer" means.** Every Secure by Design control is a design question that a person answers. No
check can settle one, so a prompt here never *meets* a control: it helps you answer it, and it is checked through
the ASVS requirements the control is paired with, which `sv` can test on the running app.

**How they were tested (4 October 2026).** The test app was a small club site in Python's standard library:
sign-in, private notes, one seat to book, an assistant that calls an AI service, and an admin page for
announcements. Fresh helper agents of the same Claude model built it twice without any prompt and once with each
prompt, each in a folder of its own, and `sv report --run` checked every build behind its network fence (with
`--slow` where sessions are timed). `securevibe.toml` held no limits or session times: where a build wrote its
own, `sv` held it to those, and where it wrote none, `sv` used numbers standing in for the owner's (5 wrong
passwords in 15 minutes, 10 records a minute, 2 minutes unused, 4 minutes in all). A prompt is listed under "Shown
to work" only when the build with it passed its check and the builds without it failed. For a check that only ever
gives credit, failing means not credited. One build each is a small sample.

An earlier round, in which `securevibe.toml` already held those numbers, showed why they were taken out: builds
without any prompt read them and enforced them, so the file itself was acting as the prompt. Writing your numbers
into `securevibe.toml` is worth doing for that reason alone.

## Shown to work

### Decide the limits on abuse, write them down, and enforce them

> Before building sign-in or anything people can create, decide the limits with me and write them down.
>
> 1. Ask me how many wrong passwords in a row the app should allow before it pushes back, and how many
>    records (notes, posts, messages) one person may create in a minute. Suggest sensible numbers if I
>    am not sure. If securevibe.toml already has them under [policy], use those.
> 2. Write the numbers into securevibe.toml under [policy] as `failed-sign-ins`, `within-minutes`, and
>    `requests-per-minute`, and into security-notes.md under "Business limits" and "How sign-in is
>    protected against guessing".
> 3. Enforce them on the server, counted per account (an IP address is easy to change, so not only by
>    address). Once a limit is passed, answer with 429 Too Many Requests, say when to try again, and keep
>    refusing until then.
> 4. Write a test that goes one past each limit and shows the app pushes back.

*Helps you answer:* Secure by Design RR-07. *Checked through:* ASVS V2.4.1, V6.3.1.

*What it showed:* With the prompt the build wrote 5 wrong passwords in 15 minutes and 10 records a minute into securevibe.toml, enforced both, and was credited on both. Both builds without it were found on both. Neither limited new records at all. Each did lock an account after wrong passwords, but after 10, a number it chose and wrote down nowhere, so `sv` held it to the 5 standing in for the owner's: for wrong passwords, what the prompt changed is that the number was decided and written down.

### Decide what the app logs, and how each line reads

> Before building, decide what the app writes to its log, and put the list in security-notes.md under
> "What the app logs". At least:
>
> - every sign-in, successful or refused, with the account name that was tried;
> - every request refused because the person was not allowed (not signed in, the wrong user, not an
>   admin);
> - every admin action;
> - every limit that was hit.
>
> Each line carries the time with its time zone (for example `2026-10-04T13:05:00Z`), what happened, who
> (the account, or "anonymous"), where (the address that was asked for, query string included, and the
> client's IP address), and the result (the HTTP status the app answered with, such as 302, 403, or
> 429).
>
> Never log passwords, session cookies or tokens, API keys, or what is inside people's records. If a
> query string can carry one of those, write that value as `[removed]` rather than leaving the address
> out. Write to standard output, one event per line, in one consistent format (key=value pairs or
> JSON). Decide how long logs are kept, and write that down too.

*Helps you answer:* Secure by Design MT-01, MT-07. *Checked through:* ASVS V16.2.1, V16.2.2.

*What it showed:* With the prompt, the line recording a refused sign-in carried who, when with its zone, and where, and both checks were credited; neither build without it wrote such a line, so neither was. The refused request was logged (probe.authorization-failure-logged, V16.3.2) by the build with the prompt and by one of the two without, so that part is not shown and the prompt does not claim V16.3.2. The prompt's first wording asked for 'the path', and both builds with it left out the query string and the status; it now asks for the address with its query string and the status code, and was built again.

### Decide how sign-in works and how long it lasts

> Before writing sign-in, decide these with me and write them in security-notes.md under "Every way to
> sign in" and "How long someone stays signed in":
>
> - Use a proven library or sign-in provider for passwords and sessions where the platform allows one,
>   rather than inventing your own. Store passwords only with a hashing function made for passwords
>   (Argon2, bcrypt, scrypt, or PBKDF2 with many iterations).
> - How long a session may sit unused before the password is asked for again, and the longest a session
>   may last however busy it is. Ask me; suggest 30 minutes unused and 12 hours at most if I am not
>   sure. If securevibe.toml already has them under [policy], use those. Put both numbers in
>   securevibe.toml under [policy] as `idle-timeout-minutes` and `session-lifetime-minutes`, and enforce
>   both on the server: how long the browser keeps the cookie is not enough.
> - If the app issues its own sign-in tokens (such as JWTs), keep them short-lived, check the signature
>   and the expiry on every request, and accept only the one signing method you use.
> - Admins sign in with a second step (a code from an authenticator app).
> - Signing out ends the session on the server, not only in the browser.
>
> Write a test for each: a session unused past the limit is refused, one older than the lifetime is
> refused, and an expired or altered token is refused.

*Helps you answer:* Secure by Design AC-02. *Checked through:* ASVS V7.3.1.

*What it showed:* With the prompt the build wrote 30 minutes unused and 12 hours in all into securevibe.toml and enforced both; after 31 minutes `sv run --slow` found the unused session refused and a busy one still open, and credited it. The 12 hours is longer than the 90 minutes `--slow` waits, so V7.3.2 was not assessed and the prompt does not claim it. The build without the prompt that was run with `--slow` was found on both: it also ended sessions after 30 minutes and 12 hours, but wrote neither down, so `sv` held it to the 2 and 4 minutes standing in for the owner's. What the prompt was shown to change is that the decision is written where it can be held to, not that sessions end at all. The admin's second sign-in step the prompt asks for is not what this shows, and it stopped `sv`'s admin checks, whose settings have no field for the code.

## Not yet shown to work

**Not tested.** Each of these asks for something sound, and the builds that used them did what they asked. But the
builds without them did it too, or `sv` could not tell, so none has been shown to make the difference. Use them,
and check the result with `sv` as you would anything else.

### Decide who may do what, before any page exists

> Before you write any page or endpoint, write down who may do what in this app.
>
> 1. List every kind of user: for example someone not signed in, a signed-in member, and an admin.
> 2. For every page, form, and API endpoint, say which of them may use it. For records (notes, bookings,
>    files, messages), say whose records each kind of user may see or change. Write this as a table in
>    security-notes.md, under the heading "Who may do what".
> 3. Build it so that anything the table does not allow is refused by default. Check permission on the
>    server, on every request: hiding a button or a link is not a check. Check who owns a record every
>    time it is read or changed, not only on the page that lists them. A person who is not allowed gets
>    a refusal (403 or 404, or a redirect to sign in if they are not signed in), never the page.
> 4. For every row of the table, write a test that signs in as someone who must be refused and shows
>    that they are.
>
> If something I ask for later does not fit the table, stop and ask me to update the table first.

*Helps you answer:* Secure by Design AC-03. *Checked through:* ASVS V8.2.1, V8.2.2, V8.3.1.

*Not tested:* All four were credited on the build with the prompt, and on both builds without it: the tool already refused other members' notes and kept the admin page to admins from the description alone.

### Make the actions that must happen once happen once

> Before you build anything that takes, spends, or counts something (booking a seat, paying, redeeming a
> code, voting, claiming the last of anything), list those actions in security-notes.md under the
> heading "Business limits", saying for each what must never happen twice.
>
> Then, for each one:
>
> - Make the check and the change a single step the database does all at once: one conditional UPDATE
>   ("take the seat only if it is still free") whose row count you then read, a unique constraint, or a
>   transaction that locks what it reads. Checking first in code and writing afterwards is not enough:
>   two requests arriving at the same moment can both pass the check.
> - Make it safe to repeat: a double-click or a request sent again must not book, pay, or count twice.
> - Write a test that sends the same action many times at the same moment and shows only one goes
>   through.

*Helps you answer:* Secure by Design RR-05, DM-03. *Checked through:* ASVS V2.3.4.

*Not tested:* Neither build without the prompt was found: both took the seat in one database step. The build with it was found, wrongly: it booked once, as the prompt asks, and answered the member's repeats with "Booked" again, which the check counts as 20 bookings. A false alarm in `sv`, recorded in docs/BACKLOG.md.

### Decide what happens when something the app relies on fails

> Before you write code that calls anything outside the app (an AI service, a payment provider, email,
> another website, or the database), decide what happens when it is slow, down, or answers with an
> error, and write it in security-notes.md under "Everything the app talks to".
>
> Then build it this way:
>
> - Every outside call has a time limit of a few seconds. None waits forever.
> - When a call fails, the person sees a short, plain message, such as "The assistant is unavailable
>   right now. Please try again later." Never show them the error text, a stack trace, the other
>   service's status code, or anything the service sent back.
> - Write the full error to the app's log instead.
> - The rest of the app keeps working: one failed call never crashes the app or stops it answering the
>   next request.
> - Show visitors a plain error page of the app's own for anything unexpected, and turn off any debug
>   mode or setting that shows errors to them.
> - Write a test that makes each outside call fail and checks both the message and that the app still
>   answers afterwards.

*Helps you answer:* Secure by Design RR-01, RR-06, AS-07. *Checked through:* ASVS V16.5.1, V16.5.2.

*Not tested:* Both were credited on the build with the prompt, and on both builds without it: the tool already showed a plain message when the assistant failed and kept answering.

## Still to write

The checklist suggests more design-time prompts that no check in `sv` can show working: a design brief written as
`securevibe.toml` before any code, when to bring in a person, a list of the app's data, everything the app talks to,
safe defaults, a one-page "what we do if…" plan, which rules might apply, and what to re-read before changing a
design. They are listed in docs/BACKLOG.md, "Design-time prompts from the Secure by Design checklist", items 8 to 15.
A plan for keys (SBD-AC-05) is the library's own [secrets prompt](../PROMPTS.md#keep-keys-and-passwords-out-of-the-code).
