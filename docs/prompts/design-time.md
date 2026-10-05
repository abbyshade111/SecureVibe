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

**Tried again with two more models (5 October 2026).** Claude Sonnet 5.5 and Claude Haiku 4.5, two builds with each
prompt and two without, on the same brief ([the third trial](trial-3/README.md)). With Sonnet, the three prompts below
held on every check they were shown on, and the logging prompt also on whether a refused request is logged (V16.3.2).
With Haiku, the logging and sign-in prompts held; the limits prompt did not, because one of its two builds answered
a limit with 403 instead of 429. The prompts under "Not yet shown to work" made no difference with either model: the
builds without them were already safe on what `sv` checks. One tool, two models: other vendors' tools were not tried.

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

## Not tried yet, and no check can show them

These come from the checklist's other suggestions. Each asks for a decision only a person can make, written down
before the code, and none of them can be shown working by a check in `sv`, so each is marked **not tried** and
names no ASVS requirement. Where a Secure by Design control's own statement fits, it is named; two draw on the
checklist's escalation triggers and principles, which are not controls, and name none. What they ask for goes
under the security notes' own headings where one fits, and otherwise into `design-decisions.md`, which `sv` does
not read: a heading of your own in `security-notes.md` would be read as part of the answer above it. A plan for keys
(SBD-AC-05) is the library's own [secrets prompt](../PROMPTS.md#keep-keys-and-passwords-out-of-the-code).

In an AI coding tool connected to `sv mcp`, every design-time prompt on this page can also be chosen from the
server's prompts, where the tool shows them (for example as a slash command); `sv prompts` prints them at a terminal.

### Write the design brief before any code

> Before you write any code, write the design brief with me, as securevibe.toml.
>
> 1. Run `sv init` (or ask SecureVibe for its spec) and fill in securevibe.toml for the app as it will be,
>    not as it is now: there is no code yet. Ask me each question you cannot answer from what I have
>    told you: what the app is for, who will use it (just me, my team, customers, or the public),
>    whether it faces the internet, how people sign in, what it keeps about people, whether it takes
>    payments, whether it uses an AI service, and whether it fetches web addresses or accepts uploads.
> 2. If I am not sure whether the app will have something, write true: a capability planned and never
>    built costs a requirement that did not need meeting, and one left out is how a real requirement
>    gets switched off.
> 3. Ask me for the limits now, and write them under [policy]: how many wrong passwords in a row, how
>    many records one person may create in a minute, how long a session may sit unused, and the
>    longest it may last. Suggest sensible numbers if I am not sure.
> 4. Read the brief back to me in plain words, and change it until I agree with it.
> 5. Plan the tests the app will need: for each requirement the brief makes apply that a test could
>    show, a test whose name carries the requirement's id (such as `test_V8_2_1_...`).
>
> Do not start on the code until I have agreed the brief. When I later ask for something the brief
> does not have, update securevibe.toml first.

*Helps you answer:* Secure by Design MT-03. *Not tried:* No check in sv shows this prompt working. securevibe.toml is checked against the code once there is code, and a claim the code contradicts is reported, but that checks the file, not whether it was written first.

### Say when the app needs a person's review

> Before we build, tell me plainly whether this app needs a person's security review as well as
> SecureVibe's checks. Say yes, and why, if any of these is true:
>
> - it keeps sensitive or regulated data: health, money, children's data, government ids, or
>   anything people would be harmed by if it leaked;
> - it puts something on the internet that was not there before, such as a new site, a public
>   API, or a page anyone can reach;
> - it uses a technology or a way of building that neither of us has used before;
> - people would be badly hurt if it failed or went down.
>
> If any is true, recommend that I ask someone who knows security to look at the design before it
> goes live, and write down which of these applied and what you recommended in design-decisions.md,
> under "When to bring in a person". Do not add headings to security-notes.md for this. Do not decide
> for me that the review can be skipped.

*Helps you answer:* no single control. *Not tried:* No check in sv shows this prompt working, and the checklist's escalation triggers it draws on are not controls, so it names none. sv repeats what this section says in its report, where what was not examined is listed, and credits nothing for it.

### List the app's data, and keep only what it needs

> Before you create any database table or form, list with me every kind of data the app will keep
> about people: for example names, email addresses, passwords, messages, health details, payment
> details, or files they upload. For each one, write down:
>
> - how sensitive it is (public, private, or sensitive: would someone be harmed if it leaked?);
> - why the app needs it, and whether it could do without it;
> - how long it is kept, and what happens when someone deletes their account;
> - how it is protected: who can see it, and whether it is encrypted where it is stored.
>
> Leave out anything the app does not need. Write the list in security-notes.md, under "How each kind
> of sensitive data is protected", and write the categories into securevibe.toml under [data]. Then
> build the app to match the list: if I later ask for something that keeps a new kind of data, add it
> to the list first.

*Helps you answer:* Secure by Design DM-01, DM-05. *Not tried:* No check in sv shows this prompt working. The notes section it fills is read as the person's or the AI tool's word, at its tier, never as a check.

### Draw everything the app talks to

> Before you write code that connects to anything, list with me everything the app will talk to:
> the browser, the app's server, its database, any AI service, payment provider, email service, other
> websites, and anything else. For each connection, write down:
>
> - what is sent across it, and in which direction;
> - whether it crosses the internet, and that it uses HTTPS (or another encrypted connection) when it
>   does;
> - what the app checks about what comes back before it uses it: anything from outside the server,
>   including what an AI service answers, is treated as untrusted until checked;
> - which keys or passwords it needs, and that they come from the environment, never the code.
>
> Write the list in security-notes.md, under "Everything the app talks to". If something I ask for
> later adds a connection, add it to the list first.

*Helps you answer:* Secure by Design AS-01, AC-01. *Not tried:* No check in sv shows this prompt working. The notes section it fills is read at its writer's tier, never as a check; AS-01 is about trust zones in a larger system and is answered here only scaled down to one app.

### Start closed, with as few moving parts as possible

> Before we build, and again before the app goes live, list with me every feature, page, API
> address, setting, and debug switch the app has, and for each one ask: does the app need it?
>
> - Remove what it does not need, rather than hiding it.
> - Make every default the safe one: new accounts get the least they need, new pages need sign-in
>   unless they are meant to be public, uploads and sharing start off, and debug mode and detailed
>   error pages are off outside my own computer.
> - Prefer one well-known way of doing a thing over several, and a well-known library over code
>   written for this app.
>
> Write the list, and what was removed or turned off, in design-decisions.md, under "Safe defaults".
> Do not add headings to security-notes.md for this.

*Helps you answer:* no single control. *Not tried:* No check in sv shows this prompt working, though its debug-mode, cross-site access, and header checks reach parts of it. It draws on the checklist's principles rather than one control, so it names none. sv does not read design-decisions.md.

### Write "what we do if..." on one page

> Before the app goes live, write a one-page plan with me for when something goes wrong, for a
> person running the app on their own. In plain steps:
>
> - how to take the app offline quickly, and how to bring it back;
> - what to do if a key or password leaks: which keys the app has, where each one is changed, and
>   what has to be restarted afterwards;
> - what to do if someone else's data may have been seen: what to look at in the logs, what to keep
>   as evidence, and how and when to tell the people affected;
> - who to ask for help, and how to reach them.
>
> Write it in design-decisions.md, under "What we do if something goes wrong", and remind me once
> a year to read it again. Do not add headings to security-notes.md for this.

*Helps you answer:* Secure by Design MT-06. *Not tried:* No check in sv shows this prompt working; whether a plan exists, is right, and has been rehearsed is for a person to answer. sv reads the section as a written answer toward SBD-MT-06: documented, or stated by the AI coding tool, never checked. That shows a plan is written, not that it works.

### Flag the rules that might apply

> Before we build, tell me in plain words whether any laws or industry rules might apply to this
> app, from what it keeps and who uses it. For example:
>
> - children's data (such as COPPA in the US, or the GDPR's rules for children in Europe);
> - health information (such as HIPAA in the US);
> - card payments (PCI DSS: usually best avoided by letting a payment provider take the card
>   details, so the app never sees them);
> - personal data of people in Europe or California (the GDPR, the CCPA).
>
> You are not giving legal advice, and say so: for each one that might apply, say why, what it would
> usually mean for the design, and that I should check with someone qualified. Write what you found
> in design-decisions.md, under "Rules that might apply". Do not add headings to security-notes.md
> for this.

*Helps you answer:* Secure by Design AC-06. *Not tried:* No check in sv shows this prompt working; which rules apply is a question for a person, and a qualified one. sv reads the section as a written answer toward SBD-AC-06: documented, or stated by the AI coding tool, never checked. That shows the rules were written down, not that the design follows them.

### Before changing the design, re-read what was decided

> Whenever I ask for a new feature, or a change to how something works, before you write the code:
>
> 1. Re-read securevibe.toml, security-notes.md, and design-decisions.md.
> 2. Tell me which of the decisions written there the change touches: who may do what, the limits,
>    the data kept, what the app talks to, how sign-in works, what is logged.
> 3. Update those first, with me, and only then change the code.
> 4. If the change goes against a decision, say so plainly and ask me before going ahead.
>
> After the change, run SecureVibe's check again.

*Helps you answer:* Secure by Design MT-05. *Not tried:* No check in sv shows this prompt working. A claim in securevibe.toml that the code contradicts is reported, but whether the decisions were re-read before the change is not something sv can see.
