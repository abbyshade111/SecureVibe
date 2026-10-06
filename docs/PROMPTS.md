# Prompts for your AI coding tool

These are instructions you can paste into the AI tool that builds your app (Claude Code, Cursor, Copilot, or
another). Each one asks for something SecureVibe checks, and all but the newest have been tried: the same small app was built
twice, once with the prompt and once without, and `sv` checked both. A prompt is listed under "Shown to work" only
when the build with it passed its check and the build without it failed. The rest are listed apart, marked
**not tested**, with what happened: they are worth using, but a prompt that has not been shown to change anything
should not be trusted as if it had.

`sv prompts` prints the same prompts at a terminal (`sv prompts --requirement V1.2.4` for those aimed at one
requirement), and an AI coding tool connected to `sv mcp` can fetch them with `securevibe_prompts`. The [design-time
prompts](prompts/design-time.md) are also offered there as MCP prompts, for you to choose from your tool.

The prompts are written in this project's own words. Some were inspired by the Cloud Security Alliance's
[Secure Vibe Coding Guide](https://cloudsecurityalliance.org/blog/2025/04/09/secure-vibe-coding-guide)
(K. Huang, 9 April 2025); none of its text is copied. The same prompts, with the checks behind them, are in
`data/prompts.json`.

**How they were tested (3 October 2026).** The test app was a notes app in Python (Flask and SQLite) with
sign-up and sign-in, formatted notes, search, file attachments, an export that runs another program, a redirect
back after signing in, and a welcome email that needs an API key. Fresh helper agents of the same Claude model
built it once with no prompt, and once for each prompt, each in a folder of its own. One build each is a small
sample: a prompt that showed nothing here may still help on another app or with another tool.

**A second test app (4 October 2026).** Four of the prompts below changed nothing on the first app, because the
build without them already did the safe thing. So a second app was written to tempt the shortcut each one guards
against ([its brief](prompts/trial-2/brief.md)): a recipe app in Node.js where the request pastes the OpenAI key
straight in, asks for a PDF made by running a program on the recipe's title, and asks for a formatting toolbar.
The build without any prompt still read the key from the environment, ran the program without a shell, stored
passwords with a proper hash, and cleaned the formatted text. So these four stay **not tested**: with this AI model,
on these two apps, the safe choice was made with or without them. They may matter more with another tool.

**The rest of the first batch (4 October 2026).** Four more prompts, for things `sv` checks on the running app
(security headers, cross-site access, error pages, and who may open what), were tried on the club app the
[design-time prompts](prompts/design-time.md) were tried on: two builds with no prompt, and one with each prompt,
each started behind `sv`'s network fence and signed in to as two members and an admin. Both builds without a
prompt already passed all four checks. To be sure the checks could see the faults on this app at all, a copy of one
of those builds had each fault put back, and every one was caught. So these four are **not tested** too.

## Shown to work

### Describe the app to SecureVibe before writing code

> Before writing any code, run `sv init` in the project folder and fill in the securevibe.toml it creates: what
> the app does, who uses it, its languages, how to start it, and which of the listed capabilities it has. For any
> capability you are not sure about, delete the line instead of writing false. Keep the file up to date whenever
> the app gains or loses a capability.

*What it showed:* with the prompt, the app had a filled-in `securevibe.toml` and `sv report` checked it. Without
it, there was no such file, and `sv report` could not check the app at all. Deleting an unsure line matters:
a capability left out is reported as "not assessed", which is honest, while `false` claims the requirements that
depend on it do not apply.

### Keep the app in git from the first file

> Make the project folder a git repository before writing the first file (`git init`), add a .gitignore straight
> away that leaves out .env files, keys, and installed dependencies, and commit after each step that works.

*Requirement:* ASVS V13.3.1 (secrets are kept out of the source code and what is built from it).

*What it showed:* with the prompt, the app was a git repository with a `.gitignore`, and `sv`'s check for a
password or key committed to the history ran. Without it, the folder was not a git repository, so that check
could not run.

### Send the security headers on every page

> Send these headers on every response the app gives, error pages and the home page included: a Content-Security-Policy that starts from `default-src 'self'` and includes `frame-ancestors 'none'` (or `'self'` if the app frames its own pages), `X-Content-Type-Options: nosniff`, and `Referrer-Policy: strict-origin-when-cross-origin` or stricter. Set them in one place that every response passes through, so a new page cannot leave them out.

*Requirements:* ASVS V3.4.3, V3.4.4, V3.4.5, V3.4.6.

*What it showed (6 October 2026, Haiku 4.5, ten builds with it and ten without):* Without the prompt the headers were missing in 6 of the 6 builds sv could start; with it in 0 of 6. The trial's harm rule flagged it on the median of running-app checks answered, which counts an app that never started as none; among the apps that started, the builds with the prompt answered as many as those without it or more (median 21, against 20), and the apps that did not start were mostly ones whose securevibe.toml sv could not read, which happened in every group, the one without a prompt included. Shown by the owner's decision of 6 October 2026, with the flag recorded here.

### Keep keys and passwords out of the code

> Never write a password, API key, or token into the code, a config file, or anything else that gets committed. Read each one from an environment variable when the app starts, and stop with a clear message if one is missing. List the variables the app needs in a .env.example with placeholder values only, and keep the real .env file out of git.

*Requirement:* ASVS V13.3.1.

*What it showed (6 October 2026, Haiku 4.5, ten builds with it and ten without):* Without the prompt the check found a key in the code or a .env the .gitignore left committable in 6 of the 6 builds with a readable securevibe.toml; with it in 1 of 4. The trial's harm rule flagged it on the median of running-app checks answered, which counts an app that never started as none; among the apps that started, the builds with the prompt answered as many as those without it or more (median 25, against 20), and the apps that did not start were mostly ones whose securevibe.toml sv could not read, which happened in every group, the one without a prompt included. Shown by the owner's decision of 6 October 2026, with the flag recorded here. To be checked again: six of the ten builds with this prompt wrote a securevibe.toml sv could not read, against three of ten without it, which may be chance at this size or the prompt crowding out the specification.

### Keep private pages out of the browser's cache

> Send `Cache-Control: no-store` on every response that shows somebody's own data or anything only a signed-in person may see, its JSON answers and error pages included. `no-cache` and `private` are not enough: both let the browser keep a copy. Set it in one place that every signed-in response passes through, so a new page cannot leave it out. Write a test that a private page sends it.

*Requirement:* ASVS V14.3.2.

*What it showed (6 October 2026, Haiku 4.5, ten builds with it and ten without):* Without the prompt a private page was left cacheable in 5 of the 5 builds whose private pages sv could open; with it in 0 of 4. The trial's harm rule flagged it on the median of running-app checks answered, which counts an app that never started as none; among the apps that started, the builds with the prompt answered as many as those without it or more (median 22, against 20), and the apps that did not start were mostly ones whose securevibe.toml sv could not read, which happened in every group, the one without a prompt included. Shown by the owner's decision of 6 October 2026, with the flag recorded here.

### Guard what goes into the AI feature and what comes out of it

> Treat everything that reaches the model as untrusted: what people type, and any text the app adds from its own records. Before a message goes to the model, screen it for prompt-injection attempts, with a maintained classifier or a ruleset of the known patterns ("ignore your instructions", "reveal your system prompt" and the like), and refuse a flagged message with a plain explanation instead of sending it. Before a reply leaves the server, check it too: hold back or redact a reply that repeats the model's instructions or anything else meant only for the model, and keep secrets out of the instructions altogether; remove invisible and direction-changing characters (zero-width characters, Unicode tag characters, bidirectional overrides), and show each link's real address or drop a link whose text is a different address from its target. Write a test for each: an injection attempt is refused, a reply that repeats the instructions is held back, and a reply with hidden characters reaches the page without them.

*Requirements:* AISVS C2.1.3, C7.3.2, C7.3.4.

*What it showed (6 October 2026, Sonnet 5.5, ten builds with it and ten without):* Without the prompt, all ten builds passed the textbook prompt injection to the model, passed on a reply repeating their instructions, and let a reply's hidden characters or misleading link reach the page. With it, none of the nine whose AI feature answered did any of the three. As many apps started and could be signed in to (10 and 9), with the same median of running-app checks answered (32 and 32): no harm by the trial's rule.

## Not yet shown to work

**Not tested.** Each of these asks for something sound, and every build that used one did what it asked. But the
test could not show that the prompt made the difference, so none of them has been shown to work. Use them, and
check the result with `sv` as you would anything else.

### Build every database query with placeholders

> Whenever the app reads or writes the database, pass every value through the database library's placeholders (parameters) or an ORM. Never build a query by joining strings, with f-strings, or with format(), not even for numbers. If a person chooses a column or a sort order, pick it from a fixed list in the code rather than putting what they sent into the query.

*Requirement:* ASVS V1.2.4.

*Not tested:* The build with the prompt followed it, and `sv` wrongly flagged two of its safe queries. That is a fault in `sv`, recorded in the backlog, and fixed on 4 October 2026: both queries are now left alone. The prompt has not been tried again since.

### Run other programs without a shell

> Never run a shell command built from anything a person sends. If the app has to run another program, call it with a list of arguments and no shell (in Python, subprocess.run([...]) without shell=True; in Node, execFile rather than exec), and check each value a person supplies against what is allowed before passing it on.

*Requirement:* ASVS V1.2.5.

*Not tested:* The build without the prompt already ran the export with no shell.

### Save files under names the app makes

> Never build a file path from a name or path a person sends. Save each uploaded file under a name the app makes (a random id), keep the original name only as data in the database, and when a person asks for a file, look it up by that id.

*Requirement:* ASVS V5.3.2.

*Not tested:* The build with the prompt followed it, and `sv` wrongly flagged the file path it read back from its own database. That is a fault in `sv`, recorded in the backlog. Since 5 October 2026 the finding stays, at low confidence, and says the path was built from fixed text and a value read back from the app's own database. The prompt has not been tried again since.

### Store passwords with a password-hashing function

> Store passwords only as hashes made by a password-hashing function from a well-known library: Argon2id first, or bcrypt or scrypt, with the library's recommended settings. Never use MD5, SHA-1, or SHA-256 on their own for passwords, never encrypt them so they can be read back, and never store them as they were typed.

*Requirements:* ASVS V11.4.1, V11.4.4.

*Not tested:* The build without the prompt already used a proper password hash. Tried again on 6 October 2026 with Haiku 4.5: no reading by the trial's rule: without the prompt a weak password hash was there in 4 of 6 builds, one short of the five the rule needs; with it in 2 of 8.

### Send people back only to pages on the same site

> When the app sends someone on to another page after an action, such as back to where they were after signing in, only send them to a path on this same site. Treat a full web address, or anything starting with //, as not allowed, and send them to the home page instead.

*Requirement:* ASVS V3.7.2.

*Not tested:* Both builds checked the address before redirecting, and `sv` flagged both: it could not tell a checked redirect from an unchecked one. Recorded in the backlog. Since 5 October 2026 the finding stays, at low confidence, and names the function the address passed through (such as `safe_next`), as the owner decided. The prompt has not been tried again since.

### Clean formatted text before showing it

> If people can write formatted text (HTML, or Markdown turned into HTML) that the app shows, clean it with a well-known sanitizer before showing it: bleach or nh3 in Python, DOMPurify in JavaScript, set to allow only the formatting the app needs. Show everything else as plain text through the template's own escaping, and never mark text as safe to skip that escaping.

*Requirement:* ASVS V1.3.1.

*Not tested:* The build without the prompt allowed only a few safe tags itself. `sv`'s check reads which libraries an app uses, so it could not judge that build either way.

### Let other sites read the app only by name

> Do not turn on cross-site access (CORS) unless a page served from another address really has to read this app's answers. If one does, write the exact addresses that may, and compare each request's Origin with that list. Never answer `Access-Control-Allow-Origin: *`, and never copy back whatever Origin the request sent, least of all together with `Access-Control-Allow-Credentials: true`.

*Requirement:* ASVS V3.4.2.

*Not tested:* No build turned cross-site access on, with or without the prompt.

### Show plain error pages, and keep the details in the log

> When something goes wrong, show the person a short, plain error page with nothing technical on it: no stack trace, no file paths, no query text, no library names or versions. Write those details to the app's log instead. Debug mode, and anything else that shows errors in the browser, must be off unless a setting meant only for your own computer turns it on.

*Requirements:* ASVS V13.4.2, V16.5.1.

*Not tested:* Every build, with or without the prompt, answered errors with a plain page.

### Check on the server who may open each page and record

> For every page and every action, check on the server, before doing anything: that the person is signed in if the page is private, that the record they asked for is their own, and that only admins reach admin pages and admin actions. Closed is the default: a new page or action is refused until a rule says who may use it. Never rely on hiding a link or a button, and never on an id in the address being hard to guess.

*Requirements:* ASVS V8.2.1, V8.2.2, V8.3.1.

*Not tested:* Both builds without the prompt already refused all of these.

### Make the session hard to steal, and end it properly

> If the app keeps its own sessions, make each session id with the platform's cryptographically secure random generator, at least 128 bits of it (in Python, `secrets.token_urlsafe(32)`), and a new one at every sign-in. Send it only in a cookie set with HttpOnly and SameSite=Lax (or Strict), and Secure once the app is served over HTTPS, and never put it in a page, an address, or anything a script can read. When someone signs out, or a session expires, delete it on the server, so the old id opens nothing: clearing the browser's cookie is not enough. Where the framework's own session handling does all of this, use it rather than writing your own. Write a test for each: the cookie's attributes, and a session used again after signing out is refused.

*Requirements:* ASVS V3.3.2, V3.3.4, V7.2.3, V7.4.1.

*Not tested:* No reading by the trial's rule: without the prompt a session fault was there in 4 of the 5 builds sv could sign in to, one short of the five the rule needs; with it in 1 of 4. Reading builds 1, 4 and 7, each did all the prompt asks.

## Not tried yet

Written on 6 October 2026, with three others now above, for the commonest problems the loop trials found that no prompt covered (`docs/prompts/loop-scale/README.md`, "Findings by group"). It was left out of the prompt-library trial (`docs/prompts/library-trial/`): the trial's app seldom tempted this shortcut (in 2 of 8 Haiku builds and none of 10 Sonnet builds without any prompt), so it could not have shown anything. It needs an app that does.

### Accept changes only from the app's own pages

> Every request that changes something (a form sent, an API call that creates, edits, or deletes) must carry an anti-forgery token that the app gave the page it came from, and the server refuses a request without a valid one; or the server checks the request's Origin header against the app's own address and refuses any other. Do both where the framework allows. Set SameSite=Lax or Strict on the session cookie as well, but as a second line, not instead of the check. Write a test that sends a change from another site's address without the token and shows it is refused.

*Requirements:* ASVS V3.5.1.

*Not tested:* not tried yet.

The same prompts, with the checks behind them, are in `data/prompts.json`.

Prompts for what to decide **before** any code is written (who may do what, limits, logging, sign-in), drawn from the
OWASP Secure by Design checklist and held to the same test (3 of the 14 shown to work so far), are on a page of their own:
[Prompts to give your AI coding tool before it writes any code](prompts/design-time.md). `sv prompts` and
`securevibe_prompts` give those too; `sv prompts --requirement SBD-AC-03` finds them by the checklist control they
help you answer.
