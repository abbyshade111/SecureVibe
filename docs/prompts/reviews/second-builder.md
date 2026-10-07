# The prompt library, read by a second builder (7 October 2026)

Written by session securevibe-e9, at session paper-facts' request on the owner's behalf: an independent read of
`data/prompts.json` and `data/design-prompts.json`, with suggestions for new prompts. **Nothing here changes a
prompt.** Each suggestion is for a trial to try first, as the library's rule asks.

What it rests on:

- the prompts and their `check` and `tested` entries, as of `main` on 7 October 2026;
- `docs/prompts/library-trial/README.md`, `delivery-protocol.md`, and `docs/prompts/loop-scale/README.md`;
- the seventy loop-scale reports in `docs/prompts/loop-scale/item6-findings.json`, counted again here by build;
- the checks' own code in `crates/sv-check`, and what `sv run` gives an app in `crates/sv-run/src/docker.rs`;
- each requirement's own text in `data/frameworks/asvs-5.0.0.json` before citing it.

Where this says a probe "cannot see" something, that is from reading the probe's code, not from running it again.

## The short version

1. **The commonest problems in AI-built apps have no prompt.** In the seventy loop-scale builds, the findings
   found most often are listed below. The first five have no prompt; the sixth and seventh have only a design-time
   prompt that, with the owner away, often stopped the build.

   | Finding | Sonnet builds | Haiku builds |
   |---|---|---|
   | Cross-Origin-Opener-Policy missing | 34 of 35 | 29 of 34 |
   | No security contact | 25 | 28 |
   | Content-Security-Policy with nowhere to report | 35 | 0 |
   | Version numbers in headers | 0 | 29 |
   | PBKDF2 with too few rounds | 0 | 23 |
   | No limit on wrong passwords | 1 | 18 |
   | No limit on creating records | 5 | 13 |

   Five new prompts for these are in "New prompts", below.
2. **Two prompts can break the app under `sv run` or for real people.**
   - `secrets-in-the-environment` tells the app to stop when a key is missing. `sv run` starts the app with no keys
     of its own, so the app never starts.
   - `security-headers` allows any Referrer-Policy "or stricter". The strictest one makes browsers send
     `Origin: null` with the app's own forms, and an app that checks the Origin, as `changes-from-own-pages` asks,
     then refuses them. Ten Sonnet builds did exactly this.
3. **Three "not shown" prompts were judged by a static rule that cannot tell right from wrong.** A running probe now
   exists for each of them and can tell. They are worth trying again with that probe as the check.

## 1. Each prompt, read

Each entry says whether the prompt is clear, and whether an AI tool can follow it with nobody to ask. It also says
whether following it could break something, and whether its check really sees what it asks for.

### Coding prompts (`data/prompts.json`)

**`settings-file-first`** (shown). Clear, and followable alone.
- **Suggestion:** add one sentence: "Then run `sv report` once, and fix the file until `sv` reads it." In the
  library trial, 22 of 70 Haiku builds wrote a `securevibe.toml` that `sv` could not read. The prompt as written
  passes a build whose file `sv` refuses, and its check counts "sv report runs" as passing.
- **Suggestion:** say that a refused file counts as a failure in the check's `fails_when`, so the check matches what
  the prompt is for.

**`git-from-the-start`** (shown). Clear.
- The `.gitignore` it asks for is still the most common high finding: 61 of 69 loop-scale builds lacked one that
  leaves out `.env`. The loop arm is the exception, where the check named it and builders fixed it.
- Those builds were not given this prompt, so the gap is in delivery, not wording (section 3).
- **Suggestion:** write the line itself into the prompt: "add a `.gitignore` whose first line is `.env`". Builders
  copy a literal more reliably than they act on a description.

**`secrets-in-the-environment`** (shown). Clear, but one clause does harm: "stop with a clear message if one is
missing."
- `sv run` gives the app only what it needs to be tested: its port, the test email server, the test sign-in
  provider, and placeholder keys for OpenAI and Anthropic (`docker.rs`, "no credentials in its environment"). Any
  other key the app needs is missing, so an app that follows the prompt exits at start, and every running-app check
  goes unanswered.
- That clause may also be part of the trial's harm flag. The trial's README puts most of the apps that did not
  start down to settings files `sv` could not read, and does not say whether any stopped for a missing key; worth
  looking at before the next trial.
- **Suggested wording:** "If a key for an outside service (email, payments, maps) is missing, start anyway with
  that feature turned off, write one line to the log saying so, and show a plain 'not available' message where the
  feature would be. Never fall back to a key written in the code. If the key that signs sessions is missing, make a
  random one when the app starts and log that sessions will end when it restarts."
- That keeps keys out of the code, which is what the prompt is for, and still lets the app start inside the fence.
- **Before trying it:** check that `secrets.` finds no fallback key with this wording.

**`database-placeholders`** (not shown). The prompt is good. Its check was the problem:
`ast.sql-built-by-hand` flagged a fixed setup script and a choice from a fixed list.
- **Suggestion:** use `probe.sql-injection`, the read-only probe of the running app, as the check. It sees a query
  that really takes what a person typed, which is what the prompt prevents. Keep the static rule as a second
  signal, not the judge.

**`no-shell-with-input`** (not shown). Clear. Both briefs failed to tempt the shortcut, so it was never tested
against a builder that takes it. No running probe sees a shell command, so the static rules stay the check.
- **Suggestion:** leave it as it is until a brief tempts the shortcut. Nothing here suggests a change.

**`files-under-own-names`** (not shown). Clear. `ast.file-path-from-value` called the right answer (a path from
the app's own stored id) a finding.
- **Suggestion:** use `probe.upload-path-traversal`, which sends a name with `../` in it to the running upload, as
  the check. It judges the effect, so a path from the app's own id passes.

**`password-hashing`** (not shown). Clear, but it never mentions PBKDF2, and PBKDF2 is what Haiku used.
- In the loop-scale builds, `ast.weak-password-key-derivation` was a finding in 23 Haiku builds: PBKDF2 with fewer
  rounds than OWASP's 600,000. In the library trial, build 7 of this prompt's own arm used PBKDF2 too.
- A builder reaching for `hashlib.pbkdf2_hmac` reads nothing in the prompt telling it not to.
- **Suggestion:** add "If you can only use PBKDF2, use at least 600,000 rounds with SHA-256, and keep the count
  where it can be raised later." `design-sign-in` has the same gap: it says "PBKDF2 with many iterations", which
  a builder can meet with 10,000. Write the number there too.

**`same-site-redirects`** (not shown). Clear. `ast.open-redirect` flagged both builds because it cannot tell a
checked redirect from an unchecked one.
- **Suggestion:** use `probe.open-redirect` as the check. On 7 October 2026 it gained `redirects` in
  `securevibe.toml` (#868), so it can now ask the running app's own redirect pages for another site's address. It
  judges what the app does with the destination, which is what the prompt asks for.

**`sanitize-rich-text`** (not shown). Clear. Its check reads the libraries an app declares, so it was silent on a
build that wrote its own safe escaping, and silence there was not a judgment.
- **Suggestion:** for the prompt's second half ("show everything else as plain text"), add
  `probe.text-rendered-as-markup`, which types markup into a plain field and reads, in a browser, whether it
  became part of the page. It cites V3.2.2, not V1.3.1, so add that requirement to the prompt's list if it is used.
  Formatted text itself is meant to come back as markup, so no running probe judges the sanitizer yet.

**`security-headers`** (shown). Clear. One phrase needs tightening: "`Referrer-Policy: strict-origin-when-cross-origin`
or stricter".
- The strictest policy, `no-referrer`, makes browsers send `Origin: null` with the app's own forms. An app that
  checks the Origin then refuses its own forms, and `probe.own-forms-refused` exists for exactly this. It was a
  finding in 10 of the 35 Sonnet loop-scale builds.
- This prompt is delivered to every builder (ADR-044). A builder that also follows `changes-from-own-pages`, which
  asks for the Origin check, can follow both prompts faithfully and break every form.
- **Suggested wording:** "`Referrer-Policy: strict-origin-when-cross-origin` or `same-origin` (not `no-referrer`,
  which makes browsers send no origin with the app's own forms)".
- **Not suggested:** adding the two missing headers to this prompt (section 2, "isolate-the-window"). The prompt is
  shown as it stands, and adding to it would make the trial no longer apply.

**`cross-site-access`** (not shown). Clear and safe. No build turned cross-site access on, so there was nothing to
change. Nothing here suggests a change.

**`plain-error-pages`** (not shown). Clear. Every build already showed plain errors.
- One gap: Haiku's apps named their software's version in a header in 29 of 34 loop-scale builds
  (`probe.version-disclosed`). A common source is the framework's development server, which sends, for example,
  `Werkzeug/3.0.1 Python/3.12`: the same thing that brings debug pages. See "production-server" below, which covers
  it rather than widening this prompt.

**`check-every-request`** (not shown). Clear. Builders already did this. Nothing here suggests a change.

**`ai-feature-guard`** (shown). The strongest result in the library (10 of 10 without it, 0 of 9 with it).
- One risk: "a maintained classifier" can mean a library that downloads a model when the app starts (LLM Guard
  takes its models from Hugging Face) or a hosted screening service.
- Inside `sv run`'s fence nothing can be downloaded or reached. Such an app may fail to start, or may skip the
  screen and pass everything through. Neither shows in the trial, where builders chose rulesets.
- **Suggestion:** add "the screen must work with no network: a ruleset in the code, or a classifier whose model
  file is part of the app." That holds in production too: a screen that fails open when its service is down is
  no screen.

**`changes-from-own-pages`** (untested). Clear. `probe.cross-site-request-accepted` was a finding in 6 Haiku
loop-scale builds, which is temptation enough for a trial.
- **Before the trial:** fix the Referrer-Policy wording in `security-headers` (above). Otherwise the two prompts
  together are likely to produce `probe.own-forms-refused`.
- **Suggestion:** have the trial count `probe.own-forms-refused` as harm.

**`private-pages-no-store`** (shown). Clear. Nothing here suggests a change.
- `probe.private-page-headers`, the four security headers asked of signed-in pages, was a finding in 23 Haiku
  builds. That is the same fix as `security-headers` and is covered by its "one place that every response passes
  through".

**`sessions-hard-to-steal`** (not shown). Clear. One thing is worth knowing before a second trial:
`probe.session-id-weak` was a finding in 8 of the 35 Sonnet loop-scale builds, and Sonnet usually uses its
framework's own sessions.
- The check judges *every* cookie the app sets at sign-in, not only the session cookie. A short cookie set at the
  same time, such as a preference or a flash message, would be judged as a weak session id.
- The trial records do not keep which cookie it was. **Suggestion:** look at one of those builds before trusting
  that finding, and before writing a prompt aimed at it.

### Design-time prompts (`data/design-prompts.json`)

**The "ask me" problem runs through all of them.** `design-limits`, `design-sign-in`, `design-brief`,
`design-data-list`, `design-what-the-app-talks-to`, `design-safe-defaults`, `design-what-we-do-if`, and
`design-which-rules-apply` each tell the builder to ask the owner.
- In the library trial, with the owner away, six of `design-limits`' ten builds stopped to ask and wrote nothing.
  Two loop-scale Haiku builds did the same without any prompt.
- **Suggestion, for every prompt that asks:** add "If I am not available to answer, use the suggested values, write
  them down marked 'default, to confirm', and carry on." This keeps the decision visible and written down, which is
  what these prompts are for, without a stalled build.

**`design-who-may-do-what`** (not shown). Clear. Nothing to change. Builders already passed.

**`design-actions-once`** (not shown). Clear. The one build that followed it was flagged wrongly: it answered
repeats with "Booked" again.
- **Suggestion:** try it again once the false alarm recorded in the backlog is fixed. Until then, add "answer a
  repeated request with the result of the first one, for example 'Already booked'", which is also what the person
  needs to see.

**`design-limits`** (shown, with a warning). Covered by the "ask me" note above. A coding-prompt version with
defaults is in section 2.

**`design-when-things-fail`** (not shown). Clear. It asks for "a time limit of a few seconds" on every outside
call, and **no probe sees that yet.**
- `probe.ai-service-failure-handled` asks the app with a test model that fails at once. A model that answers slowly
  or never is still unclaimed in the backlog ("The running-app checks, reviewed on 3 October", item 10). That is
  the probe that would show this prompt's main point.
- **Suggestion:** say in the check entry that the time limit is not yet seen, as `design-sign-in` does for V7.3.2.
  It currently claims V16.5.2, and the check does not reach the slow case that requirement includes.

**`design-logging`** (shown). Clear, and the second wording fixed the query string and status. Nothing to change.

**`design-sign-in`** (shown). Clear.
- Besides the PBKDF2 number (above): "Admins sign in with a second step" is sound. But `sv` can sign in as an admin
  with a code only when `securevibe.toml` has a `totp` line under `[stack.run.users]` and the admin is enrolled with
  `SV_ADMIN_TOTP_SECRET`.
- A builder who adds the second step and not those lines will probably leave every admin check unanswered.
- **Suggestion:** add "and add the `totp` line to `[stack.run.users]` in securevibe.toml, so SecureVibe can sign in
  as the admin."

**`design-brief`, `design-when-to-bring-in-a-person`, `design-data-list`, `design-what-the-app-talks-to`,
`design-safe-defaults`, `design-what-we-do-if`, `design-which-rules-apply`, `design-before-changing`** (untested,
no check). Each is clear, and each says honestly that no check sees it.
- One conflict: `design-brief` says "If I am not sure whether the app will have something, write true".
  `settings-file-first` says "For any capability you are not sure about, delete the line instead of writing false."
  These agree on what not to do (write false). They disagree on what to do instead (write true, or leave it out),
  and both prompts can reach the same builder.
- **Suggestion:** pick one. "Write true" is the design-time answer: a planned capability brings its requirements.
  "Leave it out" is the coding-time answer: an unknown capability is reported as not assessed. Say which applies
  when, in both prompts.

## 2. New prompts

Five, for problems `sv` checks that no prompt covers, ordered by how often the loop-scale builds had them and how
much they matter. Each requirement's text was read in `data/frameworks/asvs-5.0.0.json`. **Levels matter here:**
three of them (V3.4.7, V3.4.8, and V13.4.6) are level 3, so an app held only to level 1 or 2 is not held to them.
Since #861, `sv` sets such findings apart as "about requirements this app is not held to". They are cheap to fix and
very common, but the first two prompts below matter more for most apps.

### `limits-without-asking` (V2.4.1, V6.3.1)

> Limit how often each person can try a wrong password and how fast they can create things, without waiting for me
> to choose the numbers. Use these unless securevibe.toml already has them under [policy]: 5 wrong passwords within
> 15 minutes per account, then refuse further attempts on that account until the 15 minutes pass; and 10 new
> records a minute per signed-in person. Write the numbers into securevibe.toml under [policy] as
> `failed-sign-ins`, `within-minutes`, and `requests-per-minute`, and into security-notes.md marked "default, to
> confirm". Count per account, not only per address. Past a limit, answer 429 Too Many Requests with a Retry-After
> header. Let a setting that only a test copy is started with raise the sign-in limit, since a checker signs in many
> times from one address. Write a test that goes one past each limit.

- **Rules:** `probe.failed-sign-ins-unlimited`, `probe.create-rate-unlimited` (now also asked of each request named
  under `creates`, #874).
- **Why AI-built apps get it wrong:** in the loop-scale builds, 18 of 34 Haiku builds had no limit on wrong
  passwords and 13 none on creating records.
- `design-limits` covers this, but it asks the owner, and with the owner away it stalled 6 builds of 10.
- In `design-limits`' own trial, the builds without it that did lock accounts picked a number and wrote it nowhere,
  so `sv` could not hold them to it.
  This prompt makes the number a written decision without needing anyone to answer.
- **Harm to watch:** the sign-in limit locking `sv` out. The spec now says `sv` signs in up to 60 times. The test-copy
  setting in the prompt is for that, and the trial should count signed-in checks answered.

### `password-rules` (V6.2.1, V6.2.4, V6.2.8)

> When someone chooses or changes a password, refuse one shorter than 8 characters (suggest 15 or more), and refuse
> one on a list of the most common passwords: keep a list of at least the top 3,000 in the app, and compare in lower
> case. Do not require mixes of character kinds, and do not block pasting. Store and compare the password exactly as
> it was typed: never change its case or cut it short (if the hashing function has a length limit, as bcrypt's 72
> bytes does, use Argon2id instead). Write a test for each.

- **Rules:** `probe.short-password-accepted`, `probe.common-password-accepted`, `probe.password-altered`.
- **Why AI-built apps get it wrong:** 4 Haiku builds accepted a common password, 2 a 7-character one, and 4 a
  breached one. A builder asked for sign-up writes the form and the hash, and the password policy is the part left
  out.
- **Not included:** V6.2.12, the check against breached passwords. The usual way, the Pwned Passwords range API,
  needs the network, which `sv run`'s fence does not give the app. A prompt that sends builders to it would be
  followed by an app that fails or skips the check under test.

### `production-server` (V4.1.1, V13.4.6)

> Run the app with a production web server, not the framework's development server: gunicorn or uvicorn without
> `--reload` for Python, `NODE_ENV=production` for Node. Use that same command in securevibe.toml's `start`. Leave
> version numbers out of every header and error page (`Server`, `X-Powered-By`, and the like). Send a Content-Type on
> every response that has a body, with `; charset=utf-8` on text, HTML, and JSON.

- **Rules:** `probe.version-disclosed`, `probe.content-type`.
- **Why AI-built apps get it wrong:** 29 of 34 Haiku builds sent version numbers, and 11 left the character set out.
  Both come mostly from starting the app the way a tutorial does.
- **Level:** V13.4.6 is level 3, V4.1.1 level 1.
- **Watch:** a production server can make the app slower to start. The trial should compare how many apps started.

### `isolate-the-window` (V3.4.7, V3.4.8; both level 3)

> On every HTML page, send `Cross-Origin-Opener-Policy: same-origin` (or `same-origin-allow-popups` if the app opens
> a sign-in pop-up). Give the Content-Security-Policy somewhere to report what it blocks: add `report-uri` with a path
> of the app's own, such as `/csp-report`, that accepts the browser's report and writes one line to the log. Set both
> in the same place as the other security headers.

- **Rules:** `probe.opener-policy-missing`, `probe.csp-no-report`.
- **Why AI-built apps get it wrong:** the window header was missing in 63 of 69 loop-scale builds, more than any
  other finding. All 35 Sonnet builds sent a Content-Security-Policy without a report address.
- Neither header is in the usual "security headers" lists builders draw on. It is a separate prompt so that
  `security-headers`, shown as it stands, is not changed.

### `security-contact` (no requirement)

> Add a SECURITY.md at the top of the project that says how to report a security problem: an email address or a
> form, what to include, and how soon you will answer. If the app is a website, serve the same contact at
> `/.well-known/security.txt` too.

- **Rule:** `config.security-contact`.
- **Why AI-built apps get it wrong:** it was missing in 53 of 69 loop-scale builds. No one asks for it in a brief.
- **It cites no requirement, on purpose:** nothing in ASVS, AISVS, or Appendix C asks for one, and `sv` credits
  nothing when it is there.
- It is the cheapest prompt here to show working. A trial would show whether the library's method works for a
  prompt with nothing to resist.

## 3. How prompts reach the builder

- **The specification does most of the work, and prompts compete with it for attention.** Loop-scale item 1: with
  the specification in the request, every Sonnet build could be tested. The one harm the library trial took
  seriously, `secrets-in-the-environment`'s unreadable settings files, may be a prompt crowding out the
  specification.
  - Two of the commonest settings mistakes are now named in the specification itself (`delivery-protocol.md`,
    Part A).
  - The more prompts ADR-044 delivers at once, the more this matters. Keep each delivered prompt short. Leave out
    anything the specification already says, such as where to keep data and which address to listen on.
- **Each prompt was trialed alone; builders now get them together.** ADR-044 gives every shown prompt for a feature
  in one brief, and the shown prompts for the whole app in the guidance.
  - Pairs can conflict: the Referrer-Policy and Origin pair above is one that happened.
  - **Suggestion:** add one more arm to a future trial, with every shown prompt delivered together, and count
    `probe.own-forms-refused` and apps started as harm.
- **Only shown prompts are delivered, so the commonest findings are never prompted for.** None of the five problems
  in section 2 has a prompt. Even when one is written, it is not delivered until a trial shows it, which is the
  right rule. But the trials so far tested prompts for problems builders mostly did not have.
  - **Suggestion:** order the next trial by the loop-scale counts in "The short version", most common first. Those
    are the problems a prompt has something to change.
- **The running app is what the builder never hears about.** Loop-scale's "Findings by group": builders fixed what
  `securevibe_check` named, and the running-app findings stayed the same in every arm, because the MCP server never
  starts the app.
  - So the prompts aimed at running-app checks carry the most weight in delivery: headers, limits, passwords, and the
    window.
  - Each should be written so the builder can confirm it without `sv run`, for example with "write a test that…".
    Most already are. `security-headers` and `plain-error-pages` are not, and the trial builders could not tell
    whether they had succeeded.
- **Every prompt should survive the fence.** `sv run` gives the app no network, no keys but its own placeholders, and
  a read-only folder. A prompt whose most natural reading needs the network breaks the app under test even when the
  real app would be fine. Examples: a hosted classifier, the breached-password API, or a model downloaded at start.
  The fix is usually a sentence that also makes the real app sturdier. Worth a line in each prompt's check: "works
  inside the fence".
