# A gap analysis of SecureVibe, start to finish (7 October 2026)

Asked for by the owner on 7 October 2026: "a deep gap analysis of SecureVibe - the process start to finish, etc. and
let me know where there are blind spots or areas for improvement" (BACKLOG, "A deep gap analysis of SecureVibe,
start to finish"). This is a reading, not a build: nothing in `sv` changes with it. Each proposal is for the owner to
choose; the ones that change what counts as evidence, what `sv` runs, or the repository's settings need a decision
record or the owner's yes before anyone builds them.

**How it was done.** Five reviewers read one stage each, read-only, at `main` as of 7 October afternoon (`1fe884b`):
getting started; building with an AI coding tool through the MCP server; reading the code (`sv check`); running the
app (`sv run`, `sv probe`); and the reports, the coverage numbers, and the project's own health. Three of them also
ran the built `sv` against small test apps in a scratch folder outside the repository. Each finding was looked up in
`docs/BACKLOG.md`, and only what the backlog does not already cover (or covers wrongly) is listed here. The session
that wrote this document then checked the most serious claims in the code itself. Each finding says how sure it is:

- **checked**: confirmed in the code by the session that wrote this, and for most also reproduced by a reviewer;
- **reproduced**: a reviewer ran `sv` and saw it happen;
- **read**: a reviewer established it from the code, without running it.

## The short version

`sv` is careful about *saying* what it did not check: "not assessed" is never a pass, crashes are not refusals, the
fence around the running app holds, and the reports avoid words like "secure". Where it falls short is in four
places:

1. **Some "checked" results are stronger than the evidence behind them.** The worst case: tests the AI coding tool
   writes for itself count as fully "checked", the same as `sv`'s own checks. Others: Semgrep rules for one language
   credit requirements for apps in another; a key file that was committed and then untracked counts as fine though
   the key is still in the project's history; one GET request earns "checked" for the commonest kind of data leak.
2. **Most real apps cannot be run by `sv run` at all.** The app's folder is read-only and has no network inside the
   fence, so an app that installs packages (nearly every Flask, FastAPI, Express, or Next.js app) never starts, and
   every running check reads "not assessed". The trials worked only because their briefs banned packages.
3. **Plain `sv check`, the one the AI tool runs while it builds, says nothing about the commonest web flaws**:
   cross-site scripting sinks, a server fetching any address it is given, sign-in tokens decoded without checking
   their signature, open cross-origin settings, mass assignment. And it never reads the access rules of the hosted
   backends many AI-built apps use (Supabase, Firebase).
4. **The project's own safety nets have holes.** Only "Decision records" is a required check before merging into
   `main`: the tests are not, and 19 of the last 50 test runs on `main` were cancelled before they finished. The
   network-fence tests pass without testing anything when no container backend is present.

The ten things most worth doing first are at the end ("Where to start").

## 1. Credit stronger than the evidence

These matter most, because they are the opposite of what `sv` promises: a reader sees "checked" where nothing (or
far less than it sounds) was shown.

**1.1 The app's own tests, written by the AI coding tool, count as "checked" (high; checked).** The AI tool writes
the tests, chooses the test command (`[stack.run] test`), and is told by `sv` to name requirement ids in them
(`crates/sv-cli/src/brief.rs:635`, `crates/sv-manifest/src/spec.rs`). When the command exits 0, every requirement id
found in any file under `tests/`, `spec/`, and the like is credited (`crates/sv-cli/src/main.rs:3906-3915`,
`crates/sv-check/src/suite.rs:110-135`), including a Markdown file there and a comment; the test report is not read
when the suite passes. The credit lands in the same list as `sv`'s own checks and becomes "checked"
(`crates/sv-report/src/lib.rs:1340-1352`), and the short version calls every checked requirement "an automated check
looked and found nothing wrong". So `test = "true"` and a `tests/README.md` listing ids would turn them all to
"checked". When the same AI tool merely *says* yes, it gets the lowest tier, "stated", because "the author grading
its own work" is the weakest evidence; through a test it gets the highest. Requirements no test can show
(documentation, deployment, process) can be credited the same way. *Proposal:* a tier of its own, "the app's own
tests (written by your AI coding tool)", below "checked" and named apart in the short version; ids read only from a
test's own declaration in a language `sv` parses; the test report required and read even when the suite passes; and
the requirements tests cannot show moved to supporting. This changes what counts as evidence, so it needs a record.

**1.2 Semgrep's "any language" rules credit requirements for files Semgrep was never given (high; checked).** 280
mapped Semgrep rules are marked `"languages": ["*"]` (`data/adapters.json`), and a clean run counts each of them for
every app (`crates/sv-check/src/adapters.rs:1192-1215`). But `sv` hands Semgrep only the files whose language it
knows, not templates, `web.config`, `nginx.conf`, or Dockerfiles. The reviewer worked out what that credits: a
JavaScript app's cookie settings (V3.3.1) "checked" through a .NET `web.config` rule and a Scala Play rule; a Go
app's anti-forgery protection (V3.5.1) through a Django rule; Ruby and PHP apps' TLS (V12.1.1) through nginx rules.
*Proposal:* give each such rule its real target, pass Semgrep the template and configuration files too, and credit a
rule only when Semgrep's own list of scanned paths holds a file it targets.

**1.3 A key file committed and then untracked counts as fine (high; checked, and reproduced by two reviewers).**
`config.secrets-file-committed` asks `git ls-files` (`crates/sv-check/src/git.rs:44`), which lists what git tracks
*now*, not what was ever committed, and passes V13.3.1 when nothing is listed (`crates/sv-check/src/config.rs:186`).
Its own fix tells the reader to run `git rm --cached .env`; after that, the next check lists it under "Checked and
fine" while the key is still in the history. GETTING-STARTED.md promises "the check for a password or key that was
ever saved into your project's history". Nothing in `sv` reads git history at all, and the list of secret file names
leaves out `serviceAccountKey.json`, Firebase admin keys, `.streamlit/secrets.toml`, `.dev.vars`,
`config/master.key`, and `*.pem`/`*.key`. *Proposal:* read history (`git log --all --diff-filter=A --name-only`,
under ADR-032's protections) and run the key patterns over it; until then, never credit V13.3.1 from the current
file list alone, and say "is tracked now" in the documents.

**1.4 V1.2.4 (no injection) is "checked" for apps that build queries through an ORM (high; reproduced).** The SQL
rule reads plain database-driver calls. A Go app with `db.Raw("…" + r.URL.Query().Get("n") + "…")` through GORM got
"V1.2.4 checked". Also missed: TypeORM, knex `whereRaw`, Laravel `DB::select(... . $_GET[...])`, Django `.extra` and
`RawSQL`, Supabase filter strings, and MongoDB `$where` (V1.2.4 names NoSQL). The backlog's item 18 of the 1 to 4
October review lists only driver calls. *Proposal:* read each ORM's raw-query calls, and do not credit V1.2.4 while
the bill of materials shows an ORM whose raw calls the rule does not read.

**1.5 Dependencies in .NET, Dart, Swift, Elixir, and Deno are invisible, and V15.2.1 is credited anyway (high;
reproduced).** None of `*.csproj`, `pubspec.yaml`, `Package.swift`, `mix.exs`, or `deno.json` is detected
(`crates/sv-scan/src/ecosystems.rs:24-120`). A .NET-only app is told "No package manifest was found", and a mixed app
whose npm part had a lockfile got "V15.2.1 checked" with an old Newtonsoft.Json pinned in its `.csproj`.
*Proposal:* detect these as ecosystems `sv` does not read, so they hold back the credit and the message says so.

**1.6 "Debug mode off" and "generic error messages" are credited from a 404 alone (medium; read).**
`probe.error-detail-leak` credits V13.4.2 and V16.5.1 when the missing-page answer has no stack trace
(`crates/sv-check/src/probes.rs:364-371`), which it did in 177 of about 190 trial builds that started. Frameworks show
traces on errors (500s), not on missing pages. *Proposal:* provoke a real error (malformed JSON, a non-number id) and
credit only when an error answer was seen and was clean.

**1.7 One read earns "checked" for the commonest data leak (medium; read).** V8.2.2 becomes "checked" when user B is
refused one GET of one of user A's records (`crates/sv-check/src/signed_in/admin.rs:644-744`). Nothing tries B
changing or deleting A's record, or looks for A's data in B's lists. The requirement's own line names the scope; the
counts and the short version do not. *Proposal:* B also opens every private page and the record's list (A's marker
there is a finding); optional `update` and `delete` templates under `owned`; and "checked in part" wording for checks
that rest on one sample.

**1.8 The coverage documents' headline counts requirements that can never be credited (high; read).** COVERAGE.md's
"Can settle 48%" of ASVS includes 48 requirements that can only ever be found failing; the share that can be
*credited* is 119 of 345 (34%), and 43 of 70 at level 1, not 57. REQUIREMENTS.md labels such requirements "Can be
checked". These are the numbers the README, the paper, and the owner quote. *Proposal:* a "can be credited" column,
a label of its own for finding-only requirements ("can only be found failing"), and the AISVS section's existing
sentence repeated for ASVS.

**1.9 The development-server check passes `python app.py` that starts Flask's debugger (medium; reproduced).** The
check reads the start command only (`crates/sv-check/src/launch.rs`); `app.run(debug=True)` in the code, which lets
anyone who can reach the page run code on the server, and Django's `DEBUG = True`, are not read. *Proposal:* a
code rule for both, or say "the command runs a script; whether it starts a debug server is in the code" instead of
passing.

## 2. False alarms that would cost the owner trust

**2.1 Apps that sign in with a token get false "request from another site accepted" findings (high; checked).** The
forged request is built with the signed-in session's headers (`crates/sv-check/src/signed_in/mod.rs:437-438`), which
for a token-based app include `Authorization: Bearer …` (`mod.rs:300-312`); `forgery.rs` removes anti-forgery headers
but keeps it. Another website cannot send that header, so a JSON API that keeps its token in the browser accepts the
"forged" request and is reported high. *Proposal:* send forged requests without `Authorization` when the token is not
in a cookie; a refusal then means "another site cannot send this", which is not a finding; add a fixture.

**2.2 Single-page apps get a false "private page open to anyone" (medium-high; read).** Any 2xx counts as served
(`signed_in/mod.rs:1340-1357`). A React or Vite app answers `/dashboard` with the same page shell for everyone, so
it is reported high, and every check that needs the signed-in control then reads "not assessed". *Proposal:* treat
an anonymous answer identical to the root page as a single-page app's shell, not judged, and tell builders to list
their API addresses (`/api/me`) as private pages.

## 3. What is never looked at

**3.1 Apps that install packages cannot run under `sv run` (high; checked).** `build` and `start` run as one command
inside the fence (`crates/sv-run/src/docker.rs:437`), with the app's folder read-only (`docker.rs:425`) and no network,
so `pip install` or `npm install` cannot work; the code says so (`docker.rs:981`). Yet the starter file suggests
`build = "pip install -r requirements.txt"`, and the project's own `examples/flask-booking/securevibe.toml` uses that
step and also listens on `127.0.0.1`, which the spec warns against. There is no option to build an image first.
Across 206 trial builds, every brief banned packages ("standard library only"). For typical AI-built apps, every
running check is "not assessed": honest, but it means the deepest checks are almost never available to the people
`sv` is for. *Proposal:* now, fix the example and the starter's suggestion, warn in the preflight about install steps,
and document "build your own image and set `image`"; then, as a decision with its own record, an `image-build`
option or an install step outside the fence before the app starts inside it.

**3.2 Hosted backends: Supabase and Firebase rules are never read, and their apps cannot be run (high; reproduced
for the rules).** Nothing reads `firestore.rules`, `storage.rules`, `database.rules.json`, or Supabase migrations: a
test app with `allow read, write: if true;` and a table granted to `anon` without row-level security got no finding,
and a service-role key under a `NEXT_PUBLIC_` name was reported only as "environment file not ignored". For apps
built with Lovable, Bolt, and the like, these rules *are* the access control; at run time their sign-in and data go
to a service the fence blocks. *Proposal:* rules-file checks (`if true`, no `request.auth`, no owner check); SQL
checks (a table without `enable row level security`, grants to `anon`); a secret under a `NEXT_PUBLIC_`, `VITE_`,
`EXPO_PUBLIC_`, or `REACT_APP_` name; and, when the dependencies show such a service, a plain line in the run's
summary that sign-in and data are outside what the fence can test.

**3.3 Plain `sv check` has no rule for the commonest web flaws (high; reproduced).** A Flask test app with
`render_template_string` built from a value, `Markup(request.args…)`, `requests.get(request.args['url'])`,
`jwt.decode(..., verify_signature=False)`, `CORS(origins="*", supports_credentials=True)`, CSRF switched off, and
`debug=True` drew one finding (the SQL line). An Express and Next.js app with `dangerouslySetInnerHTML`,
`res.send('<h1>' + req.query.name)`, `fetch(req.query.url)`, `jwt.decode` used as verification, `algorithms:
['HS256','none']`, `cors({origin: true, credentials: true})`, and `findByIdAndUpdate(id, req.body)` drew none. These
are reached only by the running probes (often only with sign-in set up) or by outside tools. *Proposal:* code rules,
mostly finding-only, for each: cross-site-scripting sinks by framework, a template built from a value, request data
flowing into an outgoing request, a token decoded without verification or with `none` allowed, cross-origin settings
that reflect any origin with credentials, CSRF switched off, and the request body passed whole to an update.

**3.4 Outside tools' findings for injection, XSS, and SSRF carry no requirement (medium-high; read).** Unmapped:
Bandit B610 and B611 (Django `extra` and `RawSQL`), B701, B703, B704 (autoescape off, `mark_safe`, `Markup`), B310
(`urlopen`), B614, B615; gosec G203 (unescaped template), G106, G108. In one report a Bandit SQL-injection finding
can sit beside "V1.2.4 checked". *Proposal:* map them, and fail the build when a tool finding about injection or XSS
names no requirement.

**3.5 Running checks a real attacker would try first (medium; read).**
- *Changing or deleting someone else's record*, and finding their data in your lists (see 1.7).
- *Mass assignment beyond sign-up:* `role_field_check` needs both `signup` and an admin page, and was skipped in 149
  of about 190 started trial builds; nothing adds `user_id`, `owner`, or `role` to other create or update requests.
- *Stored cross-site scripting:* the record marker is plain text, and the AI test model's replies never contain HTML,
  so "a note that runs a script for whoever opens it" and "the AI's markdown rendered as HTML" are not tried unless
  the browser section is filled in (no trial manifest had it).
- *Which accounts exist* (V6.3.8): only asked through password reset, never through sign-in or sign-up.
- *A reset code returned in the reset request's own answer* is never looked for.
- *Prompt injection through stored content:* a saved note telling the model to do something is never planted.
- *A sign-in token signed with a placeholder secret* (`secret`, `changeme`) is never tried, though it needs no
  network.
- *Models other than OpenAI's and Anthropic's formats:* an app using Gemini gets every AI check "not assessed".

**3.6 Files skipped without saying so (medium; reproduced).** `.astro`, `.ejs`, `.erb`, `.hbs`, `.pug`, `.twig`,
`.j2`, `.njk`, `.cshtml`, `.jsp`, `.ipynb`, and `.sql` are neither read nor named as unread; an `.astro` page and a
notebook with `eval` drew nothing, and the notebook run said only "Parsed 0 of them". *Proposal:* name them as
unread code; read notebook cells as Python and Astro's frontmatter as TypeScript.

**3.7 Thin spots in the secrets scan (medium; reproduced).** A value containing `://` is skipped
(`crates/sv-check/src/secrets.rs:708`), so a database address with its password (`postgresql://admin:…@…`) is never
reported. There are 11 vendor key formats; SendGrid, Groq, Resend, Supabase, Twilio, Replicate, and others are
missing. A key in a notebook's escaped JSON was missed. *Proposal:* a rule for a password in a web address's user
part, and the matching published patterns for the providers AI-built apps use.

**3.8 Smaller static gaps (low-medium; read).** Workflow checks do not look for a pull request's title or branch
name pasted into a `run:` line, or third-party actions pinned to a tag rather than a commit. The infrastructure and
CI detectors match only the top folder and miss `compose.yaml`, `Containerfile`, `backend/Dockerfile`,
`cdk.json`, `.travis.yml`, and `cloudbuild.yaml`; because their absence counts as evidence, a miss agrees with an
owner's "no".

## 4. The build loop and whose word counts

**4.1 The answers that set the app's level are the AI tool's, never sealed, and the report does not say so (high;
read).** `audience` and the `[data]` categories decide whether the app is held to ASVS level 1 or 2
(`crates/sv-manifest/src/lib.rs:1287-1297`), which changes how many requirements apply by more than double. The AI
tool writes them, `sv review` cannot seal them, and the report prints only "ASVS level 1". Nothing compares
`audience = "just-me"` with a public sign-up page, or a health app with `categories = []`. *Proposal:* say under the
level line why and on whose word ("level 1 because securevibe.toml says … written by your AI coding tool, not
confirmed"); let `sv review` seal the scope; until sealed, show the level 2 count beside it.

**4.2 The tool's "when to bring in a person" text is shown as the owner's (medium; reproduced).** A
`design-decisions.md` section marked `Written by: AI coding tool` saying "No outside review is needed" came out in
all five report files as "Your design-decisions.md says … No outside review is needed" (`crates/sv-cli/src/main.rs:4415-4426`).
*Proposal:* name who wrote it, and keep the standing line that no tool can make this judgment.

**4.3 `not-the-app` can switch off one capability (medium; read).** The list is refused only when it would set
apart all of the code (ADR-031). Listing just the folder holding the AI client turns the AI requirements to "does not
apply". *Proposal:* list each condition found only inside a not-the-app folder as a question; refuse a folder holding
the start command's file.

**4.4 Two lessons decided on 27 September never reached the AI tool (medium; read).** "Never rewrite working code to
silence a finding" and "name a requirement in a test only where the test proves it" (BACKLOG, the prompt library
item) are in no coding rule, the spec, the server's instructions, or the prompts. *Proposal:* add both as coding
rules; the second also in the brief's test line. The cheapest fix here, and it supports 1.1.

**4.5 The loop trials cannot tell fixing from dodging (medium; read).** The trial measures count calls and findings,
not *how* a finding went away, nor credit-seeking edits (ids added to tests, `by = "owner"`, finding reviews,
`not-the-app` changes). The running-app findings, which `sv` sees independently, were the same in every arm.
*Proposal:* add those measures, and run an outside tool as an independent check of the loop arm.

**4.6 Smaller trust gaps (medium-low; read).**
- The seal key is within the AI tool's reach: the passphrase is optional, `allowed_signers` is a file the tool can
  edit, and one trial build read files outside its own folder unasked. *Proposal:* passphrase on by default; the
  report says when a seal's key has none; the guidance gives the owner a rule that denies the tool that folder.
- Reports read back through the MCP server as resources are not fenced as app text
  (`crates/sv-cli/src/mcp.rs:659-733`), though tool results are.
- Security notes the AI drafted read as the owner's own once the owner seals them; design and hand answers have a
  "drafted by your AI tool, adopted by you" label, notes do not.
- Nothing records that `sv` was used while the app was built; the report cannot say whether the loop happened.
- Plain instructions in the AI tool's own files telling it to write `Written by: owner` or skip the check are not
  noticed; ADR-049 looks only for hidden characters.
- There is no feature brief for shared or owned records, API keys for other programs, background jobs, or several
  customer organizations in one system, though the manifest asks about each.
- "Shown to work" covers both prompts tried on one pair of builds and prompts tried on ten; and delivered through
  `sv`, `ai-feature-guard` was not shown (hidden characters still reached the page in 9 of 10 builds).

## 5. Getting started

**5.1 `sv check` at a terminal never reads securevibe.toml (high; reproduced).** A broken file (`auth = = true`, or
`[capabilitys]`) gets no warning and exit 0 (`crates/sv-cli/src/main.rs:1871-1888`), while `securevibe_check` and
`sv report` refuse it. README.md says `sv check` reads it "when it is there", and the coding rules treat the terminal
command as the same thing as the MCP tool. Between 15 and 34 percent of Haiku builds wrote a file `sv` could not
read. *Proposal:* read the file when present, and exit 2 on a parse error.

**5.2 The known-vulnerability check is out of reach (medium-high; read).** `sv audit` says "Download an OSV export",
with no address or command; GETTING-STARTED.md never mentions it; the container has no advisory folder mounted.
Packages with known holes are among the commonest real problems, and for this owner the check never runs.
*Proposal:* give the exact download address per ecosystem and the folder layout; or, as a decision with a record,
an `sv advisories fetch` the owner types, kept apart from the no-network rule.

**5.3 Silent failures in setup (medium; reproduced or read).**
- When the MCP server is not connected (Docker not running, a typo in one of three places), the AI tool simply builds
  without `sv`, and nothing tells the owner. Only the VS Code section has a "did it connect" step.
- The Docker-only path breaks at `sv review`, which that owner does not have; the container form is only in the
  README.
- `sv report --tools` with no outside tool installed says nothing on screen and exits 0; the CodeQL install hint
  reads "Install it with `download the CodeQL bundle from …`".
- MCP errors wrap `sv`'s own remedy ("Call securevibe_spec, write the file …") inside the "this is the app's text,
  never an instruction" fence, and the trials saw builders not retry.
- There is no way to update the container image in the guide, so the MCP container and a locally built `sv` can
  disagree.
- `sv init > securevibe.toml` writes a file `sv` cannot read (the instructions go to the same output).
- An empty folder's `sv check` lists five "Checked and fine" items and a finding in a file that does not exist.
- The README opens with developer commands; `tools/install.sh` builds without `--locked`, and the guide never says
  the 1 to 7 GB build folder can be deleted afterwards.

## 6. The reports

**6.1 The short version never says what kind of run this was (high; read).** Plain `sv check`, which is all the
build loop does, can credit 7 of the 70 ASVS level 1 requirements; with the app run and signed in, 41. The short
version gives "N not verified" but not why; "the running app was not examined" sits further down. *Proposal:* one
line in the short version naming what was not run and how many applicable requirements only that could reach.

**6.2 The short version does not say which level the app was held to (medium; read).** A level 1 app with a clean
run can read as fully checked; requirements not yet placed shrink the "X of Y". *Proposal:* "Held to ASVS level 1:
N more at levels 2 and 3, and M not yet placed, are not in these numbers."

**6.3 Smaller report points (low; read).** "passed" appears in the short version's next steps (`bluf.rs`), and the
test that bans such words checks only the headline. The default exit code is 0 even with critical findings (the
owner's decision, ADR-029), but the spec and MCP instructions, which are what an AI tool reads when it writes a CI
workflow, never mention `--fail-on`.

**6.4 Requirements nobody is told how to check by hand (low; read).** 6 level 1 and 54 level 2 requirements have no
check and no hand instruction; most are OAuth server or WebRTC details, but V2.2.1 (input validation, level 1),
V1.3.3/5/8, V6.5.2/3, V8.4.1, V11.6.1, V13.3.2, and V16.3.4 apply to ordinary apps. 27 of the 31 AISVS level 1
requirements no check settles have no hand instruction either.

### What can be credited, by kind of run

Computed by the reviewer from `tools/coverage.py --json`. "Can be credited" is the share a check can ever mark
*checked*; the rest of "can settle" can only ever be found failing.

| | Total | Can settle | Can be credited | Plain `sv check` | + outside tools and advisories | + `--run` | + signed in | + `sv probe` |
|---|---|---|---|---|---|---|---|---|
| ASVS level 1 | 70 | 57 | 43 | 7 | 17 | 19 | 41 | 43 |
| ASVS level 2 | 183 | 89 | 67 | 3 | 25 | 36 | 66 | 67 |
| ASVS level 3 | 92 | 21 | 9 | 0 | 3 | 5 | 6 | 9 |
| AISVS levels 1 / 2 / 3 | 51 / 95 / 45 | 20 / 16 / 2 | 14 / 6 / 1 | 0 | 0 | 14 / 5 / 1 | 14 / 6 / 1 | same |

Thinnest chapters at levels 1 and 2, by share that can be credited: WebRTC (V17) 0 of 7, business logic (V2) 1 of 11,
OAuth (V10) 6 of 29, data protection (V14) 2 of 9, configuration (V13) 3 of 13, authorization (V8) 2 of 7.

## 7. The project's own health

**7.1 The tests are not required before merging, and many runs on `main` never finish (high; checked).** The only
required check on `main` is "Decision records", and "up to date with `main` before merging" is off. Of the last 50
test runs on `main`, 19 were cancelled (a newer run replaces a queued one), 2 failed, 28 passed, and 1 was running,
so about 4 in 10 commits on `main` are never tested; `rust.yml`'s comment says every run on `main` finishes. Two
pull requests merged on 7 October with a failing test job (#871 and #873). *Proposal, the owner's call (repository
settings):* make the test and image jobs required, consider "up to date before merging" or a merge queue, and give
`main` a concurrency group per commit.

**7.2 The fence tests pass without testing the fence when there is no container backend (medium; read).** About ten
test files print "no container backend here" and pass (`crates/sv-run/tests/fence.rs`). If the runner's Docker breaks,
they stay green. *Proposal:* `SV_REQUIRE_BACKEND=1` in CI turns that branch into a failure.

**7.3 The files that decide what counts as evidence are governed by no decision record (medium; read).** 85
tracked files are in no record's "Governs" list, among them `suite.rs` (the test credit in 1.1), the report's
status order, `data/applicability-v2.json`, `data/human-checks.json`, and `tools/coverage.py` (the public numbers).
The owner decided on 6 October that large shared files stay ungoverned and the weekly review catches what slips; the
backlog notes the weekly review left no trace on its first Monday. *Proposal:* govern the small evidence-policy
files, and confirm the weekly routine runs.

**7.4 Code is merged far faster than it is reviewed (medium; read).** Since 1 October: 785 merges and about 77,000
lines added under `crates/` and `data/`. The two after-the-fact reviews found 24 and 17 faults, at least 8 of them
false credits. *Proposal:* extend `coverage.py --credits` so that every check that can credit must also be seen not
crediting somewhere in the test suite, turning "break your own rule" into a CI gate.

**7.5 The backlog is too large to read reliably (medium; read).** `docs/BACKLOG.md` is about 7,500 lines with about
136 top-level items, of which about 111 are done but still listed; the claim protocol failed twice on 6 October;
there are 457 remote branches. *Proposal:* move done items to a file of their own; and either track claims as GitHub
issues with assignees or have CI refuse a claim for an item already claimed on `main`. Deleting merged branches is
the owner's to approve.

## Where to start

Ordered by how much each would change what the owner can trust, against what it costs. Items marked *decision* need
a record or the owner's yes first.

1. **The app's own tests in a tier of their own** (1.1). *Decision.*
2. **Require the test job before merging, and stop cancelling `main`'s runs** (7.1). *Owner's yes (repository settings).*
3. **Credit Semgrep's any-language rules only for files it scanned** (1.2).
4. **Read git history for committed key files**, and stop crediting V13.3.1 from the current list alone (1.3).
5. **Make `sv run` work for apps that install packages**: fix the example and the starter now (3.1); an image-build
   step later. *Decision for the second part.*
6. **Fix the two false alarms**: token-based apps and single-page apps (2.1, 2.2).
7. **Code rules for the commonest web flaws in plain `sv check`** (3.3), and map the unmapped Bandit and gosec rules
   (3.4).
8. **Supabase and Firebase access rules** (3.2).
9. **Say in the short version what kind of run it was, which level, and on whose word** (6.1, 6.2, 4.1).
10. **"Can be credited" in the coverage documents** (1.8), so the public numbers say what they mean.

Several of the rest are a line or two each and could ride along with these: the two missing coding rules (4.4),
`sv check` reading the manifest (5.1), the exact advisory download address (5.2), the reset code in the reset
answer (3.5), and the `--fail-on` advice (6.3).

## What works well and should be kept

- "Not assessed" is never a pass and never a failure, and a check that could not run says why, all the way through.
- A crash is not a refusal: credits and findings resting on a server error or no answer are moved to "not assessed".
- Every running check proves its setup first (user A reads back their own record before B is tried; the real token
  must open the page before a forged one is judged).
- The network fence (internal network, no gateway, read-only root, no capabilities, resource limits), verified with
  Docker, and `sv probe`'s few, read-only, public-only requests.
- Tiers that say whose word it is: the AI tool's answers are its own, the owner's need a seal, and an unsealed
  "owner" falls back to the tool's tier.
- Text from the app is fenced as data before it reaches the AI tool, with a fresh tag each time.
- Outside tools are honest: a missing tool, a skipped file, or a tool error is never shown as clean.
- Advisories never say "no known vulnerabilities" with no data, partial data, or an incomplete bill of materials.
- Keys are redacted everywhere, and git runs with its program-running settings neutralized (ADR-032).
- The coverage generator checks itself and the credit census holds the documents to what the tests really credit.
- The trials are written down before they run, with dated amendments and "no reading" where the data cannot decide.
- The backlog records honestly who decided what, the duplicated builds, and each review's fault count.
