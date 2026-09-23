# What is still to do

Agreed work not yet started, so it lives somewhere more durable than a chat between sessions. Each item says what
an owner would notice, because that is what decides the order. Remove an item when it lands.

**Claiming an item happens here, not in a message.** Before starting something, add `**[taken: <session>, <date>]**`
to its first line and commit that on its own; release it the same way if you stop. A message claiming an item is
invisible to a session that is not running, which is how two sessions spent two hours of 20 September 2026 both
building the query recipe: each read this file, each correctly saw the item unclaimed, and neither was wrong.

## In progress right now

- **The evaluation harness is in use** by session keen-meninsky-691a27 from 23 September 2026, on branch
  `claude/report-table-escaping`, checking a template change to `scripts/docs-build.ts` and
  `src/features/apikeys/repo.ts`. Two sessions ran it at once on 20 September 2026 for eight minutes because
  each said so only in a message. This line is removed when the run finishes.

## Mine (this session's half of the split agreed on 19 September 2026)

- **The test job hangs on a runner, and nobody knows which file.** **[taken: this session, 22 Sep 2026]** Seven
  fast files pass in the first six seconds and then the log goes silent until the step is killed, whether the
  files run together or one at a time. It has never reproduced locally. Because the checks cannot be trusted to
  finish, they run by hand only: the `push`, `pull_request` and `schedule` triggers are commented out in
  `.github/workflows/checks.yml`, so nothing here is actually checked on the way in. The diagnostic that names
  the stuck file — a loop printing each file before running it, ninety seconds each, stopping after three —
  is preserved at `876cbe6` on `claude/query-recipe`. Blocked until 22 September 2026 on metered minutes; the
  repository is public now, so the minutes are free and this is unblocked.
- **"What only you can do".** A list on the Results page and in the reports, derived from facts rather than
  prose: settings left unset, named outside services with no address, planned features that came back not-built.
  For each, what the owner must do and what stays switched off until they do. `reports/going-online.ts` already
  has this shape for deployment, so it extends a pattern rather than inventing a third list.
- **"Not applicable", with a reason, instead of a control an owner cannot act on.** AC-02 begins "if your
  organisation has a central sign-in system"; an owner who has no organisation is rated **at risk** on it anyway,
  for ever. The answer is not a dismiss button — that lets anyone turn a red rating green by clicking, which is
  the overstatement this whole project exists to avoid. Two parts instead. Where the control is really asking a
  question, ask it in the wizard (does your organisation have a central sign-in system?) and let the existing
  applicability rules mark it not applicable, as TLS requirements already are for a local-only app. Where no
  question fits, let the owner record a **reason**: the control stays visible, reads "not applicable — because
  …", the rating reflects it, and the reports name who decided and when. One hides a control; the other answers
  it, and only the second can be audited.
- **The red rating and the green ticks are different scoreboards, and the page does not say so.** "At risk"
  comes from Secure by Design — one unmet critical control is enough — while the ticks below are ASVS, where the
  same app passes 107 of 159. Both true, and read together they look like a contradiction. The rating needs to
  carry which standard it comes from, and the ASVS section needs to say that a good score there does not lift a
  critical control elsewhere.
- **The authorization tests cannot see an admin area that is not called "admin".** `tests/security/authz.test.ts`
  looks for routes whose auth is the literal `role:admin`, while the neighbouring assertion resolves the member
  role from the config. An app whose admin role is named `owner` — as a real owner's app was — has sixteen
  properly restricted admin routes and reports three failing authorization tests, because the check cannot find
  what it is looking for. Worse than the false failure is the silent version: the evidence those tests provide is
  only as good as the role happening to be named "admin". Resolve the role from the config, as line 86 already
  does.
- **"Files in place" instead of "built".** planCoverage called "See graphs and summaries of trends over time"
  *built* on the evidence that a page existed at the planned path and tests named as planned passed — while
  nothing drew anything. Where the only evidence is that files exist, the row should say that in those words.
- **A check for damaged saved answers.** A record type with no fields cannot have come from someone describing a
  record: offer to remove it. A name that looks like a truncated sentence, and a description that reads as an
  answer to a different question, are questions rather than offers — the owner decides. Removing one must set
  `designStale` and `buildStale`, as `PUT /projects/:id/profile` does. Both of the owner's apps had one, and a
  rebuild recreates them from the answers.
- **Live spending during a build.** The run's own record carries no `llmUsage` while it runs, so the page has
  nothing to show, while `workspace/llm-audit.jsonl` has every call. An owner watching a slow, paid build lost
  the one number that said it was still working.
- **The changed-files list should fold away.** "What changed since the previous version" prints every file —
  65 of them after a rebuild — so the comparison a person came for is buried under a list they scroll past. Fold
  it by default behind a count they can open, and keep the summary above it visible. Same component as the skip
  counts below, so do both at once.
- **A build in progress is invisible from anywhere but the build page.** The live spending figure and the
  activity feed arrive on the run's event stream, which only that page listens to. An owner who wanders off
  mid-build — to their project list, to another app — sees nothing to say that something is running and costing
  them money, and coming back recovers only the figure from the last completed stage. That is the moment a
  first-time user force-quits a build they have already paid for. Wants a small persistent indicator wherever
  they are, which is more than a line of code: something has to hold the run's state above the page.
- **A stopped build can only be resumed from the build page, and nothing points there.** "Carry on from where it
  stopped" lives on the build page for that specific run, and the Results page offers no way back to it — so an
  owner whose build stopped part-way has the option, cannot reach it, and is left with a rebuild that pays again
  for work already done. It happened the night an owner's AI credit ran out mid-build: the only route was a URL
  typed by hand. The Results page should offer it directly whenever the last run is a full build that did not
  finish, with the same wording about keeping what was already written.
- **Skip counts that read as failures.** "179/201 app tests passing" invites "22 are failing". The skip reasons
  already exist in the template's `skipReason`, so the line can name them: "0 failed, 22 skipped because this app
  has no uploads, scheduled jobs or assistant." Two places: `eval/metrics.ts` and `web/src/components/VersionDiff.tsx`.
- **Scanning uploaded files for malware (ASVS V5.4.3).** **[taken: this session, 20 Sep 2026]** Policy settled in
  `docs/adr/ADR-011.md`: mandatory wherever files arrive from outside, and mandatory means an unscannable file is
  refused rather than stored and flagged. The entry below predates that decision and is kept for its reasoning. Our scanners ask whether the code has a weakness; an
  antivirus scanner asks whether a file is known-bad content. Nothing we run does the second. The template
  already stops a file pretending to be an image — size enforced before the body finishes, magic bytes sniffed,
  declared type and extension cross-checked, stored outside the web root under a random name — but a genuine
  image carrying a known exploit, or a document with a malicious macro, passes all of that. Worth adding as an
  optional connection to a scanner the owner runs (ClamAV being the usual one) for apps that accept uploads, with
  the same wizard shape as an outside service. It must stay honest when absent: the app says uploads are
  unscanned rather than implying they were checked. Not a new build-time scanner: malicious packages are rarely
  in antivirus signatures, and that risk is already covered by disabled install scripts, a minimum package age
  and the OSV check. V5.4.3 stays manual-only until an app actually scans.
- **The same scanner, on SecureVibe's own Security page.** **[taken: this session, 20 Sep 2026]** A second use of the same connection, and the stronger
  of the two for SecureVibe itself: an opt-in external tool beside Trivy, Semgrep and the AI scanner, run on
  demand like any other check. It earns its place most on an **uploaded** app — code SecureVibe is handed and
  never runs is precisely untrusted content — and on a built app's own uploads folder, where whatever an owner
  has been trying out is sitting. It must behave like the other opt-in tools when absent: say the check did not
  run, never imply a clean result. Expect few hits on ordinary source; the honest claim is "nothing known-bad in
  these files", not "this code is safe".
  For an **uploaded** app this belongs in the ordinary run rather than behind a switch: the owner is handing
  SecureVibe files from somewhere else, so asking whether any of them is known-bad is part of checking them, not
  an extra. Still conditional on the scanner being installed, and still silent about what it did not check — an
  uploaded app whose scan did not run must say so on the page and in the report, beside the checks that did.

- **Let an uploaded app be checked without answering the questions first.** `POST /projects/:id/runs` refuses an
  uploaded app that has no design: "Answer the questions about your app before checking it." The reason is real —
  the answers decide which rules apply, and a compliance report written without them is guesswork — but it is the
  wrong shape for what people actually do. The first person to hand SecureVibe somebody else's code on
  20 September 2026 said plainly "I just want to check the code that's uploaded", and most of what would tell her
  something does not need a single answer: secrets, dependencies, configuration, the AI review and the virus scan
  all read the code as it is. What needs the answers is the ASVS mapping, and only the applicability part of it.
  So the split to build is: run every check that does not depend on the answers straight away, and show the
  compliance section as unanswered rather than absent — "these rules may or may not apply to your app; answer
  eight questions and we will say". That also fixes the worse half, which is that somebody checking code they did
  not write cannot honestly answer half the wizard, and guessing puts made-up facts into a report. A shorter set
  of questions for uploaded apps is probably part of the answer.

- **One test in `web/` and nothing runs it.** `web/src/pages/plainActivity.test.ts` exists, passes when run by
  hand, and is executed by no suite: the root `npm test` script is `npm run test -w server`, the server's vitest
  only includes `tests/**`, and `web/` has no vitest configuration at all. So it has never guarded anything, and
  a change that broke it would go unnoticed. Either give `web/` a test run of its own and put it in the checks, or
  move the file where the server suite will pick it up — but not leave a file that looks like coverage and is not.

- **A report that says 0 of 106 when the truth is "we did not look".** The first app anybody handed SecureVibe
  from outside, on 20 September 2026, was a Python Flask app: 7 `.py` files including `auth.py`, `db.py` and a
  21KB `main.py`. The run finished, cost twenty cents, and reported **0 of 106 applicable ASVS requirements
  verified**, one critical configuration problem and ten high/medium issues. Every one of those ten was in
  `static/app.js` and `static/index.html`. The static analysis read **1 code file and 1 template**; not one line
  of Python was examined. The dependency check read **0 packages** because `requirements.txt` is not a lockfile
  it knows, and then raised `deps.lockfile-missing`. Several configuration findings are npm concepts
  (`config.ignore-scripts`) asked of an app with no npm. The AI review — the one checker that could have read
  Python — reviewed all 139 requirements and cited **0 places in the code**.
  This is the exact failure the project exists to prevent, pointing the other way: not a pass we did not earn,
  but a damning report we did not earn either. "0 of 106 verified" reads as *this app is catastrophically
  insecure*; it means *this app was not assessed*. An owner shown that would either despair or, worse, rewrite
  working code to chase findings that are artifacts of assuming Node.
  Three things, in order. **Say what was read**: every report needs the file count and the languages it covered,
  beside the score, so "1 of 12 files" is visible. **Refuse to score what was not read**: an app whose code the
  scanners cannot parse gets "not assessed" rather than zero, on the same principle as a skipped test not being
  a failing one. **Then decide about languages** — Python and plain JavaScript at least, or say plainly on the
  upload page which languages are actually checked, before somebody spends twenty cents finding out.

- **An uploaded app cannot be checked again from the page that shows its results.** The Results page offers
  "Update to the latest template", which only applies to an app SecureVibe built, and "Rerun the reports", which
  rewrites the reports from saved results and checks nothing. The action that actually re-runs the checks lives
  on the build page and nothing links to it, so on 20 September 2026 an owner wanting to re-check an uploaded
  app after a fix had landed read both buttons, correctly concluded neither was the one, and had to ask. She had
  hit the identical shape the night before with resume: the action exists, works, and has no route to it from
  where a person looks for it.
  Worth fixing as one thing rather than two: the Results page should offer "Check this app again" whenever a
  re-check is possible, which is always for an uploaded app and after a template update for a built one. And
  while there, the two existing buttons need to say what they do not do — "Rerun the reports" saying "nothing is
  checked again" in small grey text under it was not enough to stop somebody reasonably wondering.

- **Nine more findings that are artifacts of assuming SecureVibe built the app.** ADR-012 gated the two worst
  (`deps.lockfile-missing`, `config.ignore-scripts`) and the Flask app's re-run on 20 September 2026 showed
  three more classes still firing:
  `config.node-engine-pinned` says "package.json has no engines.node requirement" to an app with no
  package.json — clear-cut, same gate, simply missed.
  `config.readme-run-instructions` greps the README for the literal strings `npm run setup` and `npm start`.
  The question it is asking — does the README say how to run this safely — is fair for any app; the test is
  ours. It needs to ask the question in a way that a Python app can pass.
  The seven `docs.*` checks look for `docs/validation.md`, `docs/logging.md` and their siblings, which is the
  documentation layout SecureVibe's own template generates. This is the subtle one and worth getting right
  rather than fast: "your validation rules are not documented" may well be true of somebody else's app, but
  concluding it from the absence of *our* file paths is checking for our convention and reporting it as their
  failure. The honest result for an app we did not build is "could not verify", which is the same not-assessed
  distinction the compliance score just learnt, applied one level down at the individual check.
  Deliberately not fixed during the comparison runs: changing the checks between arms would have left the three
  apps measured against different rules, which is the one thing that experiment cannot survive.

- **The AI review cites nothing at all on an app it is the only checker for.** Measured on 20 September 2026,
  the same reviewer, days apart: SecureFit, a Node app SecureVibe built, 132 of 192 requirements reviewed and
  **231 places cited in the code**. The uploaded Python app, 139 of 139 reviewed and **0 places cited**, twice,
  at twenty cents a time. Nothing in the prompt is about TypeScript, and the review is handed the files
  whatever they are written in.
  This matters more than the static-analysis gap it sits behind. Our own rules not reading Python is a stated
  limit with a report line that now says so. The AI review is what tier 2 in ADR-012 *is* — it is the whole
  substance of "an app in another language still gets a real check" — and on this evidence it is contributing
  nothing to it. Until somebody finds out why, the honest position is that an uploaded app in an unsupported
  language gets the secrets scan, the virus scan, the dependency check and the external scanners, and should
  not be described as getting the AI review in any meaningful sense.
  Worth checking first: whether the file-selection step hands it any Python at all, whether the citation
  verifier is rejecting citations it cannot resolve to a known file type, and whether "cited 0 places" is
  distinguishable in the data from "made no findings" — the third possibility being another check that cannot
  tell its two zeroes apart.

- **You cannot get an AI review of your own app without rebuilding it.** For an uploaded app the AI review comes
  with an ordinary check, for twenty cents. For an app SecureVibe built, the only route to one is a full build:
  about $3.75, and it rewrites the code. So an owner who wants a second opinion on the app they already have
  must pay fifteen times as much and accept changes they did not ask for. The verify-only path already supports
  AI — `runs.ts` only forces `withoutAi` because the buttons offering it do. A "check again, with the AI review"
  option beside the free one would cost a line of UI and close a gap that currently makes the native case worse
  served than the uploaded one.

- **A report that only becomes a PDF when somebody clicks a dialog is not archivable.** SecureVibe writes each
  report as HTML, JSON and Markdown; the "Save it as PDF" button hands the HTML to the browser's print dialog,
  so no PDF exists on disk until a person saves one, one report and one dialog at a time. On 20 September 2026
  the owner wanted the three reports for every application, for a paper's appendix: seven apps, twenty-two
  documents, twenty-two dialogs. They were produced instead by driving the same rendering headlessly.
  That is a workaround, and the need is ordinary rather than exotic — an appendix, an auditor, a handover, a
  record of what the app looked like on the day somebody signed off on it. Writing the PDFs alongside the HTML
  at report time would cost a rendering step and remove the manual one entirely. Worth doing as part of the
  hand-off pack rather than beside it, since that is already the thing somebody sends to another person.
  The related half: an owner cannot currently export every app's reports at once at all. Each has to be opened
  in turn.

- **The self-assessment reports 4 critical and 113 high against SecureVibe, and almost none of it is real.**
  A self-assessment on 20 September 2026 returned 31 of 161 requirements verified, 4 critical, 113 high. Checked
  one by one, the bulk is SecureVibe's own rules misfiring on SecureVibe: 62 `route-outside-registry`,
  13 `child-process-exec`, 17 `fs-user-path`, 11 `path-join-user-input`. Those rules assume the thing being
  scanned is a generated application, which is meant to declare its routes in a registry and never spawn a
  process. SecureVibe is a build tool: spawning processes and joining paths is its job. Same class as asking a
  Python app about its npm lockfile, one level up — the target is not what the rules assume, and the report says
  so in the language of failure.
  The six findings that are *not* explained by that were checked individually and are all legitimate: three
  "hardcoded secrets" are deliberately-wrong passwords (`not-a-real-password-1`) that DAST posts to a login form
  to prove it rejects them, and three `tls-reject-unauthorized-false` are the runtime probes connecting to the
  app under test over its own self-signed certificate — including the probe whose entire purpose is to attempt a
  TLS 1.1 handshake and confirm it is refused.
  So the self-assessment is currently unusable as a signal: its true findings are buried under a hundred false
  ones, and an owner or a reviewer reading it would reasonably conclude the opposite of the truth. It needs the
  same treatment the uploaded-app case just got — rules that declare what kind of target they apply to, and a
  report that says "this check does not apply to this thing" rather than failing it.

- **The runtime probe's HTTP client accepts any certificate from any host.** `scanners/dast/http.ts:244` sets
  `rejectUnauthorized: false`, which is correct for what it does — connecting to a freshly built app on
  loopback with a self-signed certificate — and is enforced by nothing. The two other places that disable
  certificate checking both pin `127.0.0.1` at the call site; this one takes whatever URL it is handed. The
  guarantee holds because of who calls it rather than because of what it enforces, which is the shape this
  project has spent a week finding in other places. Refusing a non-loopback host in the client would make it
  true by construction and cost one line.

- **The template suite ran 30 of its 33 files and said it was green.** The launcher takes an explicit list of
  test files, and three were never added to it: `tests/nav.test.ts`, `tests/theme.test.ts` (four tests moved
  there on 20 September) and `tests/assistant-progress.test.ts` (written that evening). Twelve tests, including
  every test of the work one session had just finished, were not run by the suite that reported on it. The list
  is now regenerated before each run rather than maintained, and the output states the file count so a
  shrinking suite is visible.
  It cannot simply be a glob, which is the interesting part: `~/Desktop` is TCC-protected on macOS, so the
  launcher's shell can open a path it is handed but cannot enumerate the directory — every glob returns "no
  matches found" there while working in a terminal, and node given the bare directory finds `tests/security/`
  and misses the four files at `tests/` root. Three separate silent failures of the same kind, in the thing
  whose job is to notice failures.
  The durable fix is for the repository not to live under `~/Desktop` at all, which is already on this list for
  the iCloud reason and now has a second.

- **Take a zip, since that is what people have.** The first person to hand SecureVibe somebody else's code on
  20 September 2026 had it as a `.zip`, chose it in the picker, and it uploaded as a single 155KB file without
  complaint — the check would then have run over a folder holding one lump of compressed bytes, found almost
  nothing, and read as a clean result. It now refuses a lone archive and says to unpack it first, which is the
  honest stop-gap and still asks the person to do something SecureVibe could do for them. Unpacking server-side
  is the real answer and needs care rather than a library call: every entry's path checked before it is written
  (no `..`, no absolute paths, no symlinks, no links out of the staging folder), the uncompressed size capped
  before extracting rather than after, and the same skip list applied to what comes out. A zip from outside is
  untrusted input in exactly the way ADR-011 means, so whatever lands should also be what the virus scanner is
  pointed at.

- **The rest of the virus scanning, now the policy and the two scans are in.** Three things were deliberately
  left out on 20 September 2026 so the mandatory half could land. First, a Settings switch to run the scanner on
  demand against an app SecureVibe built — the uploaded-app case runs by itself, and the built-app case has
  nowhere to be turned on from yet. Second, the reports naming the scanner as something the owner has to keep
  running: an app whose uploads are scanner-gated has a dependency on a background service, and that belongs in
  "what only you can do" beside an outside service with no address. Third, and most important to get right,
  the reports must keep two claims apart that are easy to merge — "this app refuses a file it cannot check",
  which a SecureVibe run does show, and "this app's uploads are scanned", which it cannot show, because the app
  is checked inside a sandbox that puts the scanner out of reach (ADR-011). V5.4.3 stays unverified by a run.

- **The harness should hold a lock while it runs.** ~~Unclaimed~~ **[taken: recipe-library session, 20 Sep 2026,
  after the query recipe lands]** Two sessions ran it at once for eight minutes on 20 September 2026, each having
  said in a message that they would say something first. Almost nothing is actually shared — each session has its
  own checkout of the baselines and the template, each run makes its own scratch workspace with its own tool
  caches, and the apps bind ephemeral ports — so the collision is one laptop's processor, memory and disk, plus
  the fact that neither session can see what the other is running. A lock naming the session, the branch and the
  start time fixes the second half: a second run either waits or is told "a five-app run started four minutes ago,
  expect the harness free at 13:58". It has a second use immediately, because the sweep that clears leftovers needs
  to tell a dead workspace from a live one, and a lock is what answers that.
  Two things deliberately **not** done, so nobody proposes them again without new reasons:
  - *Containers.* They isolate filesystems and ports, which are already isolated, and they do not create processor
    cores. They would also likely break the reuse that makes a build four minutes rather than eight.
  - *A shared limit on total builds in flight, so both sessions can run at once.* Considered and declined on
    20 September 2026: it solves wanting to run simultaneously, and what we have is wanting not to collide. Use
    `--only <app>` when one app answers the question — four and a half minutes rather than fourteen — and the lock
    for the rest.
- **The harness should clear its own leftovers when it starts.** It removes its scratch workspace when a run
  finishes normally and not when a run is killed, and a run gets killed whenever someone spots a problem early —
  which is the harness working as intended. Fifteen abandoned workspaces reached 18GB on a disk with 17GB free
  on 19 September 2026, one run away from failing. A disk-full failure mid-build is the worst kind, because it
  reads as a regression in whatever changed last and sends both sessions hunting in the wrong place. Removing any
  `securevibe-eval-*` older than a few hours before starting costs nothing and needs nobody to remember.

## From the first two people to use SecureVibe (19-20 September 2026)

Watched rather than reported: these came from two owners using it, one on an app built days earlier and one
building from nothing.

- **The agent is told how many tests failed, and not which.** `runTestCheck` in pipeline/checks.ts hands the
  generation agent a summary and a count — "178 passed / 1 failed / 44 skipped" — while the very same result
  object carries `details.tests`, every test with its name and outcome. On the first app built by a stranger the
  agent said so itself: it could not isolate the failing test because the tool "only returns a pass/fail summary
  count, not per-test names", re-ran twice, spent budget, and handed the owner a recommendation to run it again
  with verbose output. The information existed and was withheld by us, and it cost her money to find that out.
  Include the failing tests' names, and their file, in what the tool returns.
- **A recipe for querying records.** **[taken: recipe-library session, 20 Sep 2026]** The engine landed in the
  template on 20 September 2026 (`src/db/query.ts`, `eb35de0`): search, filter, sort and paginate settled once,
  with the ownership clause structural and fifteen tests on it. What remains is the per-entity half — turning a
  record type's fields into a query, fixing the scope once from its `access` answer so no call site chooses, and
  the search and sort controls on the list page. Original reasoning kept because it is still the argument:
  First impression from an owner reading a generated app: the database code
  is where it looks least like something a person would want to inherit. Search, filter, sort and paginate are
  written fresh per feature, which is both the most repetitive thing the agent does and the place a mistake is
  most expensive — a missing ownership clause in a query is a data leak, not a cosmetic bug. It is the same
  argument the other recipes won: settle it once, test it once, and stop paying an AI to rediscover it.
- **Find your best Ab needs a clean-up pass.** The first app built from nothing by someone other than the owner,
  and the one to read carefully before deciding what else matters. Worth going through it feature by feature
  rather than fixing whatever catches the eye first.
- **An assistant that is working should say so.** **[taken: recipe-library session, 20 Sep 2026]** Pressing "Run research" in the health-tracking app returns nothing
  until the answer arrives: no page of its own, no progress, no sign the request was even received. An owner
  cannot tell a slow answer from a broken button, and the honest fix is the one the build page just got — show
  the work happening. Every app with an assistant has this, so it belongs in the template or a recipe, not in one
  app.
- **The Features page refuses before anyone has typed.** Clicking into the record-type box raises a red banner
  saying nothing was saved because there is nothing there — an error about the user's failure to have already
  done the thing they are in the middle of starting. Validation should wait for the field to be left, or for a
  save, not fire on focus.
- **A follow-up question can only take one answer.** When several apply, the owner has to pick one and lose the
  rest. Multiple selection where the question allows it, and the answers it may set must still come from the
  same allow-list, so this widens what an owner can say without widening what the flow may change.
- **Make resume reachable, and pin the fix with a test.** The resume bug — a continued build reaching the writing
  step with no manifest and refusing — is fixed but has no test, and nothing in either suite or the five sample
  apps exercises resuming an interrupted build. That is why it survived a day of green checks. A test that
  continues a run whose writing step failed, and asserts it writes rather than refuses, is the guard that should
  have existed first.
- **Copy an application.** Somewhere to try a change without overwriting the original: an owner who wants a
  different set of records, or to see what a rebuild does, currently risks the app they already have.
- ~~**`UX-01` looks like a requirement id and indexes nothing.**~~ **Done 20 September 2026.** `tests/security/theme.test.ts` names four tests
  `UX-01 …`, and `UX-01` appears in no framework file and no knowledge file — so it is credited to nothing, screened
  by nothing, and reads to anyone else as a citation. Either it becomes a real entry somewhere with wording the
  test-name checker can compare against, or the tests drop the prefix and say what they show in plain words, as the
  secrets tests do. Found while looking for a catalogue to file an assistant-progress test under, on 20 September
  2026. Same family as the mislabelled requirement names: an id is a claim, and a claim wants something behind it.
- **One spelling standard, American English, with the Oxford comma.** The interface, the reports and the code
  comments are written in British English today ("colour", "behaviour", "recognise"). Owner-facing text first —
  the wizard copy, the reports, the finding descriptions — and the knowledge files that feed them, since a report
  that mixes conventions reads as carelessly assembled whatever else is true of it.

## The recipe-library session's half

- The chart recipe (landed 19 September 2026), then a "needs attention" view, then keeping an assistant's answer
  as a record with its sources, then an outside-service connection recipe now the wizard carries a host.
