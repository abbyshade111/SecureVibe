# What is still to do

Agreed work not yet started, so it lives somewhere more durable than a chat between sessions. Each item says what
an owner would notice, because that is what decides the order. Remove an item when it lands.

**Claiming an item happens here, not in a message.** Before starting something, add `**[taken: <session>, <date>]**`
to its first line and commit that on its own; release it the same way if you stop. A message claiming an item is
invisible to a session that is not running, which is how two sessions spent two hours of 20 September 2026 both
building the query recipe: each read this file, each correctly saw the item unclaimed, and neither was wrong.

## Mine (this session's half of the split agreed on 19 September 2026)

- **The test job hangs on a runner, and nobody knows which file.** **[taken: this session, 22 Sep 2026]** Seven
  fast files pass in the first six seconds and then the log goes silent until the step is killed, whether the
  files run together or one at a time. It has never reproduced locally. Because the checks cannot be trusted to
  finish, they run by hand only: the `push`, `pull_request` and `schedule` triggers are commented out in
  `.github/workflows/checks.yml`, so nothing here is actually checked on the way in. The diagnostic that names
  the stuck file — a loop printing each file before running it, ninety seconds each, stopping after three —
  is preserved at `876cbe6` on `claude/query-recipe`. Blocked until 22 September 2026 on metered minutes; the
  repository is public now, so the minutes are free and this is unblocked.
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

- **A shorter set of questions for uploaded apps.** **[taken: restored first session, 24 September 2026]** Somebody checking code they did not write cannot honestly
  answer half the wizard (which records it keeps, what its features are), and guessing puts made-up facts into a
  report. The check and the reports no longer wait for the answers, and the AI review reads against ASVS Level 1
  without them (24 September 2026); what the answers still decide is the applicability of the rules above the
  floor. A shorter set that asks only what applicability needs would make answering honest for an uploaded app.
- ~~**A report that says 0 of 106 when the truth is "we did not look".**~~ **Done 24 September 2026.** All three parts: every report says what was read and in which languages (codeCoverage), an app whose code was not read is "Not assessed" rather than scored, the language boundary is settled in ADR-012 and the upload page says what the check will read before anything is uploaded; the AI review now reads every listed language (PR #41). Original text kept: The first app anybody handed SecureVibe
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


- **PDFs written at report time.** SecureVibe writes each report as HTML, JSON and Markdown; the "Save it as PDF"
  button hands the HTML to the browser's print dialog, so no PDF exists on disk until a person saves one, one
  report and one dialog at a time. The related half landed on 24 September 2026: "Download every app's reports"
  on the across-apps page gives one zip with a folder per app and an index, so an appendix or a handover no longer
  means opening each app in turn. What remains is the PDF itself, which needs a browser engine at report time
  (SecureVibe ships none; the hand-off pack is where it belongs, so whoever receives it has the reports as files
  rather than pages). Worth deciding whether a dependency on the owner's installed browser is acceptable before
  building it.
- ~~**The template suite ran 30 of its 33 files and said it was green.**~~ **Done (list regenerated before each run, count printed); the durable half, moving the repository out of ~/Desktop, stays with the iCloud item.** Original text kept: The launcher takes an explicit list of
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


## From the first two people to use SecureVibe (19-20 September 2026)

Watched rather than reported: these came from two owners using it, one on an app built days earlier and one
building from nothing.

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
- **An assistant that is working should say so.** **[taken: recipe-library session, 20 Sep 2026]** Pressing "Run research" in the health-tracking app returns nothing
  until the answer arrives: no page of its own, no progress, no sign the request was even received. An owner
  cannot tell a slow answer from a broken button, and the honest fix is the one the build page just got — show
  the work happening. Every app with an assistant has this, so it belongs in the template or a recipe, not in one
  app.
- ~~**`UX-01` looks like a requirement id and indexes nothing.**~~ **Done 20 September 2026.** `tests/security/theme.test.ts` names four tests
  `UX-01 …`, and `UX-01` appears in no framework file and no knowledge file — so it is credited to nothing, screened
  by nothing, and reads to anyone else as a citation. Either it becomes a real entry somewhere with wording the
  test-name checker can compare against, or the tests drop the prefix and say what they show in plain words, as the
  secrets tests do. Found while looking for a catalogue to file an assistant-progress test under, on 20 September
  2026. Same family as the mislabelled requirement names: an id is a claim, and a claim wants something behind it.

## The recipe-library session's half

- The chart recipe (landed 19 September 2026), then a "needs attention" view, then keeping an assistant's answer
  as a record with its sources, then an outside-service connection recipe now the wizard carries a host.
