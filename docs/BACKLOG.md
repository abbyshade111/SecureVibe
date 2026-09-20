# What is still to do

Agreed work not yet started, so it lives somewhere more durable than a chat between sessions. Each item says what
an owner would notice, because that is what decides the order. Remove an item when it lands.

## Mine (this session's half of the split agreed on 19 September 2026)

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
- **Scanning uploaded files for malware (ASVS V5.4.3).** Our scanners ask whether the code has a weakness; an
  antivirus scanner asks whether a file is known-bad content. Nothing we run does the second. The template
  already stops a file pretending to be an image — size enforced before the body finishes, magic bytes sniffed,
  declared type and extension cross-checked, stored outside the web root under a random name — but a genuine
  image carrying a known exploit, or a document with a malicious macro, passes all of that. Worth adding as an
  optional connection to a scanner the owner runs (ClamAV being the usual one) for apps that accept uploads, with
  the same wizard shape as an outside service. It must stay honest when absent: the app says uploads are
  unscanned rather than implying they were checked. Not a new build-time scanner: malicious packages are rarely
  in antivirus signatures, and that risk is already covered by disabled install scripts, a minimum package age
  and the OSV check. V5.4.3 stays manual-only until an app actually scans.
- **The same scanner, on SecureVibe's own Security page.** A second use of the same connection, and the stronger
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
- **An assistant that is working should say so.** Pressing "Run research" in Pain in the Butt returns nothing
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
- **One spelling standard, American English, with the Oxford comma.** The interface, the reports and the code
  comments are written in British English today ("colour", "behaviour", "recognise"). Owner-facing text first —
  the wizard copy, the reports, the finding descriptions — and the knowledge files that feed them, since a report
  that mixes conventions reads as carelessly assembled whatever else is true of it.

## The recipe-library session's half

- The chart recipe (landed 19 September 2026), then a "needs attention" view, then keeping an assistant's answer
  as a record with its sources, then an outside-service connection recipe now the wizard carries a host.
