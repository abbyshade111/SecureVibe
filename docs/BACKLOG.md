# What is still to do

Agreed work not yet started, so it lives somewhere more durable than a chat between sessions. Each item says what
an owner would notice, because that is what decides the order. Remove an item when it lands.

## Mine (this session's half of the split agreed on 19 September 2026)

- **"What only you can do".** A list on the Results page and in the reports, derived from facts rather than
  prose: settings left unset, named outside services with no address, planned features that came back not-built.
  For each, what the owner must do and what stays switched off until they do. `reports/going-online.ts` already
  has this shape for deployment, so it extends a pattern rather than inventing a third list.
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

## The recipe-library session's half

- The chart recipe (landed 19 September 2026), then a "needs attention" view, then keeping an assistant's answer
  as a record with its sources, then an outside-service connection recipe now the wizard carries a host.
