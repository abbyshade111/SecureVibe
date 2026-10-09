# A dashboard view for `sv`: explore it

**Status:** partly done: 3 of 8 parts done, 1 claimed, 4 open, as its markers read on 8 October 2026

Asked for by the owner on 8 October 2026 ("explore building out a
dashboard view for sv"). Today `sv` writes one report per run (`report.html`, `compliance.md`, `security.md`,
`report.json`) and nothing that shows an app at a glance, several runs over time, or several apps side by side. The
exploration is a written proposal, `docs/DASHBOARD.md`, and nothing is built from it without the owner's decision:
1. **What a dashboard could show**, from what `sv` already records: one run at a glance, one app's runs over time,
   several apps together. What each needs that `sv` does not keep today (a run's history, for one).
2. **How it could be delivered**: a page written beside the report, a command that writes one page for several
   reports, or a page served while `sv` runs. Each against `sv`'s rules: no network connection of its own, nothing
   fetched from the internet by the page, nothing written into the app's folder that is not already, and plain
   language.
3. **How it stays honest**: a not-assessed requirement is never drawn as a pass, a count never reads as a grade,
   and a chart says what it leaves out, the same as the reports (the short version's banned words).
4. **A recommendation**, with a first step small enough to build and test, and the questions only the owner can
   answer. Status: proposed. Anything that changes what `sv` writes or serves is a decision with its own record.
**Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("can you add an item to the backlog,
or take it yourself"), in branch `claude/securevibe-e2-dashboard`: the proposal only.
**Proposal written the same day:** `docs/DASHBOARD.md`. It recommends, first, one bar at the top of `report.html`
showing the requirements that apply by what stands behind each, with "not verified" in its own color and the numbers
written beside it; then `sv dashboard` for several apps, with its own decision record; and history over time last,
once the owner has chosen where it is kept. Four questions wait for the owner at the end of the proposal.
**The owner's answers, the same day**, after a mock-up: for the owner now and optional for anyone; views of every app
on this computer, one app in detail, and over time; history if it can be kept safely; a page in the browser first.
Recorded in `docs/DASHBOARD.md` (its last four sections) and ADR-057 (proposed). Four build items follow, each to be
claimed on its own:
1. **The bar at the top of `report.html`** (`docs/DASHBOARD.md`, "Build order", 1).
   **Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("Yes, please go ahead when you're
   ready"), in branch `claude/securevibe-e2-glance-bar`. The owner also asked for how many requirements do not
   apply: a second, thinner bar shows where every requirement `sv` knows went (apply, do not apply, could not be
   placed, above the level, counted apart), apart from the first, so the ones that do not apply are never mixed
   with the evidence for the ones that do. Accepts this part of ADR-057.
   **Done the same day** (DESIGN, "The short version opens with two bars"; ADR-057, Later): both bars, to scale,
   with every count in words, and no script. Breaks: a part one too large, "not verified" in the checked color, the
   ones that do not apply left out, the bars left off the page, and empty parts kept, each failed a test.
2. **`sv dashboard`**, one page for the app folders it is given (2).
   **Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please start on the sv dashboard
   command next"), in branch `claude/securevibe-e2-dashboard-command`: `sv dashboard <app folders> --out <file>`
   reads the `report.json` already in each app's `securevibe-report` folder and writes one page, every app in
   alphabetical order with its own page beside it, made the way `report.html` is (no script, nothing fetched). It
   writes only the file it is told to, and never over a file it did not make. Accepts this part of ADR-057.
   **Done the same day** (DESIGN, "`sv dashboard`: one page for several apps"; ADR-057, Later): the command, the
   guide's "All your apps on one page", and the README. Breaks: the apps left unsorted, an app's name not escaped,
   the check for a place inside an app off, a file it did not make overwritten, the reports' own text not escaped,
   and the counts not taken from the report, each failed a test.
3. **History**, switched on by the person and kept outside every app's folder, and the over-time view (3).
   **Claimed on 8 October 2026 by session securevibe-e2**, at the owner's word ("please continue to work off the
   backlog"), in branch `claude/securevibe-e2-history`, as ADR-057 and `docs/DASHBOARD.md` ("Keeping history safely")
   set it out: `sv history on` and `sv history off` (a setting in the person's own `~/.config/securevibe/`, never in
   `securevibe.toml`); while it is on, each `sv report` at the terminal adds one small record for the app under
   `~/.local/share/securevibe/history/`, readable only by the person (the counts, the kind of run, the level, the
   `sv` version, the `securevibe.toml` fingerprint, and each finding's fingerprint, severity, rule, and title; no
   code, no file's contents, no credential), at most 100 for each app; `sv history forget FOLDER` and `sv history forget
   --all`; and in `sv dashboard`, each app's runs over time, set against the last run that can be compared (same
   kind, level, `securevibe.toml`, and `sv`), and otherwise said not to be compared and why. No requirement is ever
   credited from history, and the reports never read it. Accepts this part of ADR-057.
   **Done the same day** (DESIGN, "History: each app over time"; ADR-057, Later): the command, the record kept by
   `sv report`, the over-time view, and `sv dashboard` with no folders. Breaks: history always on, a record others
   can read, no limit on how many are kept, every run compared whatever its kind, history's text not escaped on
   the page, and `forget` that deletes nothing, each failed a test (`crates/sv-cli/tests/history.rs`).
4. **A progress page during a run**, if wanted once the first three are in use (4).
   **The owner's decision, 9 October 2026:** skipped for now; the owner means to come back to the dashboard later
   ("we can skip for now, I want to come back to the dashboard later anyway").
