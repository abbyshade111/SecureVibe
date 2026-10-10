# From the gap analysis: the four the owner chose to do first

**Status:** done, as its markers read on 8 October 2026

"go ahead with the first four - I definitely want
the tests required before merging and thought I had turned that on" (the owner, 7 October 2026). From the places to
start in `docs/GAP-ANALYSIS.md`.
1. **The app's own tests in a tier of their own** (1.1). A new status, below *checked*; ids read only from code;
   requirements a test cannot show never credited by tests. **`Status: proposed`: ADR-050.**
   **Done the same day** (ADR-050, accepted, "As built"; DESIGN, "The app's own tests are a tier of their own"):
   *tested by the app's own tests*, counted apart in every table and summary, settling no threat. Still open, from
   ADR-050's consequences: reading the test report even when the suite passes, and showing that a test fails when
   the protection it names is removed.
   **Part status:** done, date not recorded
2. **The tests required before merging, and every commit on `main` tested** (7.1). `test` made a required check
   (a repository setting the owner makes, since a session cannot), and `rust.yml`'s concurrency group on `main` made
   one per commit so no run there is canceled. **`Status: proposed`: ADR-051.**
   **Done the same day** (ADR-051, accepted, "As built"): `rust.yml` tests every commit on `main`, and `latest` is
   moved only by the newest. **Waiting on the owner:** adding `test` to the ruleset, which a session may not do.
   **Part status:** done, date not recorded
3. **Semgrep's any-language rules credited only for files Semgrep scanned** (1.2). Narrows what counts as evidence:
   ADR-018, Later.
   **Done the same day** (DESIGN, "A Semgrep rule counts only when Semgrep was handed a file it reads"; ADR-018,
   Later, 7 October 2026): each mapped rule carries the files it reads, from its own `paths`, and counts only when
   Semgrep was handed one; for rules of one language too. The other half of the proposal, handing Semgrep the
   templates and configuration files as well, is its own item below.
   **Part status:** done, 7 October 2026
4. **Git history read for committed key files** (1.3). A key file committed and then untracked is still found, and
   V13.3.1 is no longer credited from the current file list alone. Changes what git is asked: ADR-032, Later.
   **Done the same day** (DESIGN, "A key file committed once is still in the history"; ADR-032, Later, 7 October
   2026): `git log` reads every file ever added, with the programs it could run switched off; a shallow copy is
   "not assessed"; four more key-file names.
   **Part status:** done, date not recorded
**All four claimed on 7 October 2026 by session securevibe-e2**, at the owner's word, each in its own branch
(`claude/securevibe-e2-app-tests-tier`, `claude/securevibe-e2-tests-required`,
`claude/securevibe-e2-semgrep-scanned`, `claude/securevibe-e2-git-history-keys`).
