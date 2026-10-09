# From the end-of-day write-up of 8 October 2026: ideas for `sv` itself

**Status:** open

Proposed by session securevibe-review
in the write-up the owner asked for that evening ("additional suggestions for improvements, new features, changes,
etc. are very welcome"); none is claimed, and each is claimable on its own. The guard per check, also proposed
there, is item 8 of "From the architecture assessment of 8 October 2026" and is not repeated here.
1. **Fail CI only on what is new.** `sv report --baseline <older report folder>`, exiting on the findings not in
   the baseline, so a team can adopt `sv` on an app with a hundred existing findings without setting them all
   aside. The history the dashboard work keeps has the data. A day, and a decision record: an exit code is a default
   that changes a conclusion (ADR-029 governs the exit codes).
   **Claimed 9 October 2026 by session securevibe-e2**, from the roadmap (Phase 4, item 6, the first unclaimed part
   in its order), in branch `claude/securevibe-e2-baseline`: `sv report` and `sv check` take `--baseline <older
   report folder>`, read that folder's `report.json`, and with `--fail-on attention[:SEVERITY]` exit 1 only for a
   finding at or above the bar that the baseline does not hold, matched by its fingerprint or an earlier one. Every
   finding is still listed and counted as it is today, each one the baseline holds marked so in every report file;
   nothing is set aside, and exit 2 (a check that could not run) and 3 (`sv` failed) are unchanged. A baseline folder
   with no readable `report.json`, or one made for another app, stops the run with exit 3 and says which, rather than
   quietly comparing against nothing. **`Status: proposed`: ADR-029, Later, 9 October 2026** (what exit 1 means with
   a baseline). Read on `main` and the open pull requests just before this claim: no other session had claimed it.
   **Done the same day** (`docs/design/0338-fail-only-on-what-is-new-baseline-9-october-2026.md`; ADR-029, Later,
   accepted): `--baseline` on `sv check` and `sv report`, the held findings marked in every report file and as
   SARIF's `baselineState`, and a baseline that cannot be read or names another app refused with exit 3.
2. **A corpus of known verdicts as a regression test.** The example apps and the trial apps already scored, with
   their expected counts per requirement checked in, run nightly and compared with the night before: the honesty
   rule turned into a measurement, so a change that credits more or finds less has to say why. Builds on the
   nightly routine in the process item below.
   **Claimed 8 October 2026 by session securevibe-review**, with part 3 of the process item, in branch
   `claude/securevibe-review-nightly`: as a snapshot held by a test at pull-request time rather than a nightly
   comparison, which is stronger.
   **Done the same day** (design entry "A nightly run on main, and the example apps' verdicts held to a snapshot"):
   `crates/sv-cli/tests/verdicts.rs` holds every example app's requirement statuses to `tests/verdicts/<app>.json`,
   names each difference, and is updated by `SV_UPDATE_VERDICTS=1` when a change is meant. Only the static report is
   held; the nightly run of the suite is the process item's part 3.
3. **Fuzz the readers of untrusted input.** `cargo fuzz` targets for the JSON-RPC framing, `securevibe.toml`, the
   lockfile and SBOM readers, and the tool-output parsers, run weekly in CI; each reads what an app or a tool hands
   it, and a planted file that panics `sv` would be found here before an owner finds it. Two days to set up.
4. **Signed releases.** The container image signed and provenance published for the binary (the SLSA generator or
   cosign), so an owner can verify that what they run is what CI built; `install.sh --locked` and the image exist.
   Half a day, and a line in the paper's threat model.
5. **"Explain this requirement" from the report.** A person reading "V7.4.1 not assessed" needs the requirement's
   text, what `sv` would have checked, and what to do; the data files hold the first two. A command, or a column in
   `report.html`. A day.
   **Claimed 9 October 2026 by session securevibe-e9** ("please continue to work through and pick up new items as
   you merge"), from the roadmap (Phase 4, item 6), in branch `claude/stackvet-e9-explain`. It is the first part
   that neither spends the owner's money nor changes what is published: parts 3 and 4 add weekly CI runs or release
   signing, so they wait for the owner. `sv explain ID [PATH]` prints:
   - the requirement's own words, its level, and where the level comes from, as `stackvet_explain` gives them;
   - the checks that can speak to it, and the kind of run each needs, from `data/reach.json`, which
     `tools/coverage.py` gains a `checks` list for;
   - what to do: the coding rules and shown-to-work prompts that cite it, or, where only a person can check it, the
     check by hand;
   - with an app folder, its status in that app's last report and the reason given there.
   It reads files only and credits nothing. Read on `main` and the open pull requests just before this claim: no
   other session had claimed part 5.
   **Done the same day** (DESIGN, "sv explain: one requirement at the terminal"): `sv explain ID [--app DIR]` (the
   app given with `--app`, as `sv prompts` takes it), with `data/reach.json`'s new `checks` part. Not a column in
   `report.html`: the command answers where the person reads the report.
6. **A GitHub Action wrapping the image**, so `sv report --tools` runs on each pull request of an owner's app with
   the SARIF uploaded to code scanning. Adoption more than capability; the image and the SARIF writer exist.

**The owner's decision, 9 October 2026**, asked by session securevibe-e2 with a recommendation for each open choice: **yes to part 3** (fuzzing the readers of untrusted input, weekly in CI), **yes to part 4** (signed releases: the image signed and the binary's provenance published, with GitHub's own keyless signing, which costs nothing), and **yes to part 6, as recommended, after part 4** (a GitHub Action wrapping the signed image). None claimed yet.
**The owner's word to session securevibe-e9, the same day:** "part 3 - go ahead with the fuzzing please, part 6 I'd
like to work towards that, but bring me a build plan before executing". **Part 3 claimed 9 October 2026 by session
securevibe-e9**, in branch `claude/stackvet-e9-fuzz`: `cargo fuzz` targets for the readers named above, a weekly run in
a workflow of its own, and a crash found turned into an ordinary test before it is fixed. **`Status: proposed`:
ADR-077.** **Part 6's plan claimed the same day by session securevibe-e9**: a written build plan for the owner, in
this item, before anything is built; nothing is published or built from it without the owner's word. Read on `main`
and the open pull requests just before this claim: no other session had claimed part 3 or part 6.
**Part 3 done the same day** (`docs/design/0340-the-readers-of-untrusted-input-fuzzed-weekly-9-october-2026.md`, ADR-077 accepted): four `cargo fuzz` targets in `fuzz/`, outside the
workspace, seeded from the repository by `fuzz/seed.sh`, and `.github/workflows/fuzz.yml` running each for five minutes
every Monday and by hand. A minute each here found no crash; a planted one was found within two minutes.
**Part 6's plan brought to the owner, 9 October 2026**, by session securevibe-e9, with six questions and a
recommendation for each; **the owner's answer: "as recommended"**. Part 4 first; then the Action, as `action.yml` in
this repository, not on the Marketplace; `sv` alone, without `--tools` or `--run`; `findings.sarif` uploaded to code
scanning where it is available and the report kept with every run; failing only when a check could not run, unless
the repository asks for more. **Part 4 claimed 9 October 2026 by session securevibe-e9**, in branch
`claude/stackvet-e9-signing`: the image's build provenance signed with GitHub's own keyless signing and pushed beside
it. No binary is published, so none is signed. **`Status: proposed`: ADR-080.** **Part 6 claimed the same day by
session securevibe-e9**, to be built once part 4 lands. **`Status: proposed`: ADR-081.** Read on `main` and the open
pull requests just before this claim: no other session had claimed part 4 or part 6.
