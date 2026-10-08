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
2. **A corpus of known verdicts as a regression test.** The example apps and the trial apps already scored, with
   their expected counts per requirement checked in, run nightly and compared with the night before: the honesty
   rule turned into a measurement, so a change that credits more or finds less has to say why. Builds on the
   nightly routine in the process item below.
   **Claimed 8 October 2026 by session securevibe-review**, with part 3 of the process item, in branch
   `claude/securevibe-review-nightly`: as a snapshot held by a test at pull-request time rather than a nightly
   comparison, which is stronger.
3. **Fuzz the readers of untrusted input.** `cargo fuzz` targets for the JSON-RPC framing, `securevibe.toml`, the
   lockfile and SBOM readers, and the tool-output parsers, run weekly in CI; each reads what an app or a tool hands
   it, and a planted file that panics `sv` would be found here before an owner finds it. Two days to set up.
4. **Signed releases.** The container image signed and provenance published for the binary (the SLSA generator or
   cosign), so an owner can verify that what they run is what CI built; `install.sh --locked` and the image exist.
   Half a day, and a line in the paper's threat model.
5. **"Explain this requirement" from the report.** A person reading "V7.4.1 not assessed" needs the requirement's
   text, what `sv` would have checked, and what to do; the data files hold the first two. A command, or a column in
   `report.html`. A day.
6. **A GitHub Action wrapping the image**, so `sv report --tools` runs on each pull request of an owner's app with
   the SARIF uploaded to code scanning. Adoption more than capability; the image and the SARIF writer exist.
