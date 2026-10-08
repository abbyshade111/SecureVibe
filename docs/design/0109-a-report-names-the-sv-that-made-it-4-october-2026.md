# A report names the `sv` that made it (4 October 2026)

`report.json` did not say which `sv` made it, and the published image's `sv --version` printed "commit unknown". Seven
of the owner's 25 reviews of family-hub named a rule (`tests.name-does-not-match-requirement`) that the newest
published image did not have, and nothing in the report could explain it. The cato-pipeline session reported it.

- **Every form of the report says it.**
  - `report.json` has `"sv": {"version", "commit"}`.
  - The SARIF's `tool.driver` has `version`, and the commit under `properties`.
  - The page and both Markdown files say "Produced by `sv` 0.1.0 (commit 9573c0d1a2b3)", the commit cut to twelve
    characters.

  A test runs `sv report` and holds every form to what `sv --version` says.
- **The image knows its commit.** Its build context has no `.git`, so `build.rs` now takes the commit from
  `SV_GIT_COMMIT` when one is given. The value has to be 7 to 64 hexadecimal characters, so a word or a branch name is
  not taken for one. Otherwise it falls back to git, and then to `unknown`. The Dockerfile takes it as a build
  argument, and both image jobs pass `github.sha`. The smoke test's new `--commit` asserts that the built image's
  `sv --version` names it.
- **Same app, same report.** The report stays the same for the same app with the same `sv`. A new commit changes
  only the line that names it.

Tried by hand: built with a commit given, with a word given, and with none, `--version` named the given commit, then
the checkout's, then the checkout's. The image path is first tried for real by the CI image job, since this
environment has no Docker daemon. Two breaks were each caught by the end-to-end test: the values left out of the
report, and the page not printing them.
