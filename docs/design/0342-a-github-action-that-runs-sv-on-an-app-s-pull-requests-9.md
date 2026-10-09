# A GitHub Action that runs sv on an app's pull requests (9 October 2026)


Backlog 0191, part 6 (the end-of-day write-up of 8 October 2026); ADR-081. The owner's decisions of 9 October 2026:
the plan's six answers, "as recommended", and `@main` for the reference apps write.

**The problem.** `sv report` writes `findings.sarif`, which GitHub's code scanning reads, and the published image runs
`sv` with nothing to install. Putting the two on an app's pull requests took a workflow somebody wrote by hand.

**What is done.** `action.yml` at the repository root, a composite Action of seven steps:

1. **Find the app.** The `path` input, resolved inside the repository (a path outside it is refused), must hold a
   `stackvet.toml` (or the older `securevibe.toml`); without one the run stops with exit 3 and says how to make one.
2. **Check the image.** The published image is pulled and checked with `gh attestation verify --repo
   abbyshade111/StackVet --signer-workflow .../rust.yml`, so only an image this repository's publish job signed
   (ADR-080) runs. Any other image, given with the `image` input, runs as given, with a notice saying so.
3. **Run `sv report`** in the image with `--network none`, as the runner's user, with the repository mounted
   read-only and the report written to a folder under the runner's temporary folder. `fail-on` passes `--fail-on` on.
   `HOME` is `/tmp` inside the container, where `sv` makes the key it seals reports with; the key goes with the
   container, since sealing matters only to `sv`'s MCP server on the owner's own computer.
4. **The summary** on the run's page is `security.md`, cut at 900,000 bytes.
5. **Code scanning**: `findings.sarif` uploaded (`github/codeql-action/upload-sarif`, the commit `codeql.yml` already
   pins) when `upload-sarif` is `true`, or `auto` on a public repository and not from a fork.
6. **The report folder** kept with the run (`actions/upload-artifact`, the commit `fuzz.yml` already pins).
7. **`sv`'s exit status** passed on: 0 finished, 1 needs attention (only with `fail-on`), 2 not assessed.

The README's "On each pull request: the GitHub Action" gives the workflow file to add, and what each limit means.

**Where it differs from the plan.** `@main`, not `@v1`: `v1` is the branch v1 is archived on, so `@v1` would load the
old app. Asked while it was built, the owner chose `@main`.

**How it was tried.**

- **Its steps, run here.** The published image could not be pulled in the session (the registry's file host is
  blocked), so a small image was made from the native `sv`. The Action's bash steps, read from `action.yml` and run
  as a runner would:
  - reported on `examples/flask-booking` (exit 0, all five files, a 3,744-byte summary);
  - stopped with exit 3 on a folder with no `stackvet.toml`, and on `path: ../..`.
- **As a normal user.** As user 1001, without `HOME` set, the report was complete but `sv` said it could not seal it,
  which is why `HOME` is set.
- **In CI.** The `image` job runs the Action, as `uses: ./`, on the example app with the image it builds, and on
  `docs/`, where it must fail.
- **Its tests.** `crates/sv-cli/tests/action_file.rs` holds it to the published image and its signature check, no
  network, a read-only checkout, the runner's user, no `--run`, `--tools` or `--slow`, commit pins, and `@main` in the
  README. Each was broken in turn and caught.

**Not tried.** The upload to code scanning and the signature check against the published image run only on GitHub;
the first app that uses the Action is their first real run.
