# Contributing to StackVet

Thank you for thinking about it. StackVet (`sv`) checks apps against the OWASP standards and says plainly what
was verified and what was not, so the one thing a change must never do is make the report claim more than it
knows. Most of what follows comes from that.

By taking part you agree to the [code of conduct](CODE_OF_CONDUCT.md). A problem that could be a security hole in
`sv` itself goes through the private route in [SECURITY.md](SECURITY.md), never a public issue.

## Before you start

- **Look at [docs/BACKLOG.md](docs/BACKLOG.md)** for what is planned, and **claim the item you are taking** by
  editing its entry to say so, in a commit of its own, before any other work. Several people and AI sessions work
  here at once, and a claim written into the repository is the only one everybody sees. A message is not a claim.
- **For anything larger than a fix, open an issue first** (the "Idea" template), so the design can be agreed
  before the code is written.
- **Read the part of [docs/DESIGN.md](docs/DESIGN.md) for whatever you touch.** It says why things are the way
  they are, including the ways they were wrong before.

## Building and testing

You need Rust 1.95 or newer. From the repository's top folder:

```bash
cargo fmt --all --check                    # formatting
cargo clippy --all-targets -- -D warnings  # lints, with every warning an error
cargo test --workspace                     # every test
```

These are exactly what CI runs, and all three must pass. A few more things to know:

- **Tests that start an app need Docker** (or Colima). Without it, they check that `sv` says plainly it could
  not run them, and they print which of the two they did.
- **`docs/COVERAGE.md` is generated.** After changing a rule, a map from another tool's rules, or a requirement a
  check cites, run `python3 tools/coverage.py` to regenerate it; never edit it by hand. A test fails while it is
  out of date.
- **The container** is built with `docker build -t stackvet/sv .`. `python3 tools/image_smoke.py stackvet/sv`
  drives it as an AI coding tool would; CI runs both on every pull request.

## The rules every change keeps

- **Evidence is honest.** Something nobody assessed is never a pass and never a failure, and a check that could
  not run says so in the report. Never make a check look stronger than it is; automating a manual check means
  producing real evidence for it, never lowering the bar for what counts. A requirement is cited only when the
  check really speaks to it.
- **Break your own rule and watch what catches it.** A new check is not known to work because its tests pass. It
  is known to work when you disable the thing it guards, run the tests, and see them fail. Do that for every
  guard you add, count how many tests catch each break, and say so in the pull request. If only one test
  catches it where you expected several, add the test that makes it deliberate.
- **`sv` opens no network connection of its own.** Data it needs from outside is something the user downloads
  and points it at.
- **Never print, log, or commit a key or password**, including in a test. Test data that must look like a key
  is built from pieces at run time.
- **History is never rewritten.** No force-pushing to `main`, no squashing old commits: papers and documents
  cite commit hashes here. SecureVibe v1 is archived on the `v1` branch; a change to it is made there.

## Writing

- **Plain language.** The people reading the reports are often not programmers. No jargon without an
  explanation.
- **American English with the Oxford comma** (color, behavior, organization; "a, b, and c") in everything a
  person reads: reports, documents, comments, and error messages. Identifiers and JSON keys keep their names.
- **Say what was verified and what was not**, in the code's messages and in your pull request alike.

## Pull requests

Fill in the template: what changed and why, how it was verified, **what was not verified**, and the backlog
entry or issue it closes. Keep one pull request to one change. It can be merged once CI passes.
