# `sv` audits its own dependencies, weekly (28 September 2026)

Review item 12: `sv` holds apps to V15.2.1 and did not hold itself. `.github/workflows/audit.yml` now runs
`sv audit .` against OSV's export of known vulnerabilities in Rust crates every Monday, and whenever
`Cargo.lock` or a `Cargo.toml` changes. The workflow downloads the export; `sv` still fetches nothing.

Two changes to `sv audit` made that possible, and both apply to every app, not only to `sv`:

- **It respects `not-the-app`.** Run on this repository before, it counted 39 known vulnerabilities, every
  one from `examples/flask-booking`, an example app, and it called the list incomplete because of test
  fixtures' lockfiles it cannot read. The folder listing is now split by securevibe.toml's `not-the-app`
  (`Listing::split`) before the bill of materials is built. What is in those folders is still compared and
  listed apart, one line per vulnerability, and neither counts against the app nor makes its list incomplete.
- **Its exit status says what it found.** 0 only when everything was compared and nothing matched; 1 for a
  known vulnerability in the app; 2 when the comparison did not cover the whole app. It used to be 0 in
  every case, which a CI job cannot act on, and "not assessed" must never read as clean.

On 28 September 2026, against the crates.io export (2,858 records), `sv`'s 68 crates matched none.

**Later, 28 September 2026: folders set apart count again.** The first change above was wrong, and is
undone. The section "Folders the manifest says are not the app" says why that list may hide nothing: the AI
coding tool writes securevibe.toml, so a line in it that stopped findings counting would let it hide one
by naming the folder it is in, `src` as easily as `examples`. Not counting known vulnerabilities there did
exactly that for `sv audit`. Now `sv audit` lists what is in those folders apart and counts it all the same:
a known vulnerability there is status 1, and an ecosystem not compared, a version it could not compare, or
an unreadable lockfile there is status 2. `sv report` never stopped counting them, so it needed no change.

That makes `sv audit .` on this repository status 2 for good: some test fixtures hold lockfiles that cannot
be read, on purpose. So the weekly job no longer audits the whole repository. It copies the files `sv` is
built from (the workspace's `Cargo.toml` and `Cargo.lock`, and each crate's `Cargo.toml`) to a folder of
their own and audits that. The owner chose this on 28 September 2026: the choice of what is audited is
made in a file a person reviews, where securevibe.toml could have made it quietly.
