# gosec is fenced like the rest, and the tools that walk the folder are not run over a link (8 October 2026)


From the review of 8 October 2026, item 3 (`docs/backlog/0188-…`), the fourth sub-item in the roadmap's Phase 1
order. The three findings were each tried against the real tool before anything was built, with gosec 2.22.9, Brakeman
8.1.0, and CodeQL 2.27.2 installed for the purpose; two of the three held, and one did not.

**gosec downloaded and compiled, undeclared.** Run as its entry ran it (the owner's `PATH`, `GOTOOLCHAIN=local`, and
nothing else about Go), gosec loaded the app's packages through `go list`, which downloaded the app's modules (46 MB
for one `golang.org/x/text` dependency into a fresh module cache) and, for a file that uses cgo, started the C
compiler (32 `gcc` runs, counted by a wrapper first on the `PATH`). `sv` lets a tool do neither: the network is for
`sv probe` and the install step alone, and a C preamble is the app's own code run on the owner's computer. **gosec now
starts with `GOPROXY=off` and `CGO_ENABLED=0`** (`data/adapters.json`, its `env`). With the modules absent, its
rules still read the code (shown: G401 and G501 found in an app whose dependency was never downloaded), but its three
analyzers, which need a built package, do not (`Error building the SSA representation`), and a cgo file is left out
of the build. Both are now said rather than hidden, which took two more things:

- **The log is read for what it checked.** gosec's SARIF names only what it found, and with `-quiet` a clean run
  wrote no report at all (so a clean gosec run was never credited, which the credit census could not see, since no
  test ran the real tool). `-quiet` is gone; its log names each file it checked (`Checking file: …`), and the entry's
  new `read_log_prefix` makes `sv` compare that with the Go files in its own listing: a file the log never names is
  listed as unread, and a log naming none is a run that read nothing, neither credited as clean. A log longer than the
  64 KB `sv` keeps says so instead of guessing. `-tests` is given, so test files are read as every other tool is
  handed its test files.
- **A line that means part of the run did not happen** (`unfinished_when`, with the SSA line and what it means, in
  words with the remedy: `go mod download` in the app, by the owner) withholds the clean run and leaves the findings.

**A linked file is read through, by two of the three.** Given an app holding a link to a `.go` or `.rb` file outside
it, gosec and Brakeman each read the file and reported what was in it, at the link's name, so a report "about the
app" would carry code and lines from wherever the link pointed; neither entered a linked folder. CodeQL did not read
the linked file at all (its source archive held every other file). **A tool marked `follows_links` is not run over an
app whose listing holds a link**, with the links named (five, then a count) and the remedy, since `sv` itself never
follows one; gosec and Brakeman are marked, CodeQL is not, and `Adapters::load` refuses the mark on a tool handed
`{files}`, which reads only what it is given.

**CodeQL ran nothing planted.** Tried the ADR-032 way: `preinstall`, `postinstall`, and `prepare` scripts in a
TypeScript app's `package.json` (with a `tsconfig.json`, where its extractor might have installed types), and
`sitecustomize.py`, `usercustomize.py`, and `setup.py` in a Python app, each writing a mark. None was written, and
the linked file beside them was not read. So its entries carry no guard, and the test that plants them stays, for the
day a newer CodeQL is installed.

**Breaks.** Each failed one of the tests below, with the guard taken out: `GOPROXY` dropped from the entry
(`tool_fence.rs`); the links check skipped (`fence_tests.rs`, and the real gosec and Brakeman tests); the log read
for nothing (`fence_tests.rs`, "names none"); the cap on the log ignored; the unfinished line ignored. Held by
`crates/sv-check/src/adapters/fence_tests.rs` (a stand-in tool that says on its stderr whatever the test puts
there), `crates/sv-check/tests/tool_fence.rs` (what the entries say), and three tests that run the real tools where
they are installed and say so where they are not: `tests/gosec_fence.rs` (the C compiler's mark, the empty module
cache, the link, each with its control run bare), `tests/brakeman_links.rs` (the link, with its control), and
`the_real_codeql_runs_nothing_the_app_plants_and_follows_no_link` in `tests/codeql.rs`.

**Not done.** Which of gosec's rules need the analyzers is not known rule by rule, so an SSA failure withholds the
whole clean run rather than only G407's credit. A linked folder, which neither tool entered, is refused with the
rest: the listing does not say which kind a link is, and a tool version that does enter one would be read through
silently if it were let in. And a Go file that Go's own tooling never builds (one under `testdata/`, or behind a build tag for
another system) is listed as unread, which is true: gosec never looked at it, and the report says so rather than
crediting it.
