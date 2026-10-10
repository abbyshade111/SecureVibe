# A deep review of sv for observability: what it can show of itself, and what it should

**Status:** partly done: part 1 items 3, 7, and 9 to 11; part 2 (9); part 3 (A to K, the owner's decisions)

Asked for by the owner on 9 October 2026, when choosing a record of the build loop for finding 22(d) of the gap
analysis: "observability is really important, so let's go with the first option and also please add a review task
to the backlog to do a deep review of sv and how we can build in observability throughout".

A review, not a build: read `sv` end to end and write down what a person (the owner, someone they help, or a later
session) can see of what `sv` did and why, and where they cannot. Among the questions:

- **A run.** What each command and MCP tool call leaves behind: which checks ran, which were skipped and why, how
  long each took, what each outside tool was given and gave back, and where a run that stopped part way leaves its
  trace. Whether a report can always be traced to the run, the `sv` version, and the data files that made it.
- **The build loop.** ADR-076's record of the MCP calls, once built: what else the loop needs written down, such as
  the findings fixed between two checks and the ones set aside.
- **Credit.** Whether every requirement's status can be followed back to the check, the evidence, and the rule that
  gave it (`sv explain` and `data/reach.json` go part of the way), and whether a credit that changed between two
  reports says why.
- **The running app.** What the fence, the stand-in services, and the probes record of what they saw, and what is
  kept after the containers are gone.
- **Failures.** Whether every error a person can meet says what failed, what it means for the report, and what to do;
  and whether a check that could not run is always visible, never silent.
- **Over time.** What the dashboard's history (ADR-057), the weekly review, and the paper's figures could read from
  these records.

It ends in a write-up in this item with findings ranked by what each costs and buys, each claimable on its own, and
the owner's decisions called out. It writes nothing that leaves the person's computer and adds no network connection;
anything it proposes that would is the owner's decision. Read the day's write-ups in the backlog first ("From the
review of" and "From the architecture assessment of"), so it does not find again what they found.

**Claimed on 9 October 2026 by session paper-facts**, at the owner's word ("please go ahead"), in branch
`claude/observability-review`. A review: it reads `sv` and writes its findings here; it builds nothing.

## The review, 9 October 2026 (session paper-facts)

Read at `928ee53` in five parts at once: a run and its report; the build loop and the MCP server; following a
credit back; the running app; failures, silent checks, and records over time. The day's write-ups were read first
(0003, 0006, 0187, 0188, 0191) and nothing below repeats them; where a finding touches an item already in the
backlog, the item is named. Each finding's evidence was read in the code by one reviewer; those marked **(read
twice)** were read again by this session before being written here, and the rest should be read once more by
whoever claims them. Nothing was built or run.

**The short answer.** `sv` is careful about what it *concludes* and says plainly what it did not assess, and it
keeps almost nothing of what it *saw*. Every probe's response, the app's own log, what the stand-in services
received, the mail, each outside tool's raw output, and how long anything took are held in memory and dropped. A
report says which `sv` made it but not when (outside `report.json`), not from which data files, and not how long
each part took. When `sv` itself fails part way, by a crash or by a data file it cannot read, it can leave no trace
at all. Exit codes, gaps, the lock, the seal, and the MCP timeout message are done well and are the pattern for the
rest.

Each numbered finding below can be claimed on its own. Part 1 is wrong or unsafe today and is not the owner's
decision; part 2 is cheap visibility, also not the owner's; part 3 needs the owner, and says so.

### Part 1: wrong or unsafe today (small each, fix first)

1. **A crash line can carry a password into the report.** **(read twice)** When the app never answers, its error
   line or last line (`docker logs --tail 20`, `crates/sv-run/src/docker.rs` `never_ready_detail` and `crash_line`)
   and a failed install's last 400 characters (`install_failure`) go into `RunStatus::CouldNotStart` and a gap word
   for word (`crates/sv-cli/src/assemble.rs`, the `Err(reason)` arm), through no `secrets::redact_text`. Only the
   seed failure removes `sv`'s own test secrets. A database error that prints its address with the password would
   reach `report.html` and `report.json`; `sv bundle` refuses to zip it, but the files on disk keep it. Fix: redact
   both before they leave `sv-run`, then break it with a key built from pieces in a crash line.
2. **`sv explain` says the owner answered when the AI coding tool did.** **(read twice)** `status_words`
   (`crates/sv-cli/src/explain.rs`) turns `attested` into "answered by you in stackvet.toml" and `documented` into
   "answered in the security notes", while the report says "stated by the AI coding tool, confirmed through sv
   review" for the same status when only the tool's answer stands behind it (`shown_label`, `confirmed_only` in
   `crates/sv-report/src/lib.rs`). The one place found where a person's word is overstated. Fix: use the same test
   as the report, or read the label from the JSON once part 2, item 17 gives it one.
3. **One bad byte in the build-loop record makes the report say `sv` was never used.** **(read twice)**
   `read_at_most` (`crates/sv-cli/src/build_loop.rs`) ignores `read_to_string`'s error; on text that is not UTF-8
   the buffer stays empty, `summarize` counts no call and no unreadable line, and the report says "Nothing shows that
   sv was used". ADR-076 says a line that cannot be read is counted and said. Fix: read bytes, decode line by line,
   count a bad line as unreadable.
4. **Two running-app suites' steps never reach anyone.** **(read twice)** The steps of the MCP-server suite (eight
   `steps.push` in `crates/sv-check/src/mcp_server.rs`) and the fetch suite (two in `fetch.rs`) are collected
   nowhere: `run_steps` (`assemble.rs`) and `sv run`'s printout take only the signed-in, sign-in-provider, and AI
   suites'. Their findings and credits arrive; what was asked does not. Fix: add them, with a test that fails without.
5. **A crash in `sv` exits 101, says nothing useful, and loses the run.** **(read twice)** `main`
   (`crates/sv-cli/src/main.rs`) turns an `Err` into exit 3; there is no panic hook anywhere, so a panic exits 101,
   a code no document names, with Rust's default line and stripped symbols. Fix: a hook that prints "sv itself
   failed, a fault in sv and not in your app", the place, and that nothing was assessed, and exits 3. (0065 item 5
   fixed one panic's source; catching a panic per check is part 3, item F.)
6. **A data file `sv` cannot read can leave no mark in the report.** **(read twice)** When `level-hints.json` does
   not load, `assemble.rs` prints one line to stderr and goes on; through MCP nobody sees it, and the report has no
   gap. Fix: a `Gap`. Look for others of the same shape while there.
7. **The build-loop record stops at 4 MB without a word.** **(read twice)** `MAX_BYTES`'s comment in
   `build_loop.rs` says "a report reads the first part and says the rest was left out"; `record` just returns at the
   cap and `BuildLoop` has no field for it, so "the last check came to …" names a check that was not the last.
   Fix: a `full` flag and a sentence.
8. **The dashboard's history drops a run it cannot read, silently.** **(read twice)** `runs_in`
   (`crates/sv-cli/src/history.rs`) passes over a file that does not parse, and `Run`
   (`crates/sv-report/src/dashboard.rs`) has no `#[serde(default)]`, so the first field added to `Run` makes every
   older run vanish from the page. Fix: defaults on `Run`, and the page counts what it could not read.
9. **`sv explain` repeats an unsealed `report.json` as `sv`'s.** **(read twice)** It reads any `report.json` in the
   report folder (`explain.rs`) where the MCP server offers one only when its seal shows `sv` wrote it (ADR-034).
   Fix: check the seal and say "not shown to be sv's" when it fails.
10. **`sv explain ID PATH` fails.** **(read twice)** The module's doc and backlog 0191 say `sv explain ID [PATH]`;
    the parser (`cmd_explain`, `main.rs`) takes `--app DIR`, and a bare path replaces the id. Fix either side.
11. **A package list `sv` cannot read is dropped without a note.** **(read twice)** `deps::read_in`
    (`crates/sv-scan/src/deps.rs`) skips a manifest it cannot read, and a `package.json` that is not JSON gives no
    names. Technology detection counts absence as evidence by default (`absence_is_evidence`,
    `crates/sv-scan/src/lib.rs`), so a library may read as "not used". Not yet shown with a fixture that the wrong
    answer reaches a report: build that fixture first. Making such an answer "incomplete" changes what counts as
    evidence, so the fix itself is the owner's (part 3, item H); saying in the report that the manifest was not
    understood is not.

### Part 2: cheap visibility (small to medium, not the owner's)

12. **Every page dated, and a run id.** `generated: None` (`assemble.rs`) leaves `report.html`, `compliance.md`,
    `security.md`, and the SARIF undated; only `report.json` has `run_record`. Add a run id and the start time to
    each, and SARIF's `startTimeUtc`; the byte-identical tests pass a fixed clock.
13. **How long each part took.** Every `Instant::now()` outside tests sets a deadline and is never recorded.
    `started_ms` and `took_ms` on each `Examined` entry and each running-app step; "the slowest five" on the page.
14. **What each outside tool was.** Its version line (asked, then thrown away), its arguments, its exit code, and
    its time, in `Examined` (`crates/sv-check/src/adapters.rs`). Keeping its raw output is part 3, item A.
15. **Progress at a terminal.** The terminal path passes an empty progress callback, and `sv report --run --tools`
    is silent for minutes. A line per stage on stderr, with a stage per outside tool and per running-app suite.
16. **Errors that say what to do.** Of 36 sampled, 14 say what failed, what it means for the report, and what to do;
    9 say only what failed. The worst: a data file that does not parse (`format!("parsing {}")` in nine places), which
    a person cannot fix and which most likely means the data folder does not match this `sv`. One wrapper in
    `sv_frameworks::data` saying so, and "Nothing about the app was checked". Also the missing next step in
    `NoBackend` and `BackendFailed` (start Docker or Colima), and the MCP "check stopped before it finished", which
    gives no cause and no pointer to the terminal.
17. **Credit rows that explain themselves.** A needs-attention row shows only the finding, not the checks that
    passed for the same requirement nor the rule that a finding outranks every credit (now only a comment above
    `status_of`); a false alarm set aside turns "checked" into a bare "not verified" with no pointer to why
    (a `withheld_by`); `report.json` carries no tier and no "whose word" label, and `attested_by` mixes the owner's
    yes with the tool's; `sv explain` gives no finding's place, prints only `checked_by`, and reads only the latest
    report (a `--report` option). Rendering and JSON only: no status changes.
18. **What happened to the container.** The true wait (the message says "within 60s" when the app exited at once),
    the app's exit code and out-of-memory flag on that path, the seconds to healthy, how the fence was made
    (`made_with`, now shown only on failure), teardown errors (now `let _`), and that a download volume was kept, its
    name and how to remove it. ADR-052 names the old label `securevibe.deps`; the code uses `stackvet.deps`.
19. **The MCP server's errors.** It keeps no record of an error it returns; one stderr line per error (tool and
    kind, no app text), which the AI tool's own log usually keeps.
20. **Smaller ones.** A version catalog that does not parse reads as "not found" (`crates/sv-scan/src/jvm.rs`):
    say "not understood". Gaps are prose only (`Gap { what, why }`), and the trial scorer splits them on commas: add
    requirement ids and a reason code. `report.json` has no format version. Whether a report names the advisory
    database it used, its size, and its newest record was not settled: read `assemble.rs` past the part read.

### Part 3: the owner's decisions

Each changes what `sv` writes into someone's folder, what it keeps, what counts as evidence, or the fence, so each
is asked before it is built. Recommended first: **A**, then **C**, then **D**.

- **A. Keep what was seen, redacted, beside the report.** One decision covering four: each probe's request and
  response (status, headers, the body excerpt `sv` already keeps in memory), what the stand-in services received
  (the test model's `seen`, the provider's requests, the mail's to, subject, and time), the app's log lines the log
  credits rest on plus a short tail, and, behind an option, each outside tool's raw output. All through
  `redact_text`, and each finding and credit naming the records it read. It is the largest gain in "why did this
  credit?", and it puts the app's own text, which can hold personal data, into the report folder (ADR-017).
  Medium.
- **B. Say which data made the report.** The data folder's path, a hash per data file and one over the folder, and
  a mark when `sv` was built from changed source. It changes what a report claims about where it came from. Small.
- **C. History that can show a trend** (ADR-057). Per requirement, its status in each run (ids and status words,
  no code); the run's outcome and exit code; a record of a run that failed, now none; and the security notes, the
  decisions, the review seal, and the data folder in the "can these two runs be compared" key, which now hashes only
  `stackvet.toml`. Without the decision, `sv compare <older report> [<newer>]`, which reads two sealed reports and
  lists each requirement that moved and what moved it, needs nothing kept and is not the owner's. Small to medium.
- **D. More in the build-loop record** (ADR-076). Each call's outcome (ok, timed out, crashed, refused), and a line
  when the record could not be written, so a failed loop is not read as a quiet one; a line when the record is
  turned off in `stackvet.toml`, which the AI tool can edit; the names `sv` itself defines that a call asked for (a
  section, a feature, a question id); the AI tool's name and version from `initialize`, and `sv`'s; the prompts and
  report files handed over (`prompts/get`, `resources/read`, the instructions at `initialize`); and, at each check,
  the findings' fingerprints, so the report can say how many were fixed, set aside, and new between the first check
  and the last, the question this item asked. Small each; the fingerprints medium.
- **E. Record what the app tried to reach.** A stand-in name server and a catch-all listener on the fenced network
  that write down each name and address asked for: the only way to see an app calling home. Medium to large; it
  changes the fence.
- **F. A crash costs one check, not the run.** Each stage under `catch_unwind`, recorded as "not assessed: the
  check crashed". A new reason for not assessed. Medium.
- **G. `sv probe`'s exit code.** It exits 0 when it could not reach the address; 2 then would make it usable in CI.
  A default that changes a conclusion (ADR-029's area). Small.
- **H. An unread package list makes the answer incomplete** (part 1, item 11). Small to medium.
- **I. Files of `sv`'s own.** An opt-in `SV_LOG` file of stages and tools, and a crash file under the history
  folder (version, command name, place; never arguments or paths). Small each.
- **J. A build-loop record the AI tool cannot quietly rewrite.** A second copy beside the history, outside the app
  folder, and the report saying whether the two agree. ADR-076 weighed and declined keeping the record only there.
  Medium.
- **K. The helper images by digest**, not by tag (`busybox`, `mailpit`, `node`, the headless browser), and the app
  image's digest in the report. Changes what `sv` runs. Small.

### Over time: what the records could feed

The dashboard reads history (counts and finding fingerprints per run) and each app's `report.json`. The paper's
figures are made from CSV files kept by hand, and the trial scorer reads `report.json` and matches the gaps' words.
The weekly decision-record review keeps its results as prose in 0091, and 0096 (its routine left no trace) is open.
With part 2's run id, dates, and timings, and part 3's C, the dashboard could draw each requirement over time and
the paper could take its counts from `sv`'s own records rather than by hand; with D, a build's loop could be told
from its report alone.

### Done well, and worth copying

Exit codes kept apart (`crates/sv-cli/src/exit.rs`); the `CannotRun` sentences in `sv-run`; one write sequence for
the report folder, with the lock, the seal, and a folder left as it was when a run is refused; gaps named per family
of findings with the tool or stand-in that did or did not run; history outside the app's folder, never evidence, and
refusing to compare runs that differ; the build-loop record's writing guarded link by link and capped, and its
paragraph crediting nothing; a fence verified by asking Docker; test output capped and redacted; the browser naming
the sites it was stopped from reaching; the `asked!` and `quiet!` guard.

### The owner's answers, and the first claim

**The owner's decisions, 9 October 2026:** "please go ahead and yes to A, C, and D as well". A is ADR-082, C is
ADR-083, and D is ADR-084, each proposed with this note and accepted in the pull request that builds it. B and E to K
are not yet asked.

**Part 1, item 1 claimed on 9 October 2026 by session paper-facts**, at the owner's word ("please go ahead"), in branch
`claude/crash-line-redacted`: the app's crash line and a failed install's tail put through `redact_text` before they
leave `sv-run`, with a test that plants a key built from pieces in each and fails when it reaches the report.

**Part 1, item 1 done the same day** (`docs/design/0343-a-crash-line-kept-from-carrying-a-credential-into-the-report.md`):
every reason the app could not be run passes through one function that cuts credentials, in `sv run` and the report
alike, and a failed seed's line is cut the same way; without `sv`'s rules the app's words are left out. Breaks: the
redaction removed failed two tests, a call site that skipped it failed the test that reads the source, and the seed's
redaction removed failed its own test.

**Part 1, items 3 and 7 claimed on 9 October 2026 by session stackvet-e9**, with no word from the owner beyond
"continue to work off the backlog", in branch `claude/stackvet-e9-loop-record-honest`: the build-loop record read as
bytes and decoded a line at a time, a line that is not UTF-8 counted as unreadable (item 3), and a `full` flag with a
sentence when the record stopped at its size limit (item 7), each with a test that fails without it. No open pull
request or branch of the last few hours touches `crates/sv-cli/src/build_loop.rs`; item 2 is session paper-facts's,
in #1300.
**Part 1, item 2 claimed on 9 October 2026 by session paper-facts**, at the owner's word ("please go ahead with item
2"), in branch `claude/explain-whose-word`: `sv explain` reading whose word a status rests on as the report does, so
an answer only the AI coding tool gave, confirmed through `sv review`, is never told to the owner as their own.
Open pull requests and recent branches read first: none touches `crates/sv-cli/src/explain.rs`.

**Part 1, item 2 done the same day:** `sv explain` reads whose word a status rests on by the report's own rule, now one
function (`sv_report::confirmed_only_by`, with its labels in `Status::shown`), so the tool's answer somebody confirmed
through `sv review` is given as the report gives it and never as the owner's. Breaks: `sv explain` ignoring the rule
failed its new test; the rule broken failed that test and the new one in `crates/sv-report/src/whose_word_tests.rs`,
where before nothing in the report crate had failed.

**Part 1, item 8 claimed on 9 October 2026 by session stackvet-e9**, under the owner's "continue to work off the
backlog", in branch `claude/stackvet-e9-history-honest`: `#[serde(default)]` on the dashboard's `Run`, so a field
added later does not hide every older run, and the page saying how many runs it could not read, each with a test
that fails without it. Open pull requests (#1302, #1304, #1305) and the branches of the last few hours read first:
none touches `crates/sv-cli/src/history.rs` or `crates/sv-report/src/dashboard.rs`.

**Part 1, item 8 done the same day** (`docs/design/0344-the-dashboard-s-history-counts-a-run-it-cannot-read-9.md`): `Run` has defaults, so a field added later does not hide the runs
kept before it, and a kept file that does not read as a run is counted and said on the page ("could not be read as a
run, and is not shown") rather than passed over. Breaks: without the defaults the older run vanished from the test;
without the count, or without the sentence, its test failed.

**Part 1, item 4 claimed on 9 October 2026 by session stackvet-e9**, under the owner's "continue to work off the
backlog", in branch `claude/stackvet-e9-suite-steps`: the steps of the MCP-server and fetch suites carried to the
report and to `sv run`'s printout as the other suites' are, with a test that fails without it. Open pull requests
(#1305, #1308, both this session's) and the branches of the last few hours read first: none touches
`crates/sv-cli/src/assemble.rs`, `crates/sv-check/src/mcp_server.rs`, or `crates/sv-check/src/fetch.rs`.

**Part 1, item 4 done the same day** (`docs/design/0344-every-suite-s-steps-reach-the-report-and-sv-run-from-one.md`): `RunOutcome::asked` is the one list of the suites asked beyond the
anonymous ones, which the evidence, the report's steps, and `sv run`'s printout all read, so the MCP-server and
fetch suites' steps now reach both. It names every field of `RunOutcome`, so a suite added later does not build
until it is placed. Break: with those two suites taken out of the list, both new tests fail.

**Part 1, items 5 and 6 claimed on 9 October 2026 by session stackvet-e9**, under the owner's "continue to work off
the backlog", in branch `claude/stackvet-e9-crash-and-gap`: a panic hook that says `sv` itself failed, where, and
that nothing was assessed, and exits 3 (item 5); and a data file `sv` cannot read, `level-hints.json` first, made a
gap in the report rather than a line on stderr, with the others of the same shape found while there (item 6); each
with a test that fails without it. Open pull requests read first: #1311 changes `main.rs` far from `main()`, and
#1310 (items 9 and 10, session paper-facts) touches only this file.

**Part 1, items 5 and 6 done the same day** (`docs/design/0345-a-crash-in-sv-ends-as-sv-s-failure-and-an-unreadable-hints.md`): a panic now ends as `sv`'s own failure, exit 3, with what and
where and that nothing was assessed, after the unwinding has cleaned up; other threads keep Rust's line, so `sv mcp`
surviving a check thread is not reported as `sv` failing. An unreadable `level-hints.json` is a gap in the report
rather than a line on stderr; no other data file in the report's path fails silently. Breaks: without the catch, and
without the gap, each new test fails.
