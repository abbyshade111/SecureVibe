# SecureVibe — what is still to do

> Written under `agnostic/` and moved to the repository root on 26 September 2026 when `sv` became the top of the
> repository; paths written `agnostic/…` in older entries below are now at the root (`agnostic/data/…` is `data/…`).
> v1's own backlog is on the `v1` branch.

Same rules as the v1 backlog: claim an item here, in a commit of its own, before starting it. A message to
another session is not a claim.

## Next

- **`ast.download-piped-to-shell` flags a download read as data.** **Claimed on 28 September 2026 by session
  cato-examined**, at the owner's asking. Found by cato-pipeline: `curl … | python3 -c '<fixed program>'` is
  reported high, the same as `curl … | sh`, because the rule matches any pipeline from `curl`, `wget`, or `fetch`
  into a shell or interpreter, whatever that command's arguments are. An interpreter runs what arrives on standard
  input only when no program is given another way. Plan: keep flagging `| sh`, `| bash -s`, `| python3 -`, and
  `| sudo bash`; stop flagging, or report at *possible* certainty, the forms that give the program another way
  (`-c`, `-e`, a script file). A literal program is not proof of safety (`python3 -c "exec(sys.stdin.read())"`
  runs the download), which is the case for *possible* rather than silence. A test for each side, and each guard
  broken in turn.
  **Done on 28 September 2026 by session cato-examined:** the rule reports an interpreter only when it takes its
  program from standard input (`| sh`, `| sh -s stable`, `| python3 -`, `| sudo -E bash`), and not when the
  program is given another way (`-c`, `-e`, `-m`, a script file). Not reported at *possible* certainty instead:
  the engine has no per-match certainty, and the `-c` text is the author's own, as `literal_argument_is_safe`
  already treats `eval("1 + 1")` (DESIGN). On the way: `| sudo -E sh` had been missed, because only the first
  word after `sudo` was looked at, and `| grep python` would have been reported; the command must now begin
  with the interpreter. 24 cases added to the rule table, 12 on each side; five guards broken in turn each turn a case red.

- **Say in `report.json` what was examined, in a form a program can read.** **Claimed on 28 September 2026 by
  session cato-examined**, at the owner's asking.
  `report.json` says what was not examined only in sentences: `gaps`, and the SARIF's `sv.not-examined`
  notices. A program that reads it cannot tell a finding that was fixed from one nobody looked for this time.
  The owner's cato-pipeline turns `sv` findings into a plan of action and closes an item when its finding stops
  appearing, so a tool that did not run, a check that could not read what it needed, or code rules silenced by an
  unparsed language would each close items that were never fixed. Plan: an `examined` list in `report.json`,
  one entry per family of findings (a `rule_id` prefix: each outside tool, `sv`'s code rules, each check that could
  not run, known vulnerabilities, the running app), each `ran` or `not-run` with the reason the gap already gives,
  filled where those gaps are decided, and a test for each source that fails when its entry is wrong. Touches
  `sv-report` (the field), `sv-cli` (filling it), and `docs/DESIGN.md`.
  **Done on 28 September 2026 by session cato-examined:** `report.json` has `examined`, one entry per family
  of findings with a state of `ran`, `partly`, `not-run`, or `nothing-to-examine`; the longest matching
  `rules` prefix decides (DESIGN, "What was examined, for a program"). Five tests through the binary and three
  beside the code; each of six guards, removed in turn, turns its test red. `design.`, `hand.`, and `tests.`
  findings have no entry yet, so a program reads them as not looked for, which is the safe side.

- **Two limits cato-pipeline hit while wiring in `sv`.** Found on 28 September 2026 by a session on the owner's
  cato-pipeline project, while integrating `sv` (cato's ADR 0009), with `sv` built from `main` at `5117b0a`, and
  written up for this backlog. Session securevibe-e10 checked each claim about `sv`'s code against `main` the
  same day before adding it here; the reproductions below are cato's and were not rerun. Both are honest,
  fail-closed behavior; the cost is in what they block. **Each numbered item can be claimed on its own.**
  1. **`requirements.lock` beside `pyproject.toml` is not read.** For a Python project with a `pyproject.toml`,
     `sv` looks only for `poetry.lock`, `pdm.lock`, or `uv.lock` (`crates/sv-scan/src/ecosystems.rs`, the
     `pyproject.toml` entry; checked). A hash-pinned `requirements.lock` beside it is ignored, though it is the
     file `uv pip compile pyproject.toml -o requirements.lock` writes and the name Rye uses.
     `requirements.lock` is already a known lockfile, but only for the `requirements.txt` manifest (checked), and
     `from_pinned_requirements` in `crates/sv-check/src/sbom.rs` already skips `--hash` lines and reads
     `name==version`. As a result `config.versions-pinned` (medium) says there is no lockfile, which is untrue;
     the bill of materials lists no Python packages (`sbom.incomplete`, the gap "everything Python installs");
     and `examined` has `advisory.` as `partly`. Seen on cato's own repository: `sv sbom` listed 0 components;
     the same file renamed `requirements.txt` listed 41. Reproduce:
     `printf '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["PyYAML>=6.0"]\n' > pyproject.toml`,
     then `uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock`, then `sv sbom .`.
     **The owner's decision, as cato's write-up records it: fix it here.** Fix: add `"requirements.lock"` to the
     `pyproject.toml` entry's lockfiles. Two decisions come with it: which lockfile is read when several are
     present, said in the report as it is for other ecosystems; and environment markers, since a universal lock
     has lines like `colorama==0.4.6 ; sys_platform == 'win32'`, which the parser lists even where it would not
     be installed (the safe side for an advisory comparison; the bill of materials then says slightly more than
     is installed, which the report could say, or the marker could be read). Test: a `pyproject.toml` project
     with a hash-pinned `requirements.lock`, `--hash` lines and one marker line included, gives components, no
     `config.versions-pinned` finding, and `advisory.` as `ran` when the database covers PyPI; remove the new
     entry and it goes red. **Claimed on 28 September 2026 by session securevibe-e2**, at the owner's asking to
     pick a backlog item, in branch `claude/securevibe-e2-pyproject-lock`.
     **Done the same day:** `requirements.lock` is the last of the `pyproject.toml` lockfiles, so a `uv.lock`,
     `pdm.lock`, or `poetry.lock` beside it is read first. A platform condition is not read, so such a package
     is listed everywhere, and a line is now cut at its `;` whether or not a space comes before it, which fixes
     `requirements.txt` as well. Three tests (the reader, which lockfile counts, and the report end to end); each
     guard, broken in turn, turns its own test red. See DESIGN, "A `requirements.lock` beside `pyproject.toml`".
     One correction to the entry above: no ecosystem's report says which lockfile was read when several are
     there, so this one does not either. That is the next item.
  2. **One large data file blocks two checks for the whole app.** `MAX_FILE_BYTES` (2 MB,
     `crates/sv-scan/src/files.rs`; checked) is the largest file any check reads. cato vendors NIST's SP 800-53
     catalog at `oscal/catalogs/nist-800-53-rev5/catalog.json`: 10 MB of standards text, no code, no
     credentials. That one file leaves the credential scan `partly` ("1 file(s) were not read"), so a program
     reading `examined` can never treat a missing `secrets.*` finding as fixed anywhere in the app. It also
     leaves `config.mcp-server-unpinned` not assessed for the whole app: `mcp_servers` in
     `crates/sv-check/src/launch.rs` reads every file `may_start_servers` selects, JSON included, and one it
     cannot read means the check can never pass (checked; it still reads every other file and still reports an
     unpinned server it finds, so it blocks the clean result, not the findings). Both are right by `sv`'s own
     rules and `examined` reports them correctly; the problem is that a file the owner knows to be data blocks
     two families permanently, with nothing the owner can do. Reproduce: a folder with a `securevibe.toml`, an
     `app.py`, and `python3 -c "import json; json.dump({'text': 'x'*3_000_000}, open('catalog.json','w'))"`,
     then `sv report . --out out`. **Options, for the owner to choose:**
     (a) read large files in pieces for the credential scan, since its rules are line-oriented, so `secrets.`
     can be `ran`, meeting the concern in `files.rs` (a large file is likelier to hold a hash than a key) by
     giving findings there *possible* certainty rather than by not reading them; (b) stop one unrelated file
     from blocking the MCP check: a file that starts an MCP server is small, so for one over the limit first
     check whether it can be an MCP configuration at all (by name, or by scanning for `"mcpServers"` or
     `"command"`), or report the check as `partly` naming the file; (c) let the manifest name data files, such
     as `[repository] data = ["oscal/catalogs/**"]` with a reason, each listed in the report, which relies on a
     manifest an AI tool may write and so would need the visibility `not-the-app` has. cato's write-up
     recommends (a) and (b) together, which clear it without asking anyone to trust the manifest. Tests: a
     3 MB plain-text JSON and no MCP configuration leaves the MCP check run, or `partly` and naming the file,
     never not assessed; a key planted past the 2 MB mark of a large file is found and `secrets.` is `ran`;
     each guard removed in turn turns its test red. **The owner's decision, 28 September 2026: (a) and (b)
     together. Claimed the same day by session securevibe-e10**, in branch `claude/large-data-files`.
     **Done the same day:** a file over 2 MB and up to 256 MB is read in pieces for credentials (an
     assignment found in one is reported with low confidence), and the MCP check counts a large file as
     read when it never says `command`, its own rule for any file. On cato's reproduction the credential
     scan is `ran` and the MCP check is no longer not-run. See DESIGN, "A large data file no longer
     blocks the credential scan or the MCP check".
  3. **The report does not say which lockfile was read when a project has more than one.** Found on 28 September
     2026 while doing item 1. `find_lockfile` in `crates/sv-scan/src/ecosystems.rs` takes the first name in each
     ecosystem's list that exists and says nothing about the rest, for every ecosystem (`poetry.lock` and
     `requirements.lock` beside `requirements.txt`, `uv.lock` and `requirements.lock` beside `pyproject.toml`,
     `package-lock.json` and `yarn.lock`, and so on). If the two disagree, the bill of materials and the advisory
     comparison describe one of them and the owner is not told which. The bill of materials could carry a note
     naming the file read and the ones passed over. **Claimed on 29 September 2026 by session securevibe-e2**, at
     the owner's asking to pick a backlog item, in branch `claude/securevibe-e2-which-lockfile`.
     **Done the same day:** one lockfile is still read, in the same order, and the others are named in the bill
     of materials (a CycloneDX property), in `sv sbom`'s output, and in the report as a gap. `advisory.` is
     `partly` in `examined`, and the clean "nothing found" claim is withheld, so `sv audit` exits 2 rather than
     0. Six tests; each of eight guards, broken in turn, turns its own test red. See DESIGN, "Two lockfiles of
     one kind".

- **Two more analyses for the paper.** **Claimed on 28 September 2026 by session admiring-murdock-875699**, at
  the owner's asking.
  1. **What coordinating several AI sessions cost, and what it bought:** claims, merge conflicts, duplicated work,
     harness collisions, and faults one session found in another's merged work, from git and this backlog.
  2. **Test growth against fault discovery:** tests day by day beside when each fault was found and how, to see
     whether more tests meant fewer surprises. Exploratory; it may not show a clean pattern.

  Touches only `docs/paper/`.

  **Done the same day.** 1 is `docs/paper/COORDINATION.md` with `coordination.csv` and `figure-coordination.html`;
  2 is `TESTS-AND-FAULTS.md` with `faults.csv`, `tests_by_day.csv`, and `figure-tests-faults.html`. Two errors in
  `CORRECTIONS.md`, written the same day, were fixed with them: row 31 is a v1 correction, not `sv`'s, and its
  table of `sv` tests counted work still on branches for 23, 24, and 26 September. Eight disagreements in older
  paper files are the entry below.

- **Eight places where the paper's earlier files disagree with the record.** Found on 28 September 2026 by the
  coordination and fault analyses above. **Claimed on 28 September 2026 by session admiring-murdock-875699**, at
  the owner's asking. Check each against its source before changing it.
  1. `figure-how-caught.html` says 50 of the 267 changes "mention a claim". Three of the 50 (#56, #67, #71) use
     "claim" to mean an assertion: 47 were claims of work, 42 of them touching only the backlog.
  2. `figure-how-caught.html` counts 7 faults in `sv` found by one session reviewing another's work. It misses
     `11b0e6c`, `6225f3f`, and `672d4af`, each of whose messages says another session found it; the total is 10.
  3. `figure-how-caught.html` counts 8 faults found by v1's evaluation harness; `faults.csv` has 13, adding
     `2a5d2e8`'s four and `d46f119`.
  4. `TIMELINE.md` says 214 of the 267 changes were pull requests. Twelve more on 26 September (#128 to #221) were
     pull requests rebased onto `main` and appear as direct commits, so the figure is 226.
  5. `TIMELINE.md` and `figure-how-caught.html` stop at 10:52 on 27 September; `main` had 469 changes by 16:18 on
     28 September. Either extend them or say where they stop.
  6. `TOP10.md` files the fence-test weakness (#148) as found by "running the suite";
     `figure-how-caught.html` files it as "breaking a guard". The backlog says it was found running the suite on
     the owner's Mac.
  7. `TOP10.md` cites a `mkdirSync` fix, `a562749`, that is on neither `main` nor `v1`, only on
     `origin/claude/ci-hang`. Check whether it reached either in another form.
  8. `TOP10.md` says no verdict that failed open was caught by a failing test. That holds for its eight; two others
     were (`faults.csv` SV-10 and SV-49, `corrections.csv` rows 22 and 47).

  **Done the same day.** Each was checked against its source first; six held as written, and two were worse
  than stated:
  - 3: the full harness count is 14, not 13. The ledger had also missed `00456fe`, whose own title says the harness
    caught it, so `faults.csv` gained a row (V1-77) and the fault totals in `TESTS-AND-FAULTS.md`,
    `COORDINATION.md`, and their figures are now 149 (81 in v1).
  - 7: the fix never reached `v1` in any form. The whole `claude/ci-hang` branch (`3e78e98`, the test fix, and
    `a562749`, the rule) is unmerged, and `v1` as archived still has the test line that hung CI
    (`server/tests/llm/safety.test.ts`, the `/proc/definitely/not/writable` call). `TOP10.md` and `faults.csv` now
    say so. Patching `v1` is a separate decision, made on the `v1` branch if at all.
    **The owner decided on 28 September 2026 to patch `v1`: merging `claude/ci-hang` into the `v1` branch is
    claimed on 28 September 2026 by session admiring-murdock-875699.** The tags `v1-paper` and `v1-final` stay
    where they are.
  Also corrected while there: `COORDINATION.md` said review found fewer faults than the owner's use; it found more
  (28 against 26).

- **Two analyses for the paper, and a stale count.** **Claimed on 28 September 2026 by session
  admiring-murdock-875699**, at the owner's asking.
  1. **What the checks claimed against what turned out to be true:** a dated ledger of every time a reported
     number or verdict was corrected, most often downward, because it had been overstated, set beside how many
     tests existed at the time.
  2. **Who decided what:** the project's major decisions, each with who proposed it and who chose it, quoted from
     the transcripts and the backlog rather than paraphrased.
  3. **"Ten of the twelve ADRs"** in `docs/paper/METHODOLOGY.md` and `TIMELINE.md` was true when written. v1 ended
     with thirteen records, and there are seventeen across both versions (`docs/paper/ADRS.md`).

  Touches only `docs/paper/`.

  **Done the same day.** 1 is `docs/paper/CORRECTIONS.md` with `corrections.csv` and `figure-corrections.html`;
  2 is `DECISIONS.md` with `figure-decisions.html`; 3 is fixed in both files, keeping the original count and
  saying it was true when written.

- **A review of `sv` on 27 September 2026: faults, and what could be faster.** By session securevibe-e8, at
  the owner's asking ("review sv and add any issues you find or ways to improve or optimize"). Read: the
  entry points, the runner, every walker, the checks' hot loops, the MCP server, `Cargo.toml`, the
  `Dockerfile`, and CI, on `main` at `4bee715`; then a release build timed on the Flask example and on this
  repository, and one fixture built to settle a question the code could not. **Not claimed; each numbered
  item can be claimed on its own.** Every item names where it is and how it was seen; a guess is marked as one.
  Looked at and found sound, for the record: the MCP server's confinement of paths to its root (tested both
  ways of escaping), the fence being verified rather than assumed, the adapters and the bundle refusing
  symbolic links, and no panic anywhere on this repository's own 58,000 lines.

  **Faults, most serious first.**
  **Items 7, 1, and 3 claimed together on 27 September 2026 by session securevibe-e8**, at the owner's
  asking: one walk of the app, with the link rule and the size cap in it, is one change. **Done the same day:**
  `sv_scan::files::Listing`, one walk that no check repeats, links never followed and named, a 2 MB cap
  for every reader, the bill of materials built once, and the corroborators reading each file once. `sv
  report` on this repository goes from 2.86 s to 2.73 s; `sv check` is unchanged, because on trees this
  size the time is in item 6, not in the walks. See DESIGN, "One walk of the app".
  **Items 4, 5, and 8 claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to
  continue with the backlog; one pull request each.
  **Items 2 and 11 claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to
  continue with the backlog; one pull request each.
  **Item 2 was claimed twice**, a minute apart, and neither claim was on `main` when the other was made:
  by session securevibe-e2 at 03:11 UTC (pull request #328) and by session securevibe-e9 at 03:13 UTC
  (#329, which reached `main` first). securevibe-e2 had already built it by the time this was seen: branch
  `claude/securevibe-e2-run-limits`, a time limit on the test suite and on every Docker call, Ctrl-C and
  `kill` removing the run's containers, and each run removing what an ended run left, with tests against
  real containers. The owner first chose that work (#331), but securevibe-e9's own had already reached
  `main` (#332) before either session saw the other's. **The owner's decision, later the same day: #332
  stays, #331 is closed, and the two things only #331 had are ported onto #332's code:** a
  `test-time-limit` setting in `[stack.run]`, and cleanup after a run killed outright (everything a run
  starts labeled with the machine and process, and the next run removing what an ended process left, and
  saying so). **That port claimed on 28 September 2026 by session securevibe-e2.**
  **Done the same day:** see DESIGN, "A run has an end, and Ctrl-C cleans up", the part headed "Later the
  same day".
  1. **Every walker but two follows symbolic links, out of the app and round in circles.** Reproduced with
     a fixture: an app whose `vendor-link` points at a folder outside it, and whose `src/loop` points at
     `..`. `sv check` read the outside folder's `settings.py` and reported its finding, then reported it
     again at every level of the loop, about thirty times, under paths four hundred characters long
     (`src/loop/src/loop/…/vendor-link/settings.py`). It finished in a second only because the operating
     system stops following links after thirty-two levels; nothing in `sv` did. `adapters.rs:730` and
     `bundle.rs:315` already refuse links, each with its reason; `ast.rs` (the code rules), `secrets.rs`,
     `sv-scan/src/lib.rs` (the corroborators), `suite.rs`, and `ecosystems.rs` do not. Reading outside the
     app is the promise `sv` makes about the folder it is given, broken by any link the app's author or its
     AI tool left. Fix: one rule where `skip_dir` lives, applied by every walker: a link is not followed,
     and is listed once as not read, so a linked `vendor/` is a named gap rather than a silent one. Test
     with this fixture, and count: five walkers should go red when the rule is removed.
  2. **`sv run` has no time limit, and an interrupted run leaves its containers behind.** Every Docker
     call goes through `output_of` (`sv-run/src/lib.rs:327`), which waits forever; the app's own test
     suite is `docker exec sh -c <test>` (`docker.rs:424`) with nothing bounding it, so a suite that hangs
     hangs `sv report --run` with it. Cleanup is `Teardown`'s `Drop` (`docker.rs:1123`), which runs on
     every return path and not when the process is killed by Ctrl-C, since a signal ends a Rust process
     without unwinding: the app, the sidecar, the stand-ins, and the `--internal` network stay, under
     names that carry the process id, so they accumulate. The second half is reasoned from the code, not
     reproduced. Fix: a stated cap on the test command (`timeout` inside the container, say ten minutes,
     with the cap in the report when it fires, since a suite that was cut short credits nothing), a
     wall-clock limit per Docker call, and a Ctrl-C handler that runs the teardown; failing that, a
     `sv run --clean` that removes everything named `sv-…`.
     **Done on 28 September 2026 by session securevibe-e9:** every Docker call is limited to 20 minutes and
     the test command to 10, a suite stopped at the limit credits nothing and the report says it was
     stopped, and Ctrl-C lets the run remove its containers and network before `sv` exits. Tested against
     real Docker, Ctrl-C included, and each guard broken on purpose turns at least two tests red. See
     DESIGN, "A run has an end, and Ctrl-C cleans up". `sv run --clean` was not needed for Ctrl-C; a run
     ended by `kill -9` still leaves its containers, and the DESIGN section says how to list them.
  3. **No size limit in the code-rule walker or the corroborator walker.** `secrets.rs` stops at 2 MB
     (`MAX_FILE_BYTES`) and says so. `ast.rs:1313` reads any file whole and hands it to tree-sitter, so a
     50 MB minified bundle or a generated file is parsed in full; `sv-scan/src/lib.rs:490` reads every
     source file whole and keeps all of them in memory for the run (`files.push((language, relative,
     contents))`). Fix: the same cap, reported as *not read, too large* rather than skipped, which is the
     honesty rule; and the corroborators reading one file at a time.
  4. **Options are read as folders.** `sv check --help` says "--help is not a folder"; `sv scope
     --nonsense` says "no securevibe.toml in --nonsense"; there is no `sv --version` at all (the version
     appears only in a bundle's listing). `main.rs` dispatches on the first word and hands the second to
     the command as a path. Fix: a word starting with `-` is an option, an unknown one is an error that
     names the command's options, `--help` works after any command, and `sv --version` prints the version
     and the commit the build was made from, which the bundle already knows how to find.
     **Done on 28 September 2026 by session securevibe-e9:** every command's options are in one table,
     `COMMANDS` in `main.rs`, checked before the command runs. An unknown option is refused with the
     command's options and its usage; so is a second folder, a word where a command takes none, and an
     option missing its value. A folder whose name starts with `-` is named as `./-name`, which the
     message says. `--help` or `-h` after any command shows that command's usage and runs nothing.
     `sv --version` prints the version and the commit. `crates/sv-cli/tests/options.rs` holds it; each
     part, broken on purpose, turns at least two of its tests red, except `--version`, which one test
     holds.
  5. **A bad edit to a compiled-in data file makes `sv run` panic.** `signed_in.rs:1135-1153` uses
     `expect` while reading `data/breached-password-evidence.json`, which is compiled in with
     `include_str!`; the file is checked by a test, so this reaches an owner only from a source build with
     the file broken. Low. A panic in a probe run should be *not assessed* with the reason, like every
     other failure there. **Done on 28 September 2026 by session securevibe-e9:** the file is read by
     `breached_seen_in`, which says what is wrong with it (not JSON, evidence for another password, no
     count, no date), and V6.2.12 is then *not assessed* with that reason, whatever the app answered;
     the rest of the run goes on. Two tests in `signed_in.rs` hold it, each failing when the password
     match or the count is taken out.

  **What could be faster.** Timed with a release build: `sv check` on the five-file Flask example takes
  about a second, `sv check .` on this repository about three, `sv report` on the example about one. None
  is slow for a person at a terminal. Two of them are slow for an AI tool calling the MCP server after
  every change, and the first is the reason.
  6. **Everything is loaded and compiled again on every command and every MCP call.** `assemble_report`
     (`main.rs:1848-1863`) loads the four framework files (234 KB of JSON), both rule files, and the
     adapters (371 KB), and compiles every tree-sitter query (twelve rules across fourteen languages) and
     every regex, each time it runs; `securevibe_explain` reloads the frameworks per call (`mcp.rs:632`).
     The `Server` struct holds only its root. Fix: load once per process, in `Server` for the MCP server
     and at the top of `main` for the CLI, and measure the difference; most of the second above is this.
     **Claimed 27 September 2026 by session securevibe-e8**, at the owner's asking, in branch
     `claude/load-once`. **Done the same day**, and the premise corrected: the JSON was 5 ms of the
     second, and 873 ms was tree-sitter compiling 143 queries in fifteen languages for every command.
     Queries now compile the first time their language is met and are kept for the process; the MCP
     server loads everything once in `Server`. `sv check` on a small app 957 ms → 30 ms; on this
     repository 2.33 s → 1.93 s. See DESIGN, "The second before the first file".
  7. **The app folder is walked six times per report, the bill of materials is built two or three
     times, and every source file is lowercased once per signature.** The walks: secrets, the code
     rules, the corroborators, the tools' file list, the test finder, and the ecosystems. `sbom::build`
     runs in `versions_pinned` (through `check_dir`) and again in `assemble_report`; `sv check` builds it a
     third time (`main.rs:1222`). In `sv-scan/src/lib.rs:298`, `contents.to_lowercase()` sits inside the
     loop over signatures, so with about thirty signatures the whole source is lowercased about thirty
     times. Fix: one walk that yields the file list once and is handed to each check, one bill of
     materials passed down, and one lowercasing per file. This is the change that would matter on a large
     app; measure on one before and after.
  8. **Regexes compiled inside hot loops.** `logs.rs` compiles four patterns per log line
     (`common_format`, `timestamp`, `has_place`, lines 231-320), `ai.rs:1080` one per (line, word) pair,
     `secrets.rs:268` and `:331` one per file, `signed_in.rs:4336-4355` one per page. `probes.rs:1222`
     shows the fix: a `LazyLock` static, compiled once.
     **Done on 28 September 2026 by session securevibe-e9:** every fixed pattern in `logs.rs`,
     `secrets.rs`, and `signed_in.rs` is a `LazyLock` static, and `ai.rs`'s `has_word` matches a word
     by hand, since its words include the run's own token counts. A test holds `has_word` to the
     pattern it replaced, on lines with capitals, accented letters, and emoji. Timed with a release
     build on the same inputs, before and after: reading 20,000 lines of an app's output for the AI
     checks, 16.7 s to 0.05 s; the log checks 200 times over, 0.42 s to 0.004 s; the credential scan
     of 2,000 small files, 3.4 s to 0.04 s; redacting a failing test's output 2,000 times, 0.29 s to
     0.05 s. The first was the only one a person would have waited on, and only for an app that writes
     a lot while it runs.
  9. **The reports are large for what they say.** For the five-file example: `compliance.md` 160 KB,
     `report.html` 191 KB, `report.json` 367 KB, because each of about six hundred requirements carries
     its full text in every rendering, applicable or not. For a person the HTML is fine. For the AI tool
     reading `report.json`, and for anyone diffing two reports, the text once per id, or the
     not-applicable rows collapsed, would cut most of it. The owner's call on what the reading experience
     should be.
     **Claimed on 28 September 2026 by session securevibe-e10**, in branch `claude/report-shape`. **The
     owner's decisions, the same day:** in `report.json`, each requirement's text once, in a lookup
     table by id, which every section points to; in `compliance.md`, the requirements that apply grouped
     by chapter, each chapter's counts in one row (applies and checked, applies and not verified, does
     not apply, not placed yet), with the full text in an appendix; and a requirement that does not
     apply shown by its id and the reason, without its text. The HTML page keeps the full text.
     **Done the same day**, and the premise corrected: only the tests worth writing repeated the
     text, so `report.json` went from 367 KB to 334 KB, and `compliance.md` grew from 160 KB to
     169 KB while the part read before its appendix went from 63 KB to 14 KB. See DESIGN, "The
     report's shape". Not done, and not decided: `only_you_can_check` in `report.json` repeats
     word for word 50 entries of `questions_for_you` (27 KB on the example).
     **The owner's decision, the same day: drop the duplicate. Claimed by session securevibe-e10**, in
     branch `claude/only-you-once`.
     **Done the same day:** `report.json` names them as `only_you_can_check_ids`, each a question in
     `questions_for_you`; 334 KB to 306 KB on the example. See DESIGN, "The report's shape".
  10. **No release profile.** `Cargo.toml` sets none, and the binary is 35.6 MB. `lto`, `codegen-units =
      1`, and `strip = true` are the usual settings for a tool built once and shipped, and typically halve
      the size; the Docker image and the "download later" packaging item both carry the binary. Measure
      size and speed before and after, since `lto` can also lengthen CI's build.
      **Claimed on 28 September 2026 by session securevibe-e10**, at the owner's asking, in branch
      `claude/release-profile`. **Done the same day**, and the premise corrected: 27 MB of the 35.7 MB is
      the parse tables of the fifteen tree-sitter grammars, and 4.9 MB is code, so no setting can halve
      it. `lto` and one code-generation unit cut 2.4 MB for a clean build 30 s longer and no change in
      speed; the profile keeps `strip = true` only, 34.5 MB. See DESIGN, "A release profile".

  **Smaller.**
  11. **The runtime image runs as root.** `Dockerfile` sets no `USER`; the image reads mounted folders
      and writes reports into them. A non-root user, or `--user` in the documented `docker run` line,
      keeps a mistake from writing into the owner's folder as root. (`safe.directory` for git is already
      handled.)
      **Done on 28 September 2026 by session securevibe-e9:** the image runs as its own user, 10001,
      never root; `--user "$(id -u):$(id -g)"` on Linux still makes it the owner, as the README and
      GETTING-STARTED say. `tools/image_smoke.py` checks the image's user is not root, and its
      `safe.directory` check now names root explicitly, since the image's own user could not read the
      test folder. Not built in the session that made the change (its sandbox cannot reach the Debian
      mirrors from a build); CI's image job builds and drives it.
  12. **`sv` holds apps to V15.2.1 and does not hold itself.** CI has no `cargo audit` or `cargo deny`
      step; Dependabot proposes updates but compares nothing; the v2 self-assessment ran the OSV
      comparison once, by hand. A weekly job running `sv audit .` against a downloaded OSV export, or
      `cargo audit`, belongs with the weekly review entry above.
      **Claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to pick an item.
      **Done the same day:** `.github/workflows/audit.yml` runs `sv audit .` against OSV's crates.io export
      weekly and when a lockfile or manifest changes. `sv audit` now respects `not-the-app` and exits 0,
      1, or 2 for clean, found, and not fully compared. `sv`'s 68 crates matched none of 2,858 records.
      See DESIGN, "`sv` audits its own dependencies, weekly". Three faults found on the way are entries
      of their own below: the report's bill of materials ignores `not-the-app`, an ecosystem counts as
      covered by a database that only mentions it in passing, and one vulnerability under two names is
      counted twice.
  13. **`signed_in.rs` is 15,351 lines**, with 231 tests and one fake app carrying about eighty flaw
      switches; `ai.rs` is 3,338. A session touching one check reads all of it, and every session's
      change to a check lands in the same file, which is where this week's merge conflicts were. Split by
      check (sign-in, sessions, admin, passwords, uploads, flows, codes) with the fake app as a test
      module of its own. No behavior changes; the 231 tests are the guard.
      **Done on 28 September 2026, and the freeze is lifted:** `crates/sv-check/src/signed_in/` is fourteen
      files, none over 2,001 lines, with the same 233 tests; see DESIGN, "The signed-in checks, one file per
      area". The changes waiting on the freeze (securevibe-e9's V14.2.2 and V8.2.3, and the nine signed-in
      partial checks) can go ahead, each in its area's file.

      **The owner asked on 28 September 2026 for this to be shared across several sessions.** The plan
      below is by session securevibe-e9, from the file as it stood on `main` that day: 15,463 lines,
      about 7,600 of checks and 7,900 of tests, 233 tests, and one fake app (`FakeApp` and `Flaws`, about
      1,450 lines) that nearly every test drives. **The file is frozen from the moment step 0 is claimed
      until step 2 is done:** no other pull request changes `crates/sv-check/src/signed_in.rs` or the
      folder that replaces it, so a fix to a check waits, or is made by the session holding that check's
      slice, in its slice's pull request. The freeze is what keeps several sessions moving the same file
      from spending their time on merge conflicts, which is the fault this item exists to fix.

      **Rules for every step.** Code is moved, never changed: no renames, no new logic, no reformatting
      beyond `cargo fmt`. The only edits allowed are `use` lines, `mod` lines, and widening a private item
      to `pub(super)` so a sibling file can reach it. Something two slices both use stays where it is
      (the shared plumbing, below) rather than being moved by either. A test that drives several areas at
      once (`each_flaw_is_found_by_its_own_rule_and_by_no_other`,
      `a_correct_app_raises_nothing_and_every_check_says_what_it_confirmed`,
      `an_app_with_every_flaw_at_once_has_every_one_found`, and the like) stays in `mod.rs`. Each pull
      request shows it moved and did not change: `git diff --color-moved=zebra -M origin/main` has no
      lines but moved ones and `use`, `mod`, and visibility lines, and the pull request says so. And
      each one keeps every test: the names from `cargo test -p sv-check --lib signed_in -- --list`,
      compared by their last part, are the same set before and after, 233 of them unless a step says
      otherwise. The usual checks (`cargo fmt --all --check`, `cargo clippy --all-targets -- -D
      warnings`, `cargo test --workspace`) pass. Merge `main` in before merging; a conflict in `mod.rs`
      is two sessions' `mod` or `use` lines, and keeping both resolves it.

      **Step 0, one session, alone, merged before step 1 starts.** Turn the file into a folder and move
      out what every slice depends on, so the slices after it touch only their own lines.
      - `git mv crates/sv-check/src/signed_in.rs crates/sv-check/src/signed_in/mod.rs` in a commit of its
        own with no other change, so git records a rename and `git log --follow` keeps the history.
      - `signed_in/fake_app.rs`, `#[cfg(test)]`: `FakeApp`, `Flaws`, the constants beside them, its `impl
        Http`, and the helpers every test uses (`users`, `accounts`, `run_against`, `run_with_users`,
        `rule_ids`, `verified_ids`, and the request helpers `cookie_value`, `decode`, `pairs`, `form`),
        roughly lines 7,609 to 9,220 today.
      - `signed_in/rules.rs`: the `Rule` constants and finding helpers of the "Findings" section, roughly
        lines 452 to 1,254.
      - Sessions, anti-forgery tokens, and requests from templates (roughly lines 122 to 451), the
        `Http` trait, `Outcome`, `run`, `run_with`, `sign_in`, and `sign_up` stay in `mod.rs`: they are
        the shared plumbing.
      - Record the 233 test names in the pull request, as the list the later steps compare against.

      **Step 1, in parallel, one session per slice.** Each slice is claimed on its own line below, in a
      claim commit of its own, and is one pull request: its functions move from `mod.rs` into its file,
      and the tests about them move with them into that file's own `#[cfg(test)] mod tests`, which uses
      `super::fake_app::*`. Line numbers are from 28 September and will have moved after step 0; the
      function names are what count.
      - a. `signin.rs`: `guess_once`, `forwarded_check`, `brute_force_check`, `plant_log_markers`,
        `default_account_check`, `password_in_url_check`, `sign_out_on_get_check`, `logout_check`, and
        the V6.3.1 wrong-password tests.
      - b. `sessions.rs`: `session_timeout_checks`, `minutes_text`, `session_checks`, `session_id_check`,
        `most_bits`, `invented_session_check`, `private_page_checks`, `points_at`, `clear_site_data_check`,
        `record_fields_check`, `SECRET_FIELD_NAMES`, and the session-timeout and private-page tests.
      - c. `passwords.rs`: `sign_up_only`, `account_works`, `describe_password`, `judge_breached`,
        `breached_seen_in` and the breached-password evidence beside it, `password_checks`,
        `exact_password_checks`, `password_field_checks`, `change_password_checks`,
        `reveals_account_check`, `same_shape`, `password_hint`, `delete_account_check`.
      - d. `codes.rs`: `reset_checks`, the `email_code_*` functions and `EmailCode`, `wrong_code`,
        `activation_checks`, `activation_code_check`, `code_patterns`, `reset_code`, `percent_decode`,
        `reset_code_check`, `TotpSignIn` and `totp_checks`, and the password-reset, emailed-code,
        activation, and two-factor tests. The largest slice; it may be split in two (emailed codes, and
        two-factor) by whoever claims it, saying so in the claim.
      - e. `uploads.rs`: the "Uploads" section's `GIF_MAGIC`, `Upload`, `multipart`, `send_upload`,
        `upload_checks`, `disposition_params`, `download_name_checks`, `served_upload_checks`,
        `client_side_validation_check`, and the upload tests.
      - f. `flows.rs`: `finished`, `take_steps`, `flow_checks`, and their tests.
      - g. `admin.rs`: `admin_checks`, `ROLE_FIELDS`, `signed_in_session`, `role_field_check`,
        `admin_action_checks`, `owned_checks`, `record_path`, `strip_origin`, and their tests.
      - h. `forgery.rs`: `forgery_check`, `referrer_policy`, `null_origin_check`, `simple_request_check`,
        `NullOriginApp` and its tests, and the WebSocket foreign-origin (V4.4.2) tests;
        `ws_handshake` and `websocket_session_checks` go with slice b unless its session says otherwise.

      **Step 2, one session, after every slice is merged.** What is left in `mod.rs` is the plumbing,
      `run_with` calling each slice, and the cross-area tests. Check no slice's file passed about 2,500
      lines, and split one that did the same way. Add a DESIGN section saying where each check now lives,
      and mark this item done with the final line counts and the final test count.

      **`ai.rs` (3,338 lines) is not part of this.** It can be split the same way afterwards, as its own
      item.

      **Claims:**
      - Step 0: **claimed on 28 September 2026 by session securevibe-e2**, at the owner's asking to pick
        another item, in branch `claude/securevibe-e2-split-step0`. `signed_in.rs` is frozen from this
        claim's merge until step 2 is done.
        **Done the same day:** `signed_in/mod.rs` (13,192 lines), `signed_in/fake_app.rs` (1,609), and
        `signed_in/rules.rs` (664, the `Rule` type, `finding`, and the sixty rules); the 233 tests are the
        same set and all pass. Three things for step 1:
        - `rules.rs` took only the rules. The password constants and helpers after them (`COMMON`,
          `BREACHED`, `BREACHED_EVIDENCE`, `breached_seen_in`, `with_commas`, `long_date`, `random_like`,
          `context_password`, `DEFAULT_ACCOUNTS`) stay in `mod.rs` for slices a and c to take.
        - `BREACHED_EVIDENCE` is an `include_str!` with a path relative to its file; it gained a `../` when
          the file moved down a folder, and keeps working from any file beside `mod.rs`.
        - `tools/coverage.py` now reads every file under a crate's `src`, subfolders included, and leaves
          out a file declared `#[cfg(test)] mod name;` (as `fake_app.rs` is). Before, it read `src/*.rs`
          only, and moving the rules down a folder made it lose every signed-in check.
      - Step 1, slice d (`codes.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking, in branch `claude/securevibe-e2-split-codes`. One file, not split in two.
        **Done the same day:** `signed_in/codes.rs`, 3,300 lines with its 64 tests; `mod.rs` is 1,442, and its
        tests are the 12 that exercise several areas at once, beside the shared test helpers. With each of
        the nine checks made to return at once, the moved tests catch every one. `codes.rs` is past the
        2,500 lines step 2 checks for, so step 2 should split it, into emailed codes (reset, sign-in codes,
        activation) and two-factor, as the plan allows.
      - Step 1, slice a (`signin.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-signin`.
        **Done the same day:** `signed_in/signin.rs`, 1,140 lines with its 21 tests; `mod.rs` is 4,729.
        `run_with`, `run_keeping_app`, and `seeded_with` stay in `mod.rs`'s tests, since slice d's tests
        use them too. With each check made to return at once, the moved tests catch `guess_once`,
        `forwarded_check`, `brute_force_check`, and `logout_check`. `default_account_check` (V6.3.2),
        `password_in_url_check` (V14.2.1), `sign_out_on_get_check` (V3.5.3), and `plant_log_markers` are
        caught only by cross-area tests in `mod.rs`, which was so before the split.
      - Step 1, slice c (`passwords.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-passwords`.
        **Done the same day:** `signed_in/passwords.rs`, 1,954 lines with its 33 tests; `mod.rs` is 5,859.
        The breached-password evidence came along, and its `include_str!` path still works from beside
        `mod.rs`. `run_signing_up`, `run_signing_up_with`, and `with_words` stay in `mod.rs`'s tests,
        since slice d's tests use them too. With each of the eight checks made to return at once, the
        moved tests catch every one.
      - Step 1, slice b (`sessions.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-sessions`. A move
        only, with `ws_handshake` and `websocket_session_checks`: securevibe-e9's V14.2.2 and V8.2.3
        changes to the caching and record-field checks stay with securevibe-e9, after it.
        **Done the same day:** `signed_in/sessions.rs`, 2,001 lines with its 41 tests; `mod.rs` is 7,800.
        Shared and so left in `mod.rs`'s tests: `timeouts` (slice d's `code_slow_run` uses it), and
        `WS_RULES`, `ws_run`, `ws_findings`, and `bearer_ws_users` (`forgery.rs` uses them). `most_bits` is
        in `sessions.rs` as planned and `pub(super)`, since the code checks use it too. With each check
        made to return at once, the moved tests catch six of the eight; `session_checks` (the cookie's
        attributes, V3.3.2 and V3.3.4, and its renewal at sign-in, V7.2.4) and `session_id_check` (V7.2.3)
        are caught only by four cross-area
        tests in `mod.rs`, which was so before the split. `private_page_checks` and
        `record_fields_check` are in `sessions.rs` now, for securevibe-e9's V14.2.2 and V8.2.3 changes.
      - Step 1, slice g (`admin.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-admin`. A move only:
        securevibe-e9's V8.2.3 change to `probe.role-field-trusted` stays with securevibe-e9, after it.
        **Done the same day:** `signed_in/admin.rs`, 1,034 lines with its 17 tests; `mod.rs` is 9,787. With
        each check made to return at once, the moved tests catch every one: `admin_checks` 3,
        `admin_action_checks` 6, `role_field_check` 4, and `owned_checks` 2, besides the cross-area tests.
        `role_field_check` is in `admin.rs` now, for securevibe-e9's V8.2.3 change.
      - Step 1, slice h (`forgery.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-forgery`.
        **Done the same day:** `signed_in/forgery.rs`, 777 lines with its 17 tests; `mod.rs` is 10,811. The
        WebSocket foreign-origin tests use `ws_run`, `ws_findings`, and `bearer_ws_users`, which stay in
        `mod.rs`'s tests for slice b and are `pub(super)`. Each check was made to return at once: breaking
        `null_origin_check` turns 5 of the moved tests red, and `simple_request_check` 4. `forgery_check`
        (V3.5.1) turns only the three cross-area tests in `mod.rs` red, none in `forgery.rs`: nothing
        tests it on its own, which was so before the split and is left for a change that may add tests.
      - Step 1, slice f (`flows.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-flows`.
        **Done the same day:** `signed_in/flows.rs`, 371 lines with its 8 tests; `mod.rs` is 11,578. With
        `flow_checks` made to return at once, 7 of the 8 go red (the eighth is the app with no flow), and
        none of the tests left in `mod.rs` does: the all-flaws and correct-app tests do not cover flows.
      - Step 1, slice e (`uploads.rs`): **claimed on 28 September 2026 by session securevibe-e2**, at the
        owner's asking to pick another item, in branch `claude/securevibe-e2-split-uploads`.
        **Done the same day:** `signed_in/uploads.rs`, 1,261 lines with its 20 tests; `mod.rs` is 11,940.
        `MOST_UPLOAD_BYTES` came along, since only upload code uses it. `with_signup` stays in `mod.rs`'s
        tests, shared by several areas, and is `pub(super)` so a slice's tests can `use
        super::super::tests::with_signup`; other shared test helpers can be reached the same way.
      - Step 2: **claimed on 28 September 2026 by session securevibe-e2**, at the owner's asking, in branch
        `claude/securevibe-e2-split-step2`: `codes.rs` split in two, `mod.rs` tidied, a DESIGN section, and
        this item marked done, which lifts the freeze.
        **Done the same day.** `codes.rs` was split in four rather than two: two-factor out alone would have
        left 2,700 lines, past the 2,500 checked for, so it is split by area into `reset.rs` (692 lines),
        `activation.rs` (614), `totp.rs` (592), and `codes.rs` (1,426, the emailed sign-in code and what the
        three email flows share). Each moved check, made to return at once, turns the tests in its new file
        red. `mod.rs` (1,471) lost two headings with nothing under them and gained a map of the files at its
        top, and DESIGN has the same map. Final lines: `mod.rs` 1,471, `fake_app.rs` 1,609, `rules.rs` 664,
        `signin.rs` 1,140, `sessions.rs` 2,001, `passwords.rs` 1,954, `reset.rs` 692, `codes.rs` 1,426,
        `activation.rs` 614, `totp.rs` 592, `admin.rs` 1,034, `forgery.rs` 777, `flows.rs` 371, `uploads.rs`
        1,261; 15,606 in all, against 15,463 before. The difference is the new `mod`, `use`, and test-module
        lines, blank lines between moved blocks, and the map, less the two headings. Tests: the same 233. Found on the way: `tools/pwned_passwords.py` still read the breached
        password from `signed_in.rs`, which has not existed since step 0, and matched only `const BREACHED`,
        not `pub(super) const BREACHED`; it has no test, so it would have failed the next time it was run.
        Both fixed, and the reading part run to show it finds the password the evidence file records.
        `docs/PARTIAL-CHECKS.md` still names `signed_in.rs` in about sixty places; left as it is, since the
        name still points at the folder and securevibe-e9's open work edits that file.

- **Three faults in the known-vulnerability comparison, found while `sv` audited itself.** Found on 28
  September 2026 by session securevibe-e9, doing review item 12. **Not claimed; each can be claimed on its
  own.**
  1. **An ecosystem counts as covered by a database that only mentions it in passing.** `audit_against`
     (`crates/sv-check/src/advisories.rs`) treats an ecosystem as covered when any record in the database
     names it. OSV's crates.io export holds 28 records that also name PyPI packages, so with only that
     export, a Python app's packages are "compared" against 28 records and can be reported as matching
     nothing, when nothing about Python was loaded. Reproduced with the export downloaded that day. An
     ecosystem should count as covered only when the database holds a record about it and nothing else, as
     every per-ecosystem export does.
     **Claimed on 28 September 2026 by session securevibe-e9.** The fix was written before this claim, in
     branch `claude/securevibe-e9-osv-coverage`, while waiting for the entry itself to reach `main`.
     **Done the same day:** an ecosystem is covered only when the database holds a record about it and
     no other. With the crates.io export alone, this repository's example Python app is now "not compared
     for Python" rather than compared. A unit test in `advisories.rs` and an end-to-end one in
     `crates/sv-cli/tests/audit_not_the_app.rs` hold it, each failing when a mention is enough again.
  2. **One vulnerability under two names is counted twice.** An advisory published as both a GitHub
     advisory and a PyPI one (`GHSA-wvwj-cvrp-7pv5` and `PYSEC-2026-287`, which list each other as
     aliases) is two findings; `examples/flask-booking`'s 39 are about 20 vulnerabilities. Count a
     vulnerability once, naming every id it goes by.
     **Claimed on 28 September 2026 by session securevibe-e9.**
     **Done the same day:** records that name each other, directly or through a third, are one finding,
     from the record rated most serious, naming every id. `examples/flask-booking` goes from 39 findings
     to 20. See DESIGN, "One vulnerability, once".
  3. **`sv report --advisories` does not respect `not-the-app`.** It builds its own bill of materials from
     the whole folder, so on this repository the report still counts the example app's vulnerabilities
     against V15.2.1. `sv audit` splits the listing first (`Listing::split`); the report should do the same.
     **Claimed on 28 September 2026 by session securevibe-e9.**
     **Done the same day, the other way round:** the report was right and `sv audit` was wrong. Findings
     in those folders are listed apart and still counted, since securevibe.toml is written by the AI
     coding tool and a line in it must not hide a vulnerability; `sv audit` now counts them too, and the
     weekly job audits only the files `sv` is built from, at the owner's choice. See DESIGN, "`sv`
     audits its own dependencies, weekly", its "Later" part.
     Item 3 was also claimed by securevibe-e2, 27 seconds apart (#340), and built the opposite way in #342,
     which stopped counting those findings. In the review the owner asked for, securevibe-e2 found #344's
     way the right one: it is the rule `not-the-app` was built on, and the owner chose it. **#342 was closed
     unmerged at the owner's word.** Item 1 (#339) and item 2 (#345) were reviewed by securevibe-e2: no
     faults, and suggestions on each pull request.

- **Two faults found while `killed_run.rs` failed on the owner's Mac.** Found on 28 September 2026 by the
  session working in branch `claude/killed-run-colima-mount`. The test itself was fixed in #361: it wrote its
  app to the system's temporary folder, which on a Mac is under `/var/folders`, and Colima does not share that
  folder with its machine, so the app's folder arrived empty and the app never answered. Each item can be
  claimed on its own.
  1. **A run that removes leftovers and then fails does not say it removed them.** `DockerBackend::run`
     (`crates/sv-run/src/docker.rs`) removes what an ended run left before it starts anything, but the list
     travels back only in a successful `RunOutcome`. When the app then never answers, or Docker refuses,
     `sv run` and `sv report --run` say only why the run failed, and containers and a network were removed
     from the owner's computer without a word. Seen on the owner's Mac: after the failing test, nothing
     labeled `org.securevibe.owner` was left, and nothing had said so. Fix: a failed run carries what it
     removed, and its explanation names it, so both commands say it.
     **Claimed on 28 September 2026 by that session**, at the owner's asking, in branch
     `claude/failed-run-says-removed`.
     **Done the same day:** a failed run is a `RunFailed`, the reason and what was removed first, and its
     explanation gives both. `a_run_that_fails_after_removing_leftovers_still_says_what_it_removed` in
     `crates/sv-run/tests/leftovers.rs` fails when the failure drops the list and when the explanation
     leaves it out. See DESIGN, "A run has an end, and Ctrl-C cleans up", the part headed "Later still".
  2. **On a Mac with Colima, an app folder outside the home folder reaches the app empty, and `sv` says only
     that the app never answered.** Colima shares the home folder with its machine by default and nothing
     else; Docker mounts any other folder as a new, empty one without complaint. Checked on the owner's
     Colima (Docker 29.5.2): a folder under `/var/folders` appeared empty inside a container, and one under
     the home folder appeared with its file. The run is still correctly not assessed, but the reason given
     ("never answered on its health path") sends the owner looking at their app rather than at where it is.
     Fix, as a suggestion: after the app's container starts, list `/app` inside it; when it is empty and the
     folder on this computer is not, stop the run as not assessed and say the container backend could not
     see the folder, naming Colima's shared-folder setting. A test: an app folder the backend cannot see
     (on Linux, where every folder is shared, this needs a stand-in, such as a folder the check is told is
     empty inside). **Claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to continue
     with the backlog.
     **Done the same day:** when the app never answers, the run lists `/app` from a throwaway container of the
     probes' own busybox image with the same mount (no network, read-only, no capabilities). Empty there while
     the folder has files on this computer is `CannotRun::AppFolderUnseen`, which names the folder and Colima's
     and Docker Desktop's sharing settings instead of blaming the app. Asked only on failure, so a run that
     works pays nothing. `unseen_folder` in `crates/sv-run/src/lib.rs` is tested with the inside as a stand-in
     (Linux shares every folder), with three controls; the existing never-starts test in
     `crates/sv-run/tests/fence.rs` is the control that runs for real in CI, where the listing must see the
     fixture's files and the reason must stay "never answered". Not tried on a Mac with Colima.

- **A test that failed once on CI and passed when run again, not yet named.** Found on 28 September 2026 by
  session securevibe-e9 on #344: the `test` job of the push run for `51c6d71` failed in the Tests step after
  about three minutes ([run 36455276279](https://github.com/abbyshade111/SecureVibe/actions/runs/36455276279)),
  while the pull-request run of the same code passed, main was green, and the whole workspace passed locally.
  Run again once, it passed. The session could not read the log (its network policy refuses the download), so
  which test failed is not known. **Not claimed.** A session that can read that run's log: name the test, find
  why it depends on timing or on the machine, and make it deterministic. The Docker tests that race a timer
  (`crates/sv-cli/tests/interrupt.rs`, `crates/sv-run/tests/limits.rs`) are the first suspects, as a guess.
  **Claimed on 28 September 2026 by session securevibe-e2**, which read the log: the failing test is
  `a_run_first_removes_what_a_stopped_run_left_on_this_machine_and_nothing_else` in
  `crates/sv-run/tests/leftovers.rs` ("left was not started"), securevibe-e2's own.
  **Done the same day.** The cause: the file's other test starts a real run, and every run begins by removing
  what an ended process on this machine left, so it could remove the fake leftover the first test had just
  made, before that test looked for it. On CI's slower machines the removal sometimes came in between.
  Reproduced here with every processor kept busy (one failure in fifteen runs, the same message and line);
  the two tests now take turns, and sixty runs under the same load all passed.

- **Every ASVS and AISVS requirement in one list, with the checks that speak to it.** Asked for by the owner on
  28 September 2026: every requirement by level, grouped by family, each saying whether a check covers it,
  which, and what that check needs to run. `docs/COVERAGE.md` has only the counts. Generated by
  `tools/coverage.py` from the same citations, as `docs/REQUIREMENTS.md`, so it cannot claim a check the
  code does not have, and published as a page the owner can filter. **Claimed on 28 September 2026 by
  session securevibe-e9.**
  **Done the same day:** `docs/REQUIREMENTS.md`, 536 requirements by framework, level, and family, each with
  its coverage and the checks that speak to it: what each looks for, read from where the check is defined,
  and what kind of check it is, which says what it needs to run. `crates/sv-check/tests/coverage_doc.rs`
  fails when it is out of date or leaves out a requirement.

- **A shell variable reference is reported as a hard-coded credential.** Reported on 29 September 2026 by the
  cato-pipeline session, from its CI run against `sv` at `982f97e`: `export CF_ZONE_API_TOKEN="$CF_DNS_API_TOKEN"`
  was a HIGH `secrets.credential-assignment`, telling the owner to rotate a credential that was never in the file.
  `assignment_findings` (`crates/sv-check/src/secrets.rs`) skips a value that is all capitals and underscores, and
  `looks_like_placeholder` skips `${NAME}`, but `$NAME` passes both. Fix: a value that is entirely one reference is
  not a credential: `$NAME`, `$(command)` or backticks, `%NAME%`, and PowerShell's `$env:NAME`; a value that only
  contains one (`$NAME-extra`, `pa$$w0rd…`) is still judged. **Claimed on 29 September 2026 by session
  securevibe-e9**, at the cato-pipeline session's report on the owner's behalf.
  **Done the same day:** `is_whole_reference` in `secrets.rs` passes over those five shapes, `${NAME}` included,
  and nothing else. The report's table is a test, with the two values that only contain a reference as controls
  that are still reported; skipping the check, or loosening it to "contains a `$`", turns it red.
- **The MCP check still counts a large data file whose prose says "command".** Noted on 29 September 2026 by the
  cato-pipeline session: after the large-file work, `config.mcp-server-unpinned` is still not run on cato, because
  NIST's 10 MB catalog uses the word `command` in its text, and a large file is counted as read only when it never
  says `command`. That is the check working as written; narrowing it to a `command` key (`"command"` followed by `:`,
  or `command =`) would let a prose file through while still catching a configuration. **Claimed on 29 September
  2026 by session securevibe-e9**, at the owner's asking to continue with the backlog.
  **Done the same day:** a large file's pieces are judged by the same `command`-key pattern every other file is
  (`LAUNCHER` in `launch.rs`), not by the word. The catalog's prose counts as read and the check runs; a real
  `"command": "npx"` in a large file still leaves it unread and named. Held by a unit test and the end-to-end one in
  `crates/sv-cli/tests/examined.rs`, which failed on the old rule. See DESIGN, "A large data file no longer blocks
  the credential scan or the MCP check", its "Narrowed" note.

- **`sv init`'s blank template trips its own credential check.** Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
  --tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). Every app using the template gets a HIGH
  `secrets.credential-assignment` at its commented `reset = { … password = "{new_password}" … }` example:
  `looks_like_placeholder` knows `${VAR}`, `<name>`, and `{{ var }}` but not the single-brace `{name}` `sv`'s own
  manifest uses. Fix: a value that is entirely one `{identifier}` is a placeholder; `"{new_password}x9Q2vL"` is
  still judged. A test that `sv init`'s own output raises no findings would catch a return. **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
  **Done the same day:** a value that is wholly one `{identifier}` is a placeholder, and one with anything around the
  braces is still judged. A test scans `sv init`'s real template and fails on any credential finding; breaking the
  rule turned it and a unit test red.
- **A missing outside tool is reported as installed and broken under amd64 emulation.** Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
  --tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). `presence()` in
  `crates/sv-check/src/adapters.rs` reads a spawn that failed as missing and one that exited non-zero as broken;
  under QEMU on an ARM Mac, spawning a program that does not exist succeeds and the child exits 127, so Semgrep and
  CodeQL, absent from the image, read as "installed and would not start". Fix: exit status 127 with nothing on
  stderr is missing, the shell's own meaning of 127. **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
  **Done the same day:** a silent 127 is missing; a 127 that says something on stderr stays broken, since a program
  that exists can exit 127 too. Tested with a real adapter whose version command is a stand-in script; breaking it
  turned two tests red. Not run under QEMU here.
- **An app folder given with a trailing `/.` leaves outside tools' paths absolute, and their fingerprints change.**
  Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
  --tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). `sv report app/.` reported every Bandit finding at an absolute path, because `relative_to` in
  `adapters.rs` strips the folder as text and `…/app/.` is not a prefix of `…/app/backend/…`; the fingerprints
  differed from the same scan of `app`, so a reviewed finding stops matching. Fix: normalize the folder once, where
  `sv` receives it, so `app`, `app/`, `app/.`, `./app`, and its absolute path give the same report. **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
  **Done the same day:** the command line cleans the folder of `.` parts and trailing separators, and `relative_to`
  tries the folder as given, cleaned, and canonical, only where the match ends at a separator (so `app-other` is
  not under `app`). Each guard broken in turn turned its test red.
- **An app in a subfolder of a git repository is reported as not in git.** Reported on 29 September 2026 by the cato-pipeline session, from the owner's comparison study (`sv report
  --tools --advisories` on three apps, in CI under amd64 emulation and on the owner's Mac, `main` at `a836cd7`). `tracked_files` in
  `crates/sv-check/src/config.rs` looks for `.git` in the app folder itself, which exists only at a repository's
  root, so `config.secrets-file-committed` says "This folder is not a git repository" and advises putting it in git.
  Fix: ask git (`git -C <app> rev-parse --is-inside-work-tree`, then `ls-files`, which lists the subfolder's tracked
  files relative to it). **Claimed on 29 September 2026 by session securevibe-e9**, at that session's report on the owner's behalf.
  **Done the same day,** by looking for `.git` in the app's folder and every folder above it rather than asking
  `rev-parse`, so a `.git` git cannot read is still told from none: git is asked from inside the app's folder, so
  only its own files count, and a secrets file committed elsewhere in the repository is not reported. An app in a
  subfolder with no `.gitignore` of its own is not assessed rather than failed. See DESIGN, "A check reports one
  of three things".
- **Known-vulnerability matching ignores OSV's `last_affected`, so versions after it are reported.** Reported on 29
  September 2026 by the cato-pipeline session, from its CI run against `sv` at `3fc9324`: `advisory.GHSA-r374-rxx8-8654`
  (alias `PYSEC-2026-2858`) was reported against paramiko 5.0.0, while its range is `introduced: 0`, `last_affected:
  4.0.0`. `Event` in `crates/sv-check/src/advisories.rs` reads only `introduced` and `fixed`; serde drops
  `last_affected` without a word, and `in_range` then reads every version from the start as affected. Fix: read
  `last_affected` (a version above it is not affected; the named version is), and treat any other event key `sv`
  does not know as a range it cannot compare, so the next unsupported field is a gap in the report rather than a
  false finding. **Claimed on 29 September 2026 by session securevibe-e9**, at the cato-pipeline session's report
  on the owner's behalf.
  **Done the same day:** `Event` reads `last_affected` (above it, not affected; at it, still affected), and
  keeps every other key, so a range carrying one this does not read is not compared (it counts toward "not fully
  compared", exit status 2) rather than read without it. `a_version_after_the_last_affected_one_is_not_reported`
  holds the four versions from the report (3.5.1 and 4.0.0 affected, 4.0.1 and 5.0.0 not), and
  `a_range_with_an_event_this_does_not_read_is_not_compared_rather_than_reported` the unknown key, with the
  same record as its control; breaking either guard turns its test red.

- **A rate limiter's 429 may be read as the app's answer about access.** Reported to the owner on 28 September
  2026 by an agent in another project that was integrating `sv`: an open CRITICAL it listed as "F-0001, the
  anonymous user denied runtime probe" had got HTTP 429 from the app's rate limiter rather than a refusal to sign in,
  and may be a false positive. **Not claimed.** Their report was not available here, and no check of `sv`'s matches
  that name at CRITICAL, so the first step is to get the report (rule id, the request, the answer) from the owner.
  Found while looking: `probe.private-page-anonymous` (`signed_in/mod.rs`, step 1 of `run_with`) counts anything
  but 2xx as refused. It raises a finding only on 2xx, so a 429 cannot cause a false alarm there, but a 429 **is
  credited as a pass**: V8.2.1 "refused to somebody not signed in" when the rate limiter said no and the page's own
  check never ran. That is the opposite fault, a false pass, and the same reading may be elsewhere (`ok()` and
  `accepted()` are used throughout the signed-in checks, and 429 is already handled on its own in the sign-in
  guessing checks). A fix would treat 429 (and 503 with `Retry-After`) as "the app did not answer the question":
  wait out `Retry-After` once and ask again, else not assessed, never refused. The file is frozen for the split
  until step 2; this waits for it, or for the session holding slice b (private pages).
  **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item, in
  branch `claude/securevibe-e2-rate-limited`, now that the split is done. The claim covers the false pass found
  while looking (a 429 or a 503 with `Retry-After` read as the app's own answer, in the signed-in checks and any
  other probe that reads a status the same way); the reported CRITICAL still needs the other project's report
  from the owner, and stays open until it is read.
  **The false pass claimed on 28 September 2026 by session securevibe-e10**, at the owner's asking, in branch
  `claude/rate-limited-not-refused`: 429, and 503 with `Retry-After`, read as no answer rather than a refusal,
  wherever the signed-in checks read one. F-0001 itself still needs the other project's report.
  **Claimed twice.** securevibe-e10's claim was made at 00:19 UTC on 29 September but pushed only to its own
  branch, never merged; securevibe-e2 found the item unclaimed on `main` and claimed it at 00:38 UTC (#411), as
  the rule says it should. **The owner's decision, the same day: securevibe-e10's finished work (#412) is merged,
  and securevibe-e2 stands down or takes the part #412 left, the anonymous probes outside `signed_in/`** (the
  entry below). The lesson is the rule's own: a claim counts when it is on `main`, so open its pull request at once.
  **Done the same day:** every signed-in request goes through `Patient`, which waits out a 429, or a 503 with
  `Retry-After`, once, as long as the app asks and at most a minute, except the guessing checks' own requests.
  A limiter still answering after that withdraws every credit of the run into not assessed, naming the
  requests, and keeps the findings with a note. See DESIGN, "A rate limiter's answer is not the app's".
  Two things found and not changed are the entries below.

- **A 500 from the app is read as a refusal, and can be credited as one.** Found on 28 September 2026 by session
  securevibe-e10 while fixing the 429 entry above. The signed-in checks read anything but 2xx as the app refusing
  (`ok()` in `crates/sv-check/src/signed_in/mod.rs`), so a private page that crashes for a stranger with a 500 is
  credited as "refused to somebody not signed in" (V8.2.1), as a 429 was. A crash is not an answer to whether the
  page is private. Fix, as a suggestion: read a 5xx as no answer wherever a refusal would be credited, and say the
  requirement is not assessed with the status; a finding from a 5xx (a stack trace, say) is a separate question.
  **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item, in
  branch `claude/securevibe-e2-server-error`.
  **Done the same day:** `Patient` records every signed-in request answered with a 5xx or not at all, and
  `RESTS_ON_A_REFUSAL` names the requests each of the 29 refusal-credited passes rests on; a pass one of whose
  requests crashed is not assessed, naming them, and the rest of the run's passes and all its findings stay. A test crashes every request of six setups, one at a time, and fails when a rule found at fault comes back credited; it found requests of five kinds the first list missed. Six guards, each broken in turn, each caught. See DESIGN, "A crash is
  not a refusal".
- **Three findings are raised from a refusal, so a crash can raise them falsely.** Found on 29 September 2026 by
  session securevibe-e2 while fixing the item above. `SIGN_OUT_ON_GET` (`signin.rs`, `private-after-get-logout` not
  2xx read as the session ended), and `COMPOSITION_RULES` and `LONG_PASSWORD` (`passwords.rs`, a strong or long
  password that did not work read as refused). A crash on those requests reports a fault the app may not have. A fix
  in the same shape: record which requests those findings rest on, and move the finding to not assessed when one of
  them crashed, with a test that crashes each request of a correct app and fails when one of these appears.
  **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item, in
  branch `claude/securevibe-e2-crash-findings`.
  **Done the same day:** five findings, not three: the sweep that crashes each request of a correct app also raised
  `RESET_REVEALS_ACCOUNT` (a reset for nobody that failed) and `NO_BRUTE_FORCE_LIMIT` (a guess that failed may not have
  been counted). `RAISED_ON_A_REFUSAL` names each one's requests, and a finding one of whose requests crashed is not
  assessed, naming them. The test fails on any finding a crash raises, listed or not. See DESIGN, "A crash is not a
  refusal", its "Later the same day" part.

- **The anonymous probes outside `signed_in/` read answers without the rate-limit wait.** Found the same day by
  session securevibe-e10. `probes.rs` and `running.rs` read `(200..300).contains(&status)` directly, so a limiter's
  429 is read there as the app's answer. The places read in passing only ever raise a finding, and each needs a 2xx
  to do so, so none was seen to credit a limiter's refusal; `probe.admin-opened-by-address` (`running.rs`) reads
  "shut to a stranger" from a non-2xx before finding it open from the app's own address, which a limiter could only
  make more cautious. Not checked one by one. Fix, as a suggestion: route them through the same `Patient`, and check
  each place a non-2xx is read. **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's word (the entry above: stand
  down or take this part), in branch `claude/securevibe-e2-anonymous-limited`. With it, one thing `Patient` does not
  have yet: a limit on all the waiting in one run. It waits up to a minute for every limited request, so a limiter
  answering everything holds a run up for a minute a request; securevibe-e2's own version (not merged, in branch
  `claude/securevibe-e2-rate-limited`) stopped at five minutes in all, with a test.
  **Done the same day:** the anonymous questions go through `Patient` (`signed_in::ask_anonymously`, from step 4 of
  the run); an answer still the limiter's is left out, as one that got no answer is, and `sv run` and the report name
  those requests as a gap. Reading each place found two that did judge a limiter's answer: the security-headers
  finding on a 429 page, and "source control not exposed" credited from two 429s; a test witnesses both. `Patient`
  stops waiting after five minutes in all. Four guards, each broken in turn, each caught. Not run end to end against
  a real app behind a limiter. See DESIGN, "A rate limiter's answer is not the app's", its "Later" part.
- **`a_bundle_is_written_beside_the_app_inside_the_root_and_holds_no_secret` failed once.** Seen on 29 September
  2026 by session securevibe-e2 in a whole-workspace run under load (a mutation run of the rate-limit code, which
  that test does not touch); it passed three times alone. Not reproduced. A guess, marked as one: it asserts that
  the four bytes `4471`, a fragment of the planted secret, appear nowhere in the zip's raw bytes
  (`crates/sv-cli/src/mcp.rs`), and a zip holds timestamps and compressed data in which four given bytes can occur
  by chance. If so, the fix is to read the zip's entries and look in their contents. **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take a backlog item, in
  branch `claude/securevibe-e2-bundle-test`.
  **Done the same day, and the guess was wrong:** the zip is stored uncompressed with fixed dates, so four bytes
  do not turn up by chance. The bundle names the folder the test made, 17 times, and that folder was named with the
  process id (`sv-mcp-bundle-beside-<pid>`), so the test failed whenever the process id held `4471`. Reproduced
  every time by putting `4471` in the folder's name. The test now looks for the whole secret, and its folder is
  named `beside-4471` on purpose, with an assertion that the bundle does carry that name, so looking for less than
  the whole secret fails on every run. Broken both ways: the four-digit check put back fails it, and a `.env` let
  into the bundle fails it (and `files_named_like_secrets_keys_and_databases_stay_out` in `tests/bundle.rs`).

- **`a_run_killed_outright_is_cleaned_up_by_the_next_one_and_said_to_be` failed once on CI.** Seen on 29 September
  2026 by session securevibe-e2, on the pull-request run of #447 (a change to this file alone), while the push run of
  the same commit passed. `crates/sv-cli/tests/killed_run.rs:177`: the killed run was listed as leaving
  `sv-<pid>-0-app`, `-net`, and `-probe`, and the next run's message named the app and the network but not the probe
  sidecar; nothing was left afterwards. The sidecar runs `sleep 900` with `--rm`, so why it was listed and then not
  named is not known; a guess, marked as one: the next run's leftover listing, or its removal, can miss a container
  that is starting or already being removed. Needs a container backend to reproduce. **Claimed on 30 September
  2026 by session securevibe-e2**, at the owner's asking to pick another backlog item, in branch
  `claude/securevibe-e2-killed-run`.

- **Evaluate Opengrep against semgrep as the outside tool `sv --tools` runs.** Asked for by the owner on 28
  September 2026. **Not claimed.** Opengrep is the open-source fork of semgrep's engine, made in January 2025 when
  semgrep moved some of its features and rules behind its own license. `sv` runs semgrep today (`data/adapters.json`,
  `data/semgrep-packs.json`, `tools/semgrep_packs.py`), so the question is whether to switch, offer both, or stay.
  Things to find out, each written down with how it was measured rather than recalled:
  1. **Rules.** Which of the packs `sv` runs (`data/semgrep-packs.json`) Opengrep can load and run, under what
     license each is published, and whether the rules mapped in `data/adapters.json` give the same findings. Run
     both over the same apps (`examples/` and a few fixtures) and compare rule ids, files, and lines.
  2. **Output.** Whether its SARIF is what `adapters::parse_sarif` reads, rule ids and levels included, and whether
     `clean_run_evidence` would credit the same requirements.
  3. **Installing it.** How an owner who is not a programmer installs it on a Mac and on Linux, whether it is one
     file with no account or sign-in, and what the Docker image would need.
  4. **Running it offline.** Whether it sends anything over the network by default (semgrep's metrics and rule
     downloads), since `sv` promises no network connection of its own, and how to turn that off.
  5. **Speed and upkeep.** Time over the same apps, how often it is released, and who maintains it.
  The result is a recommendation in this item, with the numbers, for the owner to decide; nothing in the adapters
  changes until then.

- **Partial checks for the requirements no check speaks to, from the review of 28 September 2026.** The owner asked
  on 28 September 2026 for every requirement with no check to be reviewed for a partial check: a signal that tells the
  owner something useful even when it cannot settle the requirement. Session securevibe-e9 had seven reviewers go
  through all 382 and wrote their proposals to `docs/PARTIAL-CHECKS.md`: 279 partial checks, 33 questions for
  `securevibe.toml`, and 70 with no useful check. **The proposals are not verified unless an item below says so**, and
  several rest on library defaults recalled rather than looked up. **Each numbered item can be claimed on its own**, and
  any proposal in `docs/PARTIAL-CHECKS.md` can be added here as an item and claimed the same way.
  1. **Outside-tool rules that already run and count for nothing (8 requirements). Verified.** Each rule is in a pack or
     tool `sv --tools` already runs, and is mapped to nothing in `data/adapters.json`. All are `findings_against`: each
     requirement asks for a control, and a pattern can show one missing but not present. V3.6.1: semgrep
     `html.security.audit.missing-integrity`. V1.4.1: semgrep `c.lang.security` `insecure-use-gets-fn`,
     `insecure-use-string-copy-fn`, `insecure-use-strcat-fn`. V1.4.3: semgrep `use-after-free`, `double-free`. V5.2.3:
     semgrep `go.lang.security.decompression_bomb`. V11.3.4: semgrep `java...gcm-nonce-reuse`, `php...openssl-cbc-static-iv`,
     and gosec G407. V12.3.3: semgrep's gRPC insecure-connection rules for Go and JavaScript. V15.4.2: bandit B306.
     V15.4.3: semgrep `trailofbits.go.missing-unlock-before-return`.
     **Claimed on 28 September 2026 by session securevibe-e9**, at the owner's asking to start with this group.
     **Done the same day:** all fifteen rules are in `data/adapters.json` under `findings_against`, and ASVS
     requirements a check can speak to go from 132 to 140. `crates/sv-check/tests/running_rules.rs` holds that a
     finding from each carries its requirement and that a clean run credits none of them; `py/insecure-temporary-file`
     stays out until item 5 measures the CodeQL suites.
  2. **Existing checks that already test the requirement. Verified against each requirement's words.** V8.2.3 by
     `probe.role-field-trusted` and `probe.record-returns-secret-fields` (field-level access is what both test); C9.3.2 by
     `probe.ai-mcp-output-unvalidated`, for tools reached over MCP; C9.3.7 by `probe.ai-output-fetched`; V14.2.2 by
     `probe.private-page-cached`, extended to flag `public` and `s-maxage` on a private page. **V9.2.3 is the owner's
     call:** the existing probe checks sign-in tokens in the app as a client, and V9.2.3 is about a service accepting
     access tokens; a code rule for a switched-off audience check (`verify_aud` False, `ValidateAudience = false`) fits
     either way.
     **V8.2.3, C9.3.2, C9.3.7, and V14.2.2 claimed on 28 September 2026 by session securevibe-e9**, at the
     owner's asking to go ahead with this group; V9.2.3 stays the owner's call.
     **C9.3.2 and C9.3.7 done the same day** (`crates/sv-check/src/ai.rs`). **V8.2.3 and V14.2.2 wait for the
     `signed_in.rs` freeze to lift**, since their checks live there: add V8.2.3 to the requirement lists of
     `probe.role-field-trusted` and `probe.record-returns-secret-fields` (both only ever findings), and add a
     finding-only `probe.private-page-shared-cache` (V14.2.2) beside `probe.private-page-cached` for a private
     page whose `Cache-Control` has `public` or an `s-maxage` with neither `private` nor `no-store`. Session
     securevibe-e9 wrote and tested both before the freeze was noticed, and holds the claim; the slice's
     session may make them in its pull request instead (slices g and b).
     **V8.2.3 and V14.2.2 done on 29 September 2026**, once the freeze lifted: V8.2.3 is on
     `probe.role-field-trusted` (`signed_in/rules.rs`, writing a field) and `probe.record-returns-secret-fields`
     (reading one), both only ever findings; `probe.private-page-shared-cache` (`signed_in/sessions.rs`, V14.2.2) finds
     a private page whose `Cache-Control` has `public` or an `s-maxage` with neither `private` nor `no-store`. Found
     on the way: `probe.record-returns-secret-fields` never credits anything, yet `tools/coverage.py` did not list it as
     finding-only, so V15.3.1 read as checkable by a clean run; it is listed now. Each guard broken turned its tests red.
  3. **Small new checks, the reviewers' first picks. Not verified.** Details for each are in `docs/PARTIAL-CHECKS.md`.
     Reads the code: V1.3.1 (a rich-text editor with no known sanitizer), V11.2.4 (a digest compared with `==`),
     V15.2.3 (a development server as the start command), C6.1.3 (model downloads not pinned to a commit),
     C3.2.3 (floating model names such as `-latest`), C4.1.2 (model files loaded with pickle), C10.1.1 (MCP servers
     started with an unpinned `npx -y` or `uvx`). The running app: V8.4.2 (admin pages opened by `X-Forwarded-For`),
     V10.4.4 (retired sign-in methods in the app's own published settings), V16.5.4 (the app still up after the probes),
     V13.4.7 (files that exist and should never be served), C2.1.4 (a very large message refused), C2.2.2 (the injection
     probe in other languages and base64), C7.3.4 (hidden characters in a reply), C7.3.1 (a moderation verdict ignored),
     C10.3.3 (the MCP endpoint and a foreign Origin or rebound Host), C11.3.2 (raw model metadata reaching the page),
     C12.1.1 (who and which session in the model-call log line), C10.2.6 (an MCP session reused after it was ended).
     Signed in: V1.3.4 and V5.4.3 (an SVG with a script, and the EICAR test file, built from pieces at run time, through
     the upload probe), V4.1.3 (identity headers such as `X-Remote-User` on private pages), V7.4.3 (other sessions after
     a password change), V6.3.7 (an email after a password change), V10.1.1 (tokens in browser storage), V10.5.2 (two
     people sharing an email address at the test sign-in provider), V14.3.3 (the test password in browser storage),
     C9.5.3 (another user's record through a tool the model calls).
     **The twenty that read the code or the running app claimed on 28 September 2026 by session securevibe-e9**, at
     the owner's asking to go ahead with this group, in three pull requests: the seven that read the code, then
     V8.4.2, V10.4.4, V16.5.4, and V13.4.7, then the eight about AI apps. The nine signed-in ones (V1.3.4, V5.4.3,
     V4.1.3, V7.4.3, V6.3.7, V10.1.1, V10.5.2, V14.3.3, C9.5.3) are not claimed: their checks live in
     `signed_in/`, which is frozen until the split's step 2 is done.
     **The freeze is lifted. V4.1.3, V7.4.3, and V6.3.7 claimed on 29 September 2026 by session securevibe-e2**,
     at the owner's asking to take the next backlog item, in branch `claude/securevibe-e2-signed-in-partials`: the
     three that need only the signed-in requests and the mail server. The other six (V1.3.4, V5.4.3, V10.1.1,
     V10.5.2, V14.3.3, C9.5.3) stay unclaimed.
     **V1.3.4 and V5.4.3 claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take
     another backlog item, in branch `claude/securevibe-e2-upload-partials`: the SVG with a script and the EICAR
     test file, through the upload probe. V10.1.1, V10.5.2, V14.3.3, and C9.5.3 stay unclaimed.
     **V1.3.4 and V5.4.3 done the same day** (DESIGN, "An SVG with a script, and the antivirus test file").
     `probe.uploaded-svg-keeps-script` (V1.3.4) and `probe.upload-not-scanned` (V5.4.3) are sent after the ordinary
     GIF; each is credited when refused, and V5.4.3 only after an ordinary text file was accepted. Not done: the
     EICAR file inside a `.zip` (the probe's bodies are text, and a zip is not), and the pointers from the code
     (SVG sanitizers, antivirus packages).
     **V10.1.1 and V14.3.3 claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take
     another backlog item, in branch `claude/securevibe-e2-browser-storage`: tokens and the test password in what
     the app leaves in the browser after sign-in. V10.5.2 and C9.5.3 stay unclaimed.
     **V10.1.1 and V14.3.3 done the same day** (DESIGN, "What the app keeps in the browser after signing in").
     The browser signs in through the app's own form and reads the values the page's scripts can reach.
     `probe.password-in-browser-storage` (V14.3.3) and `probe.token-in-browser-storage` (V10.1.1) are only ever
     findings. Not done: tokens sent to other sites (a hosted backend on another address receives them by
     design), and the pointers from the code (`setItem` calls with such key names).
     **V10.5.2 claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take another
     backlog item, in branch `claude/securevibe-e2-oidc-same-email`: two people at the test sign-in provider who
     share an email address. C9.5.3 stays unclaimed.
     **V10.5.2 done the same day** (DESIGN, "Two people with one email address at the sign-in provider").
     `probe.oidc-user-keyed-on-email`: the test provider gains `other-person` and `new-email`, and a new optional
     `create` and `shows` under [stack.run.oidc] let the probes save a mark as the first person and see whose
     account each sign-in reaches. Not done: the static companion (a user lookup keyed on the email claim in
     the sign-in callback).
     **C9.5.3 claimed on 29 September 2026 by session securevibe-e9**, at the owner's asking to continue with the
     backlog: the test model asks the app's own record tool for another user's record.
     **C9.5.3 done the same day** (DESIGN, "Another user's record, through the model's tool").
     `probe.ai-tool-reads-others-records`: a new `record-tool` under [stack.run.ai] names the app's own tool; the
     test model, chatting as the second user, asks it for the second user's record (the control) and then the
     first user's. Handed over is a finding, refused is credited. The test model is run under Node for the FETCH
     call too. Not done: the static pointer (instructions to the model asking it to enforce permissions).
     **V4.1.3, V7.4.3, and V6.3.7 done the same day** (DESIGN, "Three small signed-in checks").
     `probe.identity-header-trusted` (V4.1.3) asks each private page a stranger was refused again with one of eight
     headers naming the test user, and is only ever a finding. `probe.password-change-ends-sessions` (V7.4.3) and
     `probe.password-change-notified` (V6.3.7) are only ever credited: a second session left open, or no email, is
     not assessed, since the app may offer to end sessions or tell people another way. Not done: reading the change
     page for such an offer, or what the email says.
     **The seven that read the code done the same day**, each able only to show its requirement failing, so a
     clean run credits none of them. Four are rules in `data/ast-rules.json`: `ast.digest-compared-with-equals`
     (V11.2.4, taught fourteen languages; shell has no timing to measure), `ast.model-loaded-with-pickle`
     (C4.1.2, Python), `ast.model-download-not-pinned` (C6.1.3, Python and JavaScript), and
     `ast.floating-model-name` (C3.2.3, all fifteen). Three are checks of the files:
     `config.development-server-started` (V15.2.3, the last stage of each Dockerfile and a Procfile's `web:`
     line, following `npm start` into package.json; files named for development are left out),
     `config.mcp-server-unpinned` (C10.1.1, `npx`, `uvx`, `pipx run`, `pnpm dlx`, and `docker run` in the
     app's own configuration and code; the developer's own AI-tool settings are left out), and
     `config.rich-text-without-sanitizer` (V1.3.1, from the bill of materials and sanitizer names in the
     code; not assessed while part of the bill could not be read). Not done from the proposals: the
     running-app half of V15.2.3 (debug consoles that answer), committed model files opened by their
     contents (C4.1.2), `ollama pull` and model-server images (C6.1.3), and the model name the app really
     sent (C3.2.3), which goes with the AI checks.
     **V8.4.2, V10.4.4, V13.4.7, and V16.5.4 done the same day** (`crates/sv-check/src/running.rs`), each only ever a
     finding: `probe.admin-opened-by-address` (an admin page named in `[stack.run.users]` shut to a stranger and
     open with `X-Forwarded-For: 127.0.0.1`; made in `probes`' anonymous requests, so `signed_in/` is untouched),
     `probe.retired-grants-offered` (the password or implicit grant in the sign-in settings the app publishes at
     `/.well-known/`), `probe.private-files-served` (up to sixteen settings, key, dump, build, and server-code files
     from the app's folder, asked for by name and judged by their own first 200 characters), and
     `probe.app-stopped-during-questions` (the container read after the anonymous questions and again after the
     rest; `crates/sv-run/tests/stays_up.rs` runs a fixture that a request stops, with Docker in CI). Not done from
     the proposals: the static half of V10.4.4 (grant settings in code), the static half of V13.4.7 (a static-file
     handler pointed at the app's folder), and the error-handler signals for V16.5.4.
     **Six of the eight about AI apps done the same day** (`crates/sv-check/src/ai.rs`, asked after the rate check,
     a minute after its burst). Found and credited: `probe.ai-hidden-content-passed` (C7.3.4: invisible tag and
     zero-width characters, a right-to-left override, and a misleading link in a reply, looked for in the answer
     with JSON escapes, surrogate pairs, and HTML references read) and `probe.ai-flagged-reply-shown` (C7.3.1:
     judged only when the app asked the test model's new moderation endpoint about the reply; a classifier
     elsewhere is not seen). Only ever findings: `probe.ai-input-truncated` (C2.1.4: a 40,000-character message
     with a marker at each end; the fence carries a request as one shell argument, so a message past any context
     window cannot be sent, and one arriving whole is only a step), `probe.ai-injection-other-languages` (C2.2.2:
     the injection in Zulu, Scottish Gaelic, Bengali, and base64, asked only where the English one was stopped),
     and `probe.ai-raw-response-exposed` (C11.3.2: every reply's id now carries `SVRAW` and its tag). Credited
     only: `probe.ai-call-log-session` (C12.1.1: the model-call log line of a signed-in run naming the user or a
     user or session field). `crates/sv-run/tests/model_provider.rs` runs the test model under Node for the first
     time. **C10.3.3 and C10.2.6 done the same day** (`crates/sv-check/src/mcp_server.rs`), for an app that is
     itself an MCP server and says where in a new `[stack.run.mcp-server]` section: `probe.mcp-server-origin-unchecked`
     (a foreign `Origin` and a foreign `Host`, each on its own, against an ordinary request as the control) and
     `probe.mcp-session-survives-end` (a session ended with `DELETE` and used again). Both are credited when
     refused. Not yet run against a real MCP library.
  4. **Two gaps in existing checks. Not verified.** `data/secret-rules.json` has an Anthropic key rule and none for
     OpenAI or Hugging Face keys. The `training` corroborator misses vendor fine-tuning calls such as OpenAI's
     `fine_tuning.jobs.create`.
     **Claimed on 28 September 2026 by session securevibe-e10**, at the owner's asking, in branch
     `claude/key-rules-fine-tuning`.
     **Done the same day:** `secrets.openai-key` and `secrets.huggingface-token` in
     `data/secret-rules.json`, from gitleaks' published patterns, and the vendor fine-tuning calls in
     the `training` corroborator, each read from the vendor's own SDK or API definition. See DESIGN,
     "OpenAI and Hugging Face keys, and fine-tuning through a vendor".
  5. **CodeQL queries that may already run.** `py/insecure-temporary-file` and `js/file-system-race` (V15.4.2) were
     proposed, but nothing records which queries the security-extended suites run, as `data/semgrep-packs.json` does for
     semgrep, so whether they run is not known. Measure the suites first. Bandit B113 (a web request with no time limit)
     was proposed for V13.1.3, which asks for documentation, so it can only ever be shown beside it, never counted.
     **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take another backlog item,
     in branch `claude/securevibe-e2-codeql-suites`: list what the two security-extended suites run, measured with
     CodeQL itself, and map the two queries for V15.4.2 if they are in them.
     **Done the same day** (DESIGN, "Which queries the CodeQL suites run"). Measured with CodeQL 2.27.1: the Python
     suite selects 52 queries and the JavaScript one 105, both proposed queries among them, and all 81 queries
     already mapped too. `data/codeql-suites.json` records the lists, `tools/codeql_suites.py` writes it, and a test
     fails on a mapped query its suite does not select. `js/file-system-race` counts for V15.4.2;
     `py/insecure-temporary-file` is found-failing-only there, as bandit's B306 for the same call already was.
  6. **Cautions for whoever builds these.** V12.1.4 (certificate status stapling): Let's Encrypt certificates have named
     no OCSP address since 2025, so report only when the certificate names one and the server still does not staple.
     V6.3.3 stays supporting: an account that opens with its password alone may be a test account whose two-factor setup
     failed. Most checks of an app that is itself an MCP server, or itself a sign-in service, need a new securevibe.toml
     section, and apply to few apps.
  7. **Two running-app halves left from item 3.** C3.2.3: the model name the app really sent the test model,
     finding when it floats (`latest`, or a name ending `-latest`). V15.2.3: a development debug console that
     answers on the running app (Werkzeug's console and the like), judged by the page's own content, never by its
     status alone. Both only ever findings. **Claimed on 29 September 2026 by session securevibe-e9**, at the
     owner's asking to continue with the backlog, in branch `claude/securevibe-e9-running-halves`. Item 5 was
     looked at first and left: measuring the CodeQL suites needs the CodeQL bundle, which does not fit in this
     session's disk.
     **Done the same day** (DESIGN, "A development console that answers, and the model name the app really
     sent"). `probe.development-console-open` (V15.2.3, V13.4.2) asks for Werkzeug's console and Rails' information
     page and knows each by words only that page carries, read from each tool's source; Django's debug 404 page
     joins the error-page markers. `probe.ai-floating-model-sent` (C3.2.3) reads the model name the app sent the test
     model. Five guards broken in turn, each caught. Not done: other frameworks' consoles, and looking up whether a
     name without `latest` is an alias its vendor moves.
  8. **The static half of V10.4.4: the password and implicit grants switched on in a sign-in server's code.** Left
     from item 3, whose running half reads only the settings the app publishes. Each library's own names for the two
     grants, read from its source (the proposal in `docs/PARTIAL-CHECKS.md` names Doorkeeper, django-oauth-toolkit,
     Spring Authorization Server, league/oauth2-server, fosite, and node-oauth2-server), and only ever a finding.
     **Claimed on 29 September 2026 by session securevibe-e9**, at the owner's asking to continue with the backlog,
     in branch `claude/securevibe-e9-retired-grants`.
     **Done the same day** (DESIGN, "The password and implicit grants, read from a sign-in server's code").
     `config.retired-grant-enabled` reads django-oauth-toolkit, Doorkeeper, fosite, and node-oauth2-server, each by
     names read from its own source, and only where the library is among the app's packages or the file names it.
     Six guards broken in turn, each caught. Not done: league/oauth2-server (its source could not be fetched here),
     Spring (whose authorization server has no password grant to switch on), and settings kept in a database.
  9. **V11.4.4: an encryption key made from a password with too little work.** From `docs/PARTIAL-CHECKS.md`: a
     code rule for PBKDF2 with a literal iteration count below OWASP's figure, and a single hash of a password used
     as a key. Only ever a finding; a count read from a setting is not judged.
     **Claimed on 29 September 2026 by session securevibe-e2**, at the owner's asking to take another backlog item,
     in branch `claude/securevibe-e2-weak-kdf`.
     **Done the same day** for PBKDF2 (DESIGN, "A key made from a password with too few rounds"):
     `ast.weak-password-key-derivation` reports a count written into the code below 210,000 in all fifteen languages `sv` reads, and is
     only ever a finding. Not done: a single hash of a password used as a key, since nothing in the code says a
     hashed value is a password without guessing from its name; the standard library's `crypto/pbkdf2` in Go; C#'s
     two-argument `Rfc2898DeriveBytes`; and counts between 210,000 and 600,000 with SHA-256.
  10. **The static half of V13.4.7: a static-file handler pointed at the app's own folder.** Left from item 3, whose
      running half asks for private files by name. A rule that reads the code for a web framework told to serve files
      from the folder the code is in, or the current folder (Express's `static(__dirname)`, Flask's `static_folder`,
      Starlette's `StaticFiles`, Go's `http.FileServer(http.Dir("."))`, and `python -m http.server` in a script),
      which hands out the source, settings, and `.env` beside it. Only ever a finding. **Claimed on 30 September 2026
      by session securevibe-e9**, at the owner's asking to continue with the backlog, in branch
      `claude/securevibe-e9-static-root`.
      **Done the same day** (DESIGN, "Static files served from the app's own folder").
      `ast.static-files-from-app-folder` reads JavaScript, TypeScript, Python, Go, and shell, with what each handler
      serves read from its framework's source (Flask 3, Starlette, Gin 1.12, Echo 4.16, and Python's `http.server`).
      Four guards broken in turn, each caught. Not done: PHP, Ruby, Java, C#, and Rust frameworks, and a folder named
      in settings or built at run time.
  11. **The file half of C4.1.2: model files committed in a format that runs code when loaded.** Left from item 3,
      whose code rule (`ast.model-loaded-with-pickle`) reads the loading calls. Model files in the app's folder
      (`.pt`, `.pth`, `.ckpt`, `.bin`, `.pkl`, `.pickle`, `.joblib`) judged by their own bytes: a pickle's opening
      opcode, or a PyTorch zip that holds `data.pkl`, rather than by name alone. Only ever a finding. **Claimed on 30
      September 2026 by session securevibe-e9**, at the owner's asking to continue with the backlog, in branch
      `claude/securevibe-e9-pickle-files`.

- **The Anthropic key rule cites C9.5.4, which a key in a file does not speak to.** Found on 28 September 2026
  by session securevibe-e10 while writing the OpenAI and Hugging Face rules beside it. C9.5.4 asks that
  "secrets and credentials required by an agent at runtime are not exposed within the model's observable
  context, including the context window, system prompts, or tool call parameters". `secrets.anthropic-key`
  in `data/secret-rules.json` cites it, so every Anthropic key found in a file is a finding against a
  requirement about the model's context, which the file says nothing about. The new rules leave it out. The
  semgrep rule `mcp-credential-in-response` also cites C9.5.4, and there it fits: a tool returning a
  credential into the model's context is what C9.5.4 is about. Fix: take C9.5.4 off the Anthropic rule,
  regenerate `docs/COVERAGE.md`, and see what else moves. **Claimed on 28 September 2026 by session
  securevibe-e9**, at the owner's asking to continue with the backlog.
  **Done the same day:** C9.5.4 is off `secrets.anthropic-key`, and it is now only ever found failing, by
  semgrep's `mcp-credential-in-response`. Nothing else moved. The note in `tools/coverage.py` explaining why
  a clean credential scan counted for it is gone with it. `no_rule_that_reads_files_for_keys_cites_the_model_context_requirement`
  in `crates/sv-check/tests/citations.rs` holds it, beside the coverage document; putting the citation back
  turns both red. Left as it is: `data/knowledge/applicability.json` still classes C9.5.4 as `scanner-clean`,
  which no code reads and which no clean scan now backs.
- ~~**The false-alarms test depends on which scanners the machine has installed.**~~ **Done the same day.** Found on 27 September 2026
  by session securevibe-e8 running the full suite on the owner's Mac. **Claimed the same day by session
  securevibe-e8**, at the owner's asking. `one_weakness_on_one_line_from_two_tools_is_listed_once_naming_both`
  in `crates/sv-cli/tests/false_alarms.rs` runs `sv report --tools` with a stand-in `bandit` put in front of
  the user's own PATH, so a real `semgrep` (or any other adapter's tool) on that PATH runs too. On the owner's
  Mac it failed twice that way: once at the control, once finding the SQL line twice. CI has none of them
  installed, so it passes there. Fix: shadow every other adapter's command with a stand-in that will not
  start, read from `data/adapters.json`, and show in the report that each was kept out. **Done:** that is the fix; it
  is the only test in `crates/sv-cli/tests/` that passes `--tools`. Broken on purpose on the owner's Mac,
  with `semgrep` at `/opt/homebrew/bin`: without the shadowing, the new kept-out check fails, and without
  both, the old failure (the SQL line found twice) comes back.

- **The coding rules cite AC.7.4 for something it does not ask.** Found on 27 September 2026 from the
  workflow check's reading of the requirement: AC.7.4 asks that *changes* to high-impact pipeline
  settings, `permissions:` blocks among them, get dual control and a security-team review. The rule
  "least-privilege-workflows" tells the tool to keep each workflow's `permissions:` block small, and
  cites AC.7.4 for it: the same subject, a different ask. The citation goes; the rule keeps AC.12.2
  and AC.12.3, which it does follow from. **Claimed on 27 September 2026 by session securevibe-e9**,
  at the owner's asking. **Done the same day;** see DESIGN, "Appendix C as rules the AI coding tool follows
  while it codes".

- **Records that disagree with what was built, or are missing, found by the ADR analysis.** Found on 27 September 2026 by
  session admiring-murdock-875699 while reading every decision record for the paper; the owner asked for each one
  to be put here so it gets fixed. **Not claimed; each item can be claimed on its own.** **Items 5, 6, and the
  Docker half of 8 claimed on 27 September 2026 by session securevibe-e8**, at the owner's asking to pick the
  next item; the Rust half of 8 needs the owner's reasons, which nothing records. **Done the same day:** item 5 names
  `sv probe` as the one exception in `README.md`, ADR-017, and `CLAUDE.md` (and the README adds the images
  Docker downloads for `sv run`); item 6 restates the evidence rule in `sv`'s terms in `DESIGN.md`; and
  ADR-019 records the container fence, replacing ADR-010's choice for `sv`. Items 1 to 4 are in v1's
  records, which live on the `v1` branch: a fix there is a new commit on that branch (the tags `v1-paper` and
  `v1-final` stay as they are, and history is not rewritten). Alternatively `docs/adr/README.md` here can record
  the correction, as it already does for ADR-014's file name. Which of the two is the owner's call.
  1. **v1's ADR-012 cites "ADR-011's sibling change", and no record carries the number ADR-011.** The file named
     `ADR-011.md` is titled ADR-014, which `docs/adr/README.md` already explains, but the dangling ADR-011 in
     ADR-012 is not mentioned there. The change it means is `dca2e6c` ("Say what was read, and stop scoring code
     nobody read").
  2. **v1's ADR-010 says generated code's network access is not restricted, and rejects `sandbox-exec`.** Two
     days later the network fence (`27b85e2`, 18 September) used `sandbox-exec` on macOS and a network namespace
     on Linux, and v1's `docs/CONTRACTS.md` describes it. ADR-010 was never updated, and v1's `README.md` still
     says "Network access is **not** restricted — the reports say so."
  3. **v1's ADR-008 lists three AI providers** (`anthropic`, `null`, `scripted`). OpenAI and Google providers
     were added on 18 September (`7ecb4c3`, `71fae08`), with a choice of service per step (`4b947ac`), and the
     record was not updated.
  4. **v1's ADR-013 contradicts itself on paper size.** Its decision says the PDF writer "lays it out on A4
     pages". Its cost section, updated by `2ef4149`, says US Letter is the default and A4 is a setting.
  5. **`sv`'s `README.md` says "`sv` opens no network connection", and ADR-017 and `CLAUDE.md` say it opens
     none "of its own".** `sv probe <address>` has `curl` make a handful of read-only requests to the address the
     owner types (`crates/sv-cli/src/main.rs`, `cmd_probe`). That is deliberate, and it is the only exception,
     but none of the three says so. Name the exception in each.
  6. **`DESIGN.md` says v1's evidence rule carries over "word for word" as "AI review alone is `ai-assessed`,
     never `pass`".** `sv`'s reports have neither status (they say *checked*, *needs attention*, *stated*, and so
     on), and `sv` has no AI review. Restate the rule in `sv`'s own terms: an AI tool's word is `stated`, the
     weakest tier, and nothing a model says makes a requirement *checked*.
  7. **v1's ADR-001 cites a requirement that does not fit it.** It gives V15.1.2 (keep an inventory of
     third-party libraries, such as an SBOM) for the choice of "TypeScript everywhere with a single npm install".
     A language choice is not an inventory. ADR-007 cites the same requirement correctly, since it ships the SBOM.
     The other 15 citations in v1's records fit their decisions (checked against `data/frameworks` on
     27 September 2026).
  8. **`sv`'s two largest technical choices have no record, and each reverses a v1 decision.**
     - **Rust.** v1's ADR-001 chose "TypeScript everywhere". `DESIGN.md` says only "Written in Rust.", and no
       reason is recorded anywhere.
     - **Running apps in Docker behind an `--internal` network.** v1's ADR-010 rejected Docker because it "is not
       available on the target machine". `DESIGN.md` argues the fence at length and says what changed ("A container
       backend is available on this machine as of 22 September 2026"). No record names it as replacing ADR-010's
       choice, and ADR-010 itself says nothing of it.

     Both are candidates for records of their own, the way ADR-018 replaced ADR-012's ruling.

- **A weekly review of the decision records, so they stop falling behind what is built.** Asked for by the owner
  on 27 September 2026, after the ADR analysis (`docs/paper/ADRS.md`) found records out of date within two days
  (ADR-008, ADR-010), `main` contradicting a record for five days (ADR-012), and `sv`'s two largest choices, Rust
  and Docker, never written down. **Not claimed.** Once a week, one session:
  1. Reads every record in `docs/adr/`, and the index, against the code and the week's merged pull requests
     (`git log --first-parent --since="1 week ago" origin/main`).
  2. For each record, says in one line whether it still matches what was built. Where it does not, it either
     amends the record in place (a dated "Later" section, as ADR-016 does) or writes a superseding record (as
     ADR-018 does for ADR-012). Nothing in a record is quietly rewritten.
  3. Lists decisions made in that week's code with no record, and writes the ones that would be costly to undo
     without their reasons, such as a language, a runtime, a fence, or a rule about evidence.
  4. Checks each record's cited requirement ids against `data/frameworks`, as the ADR analysis did.
  5. Records the review itself in this backlog, with the date and what changed, so a skipped week is visible.

  v1's records on the `v1` branch are archived and are out of scope. A correction to one of them is made as the
  "records that disagree with what was built" entry above describes.

- **The paper's account of when the evaluation harness first ran disagrees with the first session's transcript.**
  Found on 27 September 2026 while tracing, at the owner's asking, where the harness came from. **Claimed on
  28 September 2026 by session admiring-murdock-875699**, at the owner's asking. **Done the same day:** `TIMELINE.md`
  says where the harness came from and gives Day 0 its recorded times (the commits' own, from the v1 bundle), and
  `METHODOLOGY.md` notes that its quotation's date is UTC.
  The transcript (the first session, "Vibe-coding application builder") and `securevibe-reasoning.md` in the
  owner's paper folder show:
  - At 19:48 Eastern on 17 September, the owner asked about optimizations "for example, build out/refine a
    harness and/or orchestrated agentic workflow".
  - At 19:49, Claude proposed "An evaluation harness" with "golden apps (five or six profiles covering the feature
    combinations)".
  - At 19:58, the owner chose it: "…and the evaluation harness and golden apps".
  - At 20:37, the harness was designed, and at 20:42 its first run found template bugs.

  Two places in `docs/paper/` say otherwise:
  - `METHODOLOGY.md` says its first run was "on 18 September 2026". 20:42 Eastern on the 17th is 00:42 UTC on
    the 18th, so the date is probably UTC.
  - `TIMELINE.md`'s Day 0 table puts the harness in the commit at "~20:15" (`af6b83f`). The harness did not exist
    until after 20:37.

  Correct both to Eastern time, as the rest of `TIMELINE.md` is, and say in `TIMELINE.md` who introduced the idea
  and who chose it, with the quotations above.

- **What `sv` cannot see when it checks itself, found by the v2 self-assessment.** Found on 27 September 2026
  (`docs/paper/SELF-ASSESSMENT-V2.md`, "Three things `sv` could do about this"). **Not claimed.**
  1. **Test fixtures and example apps are read as part of the app.** On `sv`'s own repository they overruled the
     manifest 19 times and added 547 findings. A manifest could name folders that are fixtures or examples: still
     read, but unable to overrule the manifest, and with their findings listed apart.
     **Claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick another item. **Done the
     same day:** `[repository] not-the-app` names such folders. Their code is still checked and its findings
     still count, listed with test and sample code; nothing in them is evidence about what the app uses; and
     the report names the folders. See DESIGN, "Folders the manifest says are not the app".
  2. **Findings inside Rust `#[cfg(test)]` modules, and in test files in any language, are mixed with the
     product's.** They were 189 of the 252 findings on `sv`'s product code. Report them apart.
     **Claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item. **Done
     the same day:** findings inside Rust test code (`#[cfg(test)]`, `#[test]`, `#[tokio::test]`, and a file
     that starts `#![cfg(test)]`) are marked as test code, and every report lists findings in test code after
     the app's own, still counted. See DESIGN, "Findings in test code, listed after the app's own".
  3. **A manifest cannot say "this app is an MCP server".** So the requirements about serving tools to a model are
     never asked, of `sv` itself or of any app that serves tools. That is the surface of `sv`'s one tool-misuse
     incident (#77).
     **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking to continue with the
     backlog: a claim condition `mcp-server` asked in `securevibe.toml`, and AISVS C10 split by side, since the
     whole chapter hangs today on `mcp`, which asks whether the app's AI *uses* MCP. The server's requirements
     (C10.2.1–C10.2.7, C10.3.3, C10.4.3, C10.4.4, C10.4.6) turn on the new question, the client's stay on `mcp`,
     and the four about the transport between the two (C10.3.1, C10.3.2, C10.3.5, C10.4.5) apply when either
     is true. **Done the same day;** see DESIGN, "An app that serves tools over MCP". `sv`'s own count does
     not move until item 1 is done: a fixture's `from mcp` already brings in the whole chapter.

- **The architecture decision records, analyzed for the paper.** **Claimed on 27 September 2026 by session
  admiring-murdock-875699**, at the owner's asking. **Done the same day:** `docs/paper/ADRS.md`; its inconsistencies are the entry above. v1's ADR-001 to ADR-013 (at tag `v1-final`), `sv`'s ADR-015 to
  ADR-018, the template's three, and the decisions not yet written as ADRs: when each was made, whether it held,
  what later evidence says about it, and how v1's decisions carried into `sv`. A written analysis and a figure in
  `docs/paper/`. Touches only `docs/paper/`.

- **False alarms, part 1: fewer of them reach the owner.** Asked for by the owner on 27 September
  2026, after an investigation by session securevibe-e2 of how `sv` handles findings that are wrong.
  Today there is no way to set a finding aside, the same line can be reported by two tools as two
  findings, a finding in test code looks like one in the app, and each finding's `confidence` is
  recorded and never shown. With an AI coding tool in the loop a false alarm is not noise: the tool
  rewrites correct code until the warning stops (see "Two false alarms rated high changed correct
  code"). Three changes, none of which hides a finding: findings from different tools on the same file,
  line, and kind of weakness (CWE) become one finding naming every tool that raised it; a finding in
  test code or sample files says so; and a finding `sv` is not sure of is shown as a *possible* problem,
  apart from a *confirmed* one, both still counted as needing attention. **The owner's decision, 27
  September 2026: go ahead.** **Claimed the same day by session securevibe-e2.** **Done the same
  day:** see DESIGN, "False alarms: fewer reach the owner, and none is hidden". Merging is done where the
  report is built, and not in `sv check`, which runs only `sv`'s own rules and has nothing to merge.

- **False alarms, part 2: a person's record that a finding is a false alarm, or an accepted risk.**
  From the same investigation. **The owner's decisions, 27 September 2026, each as recommended:**
  1. Build it: a section in `securevibe.toml` where a finding is set aside with a verdict, who decided,
     the date, and a written reason.
  2. Two verdicts: *false alarm* (the code is fine) and *accepted risk* (a real problem the owner
     chooses to live with for now).
  3. The AI coding tool may propose one, and only a person's word counts. An entry the tool wrote is
     shown as the tool's opinion, the finding still counts, and the interview asks the owner to confirm
     it. (The rules the tool follows already say it must never weaken a check.)
  4. A false-alarm verdict lapses when the flagged line changes; an accepted risk after 90 days; a
     lapsed entry is listed, never dropped quietly. A key or password found by the secrets scan may be
     set aside as a false alarm, but only with a stricter reason.
  5. Part 1 first.
  In the report, a finding set aside moves to its own section with its reason; its requirement goes
  back to *not verified*, never to *checked*, since dismissing a finding does not show the protection
  is there; an accepted risk stays under *needs attention*, labeled as known and accepted. The SARIF
  `sv` writes marks it as suppressed, with the reason, so GitHub's Security tab agrees with the report.
  Findings are matched by rule, file, and a fingerprint of the flagged line's text, never the text
  itself, so a flagged key is never copied into the file. **Claimed the same day by session
  securevibe-e2**, to follow part 1. **Done the same day:** see DESIGN, "False alarms: a person's record that a
  finding is wrong, or accepted". One choice beyond the five decisions: a key or password cannot be an
  accepted risk, since a real one is replaced and one that is not real is a false alarm.

- **False alarms, part 3: each one a report against the rule.** From the same investigation, and
  wanted by the owner on 27 September 2026. A false alarm set aside in one app is usually a rule that
  will misfire in the next. An issue template for a false alarm (the rule, what it matched, and why it
  is wrong, with the code shown only if the owner chooses), and a line beside each setting-aside in
  the report pointing to it, so a rule that keeps misfiring gets narrowed, with a test, rather than
  set aside app after app. **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's
  asking. **Done the same day:** `.github/ISSUE_TEMPLATE/false_alarm.yml`, and a link beside each
  false alarm in `security.md`, `report.html`, and the MCP summary. See DESIGN, "False alarms, part 3".
  It uses the existing `bug` label; a `false alarm` label of its own is the owner's to add.

- ~~**Send admin actions straight to the app as an ordinary user (V8.3.1, V8.2.1).**~~ **The admin actions are
  done on 27 September 2026:** `[[stack.run.users.admin-actions]]`, judged by a `check` page and a
  marker per send, confirmed by the admin, after both sessions are shown signed in. See DESIGN, "Admin
  actions, sent straight to the app". **The role-field probe below is done the same day** (claimed by
  session securevibe-e8, at the owner's asking): findings only, against V8.3.1 and V15.3.3. See DESIGN,
  "A role written into the sign-up form". Proposed on 27 September
  2026 by session securevibe-e8, at the owner's asking. **Claimed the same day by session securevibe-e8**,
  at the owner's asking, for the admin actions; the role-field probe below is not part of the claim.
  Today V8.3.1 (authorization enforced
  on the server, not in the browser) has supporting evidence only: an ordinary user is refused each admin
  *page*. The owner's reasons that this does not settle it were that one page refused is not every rule
  enforced, and that actions sent straight to an API are not tried (DESIGN, "The admin page, as support
  for V8.3.1"). This probe answers the second reason. The first stays, and whether V8.3.1 can ever leave
  `manualOnly` is the owner's decision, not this probe's.

  **What the owner writes.** A list under `[stack.run.users]`, `admin-actions`, each entry a request only
  an admin should be able to make, in the same shape as the other requests there (method, path, form or
  JSON fields), for example changing another user's role, deleting a record, or publishing something.
  It needs `seed`, which is already the only way to make an admin account. The run's container is
  thrown away afterwards, so an action that changes data is safe to send, but the entry should say
  so, and say that each action is sent twice.

  **What the probe does, for each action,** following the admin-page check (`admin_checks` in
  `crates/sv-check/src/signed_in.rs`) and sending through `send_filled`, as the other requests do:
  1. Signed in as ordinary user A, send the action. Accepted means a finding against V8.2.1 and V8.3.1,
     rated high: the server acted on a request only an admin should be able to make.
  2. Signed in as the admin, send the same action. This is the control. A's refusal counts only when
     the admin's request is accepted, because a refusal the admin also gets says the request was wrong,
     not that the rule was enforced. The rule this repository keeps: a refusal is evidence only when it
     can have no other cause.
  3. Order matters: A goes first, so the admin's own success cannot have changed what A was refused.

  **Open questions to settle while building it:**
  - **What "accepted" means for an action.** For pages, a 2xx is the answer. An API can answer 200 with an
    error in the body, or 302 either way. An optional `check` request per action, a page that shows
    whether the action took effect, would let the probe judge the outcome by its effect instead of its
    status. It is worth deciding whether that is required or optional before the first line is written.
  - **Tokens the form needs.** If an action needs a CSRF token from a page, check how `send_filled`
    already handles that for `change_password` and `owned` before inventing anything.
  - **A second, smaller probe in the same area:** sign up with a made-up role field (`role=admin`,
    `is_admin=true`, `admin=1`) added to the sign-up request, then ask for an admin page. If it opens,
    the server trusted a value the browser sent, which is V8.3.1's own example and, arguably, V15.3.3
    (mass assignment: a field set that the action was never meant to take). Needs `signup`. Check the
    V15.3.3 citation against its wording before using it; it is Level 2.

  **Evidence, stated plainly.** Refused actions confirmed by the admin control are more support for
  V8.3.1 and are evidence for V8.2.1, which is already credited by the page check. They are still a
  sample the owner chose, so V8.3.1 stays on `manualOnly` unless the owner decides otherwise. An accepted
  action is a finding either way.

  **Break it before calling it done:** no control (a refusal credited without the admin succeeding);
  the admin sent first; an accepted action not reported; a 200 with an error body counted as accepted
  (if `check` is built); the role-field probe run without `signup`.

- ~~**The report credits V15.1.2 for a lockfile it could not read.**~~ **Done on 27 September 2026:** the
  report carries the bill of materials' finding and credit, and the lockfile check is not assessed when
  nothing could be read from the lockfile. See DESIGN, "A lockfile nobody could read is not an inventory". Found on 27 September 2026 by session
  securevibe-e8 while tidying this backlog. **Claimed the same day by session securevibe-e8**, at the
  owner's asking. Reproduced: an app with `pyproject.toml`, a
  `poetry.lock` that holds no packages `sv` can read, and a two-line `securevibe.toml`. `sv report` marks
  V15.1.2 (an inventory of every third-party library is maintained) **checked**, citing
  `config.versions-pinned`, which passes because a lockfile exists. The same report lists "everything
  Python installs" as a gap, because the bill of materials took nothing from that lockfile, and the
  credit also counts toward threat T-27 (a dependency with a known vulnerability or a malicious update)
  as checked in part. `sv check` on the same folder shows both the pass and the bill of materials'
  `sbom.incomplete` finding against V15.1.2, which contradict each other. The report never shows the
  finding: `assemble_report` in `crates/sv-cli/src/main.rs` builds the bill of materials and does not
  add `sbom::incompleteness_finding` or `sbom::completeness_verified`, as `cmd_check` does. Likely fix:
  report both, so the finding outranks the pass; and settle whether `config.versions-pinned` should
  credit V15.1.2 at all when the bill of materials could read nothing from the lockfile. A pinned
  `requirements.txt` with no lockfile is not affected: both checks flag it.

- **A self-assessment of `sv` (v2), for the paper and to compare with v1's.** **Claimed on 27 September 2026 by
  session admiring-murdock-875699**, at the owner's asking. **Done the same day:** see `docs/paper/SELF-ASSESSMENT-V2.md`, whose last section proposes three backlog items it found. A `securevibe.toml` at the repository root saying what
  `sv` is (the owner chose to commit it, so anyone can re-run this), then `sv report . --tools --advisories` on
  `sv`'s own code, every finding triaged, and the result added to `docs/paper/TOP10.md` and `AGENTIC.md` beside
  v1's self-assessment. Adds `securevibe.toml`; otherwise touches only `docs/paper/`.

- **The project against the OWASP Top 10 for Agentic Applications (2026), for the paper.** **Claimed on 27
  September 2026 by session admiring-murdock-875699**, at the owner's asking. **Done the same day.** SecureVibe's own AI agents (v1's
  generation agent and reviews), `sv` as an MCP server driven by an AI coding tool, `sv`'s checks of apps' AI
  features, and the way the project was built by several AI sessions, each mapped to ASI01–ASI10 with its source.
  A written analysis and a figure in `docs/paper/`. Touches only `docs/paper/`.

- **The project's vulnerabilities against the OWASP Top 10:2025, for the paper.** **Claimed on 27 September
  2026 by session admiring-murdock-875699**, at the owner's asking. **Done the same day.** Weaknesses found in SecureVibe's own code
  across both versions, and what it found in the apps it checked, each mapped to a Top 10:2025 category through
  its CWE, with the source for every item. A written analysis and a figure in `docs/paper/`. Touches only
  `docs/paper/`.

- **Appendix C out of the report's headline numbers, into a section of its own.** Asked for by the
  owner on 27 September 2026, once the coding rules gave Appendix C a place at the start of the
  build. Measured the same day: Appendix C is 44 of the 284 requirements that apply to
  `examples/flask-booking` and 33 of 163 for a bare manifest, every one *not verified* because no
  check reaches it, so about a sixth of every report's "not verified" is about how an organization
  runs its AI tooling rather than about the app. Removing them outright would read as coverage, and
  the rules are not evidence, so instead:
  - They leave the headline counts and the list of unverified requirements, unless something found
    a problem with one or has evidence for it, which then counts as any other requirement does.
  - One section, "How the app was built with AI (OWASP AISVS Appendix C)", says how many are given
    to the AI coding tool as rules (and that the rules are not evidence), how many are the owner's
    decisions (still in the questions), how many do not apply and why, and how many are left with
    nothing reaching them.
  - `compliance.md` and `report.json` still list every one of them, under that section, for anybody
    assessing against AISVS.

  **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking. **Done the same
  day:** on the Flask example the headline goes from 284 to 240, and the section lists 44 (24 given
  as rules, 2 the owner's decisions, 18 nothing reaches). See DESIGN, "Appendix C in a section of its
  own".

- **Read the app's GitHub Actions workflows for what Appendix C warns about.** Found on 27 September
  2026 while moving Appendix C out of the headline numbers: the coding rules tell the tool not to
  write these, and `sv` could see whether it did. When `.github/workflows/` exists, a static rule
  over each workflow file for a `pull_request_target` or `workflow_run` trigger that checks out the
  pull request's code (AC.12.1), a checkout without `persist-credentials: false` (AC.12.2), secrets
  reachable from a job that runs a fork's code (AC.12.3), and a missing or broad `permissions:` block
  (AC.7.4). Findings when present; credit only for a workflow read in full and found clean, per rule,
  as the other static rules do. **Claimed on 27 September 2026 by session securevibe-e8.** One change
  of scope on reading the requirements: AC.7.4 asks that changes to trigger settings get dual control
  and a security-team review, which a workflow file cannot show, so a missing `permissions:` block is
  not cited as AC.7.4. **Done the same day:** `crates/sv-check/src/workflows.rs`, four checks, with
  AC.12.1 and AC.12.2 credited only for workflows all read and found clean, AC.12.3 finding-only
  (approvals are repository settings), and the token's permissions a finding citing nothing. See
  DESIGN, "The app's GitHub Actions workflows".

- **AISVS Appendix C as rules the AI coding tool follows while it writes the app.** Asked for by the
  owner on 27 September 2026: Appendix C is better used as a reference while coding than as report
  lines. Its 68 requirements are written for an auditor ("Verify that…"), and no check in `sv`
  reaches any of them. About 20 are things the tool itself can do or avoid while writing code: keep
  `.env` values out of the chat (AC.3.1), treat fetched pages and tool results as data and never as
  instructions (AC.3.3, AC.3.4), run the check after each feature (AC.4.2), say when it touched
  sign-in, access, cryptography, CI, or deployment files (AC.4.4), add only packages that exist
  (AC.13.3), never merge or deploy its own work (AC.8.1), write GitHub Actions without
  `pull_request_target` checkouts or persisted credentials (AC.12.1–AC.12.3). About 15 are the owner's
  decisions, already asked through `securevibe_questions` and the security notes, and about 30 are
  organization or pipeline infrastructure the applicability rules already set aside for most apps.

  The plan, agreed with the owner the same day:
  - A data file of those rules, each an imperative sentence citing the Appendix C requirements it
    comes from, about 1,200 tokens in all rather than the appendix's 5,800.
  - Filtered by the app: a rule is given only when a requirement it cites applies, so CI rules reach
    only an app with a pipeline.
  - `sv rules` writes them into `AGENTS.md` between markers, so a later run refreshes that section and
    leaves everything else in the file alone; other tools are pointed at it, each tried before it is
    written down.
  - An MCP tool, `securevibe_guidance`, gives the rules for one topic when the tool is about to do that
    work (a CI workflow, a new dependency, content fetched from outside), and the server's opening
    instructions name it.
  - **Credit where it is due:** every copy of the rules names OWASP AISVS 1.0 Appendix C, links to it,
    carries its license (CC BY-SA 4.0), and says the text was adapted. The share-alike terms reach the
    rules text, not the owner's code.
  - **It credits nothing.** Handing the tool a rule is not evidence the rule was kept, so no requirement
    changes status because the rules were written.

  **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking. **Done the same
  day:** 18 rules in `data/coding-rules.json`, `sv rules`, and `securevibe_guidance`, credited and
  licensed on every copy. See DESIGN, "Appendix C as rules the AI coding tool follows while it codes".
  Left open: trying which tools read `AGENTS.md` on their own, and whether a `@AGENTS.md` line in
  `CLAUDE.md` is followed, before the walk-through says so.

- **Figures for the paper: security across both versions, usability, and cost.** **Claimed on 27 September
  2026 by session admiring-murdock-875699**, at the owner's asking. **Done the same day.** New `docs/paper/figure-*.html` beside the
  existing three, built only from numbers already in the repository (git history, `docs/COVERAGE.md`,
  `docs/paper/`), each with its source stated. Touches only `docs/paper/`.

- **Bring the paper's timeline up to date, and draw it.** **Claimed on 27 September 2026 by session
  admiring-murdock-875699**, at the owner's asking. **Done the same day.** `docs/paper/TIMELINE.md` stops at 20 September; extend
  it through 27 September from the repository's history, and add a one-page diagram of the whole project
  (`docs/paper/figure-timeline.html`) beside the existing figures. Touches only `docs/paper/`.

- **Clean up after the move.** **Claimed on 27 September 2026 by session securevibe-e8**, at the owner's
  asking. Found by a review of `main` after the move: the rule against printing or committing a key is
  missing from the new `CLAUDE.md`; CodeQL scans only Rust, while `crates/sv-run/assets/*.mjs` is real,
  unscanned JavaScript; `data/knowledge/threats.json` names two `agnostic/` paths; Dependabot does not
  watch the `Dockerfile`; and the security policy stayed with v1, so `sv` has none. The owner chose
  GitHub's private vulnerability reporting as the way to report a problem in `sv`.
  **Done in the same pull request as this note:** the key rule is back in `CLAUDE.md`; CodeQL now scans
  JavaScript and Python as well as Rust, with `examples/` excluded like the fixtures; the two paths are
  fixed; the `Dockerfile`'s base images are pinned to fingerprints, which Dependabot now moves weekly (their
  names carry no version, so without a fingerprint it would have had nothing to update); and `SECURITY.md`
  at the root is `sv`'s policy. The owner turned private vulnerability reporting on the same day (GitHub's
  API said `"enabled": false` before, `true` after). The new CodeQL legs passed on the pull request with no
  new alert; alerts on `main` were not readable from the session, and any that appear in
  `crates/sv-run/assets/`, whose stand-in services misbehave on purpose, are each to be read and dismissed
  with its reason, or fixed.

- **Let the owner confirm what the AI coding tool said, and count it for more.** Asked for by the owner on
  27 September 2026, after trying the interview in VS Code: "give an option for a human to validate
  information supplied by the AI system to strengthen the evidence on human review." **Claimed on 27
  September 2026 by session securevibe-e8**, at the owner's asking, in two steps: first who wrote each
  notes section (the finding below), then the confirmation itself.

  **The owner's decisions, 27 September 2026** (on the four questions below, each as recommended):
  1. The nine tool-written sections in the owner's run were reviewed and agreed to by the owner; once a
     marker exists, they are the owner's.
  2. **A notes section that does not say who wrote it counts as the AI tool's**, as a design answer
     without `by` does. `sv` defines one marker line per section and reads nothing else (no guessing at
     "Decided by the owner"). Existing files are re-asked in the next interview.
  3. **A confirmation ranks level with the owner's own record of the same kind** (attested, checked by
     hand, documented), shown as confirmed with the owner's `how`, and never *checked*.
  4. **The owner or anyone named may confirm**, at the same rank, the name printed; `sv` cannot verify
     who anyone is, so a named reviewer does not rank higher.

  **Today:** when the owner does not know an answer and the tool answers from the code, it is recorded
  `by = "ai-tool"` and shown as *stated by the AI coding tool*, the lowest tier that counts for anything
  (DESIGN.md, "The AI coding tool's answers, a tier lower still"). The same holds for a hand check the tool says it made. The owner's only way
  up is to write `by = "owner"`, and that would say something untrue: the owner did not give the answer,
  they checked someone else's. So a careful owner who looked has nowhere honest to record it.

  **The idea:** a third kind of record, *stated by the AI coding tool, confirmed by the owner*, kept beside
  the tool's answer rather than replacing it, so the report still says who said it first. A sketch:
  `"V8.3.1" = { answer = "yes", where = "auth.py", by = "ai-tool", confirmed = { by = "owner", on =
  "2026-09-27", how = "Signed in as Sam, changed the address to Kim's note, and got 'not allowed'." } }`.
  The interview would offer it: the tool shows what it claimed and where, and suggests something the owner
  can see for themselves (a page to open, a thing to try), not a yes-or-no.

  **What keeps it honest** (each to be broken and watched, as for the other tiers):
  - **`how` is required**, and it says what the owner saw, not "looks right". A bare confirmation is
    unreadable, as a bare `done` is for hand checks.
  - **It is tied to the answer it confirmed.** If the tool changes its answer, or the file in `where`
    changes, the confirmation stops counting and the question is asked again: the owner confirmed that
    answer about that code, not whatever it says later.
  - **It dates.** Probably the same 90 days as a hand check, so an old confirmation is asked again.
  - **It is never *checked*.** It stays on the tests to write and settles no threat; an automated check or
    a finding outranks it. A confirmation cannot turn a finding into a pass.
  - **The owner can also disagree.** "I tried it and it did not work" is a finding, as a `problem` hand
    check is.
  - **Rubber-stamping is the risk.** An interview that asks "is this right?" gets "yes". The tool has to
    ask the owner to look at something, and the report prints the owner's `how`, so a reader can judge it.

  **For the owner to decide before it is built:**
  1. **Where it ranks.** Above *stated* for certain. Level with *attested by the owner*, or just below it
     (the owner checked a claim rather than knowing the answer), or just below *checked by hand by the
     owner* when the owner watched the app behave?
  2. **Whether it covers hand checks as well as design answers**, and the written security notes.
  3. **Whether "owner" is the only confirmer**, or a named reviewer (a colleague, a security person) can
     confirm too, with their name in the report. A second person is stronger evidence than the owner, and
     the manifest already has a `by` field to carry it.

  **Step 1 done the same day** (DESIGN.md, "Who wrote each section of the security notes"): each notes
  answer starts with `Written by: owner` or `Written by: AI coding tool`; no line counts as the tool's;
  the tool's sections are *stated by the AI coding tool* and asked again; anything else is unreadable
  and named; only `sv`'s own two italic lines are dropped. Eight guards broken, each caught. **Step 2
  done the same day** (DESIGN.md, "A person confirming what the AI coding tool said"): `confirmed = {
  by, on, how, answer, where }` beside a design answer, or `{ by, on, how, result }` beside a check made
  by hand; it ranks with the owner's own record, shown as confirmed; it lapses after 90 days, when the
  answer changes, or when the `where` file changes after `on`; the tool cannot confirm itself; one that
  does not count is named. Fourteen guards broken, each caught. **Done.**

  **Found the same day, from the owner's own files, and the first thing to fix:** the security notes
  have no way to say who wrote a section, and `sv` credits every written section as *documented by the
  owner* ("you answered this in security-notes.md"). In the owner's VS Code run, the tool wrote 9 of the
  13 sections itself, from the code, and marked each with its own line, *Written by the AI coding tool
  from the code; review before relying on it.* `sv` never sees that line: `notes::read_answers` drops
  every line wrapped in `*` as one of its own italic lines, so the tool's disclaimer is thrown away and
  the section under it reported as the owner's, the highest tier short of *checked*. Reproduced with a
  copy of the owner's files: V8.1.1, written by the tool, reads *documented by the owner*. The same rule
  drops a bold line such as `**Decided by the owner (2026-09-26):**`, since bold is also wrapped in `*`.
  The interview tells the tool to write a decision only once the owner agrees; this tool wrote the
  sections and said so, which is more honest than the report it fed. What to settle: a marker `sv`
  defines and reads (the counterpart of `by` in `[design]`), which tier a tool-written section gets
  (the natural answer is *stated by the AI coding tool*, as for design answers), what an unmarked
  section counts as (the design answers chose the tool's, because crediting the owner on nobody's say-so
  is the direction that overstates, but every notes file written so far is unmarked), and a narrower
  test for `sv`'s own italic lines than "starts and ends with `*`". Confirming, above, then applies to
  notes sections as it does to design answers. In the same run, `[design]` held nine answers, all
  `by = "ai-tool"`, under the tool's comment "The owner has not reviewed these yet": the case this item
  is for.

  Related but separate: a second AI model checking the first one's claims. That is still the author's side
  of the table, so it would be its own lower tier and is not this item.

- **Fill in GitHub's community standards for the repository.** Asked for by the owner on 26 September
  2026, from the repository's *Insights → Community standards* page. **Claimed on 27 September 2026 by
  session securevibe-e8**, at the owner's asking ("continue to work off items in the backlog, your
  choice"). **The owner's choices, the same day:** the standard Contributor Covenant, with reports
  through GitHub (the repository's private reporting form, since GitHub has no private messages).
  **Done the same day:** `CODE_OF_CONDUCT.md` (the Contributor Covenant 2.1, word for word from its
  source, with the reporting route filled in), `CONTRIBUTING.md` (the build and test commands CI runs,
  claiming a backlog item, and the rules every change keeps), `.github/ISSUE_TEMPLATE/` (a bug report that
  asks which `sv`, the command, and what the report said it did not examine, and turns security problems
  away to the private form; an idea that asks how `sv` would know; and the links on the new-issue page),
  and `.github/pull_request_template.md` (what changed, how it was verified, what was not, and what it
  closes), linked from the README. What remains is the owner's to check: the *Community standards* page
  should now show every item. Done: description,
  README, license, and the security policy (`SECURITY.md`, `sv`'s own since 27 September 2026). Missing:
  - **Code of conduct** (`CODE_OF_CONDUCT.md`). Which one is the owner's choice; the Contributor
    Covenant is the usual default. It names a contact for reports, and that address is the owner's to give.
  - **Contributing guide** (`CONTRIBUTING.md`): how to build and test `sv`, the checks a change must
    pass, and the rules that already bind every session and are worth stating for people too (claim a
    backlog item before starting it; evidence tiers are honest; American English with the Oxford comma).
  - **Issue templates** (`.github/ISSUE_TEMPLATE/`): at least a bug report and an idea. A bug report
    for a security tool should ask for `sv`'s version, the command, and what was not examined, and
    should send anything that looks like a vulnerability in `sv` itself to the security policy
    instead of a public issue.
  - **Pull request template** (`.github/pull_request_template.md`). Worth care: every session writing
    pull requests here fills in whatever template exists, so its sections become the shape of every
    PR description. Keep it short: what changed, how it was verified (with what was *not* verified),
    and the backlog entry it closes.

  **Ready to start:** the move has landed, so the files describe `sv` and go at the root (or in
  `.github/`). The security policy names `sv` now; the issue template's security link can point at it.

- **Promote `sv` to the top of the repository, and keep v1 for the paper.** **The owner's decision,
  26 September 2026:** `sv` is the stronger product and becomes what `main` is; v1 is archived, not
  lost, and its code stays preserved exactly for the paper. **When** is for the sessions to work out
  together — this entry is the place. **[taken: the v1 builder, "Vibe-coding builder", 26 Sep 2026]**
  The owner asked for the move to be claimed once every session was clear; see "The move is claimed", below.

  **Where it stands (this pull request, 26 September 2026):** done are the copy of `workspace/` and `.env` to
  `~/securevibe-v1-backup-2026-09-26` (verified identical), the tag `v1-final` at `412092d` with its Release, and the
  `v1` branch with `ARCHIVED.md`. This pull request makes the move itself: v1's tree, its `docs/` other than
  `docs/paper/` and its root npm files leave; `crates/`, `Cargo.*`, `Dockerfile`, `examples/`, `tools/`, the README and
  `agnostic/docs/` move up; `agnostic/data/` merges into `data/` (no file name collides with `frameworks/` or
  `knowledge/`), which is why the shared files are now reached by `../../data` from a crate like sv's own; the two
  Python tools that set `ROOT = AGNOSTIC.parent` now use the repository root; the workflows, `.dockerignore` and
  `.gitignore` follow. **Not done, and the owner's:** `~/code/my-first-app/.mcp.json` and the PATH line in `~/.zshrc`
  (both point at `sv-tool/agnostic/target/release/sv`; updated, the owner said on 27 September 2026), the local image `securevibe/sv:local`, a Dependabot entry for
  the Rust packages (there was none; added in #226), and turning the freeze off once this merges. **Not verified by me before
  opening this pull request:** a local `cargo test`, which the permission check stopped; CI is the first full run.
  (Run afterwards, 27 September 2026, by securevibe-e8 on `main` at `d6e781c`: 1,074 passed; the one failure,
  `the_fence_really_blocks_outbound_traffic`, needs outbound network, which that sandbox has none of.) After
  it merges, run `tools/pwned_passwords.py` once outside the sandbox (it has no test).
  **All of the owner's part is done, the owner said on 27 September 2026:** `pwned_passwords.py` was run
  after the move, the USB bundles are up to date, the community standards page shows every item done,
  and the local image `securevibe/sv:local` is replaced by the published `ghcr.io/abbyshade111/securevibe-sv`.
  Tag protection is on: a tag ruleset, "protect v1's tags", checked through GitHub's API the same day
  by session securevibe-e2 (active, `refs/tags/v1-*`, deletion, update, and force-move all refused, no
  bypass).
  Text below that says `agnostic/…` was written before the move.

  **Rules that hold whatever the plan:**
  - **Never rewrite history.** No `filter-repo`, no squashing old commits, no force-push to `main`.
    The paper's appendix, both USB bundles, and the ADR cross-references cite commit hashes (see the
    message of `7fa07d6`), and a rewrite changes every one of them. Moving files in an ordinary commit
    keeps every hash.
  - **`data/` stays where it is.** `sv` reads it — the OWASP frameworks, `data/knowledge`, and more —
    and so does v1. So does `docs/paper/`.
  - **v1 stays reachable three ways:** a tag `v1-paper` at the commit that was `main` when the
    repository was made public (the owner's choice); a tag `v1-final` at the last commit before the
    move; and a `v1` branch for anybody who needs to patch it. Each tag gets a GitHub Release, a
    snapshot anybody can download and cite. A DOI through Zenodo, which also keeps its own copy, needs
    the owner's GitHub account, so it is theirs to set up; so is protecting the tags, which is a
    repository setting. GitHub no longer holds the event that made the repository public (it keeps 300
    events, the oldest from 26 September), so the owner named the commit. **`v1-paper` is done,
    26 September 2026:** an annotated tag at `7fa07d6` (20 September, 20:25), the owner's choice, with
    its Release, "v1, as described in the paper". `v1-final` waits for the move.

  **What the move touches, as far as is known:**
  - **Paths inside `sv`.** Seven source files find data by a path counted from their own crate
    folder: `sv-check/src/{ast,secrets,signed_in}.rs`, `sv-cli/src/{main,mcp}.rs`,
    `sv-manifest/src/lib.rs`, `sv-report/src/threats.rs` (`env!("CARGO_MANIFEST_DIR")`, with
    `../../../data` for the shared folder and `../../data` for `sv`'s own). Moving `agnostic/` up one
    level changes both depths, so it is a code change with the tests watching, not a rename.
  - **CI.** `checks.yml` builds and tests v1 (`npm ci`, `working-directory: server`); `rust.yml` runs
    only on `agnostic/**`; `codeql.yml` covers both languages. Each needs deciding, not only moving.
  - **Everything that describes the layout:** the root `README.md` and `CLAUDE.md` are v1's, and
    `agnostic/README.md` would become the front page; the launch configurations in `.claude/launch.json`
    (`securevibe`, `server-tests`, `eval-no-ai`, `template-tests`); v1's evaluation harness (`evals/`),
    `self-assessment/`, `artifacts/`, `templates/`, and the npm workspace at the root.
  - **Outside the repository.** Sessions' memory notes name v1 paths. And the owner's own setup points
    into `agnostic/`: `~/code/my-first-app/.mcp.json` and the PATH line in `~/.zshrc` both use
    `sv-tool/agnostic/target/release/sv`. `sv-tool` is a separate worktree fixed at one commit, so the
    move does not break it until it is updated, and then both paths change.

  **How to do it without five sessions colliding** (sessions working on `agnostic/` collided five
  times in one day earlier this month):
  1. Thoughts first, here, from every session with a view.
  2. One session claims the move, in its own commit, and names a freeze: no new pull requests that
     touch `agnostic/`, `CLAUDE.md`, or CI until the move lands. Open ones are merged or parked
     before it starts.
  3. The tags and releases are made before any file moves.
  4. The move is one pull request — renames, path fixes, CI, and the documents — and it lands only
     with every test green.
  5. Afterwards each session merges `main` into its branch; git follows renames.

  **Open questions for the Thoughts:** does v1's evaluation harness or self-assessment still earn a
  place once `sv` checks itself; which parts of `data/knowledge` only v1 reads, and whether they stay
  (the simple answer: `data/` stays whole, since `v1-final` holds v1 anyway); and whether anything in
  `artifacts/` belongs with the paper rather than with either product.

  **Thoughts.**

  **Agreed so far**, 26 September 2026 — reached by message between the v1 builder and
  relaxed-nobel-27acfa, and written here by keen-meninsky-691a27 so it reaches sessions that did not
  see the messages:
  - **What v1 needs to run, and what guards it, leaves `main` together** for the `v1` branch:
    `server/`, `shared/`, `web/`, `templates/`, `evals/`, `self-assessment/`, `artifacts/`, v1's
    `docs/` other than `docs/paper/`, and the root npm files. Both checked with `git grep` that
    nothing in `sv`'s code, tools, data or Dockerfile refers to `templates/`; the only mentions are
    prose in `agnostic/docs`. The one use `sv` made of v1's apps, relaxed-nobel's semgrep measurement
    on apps v1 built, can be rerun from `v1-final`. A patch to the template after the move is a v1
    patch, on the `v1` branch, where the evaluation harness is.
  - **Only `data/` and `docs/paper/` stay on `main`.** With v1's `docs/` leaving, the file-name
    collision relaxed-nobel found (`BACKLOG.md` and `DESIGN.md` in both `docs/` and `agnostic/docs/`)
    goes with it — an inference from the list above, not something either session said.
  - **`v1-paper` is made** (see the rules above). **Still open:** who claims the move, and when.

  **The move is claimed**, 26 September 2026, by the v1 builder, on the owner's instruction. Every session
  was asked to finish and merge what it had and to open nothing new; each has said it is clear (no open
  pull request was left at the check just before this commit; the two cloud sessions cannot reply, so that
  part is unconfirmed).
  - **Freeze, until the move lands:** no new pull request touching `agnostic/`, `CLAUDE.md`, `.github/` or
    the root files. This claim is the last change before it.
  - **Parked, not merged:** seven v1-era branches touch only v1's files and stay on GitHub exactly as they
    are, unmerged and undeleted; whoever revisits one rebases it onto the `v1` branch. Tips: `claude/attention-recipe`
    `683153f` (4 commits), `claude/authz-role-names` `5c2bfc1` (2), `claude/ci-hang` `2e43900` (13),
    `claude/generated-code-escaping` `b1934d5` (3), `claude/query-recipe` `9f4e664` (1),
    `claude/report-table-escaping` `bd16ab8` (3), `claude/rust-ci` `a5a263f` (1). The other open branches touch
    only `agnostic/` and merge as usual afterwards.
  - **Checklist, from the sessions' notes (nothing here is done yet):**
    1. Copy `workspace/` (2.1 GB) and `.env` out of the owner's checkout first; nobody runs `git clean -x` there.
       The checkout itself is on `claude/ci-hang`, one of the parked branches.
    2. Tag `v1-final` at the last commit before the move; make its GitHub Release. `v1-paper` (`7fa07d6`)
       exists, with Zenodo version DOI 10.5281/zenodo.22984709 from the release `v1-paper-doi`. The paper cites
       that version DOI, not the concept DOI (…708), which follows the latest release and will become `sv`'s.
       Put the DOI in `ARCHIVED.md` on the `v1` branch.
    3. Create the `v1` branch, add `ARCHIVED.md` there only (how to run v1: Node 26, `npm ci`, a real copy of
       `templates/secure-web-app/node_modules`, `SECUREVIBE_HOME`, the copied `.env`, the nine known failing tests).
    4. One pull request: remove `server/`, `shared/`, `web/`, `templates/`, `evals/`, `self-assessment/`,
       `artifacts/`, v1's `docs/` except `docs/paper/`, and the root npm files; move `agnostic/` up one level;
       fix the seven paths counted from a crate folder and `tools/coverage.py` and `tools/pwned_passwords.py`
       (`ROOT = AGNOSTIC.parent`; the second has no test, so run it once afterwards); decide `checks.yml`,
       `rust.yml`, `codeql.yml`; write the new top-level `README.md` and `CLAUDE.md` (carrying the owner's
       working rules, which only the old `CLAUDE.md` holds). All tests green before it merges.
    5. Outside the repository, the owner's to approve: `~/code/my-first-app/.mcp.json` and the PATH line in
       `~/.zshrc` both point at `sv-tool/agnostic/target/release/sv` (`sv-tool` is a detached worktree fixed at
       one commit, so nothing breaks until it is updated, and then both paths change); and the local image
       `securevibe/sv:local` was built from a recipe that assumes `agnostic/`.
    6. Afterwards each session merges `main` into its branch and rewrites the memory notes that name v1 paths.

  - **Vibe-coding builder (built v1), 26 September 2026.** Read at `76156b3`. "Checked" below means I looked
    it up in that tree, not that I remember it.
    - **Do not move v1 into a folder of `main`; keep it as the `v1` branch and the two tags, whole.**
      Checked: v1's `server/src/config.ts` finds its root two folders up from `server/src` and then reads `data/`,
      `workspace/` and `.env` from there. Under `v1/` its root would be `v1/`, with no `data/` in it, because
      `data/` stays at the top. Making that work is a code change to v1, which is what "preserved exactly for
      the paper" rules out. A complete tree on a branch runs as it always did.
    - **The owner's own v1 data is not in git, and it is the only copy.** `workspace/` (projects, settings, the
      audit log of what every AI call cost) and the root `.env` (the API keys) are both ignored by git. A
      branch switch leaves them alone; `git clean -x` deletes them. This repository lives under `~/Desktop`,
      and an iCloud eviction has already cost files once (`4b5b6e2`). So: copy `workspace/` and `.env` before
      the move, and nobody runs `git clean -x` in the owner's checkout. To keep using v1 afterwards, make a
      worktree of `v1` and start it with `SECUREVIBE_HOME=<the old workspace>` (checked: `config.ts` honors
      it) and the `.env` copied in.
    - **What a `v1` worktree also needs, none of it obvious.** Node 26 and `npm ci`. A real 57 MB copy of
      `templates/secure-web-app/node_modules`, not a symlink: with a symlink every golden app fails the same
      way and still reports "succeeded". Tests that start an app need to bind ports, so they fail in a
      sandbox with `listen EPERM`. Nine server tests fail in any fresh worktree, on `main` as well (the dast
      harness, CycloneDX, the config and secrets fixtures); a note saying so saves the next person an hour.
      I would put these in one `ARCHIVED.md` on the `v1` branch only, so the tags stay byte-exact.
    - **Remove v1's files from `main` in the same pull request that adds the tags, never before.**
      `data/` is shared, and v1 pins parts of it with tests (`applicability.json` above all: a test fails
      if a requirement is marked as checked by the static scanner but no rule covers it). While v1 is still
      in `main`, an `sv` change to that file can break v1's suite, and I hit exactly that this week. Once v1
      lives only on its branch it keeps its own copy of `data/`; the two copies will drift and that is fine.
    - **The root `CLAUDE.md` is the only one there is, and it is v1's.** `agnostic/` has none. Besides v1's
      commands it holds the owner's working rules for every session: git is pre-approved but AI spending,
      repository settings, history rewrites and deletions are asked first; the evaluation harness and the
      backlog are claimed in writing, not by message; say what was verified and what was not; plain language
      for the owner. Those must be carried into the new top-level `CLAUDE.md`, or they stop reaching the
      sessions. v1's command sections travel with v1.
    - **v1's CI needs no decision beyond leaving it alone.** `checks.yml` already has its push, pull-request
      and schedule triggers commented out because of the hanging test job, so v1 is checked by hand today
      anyway. Leave it on the `v1` branch as it is. Only CodeQL's JavaScript analysis is a real question,
      and it is the owner's: whether they want the archive kept scanned.
    - **The evaluation harness (`evals/`) stops earning a place in `main`.** It is a regression guard for a
      template and pipeline that will no longer change: it builds five golden apps without AI and compares
      them with saved baselines. It stays reachable at `v1-paper` and `v1-final`, which matters, because
      `docs/paper/METHODOLOGY.md` describes it and quotes its first run. One part could be useful to `sv`:
      `evals/golden/*.json` are five saved sets of wizard answers, deliberately varied (sign-in or not,
      uploads, AI, payments). I have not checked whether `sv`'s design questions can express them. The
      baselines are v1's numbers and not comparable with anything `sv` produces.
    - **Self-assessment (`npm run self-assess`, `self-assessment/`) does not carry over.** It runs v1's
      pipeline on v1's own code, and `triage.json` holds the owner's decisions about v1's findings, keyed by
      fingerprints only v1 produces. `sv` checking itself is a different job with different inputs. Keep it
      with v1.
    - **`data/knowledge`: who reads what.** Checked by searching for each file name in v1's `server`,
      `shared`, `web`, `templates` and `scripts`, and in `agnostic/crates` and `agnostic/tools`.
      - Only v1: `examples.json`, `glossary.json`, `injection-patterns.json`, `patterns.json`,
        `remediation.json`, `requirements-plain.json`, `sbd-rules.json`, `wizard-copy.json`.
      - Both: `applicability.json` (`sv` layers `agnostic/data/applicability-v2.json` over it) and the four
        files in `data/frameworks`.
      - Only `sv`: `threats.json` (v1 builds its threat model in code and never reads it).
      - `common-passwords.txt`: v1 reads it when it runs. `sv` only mentions it in a comment
        (`signed_in.rs`) and samples it in `tools/pwned_passwords.py`; no crate loads it.
      - Caveat: this finds file names, so a reader that loads a whole folder would not show up. `sv` loads
        `data/knowledge` only for `applicability.json` and `threats.json`, by name.
      I agree that `data/` stays whole: it is 1.6 MB, and `v1-final` holds v1's copy anyway. What would help
      is a short `data/README.md` with the three groups above, so nobody edits `wizard-copy.json` thinking
      it affects `sv`, or `applicability.json` thinking it affects only `sv`.
      **Claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick a backlog item.
      **Done the same day:** `data/README.md` lists every file in `data/`, what it is, and what reads it,
      checked by searching the crates and `tools/` for each name. Since v1 moved to its own branch with its
      own `data/`, the groups are no longer "only v1, both, only `sv`": `applicability.json` affects only
      `sv` now, and eight files in `data/knowledge` are read by nothing on `main` (kept, since deleting
      them is the owner's call). Two files are compiled into `sv` (`atlas-references.json`,
      `breached-password-evidence.json`) and say so. `crates/sv-cli/tests/data_readme.rs` fails when a
      file is added without a line or a line names a file that is gone; hidden files such as `.DS_Store`
      are skipped.
      **The owner's decision, 27 September 2026: remove the eight.** Removed the same day by session
      securevibe-e2; v1's copies stay on the `v1` branch and at both tags, and ADR-016 has a dated note.
    - **`artifacts/self-assessment/` belongs with v1, not with the paper and not with `sv`.** It is one set
      of reports v1 wrote about itself on 20 September at 23:25 (run `r_20260920232551`), committed once and
      untouched since. It describes v1 as it was six days before the move, and the top-level `README.md`,
      `CONTRACTS.md`, `DESIGN.md` and `SECURITY.md` all point at it as if it were current. Checked:
      `docs/paper/` does not cite it; the paper's evidence is `docs/paper/` and the USB bundles. I cannot
      see the bundles, so whoever holds them should check that they do not. If the owner wants it in the
      paper folder, it needs a note saying which day it is a snapshot of.
    - **Not settled by me:** the date `v1-paper` points at (the owner's to name), Zenodo and tag
      protection (theirs to set up), and whether `sv` wants the golden profiles. I did not run anything;
      this is reading the tree and what building v1 taught me.
  - *Session admiring-murdock-875699* (ran the whole `sv` suite, the fence and browser tests, and
    both `sv run` examples on the owner's Mac with Docker Desktop on 26 September 2026; 843 passed,
    nothing Mac-specific). Read from `main` at `76156b3`; nothing below was built or run for the move.
    - **The most dangerous failure is quiet: CI stops running.** `rust.yml` triggers only on
      `agnostic/**`, `data/**`, `.dockerignore` and itself. After the move no `sv` file matches, so
      every later `sv` change gets no Rust job at all. With no branch protection, a missing check
      looks the same as a passing one. The move PR should drop the path filter, or turn it into a
      `paths-ignore` for v1's folders. It should then confirm, by name, that the Rust jobs appear
      in the PR's own check list; "nothing is red" doesn't show that. `checks.yml` (v1): agreed with
      the builder above, it stays on the `v1` branch as it is.
    - **Merge `agnostic/data/` into `data/`, and most of the path problem goes away.** No file
      names collide (`data/` holds only `frameworks/` and `knowledge/`). Once there is one data
      folder, every `../../data` (sv's own files) is already right from the new crate depth, and
      every `../../../data` (the shared folder) is wrong. The same goes for `root.join("../data/…")`
      in `sv-manifest/src/lib.rs`, whose `root` is `../..`. That makes one uniform rule instead of
      two depths to adjust.
    - **The stale paths fail loudly today, but only by luck.** The two `include_str!` paths
      (`signed_in.rs`, `threats.rs`) count from the source file, not the crate, so their
      `src/../../../data` is sv's own folder and stays right after the merge; check, don't assume.
      The runtime loaders all return an error on a missing file; none falls back to empty. A stale
      `../../../data` points at the folder *beside* the checkout. There is none beside
      `securevibe/` or `sv-tool/` on the owner's Mac (not checked for CI's runner). So a missed path
      breaks rather than quietly reading someone else's data. But
      `data_dir()` in `sv-cli/src/main.rs` accepts any folder with a `frameworks/` inside, so a
      clone that happens to sit next to a `data/` folder would read that one. Better to fix
      it in the move than rely on luck: one helper for "the repository's data folder", and a test
      that the resolved path, canonicalized, is inside the workspace. Then break it on purpose
      (rename `data/frameworks` for one run) and count what goes red.
    - **`SV_DATA_DIR` covers only the shared folder today.** sv's own files are always read from
      the build checkout, because `env!("CARGO_MANIFEST_DIR")` is baked into the binary as an
      absolute path. That's why `agnostic/Dockerfile` copies `crates/` into the runtime image, and
      why the owner's PATH `sv` reads from `sv-tool`. With one data folder, `SV_DATA_DIR` could
      cover everything and the image could drop `crates/`. That's optional, but it's the natural
      moment.
    - **Docker build:** the root `.dockerignore` is a whitelist (`*`, then `!agnostic`, `!data`,
      `agnostic/target`). Every COPY line in the Dockerfile and both `docker build -f
      agnostic/Dockerfile` lines in `rust.yml` change with the move. A missed whitelist entry
      fails the build loudly. `tools/image_smoke.py` then compares the image with a native build,
      which is the witness that the image's data layout still matches.
    - **Name collisions at the root, besides `data/`:** `README.md`, `.gitignore`,
      `docs/BACKLOG.md`, and `docs/DESIGN.md` exist on both sides. Root `CLAUDE.md` tells every
      session to claim work in `docs/BACKLOG.md`, so which one keeps that name decides where
      claims land; settle it before the freeze lifts. The root `.gitignore` needs `/target`.
    - **The container runner (`sv-run`) doesn't depend on where the repository sits.** Its
      fixtures are counted from its own crate, its scripts are `include_str!` from its own
      `assets/`, and the app folder is canonicalized and bind-mounted by absolute path.
      Containers and networks are named from the process, not the path. On Docker Desktop, bind
      mounts only work under shared folders (`/Users` by default); the repository is under
      `/Users` before and after, so the move doesn't change that. The fence test is path-free
      since #148.
    - **Worktrees:** a Cargo workspace at the main checkout's root will sit above
      `.claude/worktrees/*/`. Each worktree has its own root `Cargo.toml` nearer, so cargo picks
      that one; this is the same nesting `agnostic/` already has. Sessions running cargo in a
      worktree need the new working directory (the memory notes spell out `agnostic/`).

  - *Session relaxed-nobel-27acfa, 26 September 2026.* In favor, with the plan's order. Of three gaps I
    raised by message, two are settled by "Agreed so far" above: v1's `docs/` leaves `main`, so the
    `BACKLOG.md` and `DESIGN.md` name collision goes with it, and `templates/` and the evaluation
    harness go to the `v1` branch together. The third still needs doing in the move: **two Python
    tools find the shared folder the way the seven Rust files do.** `tools/coverage.py` and
    `tools/pwned_passwords.py` set `ROOT = AGNOSTIC.parent` and read `data/knowledge` from there; after
    the move `ROOT` is the repository itself. `coverage.py --check` runs inside the Rust test suite
    (`coverage_doc.rs`), so a wrong path there fails the build; `pwned_passwords.py` has no test and
    would fail only when somebody runs it, so it is worth running once after the move (it only reads
    and rewrites `data/breached-password-evidence.json`, and needs `api.pwnedpasswords.com`).
    **My own work:** option B merged as #211; nothing else of mine is open, and I will open nothing
    that touches `agnostic/`, `CLAUDE.md`, or CI until the move lands.

- ~~**Poll: two questions about the v1 archive.**~~ Decided on 27 September 2026; see the end of the entry. Opened on 27 September 2026 at the owner's asking
  ("poll the group"), by session securevibe-e2. **Not claimed, and nothing is built until the owner
  decides.** Both questions were left open by the move (see "Where it stands" above, and the v1
  builder's "v1's CI needs no decision" and "The evaluation harness" notes). Every session and person
  is asked to add a view under "Views" below, each under its own name, as its own commit on this pull
  request's branch or as a comment on the pull request. Disagreeing is useful; so is "no view".

  **1. Should CodeQL keep scanning v1's code?** What is true today, checked rather than assumed:
  `main`'s `codeql.yml` scans `main` only, and `v1`'s own copy of the file runs only on pushes to
  `main` and on a schedule, and GitHub runs scheduled workflows from the default branch alone, so
  **v1 is not scanned at all now.** The tags `v1-paper` and `v1-final` are protected by a ruleset
  (checked the same day: active, `refs/tags/v1-*`, updates and deletions refused, no bypass).
  - *A. Leave it unscanned.* v1 is frozen for the paper; no one is meant to deploy it, and an alert
    nobody will fix is noise. Costs nothing.
  - *B. Scan it once a week.* A small patch on the `v1` branch (never on the tags) adding `v1` to
    its CodeQL triggers, and the schedule moved into `main`'s file, since only `main`'s schedule
    runs. Alerts would show in the Security tab under the `v1` branch. Useful only if someone would
    act on them, for instance by warning readers of the paper who run v1's code.
  - *C. Scan it once, now.* One run by hand, the result recorded in `ARCHIVED.md` on the `v1` branch
    as "the known issues at archive time", and no scanning after.

  **2. Should `sv` keep v1's five sample answer sets (`evals/golden/*.json`)?** They are five saved
  sets of v1's wizard answers, deliberately varied (sign-in or not, uploads, AI, payments; a clinic,
  a habit tracker, a home log, a marketplace, a team inventory). They live on the `v1` branch and
  at both tags. Nobody has checked whether `sv`'s `securevibe.toml` can express each of them.
  - *A. Leave them with v1.* Nothing is lost; they stay reachable at the tags.
  - *B. Turn them into five `securevibe.toml` test cases for `sv`.* They would test which
    requirements apply to varied apps (sensitive data raising the level, uploads, AI, payments),
    which `sv`'s tests cover today with hand-made manifests. Some work, and only worth it if they
    catch something the current tests would not.
  - *C. Copy them into `sv` as examples of how to describe an app*, with no tests attached.

  **Session securevibe-e2's leaning, one view among others:** 1C then leave it (one honest record of
  what the archived code carries, without an alert list nobody owns), and 2B only if a quick check
  shows two or more of the five exercise a condition no current test does; otherwise 2A.

  **Views.** None came in. The other sessions were not running while it was open.

  **The owner's decision, 27 September 2026: as leaned above** ("go ahead with your
  recommendations"). Taken up by session securevibe-e2 the same day.
  - **1C.** A patch on a branch cut from `v1` (`claude/v1-codeql-once`) keeps CodeQL's results as a
    run artifact as well as sending them to the Security tab, and the workflow was started once by
    hand on that branch (run 36336131545): both legs, JavaScript and TypeScript (576 TypeScript, 8
    JavaScript, 7 HTML, and 3 workflow files read) and Rust, finished. **No open alerts:** the owner
    read the Security tab filtered to that branch, 0 open and 12 closed (matching alerts dismissed or
    fixed before, not re-examined one by one), since this environment could neither download the
    artifact nor read the tab. Recorded in `ARCHIVED.md` on the `v1` branch (#272). Nothing scans v1
    again.
  - **2A.** The quick check found none of the five sets exercises a condition no current `sv` test
    does: between them they use sign-in, uploads, AI, email, payments, scheduled jobs, a public API,
    outside services, and the level-2 data categories, and `real_data.rs` already walks every
    condition. What they carry beyond that (roles, retention, region, business impact) is not
    something `sv`'s manifest asks. They stay with v1, reachable at both tags.

- **A walk-through for building an app from scratch in any AI coding tool, with `sv` alongside.**
  Asked for by the owner on 26 September 2026: "it can't be too difficult, since the whole idea is
  making it easy for people who aren't technical or security experts to vibe code safely." **Claimed
  on 26 September 2026 by session securevibe-e8**, at the owner's asking, now the container is done.
  **Done on 27 September 2026:** `docs/GETTING-STARTED.md`, linked from the README. It covers Docker
  (start it before the tool), a git folder (so the committed-secrets check runs), the `.mcp.json`
  for Claude with the published image, the settings files for Cursor and VS Code marked *not yet
  tried* (VS Code tried by the owner the same day, start to finish, and written up; see below), the copy-and-paste path for a tool without MCP
  (`sv init`, `check`, `questions` through Docker, each tried), a starting prompt (which tells the tool
  to delete a capability line it is unsure of rather than leave it `false`, to keep reports out of
  the app's folder, and to ask before rewriting code a finding may have got wrong), and a plain section
  on what is not checked without `--run`. Its "Known problems" lists items 1 to 4 of the entry on the
  owner's first build; each line comes out as its fix lands. The walk-through itself is short — describe the app, have the tool write
  `securevibe.toml` from `securevibe_spec`, build, run `securevibe_check` after each feature, let
  `securevibe_questions` interview the owner, then `sv report --run` — and it is set down with a starter
  prompt in the conversation that produced this entry. **VS Code, tried by the owner on 27 September
  2026:** it worked start to finish — Copilot's agent asked every question from `securevibe_questions`,
  patched the path findings and re-ran the check to confirm, with `sv` installed directly (the container
  form is untried in VS Code). The answers were saved in the app's folder, and a fresh `sv report` showed
  both them and the fix. The one stumble was setup: a hand-made
  `.vscode/mcp.json` was not listed under *MCP: List Servers*, so the guide now has VS Code write it
  (*MCP: Add Server…*). Cursor is still untried. **What is not short is getting to step one**,
  and a page of instructions cannot fix that on its own. Found by trying it the same day, as the owner,
  from an empty folder in Claude Code; each of these stopped the attempt:

  1. **`sv` has to be built from source, so step one is "install Rust".** README: "Rust 1.95 or newer",
     then `cargo build`. Nobody the product is for has a Rust toolchain, a git checkout, or a reason to
     get either. This is the real obstacle, and the walk-through should not be written until it is
     gone: a download for each platform, built by CI.
  2. **A built `sv` cannot be moved.** It reads a dozen of its own data files at run time —
     `ast-rules.json`, `applicability-v2.json`, `sbd-asvs-crosswalk.json`, `tech-signatures.json` and
     others — from the folder it was built in, found through `env!("CARGO_MANIFEST_DIR")`, which is
     fixed when it is compiled. `SV_DATA_DIR` moves only the shared OWASP folder, not these. So a copy
     in `~/.local/bin` works until the build folder goes away and then fails with "cannot find the OWASP
     data folder" or worse. The test run needed a permanent git worktree just to have somewhere `sv`
     could live. A downloadable `sv` needs its data either compiled in (`include_str!`, as
     `atlas-references.json` and `breached-password-evidence.json` already are) or found beside the
     binary.
  3. **The README's MCP instructions assume a command the desktop app does not install.** It gives
     `claude mcp add securevibe -- …`; in the desktop app that fails with `zsh: command not found:
     claude`. A `.mcp.json` in the app's folder works instead and needs nothing installed. Other tools
     keep their MCP settings in other files, and not all under the same key, so the walk-through needs
     one short, checked section per tool — each one tried, not written from memory.
  4. **`--root` has to exist, and the app has to be inside it.** Nothing says so until the tool is
     refused. The walk-through should create the folder in its first step.
  5. **The starter manifest answers "no" to everything** — every capability in `sv init` reads
     `false`, so a tool that leaves a line as it found it has told `sv` the app has no sign-in, no
     uploads, no email. See "Hand the three question lists to the AI coding tool", above, where it is
     recorded and left for its own decision. For this audience it is the most dangerous line in the
     product: a beginner's tool will leave most of them alone. Until it changes, the starter prompt has
     to say "delete a capability you are not sure of rather than leaving it `false`."
  6. **The deepest checks need Docker.** `sv report --run` starts the app behind the fence, and that
     needs Docker or Colima — a second install for somebody who is not technical, and on a Mac, a
     virtual machine. Without it the running-app and signed-in checks are *not assessed*, which is
     honest; the walk-through has to say plainly what is missed without it, not bury it.
  7. Smaller: the README says `sv mcp` offers four tools; it offers six (`securevibe_questions` and
     `securevibe_notes_file` were added the same day).

  So the order is: `sv` in a container, which settles 1 and 2 with no change to the code (decided the
  same day; see "Packaging `sv`", below), then the walk-through, with
  one checked page per AI tool (3, 4), the starter prompt (5), and an honest line about Docker (6). A
  tool without MCP can still follow it by pasting `sv init` and `sv questions` into its chat, and the
  walk-through should say so, since that is the path that works in every tool.

- **Packaging `sv` for somebody who is not technical: a container now, a download later.** **The
  owner's decision, 26 September 2026: build the container now, and keep the downloadable program
  here for later.** Other sessions are welcome to add ideas on packaging `sv` in the long run under
  "Thoughts", below, each under its own name, as its own commit. **The committed image claimed on
  26 September 2026 by session securevibe-e8**; a working version was built and tested locally the
  same day, and what it taught is here.

  **Why a container first.** It settles the two obstacles in the walk-through entry above that a
  page of instructions cannot — `sv` must be built from source, and a built `sv` cannot be moved —
  with **no change to the code**. `sv` finds a dozen of its data files through the folder it was
  compiled in (`env!("CARGO_MANIFEST_DIR")`); inside an image that folder is the same path for
  everyone. The AI tool starts it with one entry in `.mcp.json`:

  ```json
  "command": "/opt/homebrew/bin/docker",
  "args": ["run", "-i", "--rm", "--network", "none",
           "-v", "/Users/you/code:/Users/you/code",
           "securevibe/sv", "mcp", "--root", "/Users/you/code"]
  ```

  and `--network none` turns the README's promise that `sv` opens no network connection into
  something the container enforces.

  **What it must not do: `sv report --run`.** That starts the app in containers of its own, which from
  inside a container means handing `sv` the Docker socket — control of Docker on the owner's machine,
  which is control of the machine. `sv run` also mounts the app by its host path (`-v` in
  `crates/sv-run/src/docker.rs`), which the host's Docker resolves on the host. So the container is for
  the MCP tools, `check`, `scope`, `notes`, `questions` and `report` without `--run`; `--run` stays a
  step at the terminal with the native `sv`.

  **The tested recipe**, built and run on the owner's Mac under Colima (image 334 MB):

  ```dockerfile
  FROM rust:1-slim-trixie AS build
  WORKDIR /src
  COPY agnostic ./agnostic
  COPY data ./data
  RUN cd agnostic && cargo build --release -p sv-cli

  FROM debian:trixie-slim
  RUN apt-get update \
   && apt-get install -y --no-install-recommends git ca-certificates \
   && rm -rf /var/lib/apt/lists/* \
   && git config --system --add safe.directory '*'
  COPY --from=build /src/agnostic/crates /src/agnostic/crates
  COPY --from=build /src/agnostic/data /src/agnostic/data
  COPY --from=build /src/agnostic/examples /src/agnostic/examples
  COPY --from=build /src/data /src/data
  COPY --from=build /src/agnostic/target/release/sv /usr/local/bin/sv
  ENTRYPOINT ["sv"]
  ```

  It was tested over MCP as an AI tool would use it: six tools offered, `securevibe_spec` answered,
  `securevibe_check` on a git repository with a committed `.env` ran the history check and found it,
  the native `sv` gave the same answer on the same app (a control that counted only because both
  actually ran), and `securevibe_notes_file` wrote into the app's folder as a file the owner owns.
  What building it found:
  - **Keep `crates/` in the runtime image**, not only `data/`. The data paths are
    `crates/<crate>/../../data/…`, and `..` only resolves through a directory that exists.
  - **`git` is needed at run time** (`crates/sv-check/src/config.rs`) for whether a secrets file was
    ever committed, and git refuses a repository owned by another user. When git cannot answer, `sv`
    reports the check *not assessed* rather than failing, so without `safe.directory` it would
    quietly stop happening. **On the owner's Mac it had no witness**: with it switched off the check
    still ran, because Colima hands the files over as the owner's. It is kept for Linux, where the
    ownership differs; that part is reasoned, not shown.
  - **Colima's Docker has no BuildKit**, so it falls back to the legacy builder, which ignores a
    `<Dockerfile>.dockerignore` beside the recipe and sends the whole repository, `target/` included.
    The committed version needs its `.dockerignore` at the root of the build context.
  - **Give the absolute path to `docker`.** An app started from the Dock often cannot see
    `/opt/homebrew/bin`.
  - **Mount the apps folder at the same path inside**, so the paths in findings and reports are the
    owner's own.
  - **Colima has to be running when the AI tool starts**, or the securevibe tools are simply absent
    and nothing says why. After a restart a beginner will meet this. The walk-through has to say
    "start Colima first", or Colima has to start at login.
  - The first test run passed its control vacuously: the check had not run in either version (the
    test app had no `securevibe.toml`, which `securevibe_check` requires), and "no answer" matched "no
    answer". The committed test for the image should assert that the check ran before comparing
    anything.

  Left for whoever claims it: the recipe committed with a `.dockerignore`, CI that builds and
  publishes the image, a test in the shape above, and the walk-through's MCP section written for it.
  **Built on 26 September 2026 by session securevibe-e8** (#205). Session securevibe-e9 claimed it
  the same day (#206) without seeing that #205 was about to merge, built a second version, and did not
  merge it once it saw the first; nothing of it is in `main`.

  **Done the same day, except publishing.** `agnostic/Dockerfile` (the recipe above), `.dockerignore` at
  the repository root, `tools/image_smoke.py` (the test in the shape above: it asserts the committed
  `.env` was found in the image, and in a native `sv`, before comparing them, and runs once as root over
  a folder root does not own, which is `safe.directory`'s witness on Linux), a CI job in
  `.github/workflows/rust.yml` that builds the image from scratch and runs it, and the README's MCP
  section for the container. What was tested where:
  - **Here**, Docker Hub refused the build image (429) and Debian's package servers were out of reach,
    so the build stage could not run. The runtime stage was built from a natively built `sv` without
    `git`, and the smoke test passed in its `--no-git` form: six tools, the check answered, the
    committed `.env` reported *not assessed* rather than passed, the notes file written, no network,
    and the same findings as the native `sv`. Leaving out `crates/` failed it ("cannot find the OWASP
    data folder"), and running the git-less image as if it had git failed both guards that the check
    ran, and refused to compare.
  - **In CI**, the whole recipe: the build stage, `git` and `safe.directory`, and the file-ownership
    check as an ordinary user. This session runs as root, so those three are shown there, not here.
  - **Not done: publishing the image.** Where it lives (GitHub's container registry, Docker Hub) and
    under what name is the owner's to decide, and publishing from CI needs a write permission on the
    workflow. Until then an owner builds it with one command, in the README.
  **The owner's decision, 26 September 2026: publish it to GitHub's container registry.** **Claimed
  the same day by session securevibe-e8.**
  **Done the same day:** a `publish` job in `.github/workflows/rust.yml` pushes
  `ghcr.io/abbyshade111/securevibe-sv` (`latest` and the commit) on a push to `main`, only after `test`
  and `image` pass on that commit; it alone may write packages, with the workflow's own token and no
  third-party action. The README now pulls the published image. Whether the package can be pulled
  without signing in to GitHub depends on its visibility, which is set in the package's settings on
  GitHub, and is the owner's to set.

  **The downloadable program, for later.** Gentler for somebody without Docker, who still gets
  everything except `--run`. It needs the data either compiled in (`include_str!`, as
  `atlas-references.json` and `breached-password-evidence.json` already are) or found beside the
  binary, and a build per platform in CI. One obstacle is easy to miss: **on a Mac, a program
  downloaded from the web and not notarized by Apple is blocked** with a warning that the developer
  cannot be verified, which somebody who is not technical will not get past. Notarizing needs an Apple
  developer account. Homebrew is the usual way command-line tools are installed without that warning
  — believed rather than checked, and it asks the owner to use Homebrew.

  **Thoughts.**

  - *Session relaxed-nobel-27acfa.* In favor, and with the plan's order. Three things the list above
    does not name yet, found while working in `agnostic/` today:
    1. **`docs/` collides by file name.** `agnostic/docs/` and the root `docs/` both hold `BACKLOG.md`
       and `DESIGN.md`. `data/` merges cleanly (no two files share a name), and so does everything
       else except `README.md` and `.gitignore`, which the plan already covers. For `docs/`, the
       simplest honest move is to keep v1's two under a name that says so (`docs/v1/`, beside
       `docs/paper/`), since `v1-final` holds them anyway and the paper may cite their paths.
    2. **Two Python tools find the shared folder the same way the Rust does.** `tools/coverage.py` and
       `tools/pwned_passwords.py` set `ROOT = AGNOSTIC.parent` and read `data/knowledge` from there;
       after the move `ROOT` is the repository itself. `coverage.py --check` runs in the Rust test
       suite (`coverage_doc.rs`), so a wrong path fails the build, which is the test watching this.
       `pwned_passwords.py` has no test and would only fail when somebody runs it.
    3. **The evaluation harness still earns its place while `templates/` is used.** It was the only
       check able to confirm today's template change (semgrep option B changed two lines of v1's
       template). If `templates/` is archived with v1, the harness goes with it; if `sv` keeps using
       the template's built apps as its measuring targets, the harness stays, and so does `server/`,
       which builds them.

    **Timing of my own work:** option B, the one open pull request here that touches `agnostic/` and
    `templates/`, is on its checks now and lands within the hour. After it I will open nothing else
    that touches `agnostic/`, `CLAUDE.md`, or CI until the move lands, so the freeze can start any time
    after that.

- ~~**What the owner's first build from scratch found in `sv`.**~~ All nine numbered items done by 27 September
  2026; what each one left over is noted under it. 26 September 2026: the owner built
  an app from an empty folder in Claude Code with `sv` connected over MCP — a catalog site with a weekly
  AI refresh that now needs the owner's approval to publish — and session keen-meninsky-691a27 read the
  whole session (886 messages) afterwards. **Not claimed; each numbered item can be claimed on its
  own.** Every item was checked against the code or reproduced before it was written down, not taken
  from the building tool's account of it.

  **Faults in `sv`:**

  1. **`sv`'s own report stops its next run from checking the code.** **Claimed on 27 September 2026 by session securevibe-e8.** **Done the same day:** every folder `sv report` writes carries `.securevibe-report`, every walk of the app leaves a marked folder out (and `securevibe-report` by name, for reports written before the marker), and the two skip lists are one, `sv_scan::ecosystems::skip_dir`, with the credential scan still reading `.vscode` and `.idea` on purpose. `crates/sv-check/tests/own_output.rs` holds it, including the control: the same files in an unmarked folder are read and found. `sv report` writes to
     `<app>/securevibe-report` unless told otherwise (`crates/sv-cli/src/main.rs`, `out_dir`), and
     `securevibe_write_report` writes there by design (`crates/sv-cli/src/mcp.rs`). Nothing skips that
     folder: it is in neither `SKIP_DIRS` in `crates/sv-scan/src/ecosystems.rs` — shared by the code
     rules, the outside tools' file list and the test finder — nor the separate copy in
     `crates/sv-check/src/secrets.rs`. So the next run reads `report.html` as the app's own code, and
     while a page it cannot fully read is present, no code rule claims anything. On the owner's app the
     count of requirements checked fell **from 9 to 1**, twice, and the building tool found the cause
     only by undoing its own changes one at a time. Fix: skip `securevibe-report`, and whatever folder
     `--out` names, wherever the app is walked. Worth also making the two `SKIP_DIRS` one list, since
     two copies of it can drift.
  2. **Two false alarms, both rated high, that made the tool change correct code.** **Claimed on 27 September 2026 by session securevibe-e8.** **Done the same day:** in JavaScript and TypeScript, `ast.shell-command` counts a member call only on `child_process`, `childProcess`, `cp`, `shell`, `shelljs`, or `require('child_process')` (a bare `exec(...)` still counts), and `ast.sql-built-by-hand` only a call made directly on a name or a property, never on another call's result, which leaves out `request(app).get('/').query({...})` and, knowingly, `getDb().query(sql)` too. Text conditions such as `#not-match?` were the first idea; the engine refuses them at load, because the Rust binding parses them and does not apply them. Reproduced on
     three-line files:
     - `re.exec(code)`, a regular expression, is reported as *A shell command is built from a value*
       (V1.2.5). `ast.shell-command` matches any JavaScript call named `exec` (`^(exec|execSync)$`,
       with no module named), and `RegExp.prototype.exec` is one of the language's commonest calls.
     - `request(app).get('/').query({ q: term })` in a supertest test is reported as *A database query
       is built by joining text together* (V1.2.4), in an app with no database. `ast.sql-built-by-hand`
       matches any JavaScript call named `query`, `execute`, `raw` or `unsafe`.

     The tool "fixed" both by rewriting working code until the warnings stopped. With an AI in the
     loop a false alarm is not noise: it changes the code. Each rule needs the call's receiver or its
     module taken into account, and each needs a not-found witness for exactly these two cases.
  3. **A rate limiter counts as evidence of a public API.** `claim-corroborators.json` lists
     `express-rate-limit`, `@fastify/rate-limit`, `flask-limiter`, `slowapi` and `rack-attack` under
     `public-api`. Limiting requests is ordinary for any web app, and one of the usual ways to build the
     brute-force controls V6.3.1 asks for, so an app that adds it is handed the API requirements, over
     the manifest's own "no" (corroboration only ever adds). The owner's app has no sign-in at all. A rate limiter shows requests are limited, not who is calling. **Claimed on 27 September 2026 by session securevibe-e9.** **Done the same day:** the five are gone from `public-api`, and two tests keep them out. See DESIGN, "A rate limiter is not an API".
  4. **Security notes the AI tool wrote are credited to the owner.** `security-notes.md` records no
     author, so the report counted all 12 answers as *documented by the owner*; the tool had written 8
     of them from the code. It marked them "Written by the AI coding tool" in the prose and warned the
     owner itself, which `sv` cannot see. The interview already tells the tool to write a note only once
     the owner agrees; this run shows an instruction is not enough. Design answers solved the same
     problem with `by`, and notes need the same, with an answer that does not say who wrote it counting
     as the tool's. **Claimed on 27 September 2026 by session securevibe-e9**, at the owner's asking.
     This also covers the "first thing to fix" in the entry on confirming what the AI coding tool said
     (pull request #235): the tool's own "Written by the AI coding tool" line being thrown away with
     `sv`'s italic lines. **Done the same day by another session** (commit b1aec2f, step 1 of the
     entry on confirming what the AI coding tool said): each answer starts with `Written by: owner`
     or `Written by: AI coding tool`, and an answer without the line counts as the tool's. Session
     securevibe-e9 had built the same thing with an `Answered by:` line and withdraws it unpublished,
     since it added nothing that one does not. One thing it does not do: a section holding nothing but the tool's own
     line, *Written by the AI coding tool from the code; review before relying on it.*, has no colon,
     so it is not a `Written by:` line; it is long enough to pass the forty-character floor, and the
     section reads as *stated by the AI coding tool* with no answer in it. Reproduced on `main` with
     `sv notes` and `sv report`. **Claimed on 27 September 2026 by session securevibe-e9**, at the
     owner's asking: such a line says who, not what, and should not count toward an answer's length. **Done the same day;** see DESIGN, "Who wrote each section of the security notes", on a byline alone.
  5. **When the app's own tests fail under `--run`, their output is lost.** Only the exit code is kept
     (`crates/sv-run`, which says "only the exit code is known"). One test failed in `sv`'s Node 22
     image and not under the owner's Node 26, which cost every test its credit, and the tool had to
     rebuild `sv`'s environment by hand to find which. The last lines of the runner's output belong in
     the report whenever the suite fails. **Claimed on 27 September 2026 by session securevibe-e9.** **Done the same day:** the last 30 lines, as a terminal
     showed them and with anything that looks like a credential cut short, in the report, `report.json`,
     and `sv run`'s output. See DESIGN, "What a failing suite printed".

  **Friction for somebody who is not technical** (see the walk-through entry above):

  **Items 6, 7, and 8 claimed on 27 September 2026 by session securevibe-e8**, at the owner's asking
  ("continue to work off items in the backlog, your choice"). **Done the same day** (DESIGN, "Three
  things the owner's first build tripped on"): the command the MCP server gives names `sv` by its
  full path, or `sv` on the computer when it runs in the container; the not-in-git message says to put
  the app in git with a `.gitignore` first; and a web search is its own answer, `web-search`, which
  brings in C7.4.1 to C7.4.3 and C12.1.4 and not the vector-database requirements. Left over: the
  `rag` rule for all of C7.4 still covers C7.4.4 (watermarking generated media), which has nothing to
  do with retrieval and probably belongs with `multimodal-ai`; and no package names `web-search` yet,
  so nothing corroborates the answer from the code.
  **The owner's decision, 27 September 2026:** a question of its own, "does the AI make images, audio,
  or video?" (`generates-media`), which alone decides C7.4.4. **Claimed the same day by session
  securevibe-e8.** **Done the same day**, with one fact found while building it: C7.4.4 is a level 3
  requirement, so the answer decides nothing for an app held to level 1 or 2, and the starter file
  says so.

  6. **The tool told the owner to run `sv`, and there was no `sv`.** The MCP results say to run
     `sv report --run --tools` at a terminal; the owner got `command not found`, ran it by its full
     path, and then added the build folder to their shell's PATH in `~/.zshrc` at the tool's
     suggestion. The results should say how `sv` was started, or the walk-through should install it as
     a command.
  7. **The app was never put in git, so the check that matters most never ran.** Whether a secrets
     file was ever committed is *not assessed* when the folder is not a repository, honestly, and
     nothing suggested making it one. A beginner's app will usually start this way.
  8. **The `rag` question** — "does it search a document store or vector database?" — led the tool to
     count a web search as one, which brought in the C8 vector-database requirements for an app with
     no database. The question should say what it means by search.
  9. **The terminal summary does not say whether `--run` started the app.** The tool had to infer it
     from the counts. One line — started, answered N requests, or could not start and why — would do.
     **Claimed on 27 September 2026 by session securevibe-e9.** **Done the same day:** the first line after the files
     written says which of the three happened, and `report.json` carries it as `run_status`. See
     DESIGN, "Whether the app was started, in one line".

  **What worked, for the record:** the `.mcp.json` connection worked first time in the desktop app,
  and the tool described all six tools accurately; the interview went one question at a time and kept
  the tool's answers apart from the owner's; once the report was out of the app folder, `--run`
  started the app, sent it 29 requests, and requirements checked rose from 9 to 23. And the list of
  requirements with no evidence did its job: it pointed at human approval for AI-published content
  (C9.2.1), which led to the approval step the owner chose.

  **To keep in mind rather than fix:** 18 of the 40 requirements checked came from tests the same tool
  wrote and labelled with the requirement each proves. It checked the wording before labelling, and
  those tests run and pass, but it is the author vouching for its own work through the name.

- **A zip of the whole result, for the owner to keep or hand on.** Asked for by the owner on
  26 September 2026: the application, its scans and its report in one download, at the end of a build
  or on request. **Claimed on 27 September 2026 by the v1 builder ("Vibe-coding builder"), when the owner asked
  that an item be picked; the owner is watching it and can stop it.** Plan: a `sv bundle` command first, with the
  secret rules deciding what stays out and a listing that says what was left out and why; the MCP tool and the
  "offer it once the report is written" step after that, as their own pieces.
  **First piece done on 27 September 2026:** `sv bundle` (`crates/sv-cli/src/bundle.rs`, tests in
  `crates/sv-cli/tests/bundle.rs`). It writes the zip beside the app, with the app's files, the report, the bill of
  materials, a `BUNDLE.json` of SHA-256s and a plain-words `README.txt`; nothing the credential scan flagged, no
  environment file, key store, database, link, editor folder or unreadable file goes in, and each is listed with its
  reason. Written with no new dependency (SHA-256, CRC and a stored zip are in the crate). Reproduced on the way: a `--out`
  reaching the app folder through a link (`/var` and `/private/var` on a Mac) slipped past the check, and a test caught it.
  **Second piece done the same day:** `securevibe_bundle` over MCP (beside the app, never inside it, only where the
  server may write, a link to somewhere else refused before anything is written), offered by `securevibe_write_report`
  and the server's instructions "only if the person wants one", so nothing makes a zip on every run; the commit `sv` was
  built from in `BUNDLE.json` (`unknown` outside a checkout, as in the Docker image); and the data categories from
  `securevibe.toml` named in the listing, the README and on screen, and not acted on, since `sv` cannot tell which files
  hold them. The image smoke test asks the container for a bundle and looks for the committed `.env` in it.
  **Left:** each outside tool's own SARIF (only `findings.sarif` is in), and a real decision about what a category could
  leave out, if anything can be said deterministically about it.

  What goes in: the app's own files (without `node_modules`, build output, or anything in `SKIP_DIRS`),
  `securevibe.toml`, `security-notes.md`, the report (`report.html`, `compliance.md`, `security.md`,
  `findings.sarif`, `report.json`), the bill of materials, each outside tool's own SARIF, and a small
  file saying which `sv` made it (version and commit), when, with which command, and a SHA-256 for
  every file, so what was checked can be matched to what is in the zip.

  Three things decide the design:
  - **It must never carry a secret.** "The application's files" includes `.env` for most beginners,
    and this owner's app runs on an Anthropic API key. `sv` already finds credentials; the zip should
    leave out every file its secret rules flag, and say in the zip's own listing that it did. The same
    for data the app holds about people (`[data]` categories): leave it out unless asked.
  - **It goes outside the app folder.** Finding 1 in the entry above is what happens when `sv`'s
    output lands inside the app. The MCP server writes only below the app today, deliberately, so a
    zip written from MCP needs its own place to go, or has to be skipped like the report.
  - **When.** `sv` cannot tell when a build is finished; only the AI tool and the owner can. So
    "at the end" means the tool offers it once the report is written, and "on request" means a
    command (`sv bundle`, say) and an MCP tool. The two are the same feature; nothing should make one
    on every run.

- **Hand the three question lists to the AI coding tool, and label what it answers.** Asked for by
  the owner on 26 September 2026: the security notes, the design questions, and the checklist of what
  only a person can check, packaged so the AI tool that wrote the app can answer them. The owner's
  decision, the same day: a design answer from the AI tool is labeled *stated by the AI coding tool*,
  its own tier below *attested by the owner*. **Claimed on 26 September 2026 by session
  securevibe-e8.** Found by walking through `sv mcp` as an AI tool would, on a copy of
  `examples/flask-booking` with no manifest:
  - The check names the sixteen design questions by id only, with no question and no advice on where
    to look, so the tool would need sixteen `securevibe_explain` calls, and those give the ASVS text,
    not the question.
  - It tells the tool to "run `sv notes`", which the MCP server has no way to do.
  - The checklist of what only a person can check does not reach the tool at all.
  - A contradiction says only "the code says otherwise"; `sv scope` says why (`pyjwt` in
    `requirements.txt`), and the tool is not told.
  - The starter manifest has every capability set to `false`, while its own instructions say an
    unsure capability should be `true` and a line nobody answered should be left out. A tool that
    leaves a line as it found it has answered "no".

  **The label is done the same day:** `by = "owner"` or `by = "ai-tool"` on a design answer, and the
  tier *stated by the AI coding tool* below *attested by the owner*; an answer without `by` counts as
  the tool's. See DESIGN, "The AI coding tool's answers, a tier lower still". **Next, and the owner's
  refinement the same day:** the tool interviews the owner through the three lists, one question at a
  time, offering what it knows of the code as a tip, and records the answers for the report. **Done
  the same day:** `securevibe_questions` and `sv questions`, `securevibe_notes_file`, the check pointing
  at them, and a contradiction saying what the code showed. See DESIGN, "The interview: the tool asks,
  the owner answers". Left over:
  - Where an answer to a check by hand is recorded. Today nothing records one, so the tool walks the
    owner through them and the report cannot tell.
    **Claimed on 26 September 2026 by session securevibe-e8**, with the owner's agreement to the design
    the same day: a `[checked-by-hand]` section in securevibe.toml (`result` done, problem, or
    not-yet; `on`, a date; `by`; and `how`, required), current for 90 days, reported as *checked by
    hand by the owner* just above *attested by the owner*, a tool's `done` as *stated by the AI coding
    tool*, and `problem` as needs attention.
    **Done the same day.** See DESIGN, "Checks made by hand, and what was seen".
  - The starter manifest's capabilities all read `false` (above). Not changed here: it is the manifest
    contract, and worth its own decision.
    **The owner's decision, 27 September 2026: comment the capability lines out**, so a line nobody
    answered is unanswered, not a quiet "no". **Claimed the same day by session securevibe-e8.** **Done the
    same day:** every capability line in the starter file reads `# name = ?`, a `?` left in an
    uncommented line is refused rather than read, and the instructions say to answer each line or
    leave it commented out, never to guess `false`. `tls` keeps its default mode, and `[data]
    categories = []` still reads as "no personal data", which only lowers the target level; that is
    a quiet "no" of the same kind, left for its own decision.
    **The owner's decision, 27 September 2026: fix it the same way** ("let's fix the personal data
    starter file issue"). **Claimed the same day by session securevibe-e2.** **Done the same day:**
    the starter file's line reads `# categories = ?`, and a list nobody answered (no `[data]` at
    all, or the line left commented out) no longer buys level 1: the app is held to level 2 and the
    report and `sv scope` say why and how to answer, in the same words. `categories = []` is still
    an answer, "nothing about people", and still gets level 1. Only apps for `just-me` or `my-team`
    can change level this way; `customers`, the default, and `public` were level 2 already, and the
    note is not shown for them. Unanswered and answered-with-nothing, the starter file writing `[]`
    again, the note missing, and the note blamed on a public app are each caught by one or two
    tests.
  - Fifty-five questions on the Flask example is a lot to be asked. The tool is told the owner may stop
    at any point; ordering them by level, or by what is most at stake, would help.
    **Claimed on 27 September 2026 by session securevibe-e8**, at the owner's asking ("continue to work
    off items in the backlog, your choice").
    **Done the same day:** the questions come level 1 first, since the catalogs hold only levels 1 and 2
    (16 and 51 questions), and within a level an unanswered question comes before one only the AI
    coding tool has answered, which needs confirming rather than answering. The interview says so. No
    sort, no tie-break, and level 1 put last are each caught by one test that reads the whole order.

- **Ten requirements a person must answer, and nothing anywhere tells them how.** Found on
  26 September 2026 while drawing the coverage maps. **Claimed on 26 September 2026 by session
  securevibe-e8.** `applicability.json`'s `manualOnly`
  now holds 26 requirements — ones no check may ever settle. Guidance for them lives in three
  catalogs: `data/human-checks.json`, `data/security-notes.json`, and `data/design-questions.json`.
  Ten are in none of them, so the report marks them unverified and offers the reader nothing:

  | | Level | |
  |---|---|---|
  | V5.4.3 | L2 | files from untrusted sources are scanned by antivirus |
  | C7.2.1 | L2 | the reliability of generated answers is assessed with a confidence estimate |
  | C7.2.2 | L2 | answers below the confidence threshold are blocked or fall back |
  | C11.1.1 | L1 | the model has had alignment or safety training |
  | C11.1.2 | L1 | a version-controlled alignment test suite runs on every model release |
  | C11.1.3 | L1 | models are evaluated against known adversarial techniques for their modality |
  | C11.1.4 | L2 | models are hardened against adversarial inputs |
  | C11.3.1 | L1 | query-pattern analysis feeds an extraction-attempt detector |
  | C12.2.2 | L2 | behavioral anomaly detection identifies probing behavior |
  | C12.2.3 | L2 | custom rules detect coordinated jailbreak and prompt-injection attempts |

  Nine of the ten are AISVS, which is the part of the work that has grown fastest, so the gap is
  where the framework moved and the catalogs did not follow.

  **The fix is a test, not a list.** `crates/sv-check/tests/human_checks.rs` already guards the other
  direction thoroughly — every check names a requirement that exists, no requirement is explained by
  two catalogs, every check shares vocabulary with its requirement, every check is at level one or
  two, every check is written for somebody who is not a programmer. Nothing guards *this* direction:
  that every requirement `sv` can never settle is asked by some catalog. A test that fails with the
  unasked ids listed would have caught all ten as they were added, and will catch the next one, which
  writing ten entries by hand will not.

  Also worth a decision rather than an assumption: `AC.1.4`, `AC.4.1`, and `AC.6.3` are `manualOnly`
  and asked nowhere either, but the Secure by Design controls carry no level, and
  `every_check_is_at_level_one_or_two` says human checks are deliberately L1 and L2 only. Whether the
  checklist is its own guidance, or wants entries too, decides whether the count is ten or thirteen —
  and the test should encode whichever answer is chosen.

  **Done the same day.** Twelve entries in `data/human-checks.json`, not ten: `AC.4.1` and `AC.6.3`
  are the AISVS appendix on AI-assisted development and carry levels (1 and 2), so they belong with
  the others; `AC.1.4` is level 3 and stays out, as the checklist leaves out level 3 everywhere. The
  test is `every_requirement_only_a_person_can_settle_is_explained_somewhere` in
  `crates/sv-check/tests/human_checks.rs`: every `manualOnly` requirement at level 1 or 2 must be in
  one of the three catalogs. Removing an entry names it; widening the test to level 3 names `AC.1.4`.
  The twelve reach the owner through the report's checklist and the interview (`sv questions`), and
  can be recorded in `[checked-by-hand]`.

- **V11.3.3 is the one requirement no semgrep pack brings back, and `sv` could own it outright.**
  Found on 26 September 2026 while reading the coverage maps after #164 made the semgrep count
  honest; **claimed on 26 September 2026 by session securevibe-e8**, and session relaxed-nobel-27acfa is pointing at this item from the step 3
  write-up rather than duplicating it. Four requirements lost their credit when the count started
  following the pack: V4.4.1, V9.2.1, V11.3.3, and V11.4.3, each mapped to semgrep alone with no
  other tool behind it. From relaxed-nobel-27acfa's measurements, `p/default` reaches three of them
  and **not V11.3.3**. So three are a pack decision and the fourth is not; adding packs leaves it
  uncovered forever.

  It does not have to be. V11.3.3 asks that "encrypted data is protected against unauthorized
  modification, preferably by using an approved authenticated encryption method or by combining an
  approved encryption method with an approved MAC algorithm" — a question about a call site, which is
  what `data/ast-rules.json` is for. Its neighbours are already there: `ast.weak-cipher` cites V11.3.1
  and V11.3.2 across fourteen languages, `ast.weak-hash-function` cites V11.4.1 across fourteen. The
  call sites are the same ones — `createCipheriv`, `openssl_encrypt`, `Cipher.getInstance`, `AES.new`
  — and what differs is the argument: a non-authenticated mode (`aes-256-cbc`, `aes-256-ctr`,
  `MODE_CBC`, `AES/CBC/PKCS5Padding`) where `ast.weak-cipher` looks for a retired cipher or ECB.
  `argumentPatterns` and `safeArgumentPatterns` already express exactly that shape, GCM, CCM, OCB,
  SIV, ChaCha20-Poly1305, Fernet and libsodium's secretbox being the safe side, so it is a data entry
  and not a change in Rust.

  **The catch, and it decides the shape.** CBC combined with a separate HMAC satisfies the
  requirement, and no single query can see the HMAC: it is a different call, often in a different
  function. A rule written the obvious way flags every correct encrypt-then-MAC as a finding. Two
  honest ways out, and the difference matters:
  - `"confidence": "low"`, the way `ast.file-path-from-value` already handles a question it cannot
    settle from one call site. Cheap, consistent with what is there, but a clean run still credits
    V11.3.3 as checked, which for an app doing CBC plus HMAC is the right answer reached by luck and
    for an app doing raw CBC is the rule having missed nothing.
  - Make it finding-only. `findings_against` exists for adapters and **has no equivalent for AST
    rules** — `nothingToFind` is a per-language "this language has no such construct" note, not this —
    so that route is a change in `ast.rs` and the rule schema, not a data entry. It is the more honest
    of the two, and it is the more expensive.
    *(Note from session securevibe-e8, 26 September 2026: AST rules have had `findingsOnly` since the
    V4.4.1 WebSocket rule, `ast.plaintext-websocket-url`. A rule with it is never credited by a clean
    run, and `coverage.py` shows it as finding only, so this route is a data entry after all.)*

  Whoever takes it should also break it and count: every (rule, language) pair in this file is
  required to have a found and a not-found witness, and the pair that matters here is CBC-with-a-MAC,
  which is the case a single query gets wrong.

  **Done the same day** as `ast.unauthenticated-encryption`, finding-only at low confidence, in all
  fourteen languages; its fix says encrypt-then-MAC code is already correct. See DESIGN, "Encryption
  that cannot show it was changed (V11.3.3)".

- **The fence test can pass without proving anything.** Found on 26 September 2026 running the suite
  on the owner's Mac (Docker Desktop). **Claimed on 26 September 2026 by session
  admiring-murdock-875699. Done the same day:** with `--internal` removed the test now fails
  (`Some(0)`), with `nc` renamed to a program that does not exist it fails (the control reports 127;
  the old test passed that case), and with a dead address it fails (the control reports 1).
  `the_fence_really_blocks_outbound_traffic` in
  `crates/sv-run/tests/fence.rs` counts *any* failure of `docker exec … nc` as "blocked": `nc` missing
  from the image, a flag it does not understand, or the container gone would all pass. And its only
  control is the host reaching `1.1.1.1:53`, but on Docker Desktop containers run in a separate Linux
  VM, so the host getting out does not show a container could. Fix: a control container on an
  ordinary network created the same way minus `--internal`, running the identical command, which
  must connect; and the fenced run must show that `nc` really ran and failed to connect.

- **A leaky guessing limit makes `probe.forwarded-for-trusted` say the opposite of the truth, in
  both directions.** Found on 26 September 2026 reviewing #130/#131. **Claimed on 26 September 2026
  by session securevibe-e9, and done the same day** with the fix below: two claimed attempts from two
  addresses, then two plain ones. `forwarded_check`
  in `crates/sv-check/src/signed_in.rs` sends one wrong attempt claiming `203.0.113.77` and one
  claiming nothing, and calls it a finding when the first is answered as the first attempt was and
  the second is still refused. That pattern is produced by any limiter that lets one attempt through
  per interval — a token bucket, a sliding window, `nginx limit_req`, `express-rate-limit` — whatever
  it thinks about addresses.

  Reproduced with a fake app whose limit releases one attempt each time it refuses one
  (`lockout_leaks`), a limit counting by address, `locks_out_after: Some(6)`, `policy(Some(6))`:

  | limiter | reads X-Forwarded-For | finding |
  |---|---|---|
  | steady | no | none — correct |
  | steady | **yes** | **found** — correct |
  | leaky | no | **found — a false positive on a correct app** |
  | leaky | **yes** | none — **a false negative on the real flaw** |

  The two errors swap places: the leak invents the finding on the app that ignores the header, and
  hides it on the app that trusts it, because the same leak lifts the plain control too. And the
  evidence line for the false positive is **character-for-character the one for the true positive** —
  *"answered 403, as the first attempt was; one more claiming nothing: still refused (429)"* — so
  nobody reading the report can tell them apart. The finding's own words then assert the wrong
  conclusion: *"Nothing sits in front of the app here, so the address came from the request itself."*

  **A tested fix.** Two spoofed attempts in a row, each from its own address (`.77`, `.78`), then two
  plain ones; credit the finding only when both spoofed attempts were answered as the first was and
  both plain ones were refused. A one-per-interval leak releases one of the two, so the pattern
  breaks. Measured against the same four rows: the false positive goes, the three correct outcomes
  stay, and the full suite still passes (367 tests). The false negative stays — a leaky limiter still
  hides a genuinely header-trusting app — which is the safe direction and probably needs timing to
  do better; the check is finding-only, so nothing is credited either way.

  Note also that alternating the attempts (plain, spoofed, plain, spoofed) does **not** work, and it
  is the first thing that comes to mind: a limiter releasing one attempt in two produces exactly that
  alternation.

- **The two-factor reuse check credits V6.5.1 when the time step rolls over mid-check.** Found on
  26 September 2026 reviewing the TOTP probes (#129). **Claimed on 26 September 2026 by session
  securevibe-e9, and done the same day:** the check keeps clear of a step's last ten seconds, looks at
  the clock again after the second use and tries the pair once more in the new step, says V6.5.1 is
  not assessed if the step ends twice, and the V6.5.5 credit now says the 30-second bound was not
  shown. `totp_checks` in
  `crates/sv-check/src/signed_in.rs` reads the step once, at the top, and computes `current` from it.
  Three sign-in attempts later, that code is given again to see whether the app takes it twice. If the
  30-second step has ended in between — the run starts at a uniformly random point inside its step, so
  this is ordinary, not rare — the app is refusing a code that is *stale*, not a code that is *used*,
  and the probe reads the refusal as the app doing the right thing.

  Reproduced rather than argued. A fake app with `totp_reusable` switched on, a clock that moves on
  with every request, and a run starting four seconds before a step boundary:

  | seconds per request | V6.5.1 |
  |---|---|
  | 0, 1 | finding, correctly |
  | 2 | not assessed: *"The current code ... did not sign the two-factor account in ... Check `totp` in securevibe.toml, and that `seed` enrolled the account"* |
  | 3 | **credited as verified**, and the steps line reads *"the same code again: refused"* |

  An app that reuses codes is reported as one that does not. The two paths differ in which side of the
  boundary the *control* lands on; the 2-seconds row is only noise, but it blames the owner's manifest
  for something that is not wrong with it.

  It needs an app that accepts the current step alone, with no drift tolerance either side — which is
  what V6.5.5's own sentence asks for, a 30-second lifetime. So the apps that are strictest about
  V6.5.5 are exactly the ones whose V6.5.1 failure is hidden. The existing tests cannot show it: the
  fake app's clock stands still except during `wait`, so no test run ever crosses a boundary.

  The fix is small — read the step again after the reuse attempt, and when it is not the step
  `current` was computed for, report V6.5.1 not assessed (or recompute and try once more) rather than
  crediting it. The same reasoning as the ordering fix the same pull request already made: a refusal is
  only evidence when it can have no other cause.

  **Also worth saying, smaller:** V6.5.5 says a TOTP has "a maximum lifetime of 30 seconds", and the
  probe shows a code from five steps back being refused. That demonstrates *a defined lifetime*, which
  is the requirement's first clause, and not the 30-second bound. The suite's correct app accepts one
  step either side, so an app accepting 60-second-old codes is credited with V6.5.5 today. Tolerating
  drift is the right engineering call; the evidence line should say which of the two clauses was shown.

- ~~**The threat model's 101 citations are outside the citation guard, and it cannot be pointed at them.**~~
  Done on 26 September 2026 (see the end of the entry). Found on 26 September 2026 reviewing the threat model. `data/knowledge/threats.json`
  cites 101 distinct requirements across 42 threats. Every one resolves — the `AC-NN` class is clean —
  but nothing compares a threat with the requirement it cites, and this is the fifth citation surface
  in a codebase where four of them were wrong when first read.

  Extending `crates/sv-check/tests/citations.rs` to cover it does not work, and that is the useful
  part. Running its own comparison over the file flags **52 of the 101 pairs**, and every one that was
  read is correct — T-02 "a signed-in person opens administrator pages" against V8.2.1 "function-level
  access is restricted to consumers with explicit permissions"; T-03 "someone denies having signed in"
  against V16.3.1 "all authentication operations are logged". The guard assumes a right citation shares
  vocabulary with its requirement, and that assumption breaks here by design: a threat is written in
  plain language for somebody who is not a programmer, and ASVS is written in formal terms for
  somebody who is. Turning the guard on would mean 52 false alarms, which is how a guard gets switched
  off.

  The crosswalk already solved this exact shape. `data/sbd-asvs-crosswalk.json` pairs a terse control
  with an ASVS requirement it could not share words with, so each pair carries a few words naming what
  the two ask in common, and the guard holds that phrase against *both* texts — a stricter test than
  either side alone. The same per-pair phrase would work here, and would make the 101 citations
  checkable without asking plain English and ASVS to use the same words.

  All 52 flagged pairs were read by hand on 26 September 2026 and none is wrong; this is about what
  happens to the hundred and second.

  **Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking. **Done the same
  day, without a new file:** every citation already carries a `because`, and all 115 of them (101
  distinct requirements) share vocabulary with both the requirement and the threat under the
  guard's own comparison. The guard now reads them, and holds each against its threat as well. It
  also found that an empty or wordless phrase passed every guard, here and in the crosswalk, which a
  third test now refuses. See DESIGN, "The threat model's citations, and the bridge phrases already
  written".

- **Investigate MITRE ATLAS for the threat model.** Asked for by the owner on 26 September 2026:
  how feasible it would be, whether it adds anything of value, and whether it is worth it. ATLAS
  (Adversarial Threat Landscape for Artificial-Intelligence Systems) is MITRE's catalog of how AI
  systems are attacked — tactics and techniques such as prompt injection, poisoning the data a model
  learns from, and extracting a model — with case studies of attacks that really happened. The
  investigation should answer, with evidence rather than impressions:

  - **Overlap.** How much of what ATLAS covers is already reached through AISVS and its Appendix C,
    which `sv` loads, and through the AI threats already in `data/knowledge/threats.json`. What is
    left once both are subtracted is the value in question.
  - **Fit with the threat model.** Whether a threat could carry the ATLAS technique it corresponds
    to as a reference, the way threats already cite requirements, and whether that helps the owner
    — who is not a programmer — or only a security reviewer reading the report after them. ATLAS
    names describe attacks; the threat model describes what could go wrong for this app in plain
    language, and the two may not line up one to one.
  - **What it could check.** ATLAS describes attacks, not controls, so it may add nothing checkable
    on its own; say whether any technique gives a question the running-app probes or the code rules
    could ask that AISVS does not already prompt.
  - **Upkeep and terms.** How ATLAS is published (machine-readable data, and how often it changes),
    its license and what attribution it asks for, and what keeping a copy current would cost — the
    same questions the Pwned Passwords item had to answer.
  - **Applies only to apps that use AI.** Most apps `sv` sees do not, so whatever is added must be
    gated on the `ai` condition like the rest of AISVS.

  The deliverable is a short written recommendation — adopt, adopt in part, or not worth it — with
  the numbers behind it, before anything is built. **Claimed on 26 September 2026 by session
  securevibe-e8. Done the same day: adopt in part.** Cite ATLAS techniques by ID on the six AI
  threats, for a reviewer; no copy of ATLAS in `sv`, no checks from it (35 of its 40 mitigations
  already have an AISVS chapter, and AISVS cites ATLAS itself), and nothing in the owner's
  plain-language view. See DESIGN, "MITRE ATLAS: adopt in part".

- **Cite MITRE ATLAS techniques on the six AI threats.** Proposed on 26 September 2026 by the ATLAS
  investigation above. **The owner said yes on 26 September 2026. Claimed the same day by session
  securevibe-e8.** Kept out of `data/knowledge/threats.json`, which v1 shares, in a file of `sv`'s
  own, so the v1 side has nothing to agree to. **Done the same day:** `data/atlas-references.json`,
  `tools/atlas_references.py`, and a reviewer's table in the report. See DESIGN, "MITRE ATLAS: adopt in
  part". Each of T-07 to T-12 cites one or two techniques with a `because`, the names are read from a
  pinned release, and the script names any cited ID renamed or withdrawn in a newer one.

- ~~**An unanswered question excludes requirements when a corroborator found nothing.**~~ Done on 26 September
  2026 (see the end of the entry). Found on 26 September 2026 reviewing the new manifest questions. `ci-cd` and `iac` are claim
  conditions — `securevibe.toml` asks about them — and when the manifest does not answer, a
  corroborator that looked and found nothing answers `false` for it, which marks requirements *not
  applicable* rather than *not assessed*. On a manifest holding only `manifest-version` and
  `[app] name`, that excludes twelve requirements, eleven of them AC.12's CI/CD pipeline hardening.

  The report says in the same breath that this is not valid. Its own note for that state reads:
  *"Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as
  finding it absent."* There was no manifest word to take, and the sentence says why finding nothing
  should not settle it.

  The two states are also indistinguishable in the outcome. With `ci-cd` unanswered the claim is
  `unverifiable`; with `ci-cd = false` written down it is `confirmed` and *"the manifest and the code
  agree"* — and both exclude the same twenty-eight requirements. Meanwhile `hosted-scm` and
  `outside-contributors`, claim conditions with no corroborator, correctly stay *not assessed* and say
  so: *"Nobody has said. Requirements that turn on this are not assessed rather than excluded."* So the
  same silence is handled two ways depending on whether a corroborator happens to exist for it.

  `resolve` is where it comes from: `(None, Some(false)) => Some(false)`. That is right for the derived
  conditions — no GraphQL library in the lockfile really does answer `graphql`, and the manifest never
  asks — and wrong for a claim condition, where absence of a `.github/workflows` folder in an uploaded
  app is exactly the case the note describes. Sixteen of the twenty-eight exclusions on that manifest
  are derived and sound; the twelve from `ci-cd` and `iac` are not.

  This is the direction `sv init` calls the one that matters: "A capability present but denied is the
  one mistake that matters — it is how a real requirement gets marked not applicable."

  **Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking, before the
  threat-model citations, the mock identity provider, and the real browser. **Done the same day.**
  An unanswered claim now stays unanswered whatever the scan found; the twelve are AC.12.1–AC.12.8,
  AC.7.3, AC.7.4, AC.9.1, and SBD-AC-07 (eight of them AC.12, not eleven), and all twelve are now
  not assessed. See DESIGN, "Finding nothing does not answer for the owner".

- **A checklist for what only a person can check.** Asked for by the owner on 26 September 2026,
  after the report readability work: *"perhaps a checklist for the checks that have to be verified by
  a human, with a short description of how to verify them."* **Claimed on 26 September 2026 by
  session securevibe-e8.** Measured against a real report first, because two earlier estimates of the
  size were wrong: 98 applicable requirements can only be settled by a person — 40 ASVS (7 at level
  1, 33 at level 2), 21 Secure by Design, and 37 AISVS. Of the ASVS ones, 20 have no plain-language
  question yet; the security notes and design questions already cover the other 20. So the new
  writing is `data/human-checks.json` with one how-to-verify line each, and a report section that
  gathers all three sources, level 1 first. The 58 Secure by Design and AISVS controls get a group
  explanation rather than 58 lines: those standards are checklists already, and 58 more rows is the
  wall of text this work exists to remove. Nothing here credits anything — each stays unverified with
  the instruction beside it. **Done on 26 September 2026.** `data/human-checks.json` (20 entries),
  `crates/sv-check/src/human.rs` gathering all three catalogs, and a "What only you can check"
  section above the tests, level 1 first. See DESIGN, "What only you can check". Left over: the 58
  design-review controls are counted rather than explained, which is deliberate, and the 33 ASVS
  level 2 entries could use the same treatment as the level 1 ones if the owner wants them broken
  out.

- ~~**A clean credential scan claims V11.1.1 and C9.5.4.**~~ Withdrawn on 25 September 2026 by session
  securevibe-e8: not a fault. V11.1.1 and V13.3.1 are on `manualOnly` in `data/knowledge/applicability.json`,
  so a clean scan supports them and checks neither (pinned by
  `the_requirements_a_clean_scan_cannot_settle_include_the_ones_it_was_settling` and
  `end_to_end_a_clean_scan_supports_the_secrets_controls_and_checks_none_of_them`); the coverage count
  that suggested otherwise had not read that list. C9.5.4 is classified `scanner-clean` on purpose, and
  stays; `docs/COVERAGE.md` says what a clean scan does and does not show about it.

- ~~**A coverage document, generated.**~~ Done on 25 September 2026 by session securevibe-e8.
  `docs/COVERAGE.md`, written by `tools/coverage.py` from the checks' own citations and the
  manual-only list, and kept current by `crates/sv-check/tests/coverage_doc.rs`, which fails when it
  is not what the script would write. The script stops if a requirement id or check name is written
  into `sv`'s code that it does not know about.

- ~~**Level 1 checks against the running app.**~~ Done on 25 September 2026 by session securevibe-e8.
  V4.1.1 and V13.4.1 as anonymous probes; V6.2.1, V6.2.4 and V6.2.5 through `signup`, beside a control
  password; V6.3.2, V14.2.1 and V7.2.3 as findings only. Level 1 goes from 21 to 29 of 70. See DESIGN,
  "Level 1, asked of the running app". Left over: a password change (V6.2.2, V6.2.3) needs the manifest
  to say how one is made; rate limiting (V6.3.1) is a documentation requirement as much as a behavior.

- ~~**Requirements with no test naming them.**~~ Done on 25 September 2026 by session securevibe-e8.
  The report's "Tests to write" lists every applicable requirement with no evidence and no test
  naming it, lowest level first, and leaves out and counts what an app's tests cannot show; `sv mcp`
  gives the list to the AI coding tool and `sv init` tells it to work down it. See DESIGN, "Tests to
  write".

- ~~**`sv report` understates a gap that `sv sbom` states correctly.**~~ Done on 25 September 2026 by
  session securevibe-e9. The report builds an SBOM and asks it, instead of reasoning about dependencies
  from `scan_report.unpinned`: an unreadable ecosystem is now reported as an empty list rather than an
  approximate one, a manifest-declared one as what was asked for, and a fully locked one as no gap at
  all. The sentence was also wrong about pip in the other direction — `flask==3.0.0` does pin a version,
  and it said `requirements.txt` "pins no versions". See DESIGN, "The report asks the bill of materials".
  Left over: the report still does not carry the SBOM's incompleteness finding or run the advisory
  comparison, which is the other half of the entry this shares a root with.

  As originally found, on 25 September 2026 while reviewing the nested-manifest walk. For an ecosystem
  whose manifest versions `sv` cannot
  read, the report says the list holds what was asked for, when the list holds nothing at all. The two
  commands on the same app — a `package.json` with `"react": "18.0.0"` and no lockfile:

      sv sbom    npm is in use but nothing readable says which versions are installed,
                 so none of its packages are listed
      sv report  package.json pins no versions, so the list of dependencies is what was
                 asked for rather than what is there

  `sv sbom` is right, and puts a `securevibe:unread:npm` component in the CycloneDX document so a
  downstream reader sees it too. `sv report` builds its gap from `scan_report.unpinned` with one
  sentence for every ecosystem, and that sentence is true of pip — `flask==3.0.0` really is the version
  asked for — and wrong of npm, where no version in a `package.json` is read at all and that
  ecosystem's bill of materials is empty. A reader is told the list is approximate when it is absent.

  Same root as the entry about `sv report` not running the bill of materials or the advisory
  comparison: the report reasons about dependencies from the scan alone and never asks the SBOM, which
  already knows the difference and says it well. Rewording the sentence is probably the wrong fix — one
  sentence covering two ecosystems will be wrong about one of them again. **Claimed on 25 September
  2026 by session securevibe-e9.**

- ~~**AISVS, beyond applicability.**~~ A duplicate of the struck entry of the same name below, done on
  25 September 2026; struck on 27 September 2026 by session securevibe-e2. One AISVS requirement has a check (C9.5.4). semgrep's `ai.*` rules
  (user input in a system prompt, model output executed, MCP servers) could be mapped to AISVS the way
  its security rules were to ASVS, with the citation guard reading each back, and `sv`'s own code rules
  could look for the same. Most of AISVS is about training and operating models and stays out of reach.
  **Potentially a duplicate** (noted on 26 September 2026 by session relaxed-nobel-27acfa): an entry
  with the same title further down, under the done items, is struck through and says it was done on
  25 September 2026 by session securevibe-e8. Check that one before taking this; this copy may be the
  original that was never struck out.
  **Claimed on 27 September 2026 by session securevibe-e2**, to strike it through as the duplicate.
  **Done the same day:** the done copy lists eight AISVS requirements semgrep's AI rules now name, which
  is what this one asked.
- ~~**Testing an app's AI feature: a fake model inside the fence, or garak.**~~ Closed on 27 September
  2026. **The owner's decision that day: garak is not taken up** ("I agree with the assessment that
  there are better options"). The test model inside the fence was built instead (below), and garak
  would have needed a hole in the fence and the app's own API credit. Kept for the record. Asked by the owner on
  26 September 2026 ("would adding a tool like garak help answer any of the AISVS requirements?") and
  answered by session securevibe-e9.

  **What garak could reach.** garak (NVIDIA's model scanner) sends attack prompts to a chat endpoint
  and scores the replies; pointed at the app's own chat route, through a manifest entry in the shape
  of the `[stack.run.users]` templates, it speaks to:

  | Requirement | Asks | garak's part |
  |---|---|---|
  | C2.1.3 (L1) | prompt injection screened and blocked | its injection probes: a reply following the injected instruction is a finding |
  | C2.1.2 (L1) | encoded or smuggled input caught | its encoding probes (base64 and the like) |
  | C7.3.3 (L2) | model output cannot trigger outbound requests | its markdown image exfiltration probe |
  | C11.1.3 (L1), C11.1.4 (L2) | the model tested against known attacks, and hardened | running it is that test; failures are findings |
  | C2.1.8 (L3) | many-shot jailbreaks detected | only partly: it has jailbreak probes; whether it has a many-shot one is not checked |

  Beside those, `sv`'s own log check could read the app's log after garak's attempts for C12.2.1 and
  C12.2.3 (jailbreak and injection attempts detected and alerted on).

  **Only ever findings.** garak samples and its detectors are heuristics: a clean run means these
  prompts did not get through this time, not that the app resists them, and a hit can be a false
  alarm, so the report has to show the prompt and the reply. The same rule as semgrep's AI rules
  (`findings_against`).

  **Two obstacles.**
  1. **The fence.** The app runs where it cannot reach OpenAI, Anthropic, or anyone else, so its AI
     feature has no model to call, and garak would be testing an error page. Getting round it means
     letting the app reach its provider, a hole in the fence and the owner's decision.
  2. **Money.** Every garak prompt then spends the app's own API credit, and a full run is thousands
     of prompts. It would need a small probe set, a stated cap, and the owner asked each time, as for
     any paid step.

  **The alternative: a fake model inside the fence.** A small container speaking the provider's API
  shape, as the test sign-in provider does for OIDC, that misbehaves on purpose: it obeys injected
  instructions, repeats its system prompt, answers with a markdown image pointing outside, or answers
  at great length. That tests the **app's own controls** rather than the model, which are what a small
  app can actually meet, and it is free, needs no network, and gives exact answers that can credit:

  - C7.3.2 (L2): `sv` plants a marker in what the model is sent, the fake model repeats it, and the
    marker must not reach the browser.
  - C7.3.3 (L2): the fake answers with an image or link to an outside address; it must not be
    fetched or rendered.
  - C7.1.2 (L1): the fake answers without end; the app has to cut it off.
  - C2.1.3 (L1): an input carrying a known injection has to be refused before it reaches the model,
    which the fake can see by whether it was called.

  Its limit: it needs the app to let its provider's address be set (`OPENAI_BASE_URL` and the like),
  which most SDKs allow and some apps hard-code. That has to be stated in the manifest, and an app
  that cannot be pointed at it is *not assessed*.

  **Neither reaches** membership inference (C11.2.5), drift and hallucination monitoring (C12.3),
  the training-data chapters, or most of the agent architecture in C9; those stay the owner's to answer.

  **The owner's decision, 26 September 2026: the fake model first, not garak.** **The fake model
  claimed the same day by session securevibe-e9**, for the four requirements above (C7.3.2, C7.3.3,
  C7.1.2, C2.1.3). garak stays unclaimed and undecided. **The fake model is done the same day:** a `[stack.run.ai]`
  section starts it, C7.1.2, C7.3.2, and C2.1.3 are credited or found, and C7.3.3 is found only.
  AISVS goes from 6 to 10 of 191 that a check can settle. See DESIGN, "A test model inside the
  fence".

  **Thoughts.**

  - *Session securevibe-e9.* The fake model first: free, exact, fenced, and able to credit the
    controls a small app owns. garak afterwards as an optional adapter, findings only, run only when
    the owner lets the app reach its provider for the run and agrees to what it spends, with the
    probe set and a cap named in the manifest.

    Asked by the owner for more ways to reach the remaining AISVS requirements, each built on
    machinery that exists or on the fake model once it does. None is claimed:
    - **C12.1.3, structured inference logs.** The fake model answers with a model name and token
      counts nobody else would use; the log check then looks for them in the app's output, as it
      does for its own markers (V16.2.1). Credit on presence.
    - **C12.2.1 and C12.2.3, injection attempts detected and alerted on.** After the C2.1.3 probe
      sends a textbook injection, the same log check looks for the app having flagged it.
    **C12.1.3 and C12.2.1 claimed on 26 September 2026 by session securevibe-e9**, at the owner's
    asking. C12.2.3 is not: it asks for rules that catch *coordinated* attempts, which one message
    cannot show, and it stays unclaimed. **Both done the same day:** C12.1.3 from the line carrying the token
    counts the test model reported, credited when structured and complete and a finding when found
    and short; C12.2.1 from a line saying the injection was caught. AISVS goes from 10 to 12 of 191.
    See DESIGN, "What the app wrote down about it".
    - **C11.2.2, rate limits on the inference route.** A number the owner states under `[policy]`,
      as `failed-sign-ins` is for V6.3.1, and one more request than that to the AI route, which
      costs nothing when the model is the fake one.
    - **C9.6.1, a kill switch.** The owner names the setting that halts the AI feature (an
      environment variable or a flag); the run starts the app with it on and asks the AI route,
      which must then answer without the fake model being called.
    - **C10.4.1 and C10.4.2, MCP responses screened.** The same idea as the fake model, for an app
      that is an MCP client: a fake MCP server in the fence whose `tools/list` breaks its own
      schema and whose `tools/call` carries an injected instruction, and the fake model reports
      whether either reached it.
    - **C9.3.4 and C9.3.7, what an agent may call.** The fake model asks for a tool call outside
      what the app declares, or to install a package that does not exist, and reports whether the
      app went ahead. Harder: the effect has to be observable, which depends on the app.

    **C11.2.2, C9.6.1, C10.4.1, and C10.4.2 claimed on 26 September 2026 by session securevibe-e9**,
    at the owner's asking, to be built in that order, one pull request each. C9.3.4 and C9.3.7 are
    not claimed: whether an app acted on a tool call it should have refused is seldom visible from
    outside it, and a check that cannot see the effect could only guess. **C11.2.2 done the same day:** one more
    message than `[policy] ai-requests-per-minute` states, after a minute's wait; credited only when
    the app's own page still answers afterwards. See DESIGN, "How often it can be asked". **C9.6.1
    done the same day:** a second copy of the app started with the owner's `kill-switch` setting
    must answer without calling the model. See DESIGN, "A kill switch, tried on a second copy". **C10.4.1
    and C10.4.2 done the same day:** a test MCP server beside the test model, whose tool answers with
    a result that breaks its schema and one carrying an injected instruction. See DESIGN, "MCP tool
    results, from a test MCP server". With that, everything claimed here is done.

- ~~**More Level 1 from the ASVS pass.**~~ Done on 25 September 2026 by session securevibe-e8. From
  the 41 Level 1 requirements no check reached: signed-in questions for V6.2.8 (a password checked
  exactly as typed, not cut short or case-folded), V6.2.6 (password fields masked), V6.2.7 (paste not
  blocked), and V3.5.3 (sign-out and creating a record refused as a plain page visit); semgrep's rules
  for text written into a page as HTML against V3.2.2 and C#'s turned-off token expiry against V9.2.1,
  as findings only; then a `change-password` entry for V6.2.2 and V6.2.3. All done, with V6.2.9 beside
  V6.2.8 (see DESIGN, "Level 1 again"); creating a record by a plain page visit was left out, because
  telling whether a GET made one needs a page that lists them.

- ~~**Three more Level 1 questions.**~~ Done on 25 September 2026 by session securevibe-e8. V7.4.2
  (every session ends when an account is deleted, through a `delete-account` entry), V6.4.2 (no password
  hints or secret questions on the sign-up and sign-in pages, only ever a finding), and V4.4.1
  (unencrypted `ws://` WebSocket addresses in the code, only ever a finding).

  - *Session keen-meninsky-691a27.* Agreed on the fake model first: it answers the fence problem,
    which garak cannot. Three things for whenever garak is taken up, each checked rather than assumed:
    - **It cannot be "an optional adapter" as `data/adapters.json` stands.** That file is SARIF-only
      by its own stated rule — "a tool that cannot emit SARIF is simply not listed yet" — and garak
      writes a JSONL report. `parse_sarif_relative_to` is the only reader `adapters.rs` has, and an
      adapter carries no `format` field. Every adapter is also handed the app's *files*, while garak
      needs a live endpoint, and no tier covers an outside tool pointed at the running app. So garak
      is a JSONL reader shaped like `crates/sv-check/src/junit.rs`, a manifest entry, and probably a
      tier of its own: a project, not a data row.
    - **`promptinject` is goal hijacking only** — `HijackHateHumans`, `HijackKillHumans`,
      `HijackLongPrompt` — with no system-prompt leak probe, which fits the fake model rather than
      garak taking C7.3.2. `latentinjection` is separate and real: instructions buried in resumes,
      financial reports, translations and WHOIS records, so indirect injection through retrieved
      content (C5.2.2, C8). Whether it reaches C10.4.2, which is specifically MCP `tools/list` and
      `tools/call` responses, depends on the app passing tool output to the model, and would have to
      be measured.
    - **Terms:** garak is Apache 2.0, like the ATLAS data, so none of the conditions the Semgrep Rules
      License carries apply to it.

- **What the remaining Level 1 and 2 requirements need.** An analysis on 25 September 2026 (session
  securevibe-e8) of the 181 ASVS requirements at Level 1 and 2 that no check reached, 30 of them at
  Level 1, by the kind of answer each needs: a document (18), a document plus behavior matching it (12),
  a design decision (16), deployment and infrastructure (22), more questions for the running app (19),
  code review (24), file uploads (9), OAuth, MFA, and JWT details (40), and unusual setups such as SAML
  or LaTeX (21). The items below are what came of it, in the suggested order; none is claimed.

- **A security-notes file, and policy numbers the probes can test.** For the 30 requirements that ask for
  a document. `sv init` writes a template with one section per applicable one, headed by its id and
  filled in from what was detected (the outside services, by the package that showed them; the data
  held, from `[data]`). A section the owner has written counts as *documented by the owner*: a tier of
  its own, never *checked*, the way a test naming a requirement is. For the twelve that ask for the app
  to behave as documented, the owner states the policy as numbers in securevibe.toml (failed sign-ins
  before a lockout, the idle and absolute session timeouts, sessions allowed at once), and the probes
  test those numbers against the running app. The design questions (16) take the same shape: yes, no, or not sure in securevibe.toml, with
  where in the code, counted as *attested by the owner*; "not sure" adds nothing.
  **Claimed on 25 September 2026 by session securevibe-e8.** The notes file itself is **done**:
  `data/security-notes.json` (nineteen questions, each a requirement that asks for a written decision
  and nothing else, and twenty more named with why they are not questions), `sv notes` to write and
  rewrite `security-notes.md`, and the *documented by the owner* tier in both reports — never folded
  into *checked*, beaten by a finding and by a check that ran, and deliberately unable to settle a
  threat. See DESIGN, "The security notes". Left over, each its own piece of work: the policy numbers
  in securevibe.toml that the probes can test (about eight requirements, V6.3.1 at level 1 among
  them), and the design questions answered as *attested by the owner*.
  **All three pieces are done**, the policy numbers on 25 September 2026 by session securevibe-e8:
  `[policy] failed-sign-ins` in securevibe.toml, and a probe that makes one more wrong attempt than
  that and watches whether the app pushes back. V6.3.1 at level 1 becomes checkable, which takes
  level 1 to 41 of 70. It runs last and never guesses at the test users, because it is the one check
  that provokes an app into refusing requests. See DESIGN, "Policy numbers, and the one requirement
  they make checkable". The session timeouts (V7.3.1, V7.3.2) are left: a stated idle timeout could
  be compared against the session cookie's own lifetime, which is instant and is evidence about the
  cookie rather than about the server, so it would be findings-only.
  **The design questions are done, on 25 September 2026 by session securevibe-e8.**
  `data/design-questions.json` (sixteen questions), a `[design]` section in securevibe.toml answered
  yes, no, or not-sure with `where`, and an *attested by the owner* tier ranked below *documented*,
  because the owner asserting a property is not the property — so an attested requirement stays on
  the list of tests to write, and settles no threat. An answer of no is a finding, and so is a
  `where` naming a file the app does not have. See DESIGN, "The design questions, and the weakest
  tier there is". Writing the guards found V13.2.2's question was about the wrong thing entirely.
  Left over from the whole entry: only the policy numbers, corrected below.

  **The "about eight" in the paragraph above was wrong, and is struck out.** It was written from the
  count of requirements that ask for behavior to match a document, without reading them. There are
  eleven, and asking a running app reaches three: V6.3.1 (Level 1 — make the stated number of failed
  sign-ins and see whether the app slows down or locks out) and V7.3.1 and V7.3.2, the idle and
  absolute session timeouts, the second of which is awkward when the real answer is measured in days.
  The other eight are out of reach for reasons that will not change: V2.3.2's business limits are
  whatever the app is for; V14.2.4, V16.2.3, and V16.3.3 need the logs or the stored data read, not
  the app asked; V15.2.1 is already the advisory check's; V6.2.11 needs the word list, which is the
  document itself; and V7.6.1 needs a real identity provider. So this is worth doing for V6.3.1 at
  Level 1 and two at Level 2, which is a smaller prize than the entry promised.

- **More questions for the running app, and an `upload` entry.** Asked with what `[stack.run.users]`
  already says. Three are done on 25 September 2026 by session securevibe-e9: `Cache-Control:
  no-store` on private pages (V14.3.2), a visible sign-out link on private pages (V7.4.4), and
  directory listings (V13.4.3). The first two are signed-in checks on the pages `private` names; the
  third is an anonymous probe beside V13.4.1, because it needs no account, and it is only ever a
  finding — six guessed paths and three server signatures cannot show that nothing lists. Level 2
  goes from 30 to 33 of 183. See DESIGN, "Three more questions for the running app".

  The logging question is **done on 26 September 2026 by session securevibe-e9**. The probes plant
  three markers — a sign-in for an account that does not exist, a sign-in that works by an account
  used for nothing else, and a private page asked for by nobody with a marker in its address — and
  the container's output is read for them afterwards. Finding them credits V16.3.1 and V16.3.2;
  *not* finding them is not assessed and never a finding, because an app that logs to a file or a
  service writes nothing there and is not logging any less for it. V16.3.1 needs both sign-ins
  found, since the requirement asks for both. Level 2 goes from 33 to 35 of 183. See DESIGN, "What
  the app wrote down". Password reset is done on 26 September 2026 by session securevibe-e9,
  on the mail server from the new-tools list below. An `upload` entry lets the probes send an oversized file, a file whose contents do not match
  its extension, and a script, which reaches V5.2.1, V5.2.2, V5.3.1, and V3.2.1 at Level 1.
  **The `upload` entry is done on 26 September 2026 by session securevibe-e9.** `[stack.run.users]`
  takes an `upload` entry — the path, the file field, the other form fields, an optional
  `serves-at` saying where an upload can be fetched back, and `max-bytes`, the size the owner
  states and the app is held to. The probes send an ordinary GIF first to show the upload works at
  all, then one larger than the stated size (V5.2.1), one named `.gif` that is not a GIF (V5.2.2),
  a `.php` fetched back to see whether the server ran it (V5.3.1), and an `.html` fetched back to
  see whether a browser would render it as part of the app (V3.2.1). Level 1 goes from 41 to 45 of
  70. See DESIGN, "The upload entry". Left over from it: V5.3.2 (paths built from submitted names)
  and V5.4.1/V5.4.2 (what the app sends back) are reachable the same way and were not written.

- **Twelve more requirements the probes could reach, from a sweep of everything they cannot.**
  An analysis on 26 September 2026 (session securevibe-e9) of all 260 ASVS requirements no check
  names, lowest level first. Not claimed; each line below is its own piece of work, and the machinery
  each needs already exists. Counts are from `docs/COVERAGE.md` at the time: 25 uncovered at Level 1,
  146 at Level 2, 89 at Level 3.

  **Four of the five Level 1 lines are done on 26 September 2026 by session securevibe-e9**:
  V2.2.2, V7.2.1, V15.3.1 and V14.3.1. Level 1 goes from 45 to 49 of 70. See DESIGN, "Four more
  Level 1 questions". The four Level 2 lines are claimed by the same session.

  **V1.2.2 was attempted and withdrawn.** The entry said "a rule in the same shape as
  `ast.download-piped-to-shell`", and that was wrong: every rule in `data/ast-rules.json` matches a
  *call*, with patterns for the function and the module it came from. A `javascript:` or `data:`
  URL is a string literal, which may be assigned rather than passed to anything, and `sv` has no
  way to scan literals on their own — the one requirement reached that way, V4.4.1, is semgrep's,
  not `sv`'s. Writing it would mean a new kind of rule, which is its own piece of work and belongs
  with the other "needs a new mechanism" items rather than being smuggled in here.
  **V4.4.1 as `sv`'s own rule claimed on 26 September 2026 by session securevibe-e8.** Semgrep's
  `detect-insecure-websocket` is in no pack the adapter runs, so the honest count lost V4.4.1. A
  string literal can be matched after all, by a query that captures the literal itself; the rule is
  a `ws://` address to another computer, and it needs a way to be finding-only, since not seeing one
  is not every socket being encrypted. **Done the same day:** `ast.plaintext-websocket-url` in all
  fourteen languages, with `findingsOnly`, a new field for AST rules; Level 1 goes from 52 to 53 of
  70. See DESIGN, "A `ws://` address written into the code". The same way would reach V1.2.2's
  `javascript:` literal, but that was withdrawn for what it means, not for how to match it.

  **Level 1 — 25 uncovered, 5 look reachable.** The rest are documentation (V2.1.1, V6.1.1, V8.1.1,
  V15.1.1 → the security-notes file), deployment (V3.4.1, V12.2.1 → the production check), the
  authorization server (V10.4.1–V10.4.5, which apply to almost nobody now that they are scoped),
  `manualOnly` (V2.3.1, V12.2.2), or a flow between two places that `sv`'s rules cannot follow
  (V1.3.1, V9.1.3, V2.2.1).

  - **V2.2.2 — validation on the server, not only in the browser.** Read the sign-up or create form
    for the constraints it states in its own HTML (`maxlength`, `pattern`, `type=number`,
    `required`), then send a value that breaks one directly. A server that accepts what its own form
    forbids is relying on the browser. `tags` and `attribute` in `signed_in.rs` already read forms
    this way for the password-field checks.
  - **V7.2.1 — a made-up session token is refused.** The probes know the session cookie's name and
    shape from a real sign-in. Send a private-page request carrying a fabricated value of that shape:
    if the page opens, the token is not being checked against anything. Distinct from V7.2.3, which
    is about whether the value is guessable rather than whether it is verified.
  - **V15.3.1 — a record hands back more than it should.** The `owned` record is already read back.
    Scan that response for field names that should never leave the server — `password`, `hash`,
    `salt`, `secret`, `token`. Only ever a finding: not seeing them proves nothing about the fields
    this app happens to have.
  - **V14.3.1 — `Clear-Site-Data` when signing out.** The sign-out response is already in hand in
    `logout_check`. Credit on presence only: the client can also clear up by itself, so absence is
    not a failure. Partial evidence, and the report has to say so.
  - **V1.2.2 — `javascript:` and `data:` URLs built in code.** A rule in the same shape as
    `ast.download-piped-to-shell`. Only ever a finding.

  Worth a judgment call rather than code: **V8.3.1** (authorization enforced at a trusted service
  layer) is arguably already demonstrated by `probe.admin-page-ordinary-user` — an ordinary user is
  refused the admin page by the server, whatever the browser was told. Citing it would cost nothing
  and settle a Level 1 requirement, but it is a citation being stretched, so somebody should decide
  rather than it being slipped in.
  **The owner's decision, 27 September 2026: supporting evidence only.** The admin page refused to
  an ordinary user is shown beside V8.3.1 and strengthens the owner's answer, but does not settle
  it: one page refused is not every rule enforced on the server, and actions sent straight to an
  API are not tried. The same standing as V2.3.1's refused skips. **Claimed the same day by session
  securevibe-e2.**
  **Done the same day:** V8.3.1 is on `manualOnly`, and `probe.admin-page-ordinary-user` cites it
  beside V8.2.1, so a refusal is listed as support and an opened page is a finding against both.
  ASVS "supporting only" goes from 5 to 6; nothing more is counted as settled. See DESIGN, "The
  admin page, as support for V8.3.1".

  **The four Level 2 lines below are done on 26 September 2026 by session securevibe-e9** (V16.2.1,
  V16.2.2, V5.4.1, V5.4.2). Level 2 goes from 36 to 40 of 183. See DESIGN, "What a log line and a
  download carry".

  **Level 2 — 146 uncovered, 4 look reachable now**, all of them because of machinery added in the
  last few days rather than anything new:

  - **V16.2.1 and V16.2.2 — what a log line carries.** The log check already finds the line holding
    its own marker. V16.2.1 asks for when, where, who and what; V16.2.2 asks that the timestamp is
    UTC or carries an explicit offset, which is a thing that can be parsed exactly. Both read the
    line that is already found, and both credit only on presence, as that check does.
  - **V5.4.1 and V5.4.2 — the name a file comes back under.** The upload check already fetches a
    file back and already reads `Content-Disposition` for V3.2.1. V5.4.1 asks that the header names
    a file; V5.4.2 asks that a hostile name is encoded rather than breaking the header, which is
    tested by uploading one containing a quote and a semicolon and reading what comes back.

  V7.3.1 and V7.3.2 (idle and absolute session timeouts) are reachable too, and belong to the
  policy-numbers work rather than here.

  **Level 3 — 89 uncovered, and this is the honest part: close to nothing is reachable.** What is
  there is the authorization server's internals (5), WebRTC media (4), safe concurrency (4), MFA
  (3), and HTTP message structure (4) — design and deployment questions, or protocol work for
  technologies almost no small app runs. Level 3 stays a person's job, and saying so is better than
  a sweep that keeps rediscovering it.

- **What a new tool, service, or process would reach.** The follow-on question to the sweep above,
  asked by the owner on 26 September 2026 and answered by session securevibe-e9. After the Level 1
  and Level 2 work from that sweep, 251 ASVS requirements have no check. About 45 of them come
  within reach with one of the additions below; the other ~200 are documentation (the
  security-notes file), design, cryptographic internals, WebRTC, or an authorization server's own
  workings, and stay a person's job. Ordered by what each buys for what it costs. Nothing is
  claimed.

  1. **More of the same machinery, no new tool (~6).** **Four done on 26 September 2026 by session
     securevibe-e9**: V16.2.4, V4.3.1, V4.3.2, and V4.4.2; level 2 goes from 40 to 44 of 183. See
     DESIGN, "GraphQL, WebSocket, and a log line's format". V4.4.3 and V4.4.4 (a WebSocket's own
     session) are not done: they need to know whether the connection is meant to be private, which
     no entry says yet. **V4.4.3 and V4.4.4 claimed on 26 September 2026 by session securevibe-e9**,
     with a `private-websocket` entry under `[stack.run.users]` saying which socket needs a sign-in. **Done the same day:** V4.4.4 is credited when handshakes with no
     session and with a made-up one are refused where the signed-in one upgrades, and V4.4.3 is a
     finding when a signed-out session still opens the socket. Level 2 goes from 63 to 65 of 183. Left
     over: V4.4.2 for a private socket, which the anonymous check cannot ask. See DESIGN, "V4.4.3 and
     V4.4.4, a private WebSocket's session". **V4.4.2 for a private socket
     claimed on 26 September 2026 by session securevibe-e9**: the foreign-origin handshake sent with the
     signed-in session, beside the others. **Done the same day**; no level changes, since V4.4.2 was already
     counted through the anonymous probe.
     Whether the log line the log check already finds is in a common format —
     JSON, logfmt, or the common log format (V16.2.4). And small
     manifest entries naming a GraphQL path and a WebSocket path: an introspection query and a
     request of a thousand aliases (V4.3.2, V4.3.1), and a handshake from a foreign `Origin` and
     one with no session (V4.4.2–V4.4.4).

     *Corrected from the first version of this entry*, which counted eleven. Tampering with a
     signed token cannot reach V9.2.2 or V9.2.3: changing `aud` or `typ` changes what was signed,
     so a correct app refuses it for the signature and says nothing about whether it checks the
     audience. It only shows an app that verifies no signature at all, which is V9.1.1 and already
     reached; V6.8.2 is about an identity provider's assertions and belongs to item 2. And
     parameter pollution (V15.3.7) has no result that means anything without knowing the app.
     V15.3.5 (type confusion) was in this list and is taken out of it: a probe for it sends
     sign-in requests shaped to get in without the password, and that is not a thing this
     session will build. It stays unclaimed. A
     "too-deep" GraphQL query needs the schema, which introspection being off withholds; a
     thousand aliases of `__typename` needs none.
  2. **A mock identity provider inside the fence (~10, all Level 2).** One small container — an
     OIDC provider made for tests — that the app is pointed at for the run, so the probes can
     drive a real sign-in and then replay the code, drop the `state`, reuse the `nonce`, change
     `aud`, and serve metadata for a second provider (V10.1.2, V10.2.1, V10.2.2, V10.5.1–V10.5.4,
     V6.8.1, V6.8.2, V6.8.4). The largest single gain, and it lands exactly on the OAuth *client*
     requirements the authorization-server fix left applying to every "Sign in with Google" app.
     **Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking, scoped to the
     five a single test provider can show: V10.1.2 and V10.2.1 (a sign-in finished in a session
     that did not start it), V10.5.1 (a wrong `nonce`), V10.5.4 (a wrong `aud`), and V6.8.2 (an
     unsigned token, and one signed with the wrong key). The provider is `sv`'s own — a short
     script in a stock Node image on the fenced network — because it has to misbehave on purpose,
     which no ready-made test provider does. Left for later: V6.8.1 and V10.2.2 need two providers,
     V10.5.3 needs metadata an app reads at start-up to change, and V10.5.2 and V6.8.4 depend on
     what the app decides rather than on what the provider sends. **The five are done the same
     day:** a `[stack.run.oidc]` section starts the test provider, and Level 2 goes from 58 to 63 of
     183. On the way it found that the sidecar's `echo | nc` cut the connection before a slow Node
     route could answer, which affected every run. See DESIGN, "A pretend "Sign in with Google"
     inside the fence". **V10.2.2 claimed on 26 September 2026 by session securevibe-e8**: it needs no
     second provider after all, since the one provider can name another in the sign-in's `iss`
     parameter and in the ID token's `iss` claim, and an app that refuses both has the defense. **Done
     the same day**, credit only; Level 2 goes from 62 to 63 of 183. See DESIGN, "Which provider a
     sign-in came from".
  3. **A mail sink inside the fence (~7).** A container that accepts the app's email and lets the
     probes read it. Password reset stops needing a person: the reset link can be used twice,
     used late, and inspected for how guessable its code is (V6.4.1, V6.4.3, V6.5.1, V6.5.4,
     V6.5.5, V6.6.2, V6.6.3). The unclaimed password-reset item is built on this. **Claimed on 26
     September 2026 by session securevibe-e9**, with the password-reset item it carries. **The mail
     server and password reset are done the same day:** a `reset` entry under `[stack.run.users]`
     starts Mailpit on the fenced network, and the probes follow the reset email to find a link
     that works twice, an old password that survives, a guessable code (V6.4.3), and an answer that
     tells whether an address has an account (V6.3.8). Level 2 goes from 44 to 45 of 183, Level 3
     from 3 to 4. See DESIGN, "A mail server inside the fence, and password reset". The count above
     was wrong: V6.5.1, V6.5.4, V6.5.5, V6.6.2, and V6.6.3 are about codes sent to sign *in*, and a
     reset code is not one. They need an `email-code` entry — a magic link or an emailed second
     factor — on the same mail server; V6.5.5 needs the slow mode as well, and V6.4.1 needs a
     sign-up that emails an activation code. The `email-code` entry (V6.5.1, V6.5.4, V6.6.2,
     V6.6.3) is **claimed on 26 September 2026 by session securevibe-e9, and done the same day**:
     V6.5.1, V6.5.4, V6.6.2, and V6.6.3 at Level 2, which goes from 45 to 49 of 183, with
     `[policy] failed-codes` as the stated number for guessing. See DESIGN, "Signing in with an
     emailed code".
     **V6.4.1 (an activation code emailed at sign-up) and V6.5.5 for emailed codes (their lifetime,
     with `sv run --slow`) claimed on 26 September 2026 by session securevibe-e9.** V6.4.1 is **done the
     same day**, finding only: an `activation` entry, codes that count up or are short, and a link
     that signs in twice. Level 1 goes from 52 to 53 of 70. See DESIGN, "An activation code emailed
     at sign-up". V6.5.5 for emailed codes is **done the same day** under `sv run --slow`: a code
     used ten minutes after it was asked for is a finding if it signs in, and credited only when a
     fresh code then works. V6.5.5 was already counted, through the two-factor check, so no level
     changes. See DESIGN, "How long an emailed code lasts".
  4. **A seeded TOTP secret (2).** Not a tool: the `seed` script makes a user with two-factor sign-in
     and hands `sv` the secret, and `sv` computes the codes itself (RFC 6238) to try one twice and
     one late (V6.5.1, V6.5.5). **Claimed on 26 September 2026 by session securevibe-e8.** A third account, made by
     `seed` with `SV_TOTP_SECRET`, so A and B keep signing in with a password alone; a `totp`
     entry for the code step; and the codes computed by `sv` (HMAC-SHA1, RFC 6238) — the current
     one as the control, the same one again, one from five steps back, and a fresh one after the
     next step begins. V6.5.5 needs no slow mode this way: an old code is computed, not waited for.
     **Done on 26 September 2026.** Level 2 goes from 54 to 55 of 183. The order changed on the way:
     an old code tried after a used one is refused by the rule that stops reuse, whatever its age,
     so it now goes first. See DESIGN, "Two-factor codes, computed rather than waited for".
  5. **A slow mode (2).** `sv run --slow`, waiting out the idle timeout the owner states, then asking
     whether the session is dead (V7.3.1, V7.3.2). Belongs with the policy numbers. **Claimed on 26
     September 2026 by session securevibe-e9, and done the same day:** `idle-timeout-minutes` and
     `session-lifetime-minutes` under `[policy]`, held to by `sv run --slow`. Level 2 gains V7.3.1
     and V7.3.2. See DESIGN, "Session timeouts, waited out".
  6. **A real browser (~6, and two existing checks made stronger).** Headless Chromium, run as a
     container inside the fence. It can see what only a browser decides: whether a request needs a
     CORS preflight (V3.5.2), whether markup submitted through a form executes when the page renders
     (V1.3.1 and the rest of V1.3), and whether authorization lives only in hidden buttons (V8.3.1).
     It also turns two partial checks into real ones — storage actually emptied after sign-out
     (V14.3.1, today only the header) and a sign-out link actually visible (V7.4.4, today only
     present in the HTML). **Claimed on 26 September 2026 by session securevibe-e8**, at the
     owner's asking. **The first part is done the same day:** `[stack.run.users.browser]` starts a
     pinned headless Chromium on the fenced network, signed in with the first user's cookies. It
     settles V3.2.2 (text typed into a form is shown as text, not drawn as markup), which only a
     semgrep finding could name before, and makes V7.4.4 real (the sign-out control can be seen,
     not only found in the HTML). See DESIGN, "A real browser inside the fence". The count above was
     wrong about which requirement the typed markup reaches: it is V3.2.2, content meant as text; V1.3.1
     asks for a sanitizer for rich text, which an app that shows text as text does not need and a
     browser cannot see being used. **V14.3.1 is done the same day as well:** a sign-in of the
     browser's own is signed out with the app's control, and what the app kept in the browser's
     storage for the signed-in person has to be gone. See DESIGN, "Signing out in the browser".
     **With that, the item is done.** Not part of it: V3.5.2 needs no browser (a request without a preflight can be sent directly) and belongs with
     the cross-site checks (**claimed on 26 September 2026 by session securevibe-e8, and done the
     same day**: the `owned` create request, when it is JSON, sent from another origin as
     `text/plain`, as a form, and as multipart, none of which a browser preflights; Level 1 goes from
     53 to 54 of 70; see DESIGN, "A request another site can send without asking"); V8.3.1 is an owner's answer and stays one. And one found on the way: an
     app that sends `Referrer-Policy: no-referrer` and refuses `Origin: null` refuses its own forms
     in every real browser, which a check could say directly. **Claimed on 26 September 2026 by
     session securevibe-e9**: the `owned` create request, sent again as the app's own page would
     send it under that policy (with `Origin: null` and no `Referer`), when the app's pages ask for
     `no-referrer`. A finding of its own with no requirement behind it, since nothing in ASVS asks
     an app to accept its own forms. **Done the same day**; see DESIGN, "An app that refuses its
     own forms".
  7. **Taint analysis (~5 ASVS, and most of the AISVS rules).** An adapter reading CodeQL's SARIF
     — CodeQL already runs in this repository's own CI — or semgrep's taint mode. Every rule `sv`
     writes matches a call; none follows a value from where it came in to where it is used, which
     is what blocked V1.2.2, V1.3.1, V2.2.1, V9.1.3, V15.3.2, and the AISVS entry's "user input
     placed in the system instructions". The small in-`sv` half: a rule kind that matches string
     literals, for the literal `javascript:` URL V1.2.2 was withdrawn over. The CodeQL adapter is
     **claimed on 26 September 2026 by session securevibe-e9, and done the same day** for JavaScript,
     TypeScript, and Python: V1.2.9, V15.3.5, V15.3.6, V16.4.1, and V1.2.2 (as a finding only) with
     `--tools`, Level 1 to 52 of 70 and Level 2 to 53 of 183. See DESIGN, "CodeQL: following a
     value". Left over: V1.3.1, V2.2.1, V9.1.3, and V15.3.2 have no CodeQL query that fits them; Go,
     Ruby, and Java entries are the same data change with their own maps; and reading a SARIF file
     from the owner's own CI, rather than running CodeQL here, needs the report's commit compared
     with the code's before a clean result could be credited.
  8. **The live site, with a TLS scanner (~5, mostly Level 3).** Beside `sv probe`: testssl.sh or
     sslyze for OCSP stapling and Encrypted Client Hello (V12.1.4, V12.1.5), the HSTS preload list
     (V3.7.4), a spoofed `X-Forwarded-For` to see whether rate limiting trusts it (V15.3.4), and,
     carefully and only on request, request smuggling (V4.2.1). The only item here that reaches
     outside the machine, so it follows whatever `sv probe` decides about the fence.
     **V15.3.4 claimed on 26 September 2026 by session securevibe-e8**, against the running app rather
     than the live site: `sv probe` sends only read-only requests, so it cannot make wrong sign-in
     attempts, and the brute-force check that finds the limiter already runs inside the fence. Once
     that check has seen the app refuse, one more wrong attempt claims a new address in
     `X-Forwarded-For`, then one more claims nothing; the first answered like the very first attempt
     while the second is still refused is a limiter believing an address the client made up. Only
     ever a finding. **Done on 26 September 2026.** See DESIGN, "A limit that believes a made-up
     address". Against an app whose limit counts by address and trips during the suite before the
     brute-force check, it is not asked; the report says why for V6.3.1, the brute-force check's own
     requirement, and does not name V15.3.4 there.
     **V12.1.5 and V3.7.4 claimed on 26 September 2026 by session securevibe-e9, and done the same
     day**, as more of `sv probe`: an ECH configuration in the site's DNS, asked of this computer's
     resolver, and the HSTS preload list from a copy the owner downloads (`--hsts-preload FILE`).
     Level 3 goes from 4 to 6 of 92. See DESIGN, "Two more things about the live site". Left out:
     OCSP stapling (V12.1.4), which could not be observed from the machine this was built on (its
     only way out intercepts TLS) and is not claimed; and request smuggling (V4.2.1), which means
     sending a live site deliberately malformed requests, which `sv probe`'s read-only rule does
     not allow.

  9. **Named pages for sign-up, password change, and one multi-step flow (3).** No new tool: three
     addresses in `[stack.run.users]`, the way `upload` names one. Try `Password123!` (V6.2.12, L2),
     the app's own name as a password (V6.2.11, L2 — the app's name is always a context-specific
     word, so one case needs no word list), and the last step of the flow in a fresh session
     (V2.3.1, L1, on `manualOnly` today, so taking it off is a decision). The guard not to get wrong
     is the one the brute-force check got wrong first: an app that refuses *every* password has shown
     nothing, so an ordinary one must be accepted first, or the answer is *not assessed*.
     **V6.2.12 and V6.2.11 claimed on 26 September 2026 by session securevibe-e8**, through the
     `signup` entry that already exists, so no new addresses are needed for them: a password from far
     down `data/knowledge/common-passwords.txt`, and one built from a word in a new
     `[policy] context-words` list — the documented list V6.2.11 names — each beside a random
     password of the same shape. **V2.3.1 claimed on 26 September 2026 by session securevibe-e8:**
     a `flow` entry naming the steps and what the last one shows when it really finished; A goes
     through in order as the control, and B jumps to the last step, and skips the middle. V2.3.1
     stays on `manualOnly` at the owner's word, so a refusal supports it and a skip that works is
     a finding. (Asked again on 27 September 2026 whether two refused skips should settle it; the
     owner's answer: no, it stays a person's check. Trying a repeated step is the way to strengthen
     it, not a lower bar.) **Done the same day**: see DESIGN, "Skipping a step (V2.3.1)". Doing a step twice
     and other wrong orders are not tried. **V6.2.11 and V6.2.12 done on 26 September 2026.** Level 2 goes
     from 49 to 50 of 183: V6.2.11 can be settled; V6.2.12 is *supporting only*, because it is on
     the shared `manualOnly` list and one refused password is not the whole breached set. The
     password list's source is not recorded anywhere in the repository, and checking the chosen
     password against Have I Been Pwned was refused by this environment's network policy, so the
     finding says "one of the 100,000 most common" rather than "breached". See DESIGN, "Two more
     passwords at sign-up".

  Additions from session securevibe-e8, which answered the same question separately on the same
  day; the two answers are merged here rather than kept as two entries. To item 5: the alternative to
  waiting is a test configuration with timeouts of seconds, which shows the mechanism works and not
  that production's number is the stated one, so it is partial evidence and has to say which half it
  saw. To item 6: V14.2.3 (L2 — list the requests that go to another host while signed in, and look
  in them for the test account's own details; only ever a finding) and V3.4.3 (L2 — the policy
  enforced, not only sent). **V14.2.3 claimed on 27 September 2026 by session securevibe-e2**, at the
  owner's asking to pick a backlog item: the real browser records every request a signed-in page
  tries to send to another host (the fence stops it leaving), and the test account's details found in
  one are a finding. **Done the same day:** the browser driver's `outside` action lists those requests, and the
  test account's email address (as written, encoded into a web address, base64, or SHA-256), password
  (as written or base64), and session cookie found in one are a finding, never printed. Only ever a
  finding: scripts a page loads from other sites cannot arrive inside the fence, so what they send is
  not seen, and the run lists the sites the pages tried to reach so the owner can look. See DESIGN,
  "What the signed-in pages send to other sites". To item 8: V12.1.1 (L1) and V12.1.2 (L2), the protocol versions and
  ciphers the live site offers, where semgrep today sees only TLS settings written in code; a scan
  is dozens of handshakes, so what `sv probe`'s four-request cap means for it needs deciding first.

  Items 2, 3, and 6 are containers on the fenced network, so they keep `sv`'s rule that nothing
  reaches outside; only item 8 does, and only to the owner's own address.

- **A production check.** `sv probe https://…`: read-only requests to the owner's own live address, for
  what the repository cannot say. HSTS (V3.4.1), TLS with a publicly trusted certificate and no fallback
  to plain HTTP (V12.2.1, V12.2.2), redirects to HTTPS only where a browser is the client (V4.1.2), and
  the `__Host-` cookie prefix (V3.3.3), which only means anything over HTTPS. The rest of deployment
  becomes a "before going live" list in the report. The fence and what the probes may send need
  thinking through first: this reaches outside the machine, which nothing in `sv` does yet.
  **Claimed on 26 September 2026 by session securevibe-e8.** The safety design is the substance: the
  address comes from the command line and nowhere else, so a person typed it and no committed file
  can aim it; GET and HEAD only, with no body, no cookies, and no Authorization header; a hard cap on
  requests, so it is three or four and never a scan; and a redirect to a different host is refused
  rather than followed, so nothing can drag the probe somewhere the owner did not name. TLS
  verification enforced rather than skipped is itself the V12.2.2 check. **Done on 26 September
  2026.** Four requirements — V12.2.2, V12.2.1, V3.4.1, V3.3.3 — and level 1 goes from 45 to 47 of
  70. See DESIGN, "`sv probe`: the questions only the live site can answer". Running it against real
  sites found two faults reasoning would not have: an error answer's headers read as the site's own,
  and a proxy's CONNECT status line read as a response. Left over: V4.1.2 (redirecting only where a
  browser is the client) needs a request shaped like an API client's and was not written, and the
  rest of deployment is still a "before going live" list nobody has written.

- **Deadlines for known vulnerabilities (V15.2.1).** Asked for by the owner on 26 September 2026.
  V15.2.1 asks that the app contains no component that has *breached the documented remediation time
  frame*; the advisory check reads every known vulnerability as a breach, so an advisory published
  yesterday and one ignored for two years look the same. The owner states the time frames as policy
  numbers (`[policy] fix-within-days`, one per severity), and each advisory's published date says how
  long it has been known. Past the deadline stays a finding on V15.2.1; within it stays a finding with
  a due date, but no longer claims V15.2.1 is breached. A clean comparison credits it exactly as now,
  and nothing here credits more than that. **Claimed on 26 September 2026 by session securevibe-e8.**
  **Done on 26 September 2026.** `[policy] fix-within-days` in securevibe.toml, the publication date
  read from each OSV record, and `sv audit` printing past the time frame first, then not judged, then
  inside it. Anything that cannot be judged — no time frame for that severity, no date, no clock — still
  counts against V15.2.1, and an unrated advisory is held to the shortest time frame. See DESIGN, "Late,
  not merely known". Left over, found while doing it: **`sv report` never runs the advisory comparison**,
  so V15.2.1 has no evidence in the report whatever `sv audit` says, and the checklist sends the owner
  to `sv audit` by hand. Bringing it into the report needs `--advisories` on `sv report`.
  **Claimed on 26 September 2026 by session securevibe-e8. Done the same day:** `sv report
  --advisories DIR` puts the findings, the clean result, and what could not be compared into the
  report, and without a database the report says it compared nothing rather than staying silent. See
  DESIGN, "In the report too". The MCP server still takes no database, deliberately.

- ~~**Keep the breached-password evidence current through the Pwned Passwords API.**~~ Asked for by the
  owner on 26 September 2026. V6.2.12's sign-up probe tries `1qaz2wsx3edc4rfv`, and the only record
  that it is a breached password is one range file the owner fetched in a browser and pasted into
  the session that day, because this environment's network policy refused
  `api.pwnedpasswords.com`. The owner has since added that host to the allowed domains, which takes
  effect for sessions started after the change. Three things to do once a session can reach it:
  a small script under `tools/` that re-fetches the range for `BREACHED` and rewrites
  `data/breached-password-evidence.json` with the new count and date; a sampled check of
  `data/knowledge/common-passwords.txt` (a few hundred entries across its ranks), so the list's
  source — recorded nowhere in the repository — is at least shown to be breach data; and a line
  in the report's V6.2.12 wording that carries the date of the last check. Only the five-character
  hash prefix is ever sent, and none of this runs inside `sv` itself: `sv` fetches nothing, and
  this is maintenance of the repository's own data, done by whoever runs the script.
  **Claimed on 26 September 2026 by session relaxed-nobel-27acfa**, which runs on a machine that
  can reach the API. **Done the same day.** `python3 tools/pwned_passwords.py` re-checks the password
  (still 133,732) and rewrites the evidence file, and the V6.2.12 wording is now built from that file,
  so it says "when last checked, on <date>" without an edit to the code. `--sample` looked up 300
  entries spread across the list's ranks: all 300 are in Pwned Passwords, with counts falling from a
  median of 391,080 in the top thousand to 8,932 in the last band. Results in
  `data/common-passwords-breach-sample.json`; see DESIGN, "V6.2.12, breached passwords". One thing
  learned: inside the Claude Code sandbox the network proxy cuts Python's reads of these answers
  short, where curl gets them whole; run outside it, every answer arrived complete.

- **Record the owner's Pwned Passwords check for V6.2.12.** The count from the range file pasted on
  26 September 2026 (133,732), in `data/breached-password-evidence.json`, with the finding's wording
  changed to say so. **Claimed on 26 September 2026 by session securevibe-e8. Done the same day**,
  with a test holding the password and the quoted count to that file.

- ~~**OAuth requirements for authorization servers are applied to OAuth clients.**~~ Done on 25 September
  2026 by session securevibe-e9. A second condition, `authorization-server`, gates V10.4, V10.6, and
  V10.7, so an app with "Sign in with Google" keeps the client's requirements (V10.1, V10.2, V10.3,
  V10.5) and is no longer asked about a server it does not run. Running one is a way of using OAuth, so
  `oauth = false` answers it without anyone rewriting a manifest, while an explicit yes always wins over
  that entailment. It has a corroborator, from which dual-purpose libraries — Authlib above all — are
  deliberately absent: putting `authlib` back in its package list undid the fix and passed the entire
  suite, so there is now a test that writes a `requirements.txt`. See DESIGN, "Using OAuth and being the
  authorization server". For v1 no requirement moves buckets; only the exclusion reason changes.

- ~~**Threat modeling that does not depend on the AI tool.**~~ Done. Asked for by the owner on 25 September
  2026. The investigation is done (session securevibe-e8): `docs/THREAT-MODELING.md`. In short, v1's
  rule-based STRIDE model (32 threats citing 80 different requirements, decided by about 20 facts about the app) needs no
  AI, and `sv` already knows nearly every fact it asks; ported to a data file, each threat would show
  what the evidence says about it (found, checked in part, not verified, cannot place) and never that
  it is mitigated. Three pull requests. The owner answered the three
  questions on 25 September 2026: no likelihood/impact scoring, v1 to read the same data file later,
  and a section of the report rather than a file of its own. **Claimed on 25 September 2026 by session
  securevibe-e8.** All three are done: the rules as data, each threat's status from the evidence,
  a "Threats" section in the reports, and twelve threats for what v1 did not model (MCP tools,
  retrieval, several services, WebSockets, several tenants): 42 threats, 115 citations. Left over: v1
  reading `data/knowledge/threats.json` in place of its own rules, a change to v1's design engine that
  the owner has agreed to and that is its own piece of work.

- ~~**AISVS, beyond applicability.**~~ Done on 25 September 2026 by session securevibe-e8. Semgrep's
  AI rules now name eight AISVS requirements (C2.1.6, C2.2.1, C7.1.2, C7.3.1, C9.1.2, C9.3.1, C9.5.4,
  C10.4.2) through a new `findings_against` list: a finding is evidence against them, and a clean run
  credits none, because these patterns can show a control missing and never present. See DESIGN,
  "AISVS from semgrep's AI rules". Left over: `sv`'s own code rules match a call and its arguments,
  and every one of these is a flow from one place to another, so none was written. Seen firing in a real
  run: 11 of the 24 rules, in Python and JavaScript; the rest are the same patterns for other vendors.

- ~~**Shell scripts.**~~ Done on 25 September 2026 by session securevibe-e8. `.sh` and `.bash` are
  read as `shell`, every rule is taught it or says why not, and a new rule,
  `ast.download-piped-to-shell` (V15.2.4), finds `curl … | sh` and its relatives. See DESIGN, "Shell
  scripts". Left over: unquoted variables are ShellCheck's, which cannot write SARIF; a request value
  copied into another variable before it reaches a path or a redirect is not followed.

- ~~**Signed-in checks in one container.**~~ Done on 25 September 2026 by session securevibe-e8. Every
  request is now an `exec` into one sidecar started per run, not a container of its own: a signed-in run
  of `examples/notes-with-users` went from 11–13 seconds to 4.3, with the same answers. See DESIGN,
  "One sidecar per run".

- **Corroborators for the remaining claims.** `multiple-services` done on 25 September 2026: gRPC and its `.proto`
  contracts, AsyncAPI documents, message-broker clients, microservice frameworks and service discovery,
  in eight ecosystems and ten languages. A `docker-compose.yml` is deliberately not evidence — most
  single apps ship one with only a database in it — and a test pins that. Left over from it: reading a
  compose file for two or more services with their own `build:` would be the strongest evidence of all,
  and needs the scanner to read YAML contents, which it does not. **Claimed on 27 September 2026 by session
  securevibe-e8**, at the owner's asking ("continue to work off items in the backlog, your choice"),
  as a narrow reading of the compose file rather than a YAML library. **Done the same day:** a `docker-compose.yml`,
  `docker-compose.yaml`, `compose.yml`, or `compose.yaml` with two or more indented `build:` lines
  answers `multiple-services`, naming the file; one build beside a database image still does not, and a
  commented-out `build:` is not counted. Read as lines, so a service written on one line (`web: {build:
  .}`) is missed, which only leaves the answer where it was. Allowing one build, never reading the file,
  and counting a comment are each caught. Services that call each other over
  plain HTTP stay invisible. Eleven of the twelve were written on 24 September 2026;
  `shared-hostname` is recorded as uncheckable instead (`noCorroborator`), because it is a fact about
  deployment that the repository does not hold. What is left is the weaker half of what was written:
  `ai-history` and `multimodal-ai` lean almost entirely on source patterns, and `public-api` cannot see
  a key checked by hand against a query parameter. Each is a data entry, not machinery.
  **A corroborator for `web-search`** (the answer added on 27 September 2026, which nothing reads from
  the code yet): **claimed on 27 September 2026 by session securevibe-e8. Done the same day:** the
  search services' libraries (Tavily, Exa, SerpApi, DuckDuckGo) and, in the code, `web_search` and
  `web_fetch`, the tool types Anthropic's and OpenAI's APIs use, which is how the owner's app does it.
  The pattern also matches an app's own function of that name; that error adds the four requirements
  rather than removing any. Its witness is the owner's kind of call; dropping the entry, the
  `web_search` pattern, or the witness each turns a test red.

- ~~**A `.tsx` file is read with a grammar that has no JSX, and counts as read.**~~ Done on 25 September
  2026. `<button onClick={() => eval(q)}>` in a `.tsx` file was not found, and the report then listed
  V1.3.2 as *checked (ast.dynamic-code-execution over 1 typescript file)*. `.tsx` is now parsed with the
  TSX grammar, each rule's `typescript` query compiled a second time against it. And whatever the
  grammar, a file whose parse holds an error lands in `AstScan::unparsed_files`: its findings stand, but
  no rule that reads code may claim a clean result while it is there, and `sv check` and the report say
  which files. Breaking either half turns two or three tests red. `.jsx` needed nothing: the JavaScript
  grammar reads JSX.

- ~~**Dependencies `sv` declares it read, and cannot match.**~~ Done on 25 September 2026. A Go app
  declaring and using `github.com/gorilla/websocket` had V4.4.1–V4.4.4 excluded as "No WebSocket
  library is used": `go.mod` gives full module paths, the signatures named `gorilla/websocket`, and the
  comparison was exact, so no Go package signature had ever matched. A Go signature now matches the
  module path or its tail on a `/` boundary, with a `/vN` suffix set aside. Most Go names in both data
  files were also wrong in themselves — `goth`, `stripe-go`, `go-openai` are not what `go.mod` says —
  and are now module paths, with a test refusing a bare name; `autocert` is a package inside
  `golang.org/x/crypto` and never appears in `go.mod`, so it is found in source instead. And
  `build.gradle.kts`, the Kotlin default, is now read, for dependencies and for pinning.

- ~~**Secure by Design controls excluded on too narrow a question.**~~ Done on 25 September 2026, at
  the owner's request after review. RR-02, DM-03, AS-06, RR-03 and AC-01 each gained a second rule
  (`external-apis`, `payments`/`scheduler`, `internet`) so a single app that needs them keeps them;
  AS-07 lost its gate. Pinned per control and as the whole checklist for a single-service web shop.
  The last point from the same review — derived levels reported as ASVS ones — is the crosswalk item
  below, done the same day. (This entry was deleted by accident on 25 September
  2026 by the commit that finished the nested-manifests item, and restored.)

- ~~**SBD-AC-05's "no secrets in code" is what the credential scan checks.**~~ Done on 25 September
  2026. Every credential rule cites SBD-AC-05, so a committed secret is a finding against it, and a
  clean scan is shown beside it as *supporting* evidence while it stays not verified. That rule is
  general: a satisfied check about a manual-only requirement is never "checked". It corrected two
  overclaims already in every report — V13.3.1 (use a key vault) and V11.1.1 (a documented key policy)
  were listed as checked by a scan of source files.

- ~~**Dependency manifests are only read at the top of the repository.**~~ Done on 25 September 2026.
  `ecosystems::detect` walks the whole app folder (skipping installed dependencies and build output),
  so a `client/` + `server/` app has its dependencies read, its pinning judged per project, and its
  packages in the SBOM; every path it returns is relative to the app folder. A lockfile in a parent
  folder pins a project only when that folder is a workspace root whose member list covers it (npm and
  Yarn `workspaces`, `pnpm-workspace.yaml`, Cargo `[workspace]`, uv `[tool.uv.workspace]`): a stray
  root lockfile pinning an unrelated project below it would be a wrong statement in the direction that
  hides something. A nested project is named by its folder ("npm in server/") so two read as two.
  Left over: the adapters still look for their tool's config (`pyproject.toml` and the like) at the
  top only, and a Yarn Berry or Bun lockfile is not one `sv` reads. **Reading Yarn Berry and Bun
  lockfiles claimed on 27 September 2026 by session securevibe-e2**, at the owner's asking to pick a
  backlog item: pinning, the package list, and so the advisory check, for both. **Done the same day:** `bun.lock` and
  `bun.lockb` count as lockfiles (every Bun app had been told it had none); `bun.lock` and Berry's
  `yarn.lock` are read for the package list, and so for known vulnerabilities; `bun.lockb`, binary,
  says it cannot be read and names the text lockfile. Checked against lockfiles Bun 1.4.2 and Yarn
  4.18.1 wrote. See DESIGN, "Yarn Berry and Bun".

- ~~**Ground the Secure by Design levels in ASVS.**~~ Done on 25 September 2026, with the owner's
  agreement to the design. `data/sbd-asvs-crosswalk.json` maps each of the thirty-six controls to the
  ASVS requirements that ask the same thing — seventeen have counterparts, thirty pairs in all — and
  each pair carries a few words naming what the two share, which the citation guard holds against
  both texts. `Frameworks::apply_crosswalk` sets a control's level to the lower of its derived level and
  its counterparts' lowest, so it can only ever come into scope sooner; a control with no counterpart
  is level 1, shown at every target. Every control records where its level came from, the report lists
  the controls above the target with that basis instead of calling them "above the ASVS level", and a
  satisfied check about a counterpart is shown beside the control as supporting evidence. Loading
  refuses a crosswalk that leaves a control out or cites an id that does not exist.

- ~~**A suppressed finding makes a tool's run look clean, and it is credited.**~~ Done on 25 September
  2026 by session securevibe-e8: bandit and gosec are made to report what they were told to skip, every
  suppressed result is shown and says so, and what cannot be shown withholds the clean-run credit.
  `docs/DESIGN.md`, "A tool told to look away, corrected again". What was found: `# nosec` on a line makes bandit report nothing
  about it, so `sv` sees an empty findings list, calls the run clean, and credits every requirement
  that adapter's rules map to — including V1.2.4 for a file whose `search()` concatenates user input
  straight into SQL. Verified by running bandit, not reasoned about:

      def search(db, q):
          return db.execute("select * from notes where t = '" + q + "'").fetchall()  # nosec

  Bandit's SARIF for that file holds `"results": []` and, in `runs[0].properties.metrics._totals`,
  `"nosec": 1` and `"skipped_tests": 0`. So the tool says plainly that it was told to look away, and
  nothing reads it: `grep -rn nosec crates/ data/` finds nothing at all.

  This is the missing-tool rule again, one layer in. A tool that is not installed already reports
  *not run* rather than a clean pass, because absent must never read as clean; a tool that ran with
  its mouth taped shut over the one line that matters is the same thing in a better disguise, and it
  is worse, because the report says an automated check looked.

  The fix is cheap for bandit, since the count is already in the report: read
  `metrics._totals.nosec` and `skipped_tests`, and where either is non-zero say how many suppressions
  there were and withhold that adapter's clean-run credit. gosec's `#nosec` and semgrep's
  `// nosemgrep` need the same treatment and neither could be checked here — gosec is not installed,
  and semgrep cannot start in this sandbox (`ca-certs: empty trust anchors`) — so what their reports
  carry is unverified. If it turns out they say nothing about suppressions, the honest interim is to
  count the markers in the files that were scanned.

- ~~**Semgrep skips some folders by default and does not say so.**~~ Done on 25 September 2026 by
  session securevibe-e8. Semgrep is handed the app's code files by name, which it reads whatever any
  ignore file says, and the list of files it writes (`--json-output`) is checked against the list it
  was given; a file it was given and did not read, or no list at all, withholds the clean-run credit.
  `docs/DESIGN.md`, "Semgrep is named the files". Left as it was: `build/`, `dist/`, `vendor/` and
  the rest of `SKIP_DIRS` are not handed to it, because no check in `sv` reads them. If built output
  can be what ships, that is a question about `SKIP_DIRS` for every check at once, not about semgrep.

- ~~**Script in a page written the way a browser reads it and a parser does not.**~~ Done on 27
  September 2026 by session securevibe-e8. The premise was wrong in a way that mattered: where an
  unquoted value ends is not a question with two answers, because the HTML standard ends it at whitespace
  or `>`. And "each keeps a page unread" was not true of all of them. Checked against pages a browser
  runs, three were counted as read with nothing taken out: an unquoted handler
  (`<button onclick=eval(location.hash)>`), a `/` between attributes (`<img/onerror="…">`), and
  `href="java&#9;script:…"`, where the entity became a tab only after the disguise check had looked. All
  three were false cleans. `html_fragments` now walks start tags the way a browser's tokenizer does and
  reads each value the way the URL standard does (put back character references, strip the ends, remove
  tabs and newlines, then read the scheme). What is still named rather than read, and why, is in
  DESIGN, "A page of markup is not a hole in the coverage". This is also the owner's decision the same
  day, asked through another session: read them the way a browser does.

  Verified: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the full workspace suite.
  Broke eight things on purpose and watched each go red: unquoted values dropped, tabs kept in a URL, the
  `javascript:` count switched off, raw-text bodies read as tags, `/` not a separator, the near-scheme
  check switched off, numeric references not decoded, and unknown named references ignored. The last one
  was caught by nothing at first, because its only fixture (`&alpha;()`) was also refused by the grammar.
  A second fixture, `x&alpha;(1)`, parses when the reference is left as written, and now catches it.

- ~~**Dart and Swift.**~~ Done on 25 September 2026 by session securevibe-e8. Both grammars, with every
  one of the nine rules either taught each language or saying why there is nothing to find in it
  (`nothingToFind`). The same change made the claim per rule: a rule that met a language it was not
  taught claims nothing and the report names it, which showed gaps in the older languages, most filled
  at once, and the last three in the entry below. See DESIGN, "Thirteen languages".

- ~~**Three rules still untaught a language.**~~ Done on 25 September 2026 by session securevibe-e8.
  Shell commands in Rust (the `Command::new("sh").arg("-c")` chain and the `.args([...])` array), weak
  ciphers in Rust (RustCrypto's types and the `openssl` crate's functions), and redirects in C (a
  `Location:` header printed by hand). Every rule is now taught every language `sv` reads, and a test
  pins it. What each misses is in DESIGN, "Thirteen languages".

- ~~**Semgrep's pack reaches 31 of the 50 requirements its map names.**~~ Done on 26 September 2026: the honest
  count, the AI pack for apps that use AI, and option B (`p/default` beside `p/security-audit`) after the owner
  reviewed the rules' license; the coverage count reaches 46 of the 50. What stays open is the separate entry
  "Later, and not a priority" below. Found on 26 September 2026 by the registry run (session
  relaxed-nobel-27acfa). The adapter runs `p/security-audit`,
  which loads 225 rules, 162 of them mapped. The map has 1,022, and `docs/COVERAGE.md` counts all of
  them, so it credits semgrep with 19 requirements no rule the adapter loads can reach: all eight
  AISVS ones and V1.3.6, V1.3.12, V3.3.2, V3.5.5, V4.4.1, V9.1.1, V9.2.1, V11.3.3, V11.4.2, V11.4.3,
  and V16.2.5. Measured by loading each pack over the fixture app:

  | Packs | Rules loaded | Requirements reached (of 50) |
  |---|---|---|
  | `p/security-audit` (today) | 225 | 31 |
  | and `p/ai-best-practices` | 252 | 37 |
  | and `p/default` | 1,087 | 41 |
  | and `p/default` and `p/ai-best-practices` | 1,114 | 46 |
  | and all of those, `p/owasp-top-ten`, and `p/secrets` | 1,185 | 47 |

  Two ways to make the coverage document true, and the owner's to choose: run more packs (more
  findings, a slower run, and the same network fetch), or count only the rules the adapter really
  loads. The two are not exclusive. Either way, the packs are the registry's, and they change without
  `sv` changing, so whatever is chosen should be re-measured when the map is regenerated.

  **For every session working on `sv`: these rules are not being run.** Since step 1 below,
  `docs/COVERAGE.md` no longer counts them and lists them by name. Before it, the instruction was to treat a
  requirement that semgrep reaches only through its map as *not checked*, whatever `docs/COVERAGE.md`
  said, and not to build on the 19 listed above as if semgrep covered them. That includes the eight
  AISVS requirements "AISVS, beyond applicability" credited to semgrep's AI rules; none of those rules
  is in `p/security-audit`.

  **Recommendations.** Each session adds its own below, under its name, as its own commit, and the
  owner decides. Asked for by the owner on 26 September 2026.

  - *Session relaxed-nobel-27acfa.* Three steps, in this order:
    1. **Make the count honest first, and without changing what runs.** Keep a dated snapshot of the
       rule ids each pack loads (`data/semgrep-packs.json`), written by a script like
       `tools/pwned_passwords.py` on a machine that can reach semgrep.dev, and have `coverage.py`
       credit semgrep only with mapped rules in a pack the adapter runs. A test holds the adapter's
       `--config` list to the packs in the snapshot, so adding a pack without measuring it fails.
       This is cheap, changes no finding, and stops the document claiming 19 requirements nobody checks.
    2. **Then add `p/ai-best-practices`.** 27 rules, six more requirements (31 to 37), most of them
       the AISVS ones the map was built for, and Semgrep only runs a rule on files in its language, so an
       app without AI code pays almost nothing. It is where the AI rules actually live.
    3. **Then decide on `p/default` with numbers from the evaluation harness, not from me.** Adding it
       reaches 46 of the 50. Measured over the example apps and v1's app template (197 files), it
       added about 3 seconds and 3 findings, all on the template, and all three are false alarms:
       `detect-non-literal-regexp` on patterns built from the app's own settings and route names, not
       from anything a visitor types. Three mistaken findings on one app is small, but the owner reads
       every finding, so it should be counted over the golden apps with `npm run eval` before adopting.

    Not recommended: `p/owasp-top-ten` and `p/secrets` on top. They add one requirement between them
    (V11.3.3), and `sv` already has its own secret scanner.

  - *Session securevibe-e8.* Agreed on the order, with three things to know before each step:
    1. **The overstatement is in `docs/COVERAGE.md`, not in anybody's report.** A report already
       credits a clean semgrep run only with rules its own SARIF says were loaded, and only for a
       language the app is in (`credit_loaded_only`, `crates/sv-check/src/adapters.rs`), so no app has
       been credited with the 19. Step 1 is fixing the document and what sessions plan from it, and it
       can be done now. When it is, `coverage.py` should also keep "can credit" apart from "can only
       find": a rule's `findings_against` is never credited by a clean run.
    2. **`p/ai-best-practices` adds findings for the AISVS requirements, not credit.** All eight are
       mapped as `findings_against`, deliberately: no user input reaching a system prompt is not an
       enforced instruction hierarchy. So the pack's value is catching the mistakes, and the coverage
       count should show those eight as "finding only", not as settled. Still worth adding, for that.
    3. **Prefer the mapped rules to the whole of `p/default`.** A result from a rule the map does not
       know still reaches the owner, as a finding with no requirement (`adapters.rs`, module notes),
       so every unmapped rule in a pack is one more thing a non-programmer may have to read and
       dismiss; `p/default` adds about 835 rules to reach four more requirements. Semgrep takes a
       registry rule by id (`--config r/<rule-id>`, repeatable), so the adapter could add just the
       mapped rules those four need beside the two packs. Whether that resolves and how long it takes
       has to be measured on a machine that reaches semgrep.dev, which this session cannot. If it
       does not work, the evaluation harness decides, as above.

    Not decided by any of this: which packs change is the owner's, and so is whether three false alarms
    on one app is too many.

  - *Session securevibe-e9.* The same three steps in the same order, with one correction to how bad
    the problem is and one more option to measure before step 3.
    1. **The per-run report is already honest; the document is what overstates.** Semgrep's adapter
       reads more than one language, so `clean_run_evidence` counts a rule only when the SARIF says
       it was loaded. A clean run of `p/security-audit` has never credited any of the 19, and the
       eight AISVS rules are `findings_against`, which credit nothing even when loaded. What is wrong
       is `docs/COVERAGE.md` and anything a session built on it. So step 1 is a documentation fix
       and should be judged as one: `coverage.py` reading the same loaded-rule snapshot the adapter
       is held to, as relaxed-nobel-27acfa proposes, with a test that fails when the two disagree.
       Worth doing first, and no report changes.
    2. **`p/ai-best-practices`: yes, and it carries little risk.** Its rules only ever raise findings
       (`findings_against`), so adding it cannot make any credit look stronger than it is. The only
       cost is more findings, and those are what the AISVS map was written to produce.
    3. **Before deciding on `p/default`, measure a fourth option: the pinned `semgrep-rules` commit
       the map was generated from (`a84ff9c`), run as a local `--config` folder limited to the mapped
       rules.** The loaded set would then equal the map by construction, so the count cannot drift
       when the registry changes a pack, and a run needs no fetch from semgrep.dev. It may be slower
       and noisier than `p/default`, which is why it is a thing to measure and not a recommendation
       yet. Whichever option wins, adopt it by default only if its extra findings over the golden
       apps are mostly real. Otherwise offer it as an opt-in (`--tools` taking a thoroughness level),
       so an owner who wants the 46 can have them without every owner reading the false alarms.

  - *Session keen-meninsky-691a27.* Checked first, before recommending:
    **no run has ever overclaimed any of the 19.** `clean_run_evidence` (`crates/sv-check/src/adapters.rs`)
    takes a rule as evidence only when `loaded.contains(rule_id)`, and that gate is on for any adapter
    whose `language` is `*`, which semgrep's is. So a clean semgrep run already credits only the 162
    mapped rules the SARIF says were loaded, and the 19 stay *not assessed* in every report. The defect
    is confined to `docs/COVERAGE.md` and `tools/coverage.py`. That is worth saying plainly, because
    "19 requirements are never checked" reads like a live false claim to an owner and it is not one;
    nothing shipped needs correcting and nothing needs doing in a hurry.

    Given that, in order:

    1. **Make the count honest — but not by subtracting 19.** The document is wrong because it counts
       the map while the engine counts the loaded rules: two sources of truth for one question, which is
       why they drifted. Record the loaded-rule list from the registry run as a fixture and have
       `tools/coverage.py` intersect the map with it, the same set `clean_run_evidence` uses. One input,
       regenerable, and stale in a way somebody can see. A hand-subtracted 31 is right today and wrong
       the next time the registry edits a pack, silently, which is how this started.
    2. **Then add `p/ai-best-practices`.** It is by far the cheapest row in the table above — 27 more
       rules for six more requirements, against 862 more rules for four in `p/default` — and it is the
       pack aimed at code that calls a model, which is where the eight AISVS requirements live. Whether
       it reaches all eight is not something the table separates, and it should be stated when measured
       rather than assumed.
    3. **Leave `p/default` to the eval harness**, as relaxed-nobel says. Note it changes *findings*, not
       only coverage, so it needs baseline updates in the same change and should not ride along with a
       documentation fix.

    One caution for whatever is chosen: a pack's contents are the registry's and change with no change
    to `sv`, so today's number goes wrong without anything here moving. Whatever lands should carry the
    date it was measured and the `semgrep-rules` commit beside it, the way the map already records
    `a84ff9c 2026-09-22`, and re-measuring belongs in regenerating the map rather than in somebody
    remembering.

  - *Session relaxed-nobel-27acfa, answering keen-meninsky's question.* Which of the six
    `p/ai-best-practices` reaches is already measured: C2.2.1, C9.1.2, C9.3.1, C9.5.4, and C10.4.2
    (five of the eight AISVS requirements), and V1.3.6. C2.1.6, C7.1.2, and C7.3.1 are in no pack
    measured here. As securevibe-e8 notes, the five AISVS ones are `findings_against`: the pack can
    find them failing and never credit them.

  **The owner, on 26 September 2026:** leaning toward that order, and toward keeping the AI pack
  separate, so that `p/ai-best-practices` only runs against apps that use AI (the `ai` condition).
  **Step 1, the honest count, claimed on 26 September 2026 by session securevibe-e8**, from the
  registry run's own list of the rules `p/security-audit` loaded
  (`crates/sv-check/tests/fixtures/semgrep/semgrep-registry-1.176.0.sarif`); what runs is not changed.
  Steps 2 and 3 are not claimed: both need a machine that reaches semgrep.dev to measure.
  **Step 2, `p/ai-best-practices` for apps that use AI, claimed on 26 September 2026 by session
  relaxed-nobel-27acfa**, at the owner's asking; step 3 is not claimed. **Step 2 done the same day:**
  adapters can carry `conditional_args`, and semgrep adds the AI pack unless the app is known not to
  call a model; when nobody has said, it runs, because its rules only ever find something. AISVS goes
  from 2 to 6 by the honest count, 5 of them findings only, plus V1.3.6. See DESIGN, "The AI pack, for
  apps that may call a model".
  **Step 1 done the same day:** `data/semgrep-packs.json` (written by `tools/semgrep_packs.py`) records
  what each pack loads, and `coverage.py` counts semgrep only through those rules, lists the rest, and
  refuses a pack nobody has measured. Level 1 is 52 of 70 and Level 2 is 62 of 183 by the honest
  count. See DESIGN, "Counting semgrep by what it runs".

  **The owner's answer, 26 September 2026:** measure the fourth option too — the pinned
  `semgrep-rules` commit the map was generated from, run as a local folder — beside `p/default`,
  before deciding.
  **Step 3's measurements, the pinned rules beside `p/default`, claimed on 26 September 2026 by
  session relaxed-nobel-27acfa**, at the owner's asking. The decision stays the owner's.
  **Measured the same day.** Four options, each over ten targets with semgrep 1.176.0: the fixture
  app (one of each kind of fault, on purpose), the example apps, v1's app template, and the code of the
  owner's six built apps in `workspace/projects` (copied without `.env`, data, or keys). The runs are
  outside the repository; only these numbers are kept.

  | Option | Rules | Requirements (of 50) | Owner's apps, per app | Fixture findings | Owner's apps and template, findings |
  |---|---|---|---|---|---|
  | A. `p/security-audit` and `p/ai-best-practices` (today) | 252 | 37 | 2.7 s | 13 | 0 |
  | B. A and `p/default` | 1,114 | 46 | 4.8 s | 28 | 10 |
  | C. The pinned rules: `semgrep-rules` a84ff9c, only the 1,022 mapped | 1,022 | 50 | 40.5 s | 30 | 148 |
  | D. A and the 26 registry rules (`r/<id>`) that reach B's nine extra requirements | 278 | 46 | 11.0 s | 13 | 9 |

  What the numbers say:

  - **B finds real faults that A misses.** On the fixture, `p/default` added 15 findings (14
    distinct): SQL injection, SSRF, path traversal, command injection, and two TLS settings, all among
    the fixture's own planted faults. A missed every one, because `p/security-audit` holds the pattern rules and `p/default` holds the rules
    that follow data from a request to where it is used. The "requirements reached" count hides this,
    since SQL injection's requirement was already reached by other rules.
  - **On the owner's apps, B's extra findings were all false alarms.** Nine were
    `detect-non-literal-regexp` on patterns built from the app's own settings and route names, not
    from anything a visitor types. All nine fall on three lines of v1's template
    (`scripts/setup.ts:37` in every app, `src/features/ai/screening.ts:49`, and
    `src/features/apikeys/index.ts:44`), so it is three fixes in the template, not nine. The tenth was
    `missing-integrity` on an icon written inline as a `data:` address.
  - **D adds the requirements and none of the catches.** It aims only at requirements not yet
    reached, so it leaves out exactly the injection rules that made B worth having. It is also slower
    than B, because each rule is fetched separately.
  - **C matches the map by construction, and it costs a lot.** Semgrep loaded exactly the 1,022 mapped
    ids, when each rule file sits in a folder of its own lowercased name and each top-level folder is
    passed relative to the rules folder. But it took about 40 seconds an app, against 5 for B, and
    gave 148 findings on the owner's apps and template. The ones read were false alarms:
    `generic-api-key` on the file hashes in `securevibe.provenance.json`, `var-in-href` on `<%= appName %>`
    in a link's text, and `html-in-template-string` on an error message containing `<id>`. One was
    real and is `sv`'s own secret scanner's business: `FIRST-LOGIN.txt`, the one-time password v1
    writes into the app folder. Not traced: `innerHTML` in one app's `static/app.js`, which fills
    dashboard tiles and may or may not include text a person typed.
  - **C also runs into the rules' license.** The Semgrep Rules License v1.0
    (https://semgrep.dev/legal/rules-license) allows use "only for your own internal business
    purposes" and does not allow distributing the rules. So a pinned copy cannot be kept in this
    repository or shipped with `sv`; each owner's machine would have to fetch the commit itself. It
    would be a fetch from GitHub instead of semgrep.dev, which is no less network. Whether an owner
    fetching them for their own app counts as their internal use is a question for the owner, not a
    measurement. A related one: two test fixtures
    (`crates/sv-check/tests/fixtures/semgrep/*.sarif`) keep rule descriptions exactly as semgrep wrote them,
    and "any portion of those rules" is in the license's definition of the rules.

  **Recommendation from session relaxed-nobel-27acfa: B.** About 2 seconds an app buys the rules that
  find injection through a request, which A is blind to. Its false alarms on these apps were one line
  of v1's template and one inline icon. Fix those template lines at the source, and measure `p/default`
  into `data/semgrep-packs.json` in the same change. D is not worth it. C is not worth it as the
  default: ten times slower, far noisier, and the license stands in the way of pinning it here. Its one
  real benefit, a count that cannot drift, is already covered by the dated pack snapshot and its test.
  The evaluation harness was not run; these numbers come from six apps v1 actually built, which is
  what it would build, and it can still be run before adopting. The decision is the owner's.

  **The owner, on 26 September 2026:** leaning toward B, and wants the Semgrep Rules License looked
  at before anything more is built on semgrep's rules: both whether `sv` running them over an owner's
  own app is the owner's internal use, and the two SARIF fixtures that keep rule descriptions word for
  word. Not decided yet; B is not claimed.

  **The local-folder half was also claimed the same day by session securevibe-e8**, on its own
  branch; the claim reached `main` after relaxed-nobel's, so the two crossed. It was already measured
  by then, and is kept below relaxed-nobel's fuller run as a second, smaller measurement of option C.
  **securevibe-e8's measurement, the same day.** Semgrep 1.176.0 and `semgrep-rules` at `a84ff9c`, every rule the map
  names copied into one file with its registry id, so nothing is fetched from semgrep.dev:

  | Rule set | Rules | Requirements reached (of 50) | Findings on the examples and v1's template (174 files) | Time |
  |---|---|---|---|---|
  | `p/security-audit`, rebuilt from the commit | 225 | 31 | 3 | 5 s |
  | the map's own rules | 1,022 | 50 | 20 | 20 s |

  - **The local copy is the registry's.** The 225 `p/security-audit` rules rebuilt from the commit gave
    exactly the registry run's 13 results on the fixture app, rule, file, and line.
  - **What loads is the map, by construction.** The SARIF listed 1,022 loaded rules, the same ids as
    the map; none was missing from the commit. So the coverage count could not drift from what runs.
  - **The 17 extra findings are all on v1's template, and on reading, none is a real fault.** Six
    `var-in-href` on links the server builds itself (navigation, the checkout link, the authenticator
    link), six `html-in-template-string` on error messages that contain no HTML, four
    `detect-non-literal-regexp` on patterns from the app's own settings and routes, and one
    `unsafe-dynamic-method` on `router[method]` from a fixed list. The example apps got none. For
    comparison, `p/default` added 3 false alarms on a similar set (relaxed-nobel-27acfa, above): the map
    holds audit rules that `p/default` leaves out, and they are noisier.
  - **The rules' license** could not be read from this session; relaxed-nobel-27acfa's could, and
    what it says is above.
  - **A detail for whoever builds it:** semgrep puts the rule file's folder in front of each id, as a
    path relative to where it was started, so it must be started in the folder holding the file.

  Smaller than relaxed-nobel's run and consistent with it: on the owner's six built apps option C was
  twice as slow again, and far noisier, than on the examples and template alone.

  **The owner's decision, 26 September 2026:** B, `p/default` beside the two packs, for now. (An
  earlier "19 more requirements definitely seems worth it" was made on securevibe-e8's smaller numbers
  before relaxed-nobel-27acfa's run and license reading reached the owner, and is replaced by this.)
  Adopting B, as relaxed-nobel-27acfa proposed: add `p/default` to the adapter, measure it into
  `data/semgrep-packs.json` in the same change (which needs a machine that reaches semgrep.dev), and
  fix the three lines of v1's template that make its regular-expression false alarms. **Claimed on
  26 September 2026 by session relaxed-nobel-27acfa**, at the owner's asking, template fix included.
  **Done the same day:** `p/default` runs beside `p/security-audit` and is measured into
  `data/semgrep-packs.json`; the coverage count reaches 46 of the 50. Two of the three template lines
  are fixed at the source (`scripts/setup.ts`, and the API-key route matching, now
  `src/lib/route-path.ts`). The third, the prompt-injection ruleset in `src/features/ai/screening.ts`,
  stays, because its patterns come from the operator's own data file and not from a visitor; apps with
  the AI feature show that one false alarm. See DESIGN, "`p/default` beside `p/security-audit`".
  The owner's condition above still holds: the license questions are looked at before B is built.

  **The owner, on 26 September 2026, on the license:** reviewed the Semgrep Rules License and judged
  this use acceptable. The license allows use for one's own purposes, personal or a company's own, and
  not reselling, and nothing here is monetized or sold, which the owner says will not change. The
  answer came to both questions above, running the rules and the fixtures' rule descriptions, so the
  condition on B, that the license is looked at first, is met. If selling or licensing `sv`, or
  bundling it into something sold, is ever raised, semgrep's rule map is the first thing to
  re-examine: it is the largest single piece of borrowed work here, and this condition governs all of
  it.

  **The golden apps, at the owner's asking, the same day.** The evaluation harness built all five
  golden apps without AI (all built, 0 regressed against their baselines), and the four options ran
  over each app's code:

  | Option | Per app | Findings across the five apps |
  |---|---|---|
  | A. Today's two packs | 3.0 s | 0 |
  | B. A and `p/default` | 5.3 s | 8 |
  | C. The pinned rules | 39.0 s | 148 |
  | D. A and the 26 rules | 10.9 s | 8 |

  B's eight are the same three template lines as before (`scripts/setup.ts:37` in all five,
  `src/features/ai/screening.ts:49` in two, `src/features/apikeys/index.ts:44` in one), so there are no
  new kinds of false alarm, and fixing those lines clears all of them. D found the same eight. C's are
  the kinds already read: `var-in-href` 68, `generic-api-key` 57, `html-in-template-string` 10, the
  same eight regular expressions, and `unsafe-dynamic-method` 5. None of the options found a real
  fault in the golden apps. That fits apps built from a hardened template; it is also why B's value
  shows on the fixture's planted faults rather than here. The recommendation stands: B, with those
  three template lines fixed at the source.

- **Later, and not a priority: could C's false alarms be brought down, if `sv` is to reach all 50?**
  Asked for by the owner on 26 September 2026, for if the semgrep coverage is expanded down the line.
  Not claimed. The license question above comes first, since it decides whether C can be run at all.
  Where to start, from both measurements: which rules make the false alarms (`var-in-href`,
  `html-in-template-string`, `detect-non-literal-regexp`, `unsafe-dynamic-method`, and
  `generic-api-key` on the hashes in `securevibe.provenance.json`), counted per rule against real
  faults over the golden apps and the examples; what `sv` knows that semgrep does not (a value from
  the app's own settings, a test file, a template that escapes by default, a file `sv` writes); and
  whether findings only the added rules make should be shown apart, as "worth a look".

- **Grammars for C++, and for HTML's embedded scripts.** C++ is the last language the scanner counts and
  cannot parse. Assessed on 25 September 2026 against what AI coding tools actually produce: C++ matters
  least of the candidates for web apps. Dart, Swift, and shell, which were worth more, are done (above). Since the claim became per rule, a grammar added without queries
  no longer turns silence into a clean claim; it moves the silence from the whole app to the rules not
  yet taught that language, and the report names them. **Claimed on 27 September 2026 by the v1 builder
  ("Vibe-coding builder"), at the owner's asking to keep working the backlog.**

  **The C++ half is done the same day.** tree-sitter-cpp needed no new query shape: dumping the parse tree
  for `fopen`, `system`, `MD5`, and a `printf`-style `Location:` header showed the same `call_expression`,
  `argument_list`, `identifier` and `string_literal` nodes tree-sitter-c already produces, so all twelve
  rules reuse C's query and function names outright — see DESIGN, "C++". What that does not reach is
  written down rather than found by surprise later: a scoped call (`std::system(cmd)`, `::remove(path)`,
  `Logger::log(msg)`) parses as a `qualified_identifier`, not the plain `identifier` these queries match,
  and is not seen; neither is `std::cout << "Location: " << u`, a chain of `binary_expression` nodes and
  never a call at all. Both are real C++ idioms and both are named gaps, not silent ones.

  The two "no grammar" tests this item said would break did, and now use Objective-C (`.m`/`.mm`,
  recognized by the scanner and deliberately left without a grammar) in C++'s place, continuing the same
  device through Ruby, C#, and C++ before it — so the property "an unread language silences every rule"
  stays exercised rather than becoming untestable the day the list of examples is empty.

  Verified: `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and the full workspace test suite
  (630 tests in `sv-check` alone) pass; `every_real_rule_is_taught_every_language_it_meets_here` now
  includes a `.cpp` file. Broke four things on purpose and watched each fail the test that should catch
  it: a rule missing its cpp query, a flipped witness, the grammar arm removed (23 tests fail, since
  loading the rules fails), and the Objective-C extension mapping removed (the "nothing can parse
  silences everything" test loses its fixture). `docs/COVERAGE.md` needed no regeneration: cpp adds no
  ASVS requirement no other language already reaches for these twelve rules.

  **HTML's embedded scripts** had been read since 25 September (DESIGN, "A page of markup is not a hole
  in the coverage"). The part still named rather than read, which was unquoted values and disguised
  schemes, was done on 27 September 2026 under its own entry, "Script in a page written the way a browser
  reads it".

- ~~**More AST rules.**~~ Done on 25 September 2026 — four more in `data/ast-rules.json`, nine in
  all. `ast.file-path-from-value` (V5.3.2), `ast.weak-hash-function` (V11.4.1), `ast.weak-cipher`
  (V11.3.1, V11.3.2) and `ast.open-redirect` (V3.7.2), across eight or nine languages each. Two new
  fields made them possible without Rust per rule: `argumentPatterns` (the call is a finding only when
  its argument says so — `createHash("md5")`, not `createHash("sha256")`) and `safeArgumentPatterns`
  (named idioms that are not findings — `redirect(url_for(...))`, `secure_filename(...)`,
  `path.join(__dirname, "a.html")`, a bare ALL-CAPS constant). A pattern for a language with no
  query is refused at load. Every (rule, language) pair has a found and a not-found witness, and a
  test fails if one is missing; breaking each filter in turn turned two to seven witnesses red.
  Left over, each its own decision rather than a data entry:
  - **Predictable randomness (V11.5.1) was not written.** `Math.random()` and `random.choice` are fine
    for shuffling a list and wrong for a reset code, and what decides it is where the value goes,
    which a single query cannot see. A rule without that would mostly report shuffles.
  - ~~Express's two-argument `res.redirect(301, url)`, Ruby's `send_file`, Java's `Paths.get`, and
    PHP's `include $x` are missed.~~ **Claimed on 26 September 2026 by session securevibe-e8. Done the
    same day**; see DESIGN, "Four ways of writing a path or a redirect that the rules missed". Ruby's
    `redirect_to` was already covered, and both rules now have queries in all fourteen languages,
    Kotlin, C, and Rust included, so the rest of this bullet was out of date.
  - The file-path rule is low confidence on purpose: it cannot tell a request value from an internal
    one held in a lowercase variable.

- ~~**Read Maven and Gradle version ranges.**~~ The lockfile check reports them as not assessed, because
  pinning lives in `pom.xml` and `build.gradle` rather than a lockfile. Reading a range out of either
  would turn an open question into an answer. **Claimed on 26 September 2026 by session relaxed-nobel-27acfa.
  Done the same day.** `sv-scan::jvm` reads each build's versions, including properties, parents in the
  folder, Gradle variables, and version catalogs. All exact passes V15.1.2, a range, `LATEST`, `1.+`, or
  a snapshot is a finding at its line, and a version `sv` cannot work out stays not assessed, with the
  line. The entry was also wrong about Gradle: only Maven was not assessed. A Gradle build without
  `gradle.lockfile` was reported as pinning nothing even when every version was exact, and that finding
  is gone. See DESIGN, "Reading Maven and Gradle versions".

- **More adapters.** Semgrep's rule map is done (25 September 2026, session securevibe-e8): 998 of the
  1,321 security rules in `semgrep/semgrep-rules`, generated by `tools/semgrep_rule_map.py` and
  checked against a real SARIF run. See DESIGN, "Semgrep: a thousand rules". Left over from it: the
  map is keyed on the registry's form of a rule id, which was reproduced rather than observed, so one
  run of `p/security-audit` on a machine that can reach semgrep.dev is owed (the fixture's README has
  the command). **That registry run claimed on 26 September 2026 by session
  relaxed-nobel-27acfa**, which can reach semgrep.dev; the rest of this entry is not claimed. **The
  run is done, the same day.** The form was right, except that the registry lowercases the path part,
  which three keys got wrong and are corrected. It also found that the pack loads only 225 of the
  map's rules; that is its own entry, "Semgrep's pack reaches 31 of the 50 requirements its map
  names", below. See DESIGN, "Semgrep: a thousand rules". `staticcheck` and `phpcs-security-audit` are each a data entry.
  `eslint-plugin-security` was looked at on 25 September 2026 and not added. Semgrep's JavaScript rules
  already include its rules under their own names (`detect-child-process`,
  `detect-eval-with-expression`, `detect-non-literal-fs-filename`, `detect-non-literal-regexp`,
  `detect-pseudoRandomBytes`, and others), mapped to ASVS, so it would add the same checks twice. And
  ESLint 10 loads its plugins from the folder it runs in: run over an app, it would load an
  `eslint-plugin-security` from the app's own `node_modules`, which runs that app's code on the
  owner's machine outside the network fence, while TypeScript needs a parser the plugin does not
  bring. The shape to keep: SARIF only, not installed means not run, and a rule mapped only where it
  can be shown to be about its requirement.

- **More probes.** **Claimed on 26 September 2026 by session securevibe-e9.** The first four questions are asked (`sv-check/src/probes.rs`); they are the ones that
  can be asked of any app by somebody who has not signed in. Redirects, HSTS on an HTTPS app, method
  handling per route and anything that sends data need either a manifest describing the app's routes or a
  session — both of which are their own items below.
  **Six more done on 26 September 2026**, all asked of any app by somebody not signed in: unused methods
  on the health path (V4.1.4), JSONP (V3.5.6), documentation and monitoring pages (V13.4.5), version
  numbers in headers and error pages (V13.4.6), `Cross-Origin-Opener-Policy` (V3.4.8), and a
  Content-Security-Policy that reports nowhere (V3.4.7). Level 2 goes from 63 to 64 of 183, Level 3 from
  6 to 11 of 92. Redirects and HSTS stay open: inside the fence the app is reached over plain HTTP, so
  whether it redirects to HTTPS, or sends HSTS there, is `sv probe`'s to ask of the live site. See
  DESIGN, "Six more questions for anybody".

- ~~**Seeded users.**~~ Done on 25 September 2026. `[stack.run.users]` in securevibe.toml says how
  accounts are made (`seed`, run in the app's container with the accounts in its environment, or the
  app's own `signup`), how to sign in and out, which pages are private or admin-only, and how one user
  creates a record another must not read. `crates/sv-check/src/signed_in.rs` asks seven things as two
  test users and an admin — private pages (V8.2.1), admin pages (V8.2.1), another user's records
  (V8.2.2), a forged cross-site request (V3.5.1), a new session at sign-in (V7.2.4), sign-out ending it
  (V7.4.1) and the session cookie's attributes (V3.3.2, V3.3.4) — and every one shows its own setup
  worked first or reports not assessed. Anti-forgery tokens are read from hidden fields (quoted or not),
  `<meta>` tags or cookies. Tested against a scripted app with each flaw switchable (every rule found by
  at least two tests), and under Docker against `examples/notes-with-users`: the correct app has all
  seven confirmed, and a copy with five flaws switched on had all five found. That run also found two
  bugs in the suite, both fixed: unquoted attributes hid the token, and a sign-out the app refused was
  reported as a sign-out that did not end the session. Left over: V3.3.1 (Secure) cannot be judged over
  the fence's plain HTTP; input handling (V5, V1.2) still needs knowledge of the app's forms.

- ~~**Load the Secure by Design checklist.**~~ Done on 24 September 2026. Left over: `multiple-services`
  had no corroborator until 25 September 2026 (see the corroborators item). The
  checklist's `scoring`, `processSteps`, `principles` and `escalationTriggers` are read past, not used.
  It was found on 24 September 2026 while chasing bad citations: `sv --help` had named the checklist
  since the first commit while `Frameworks::load` read ASVS, AISVS and Appendix C only.

- ~~**Clean coverage from the remaining checks.**~~ Done on 24 September 2026. Every check that can find
  something now also reports what it examined and found nothing wrong, each failing closed on its own
  coverage. Left over: `sv report` does not run the bill of materials or the advisory comparison at all
  — they live in `sv check` and `sv audit`, the latter because it needs an offline database path — so a
  report says nothing about dependencies either way. That is a bigger change than this item and is not
  what this entry asked for, but a reader of the reports would not guess it. **Since then:** the report
  runs the advisory comparison with `--advisories` (DESIGN, "In the report too") and asks the bill of
  materials for its gaps (DESIGN, "The report asks the bill of materials"). It still leaves out the bill
  of materials' own finding, and that turned out to matter: see "The report credits V15.1.2 for a lockfile
  it could not read" under Next.

- ~~**Credit the app's own test suite.**~~ Done on 24 September 2026 — `crates/sv-check/src/suite.rs`.
  A test counts only for a requirement it names, and only when the suite it belongs to passed. Matching
  tests to requirements by their words was considered and refused: it would credit a requirement on the
  strength of a name somebody chose for other reasons. v1's mismatch check is ported as it was —
  reporting, never withholding credit, because about a third of its flags are honest tests phrased
  differently. What is left over from this item: the suite's coverage is still all-or-nothing on one
  exit code, so a suite with one failing test credits nothing. Reading a test runner's own report
  (JUnit XML, `pytest --junitxml`) would fix that and is its own item.

- ~~**Almost every rule-to-requirement citation is semantically wrong.**~~ Done on 24 September 2026 —
  remapped, and guarded by `crates/sv-check/tests/citations.rs`. Left over: Brakeman's rule ids had
  never been seen in a real SARIF run — done on 25 September 2026: they were mostly wrong (BRAKE0002 is
  cross-site scripting and was mapped as SQL, BRAKE0013 is eval and was mapped as OS command injection,
  BRAKE0016 is file access and was mapped as SQL, BRAKE0102 is a 2016 Rails CVE, not a secret, and
  BRAKE0000, SQL injection itself, was unmapped). Remapped from `warning_codes.rb` in Brakeman 8.0.6,
  forty ids, and tested against a real run over `crates/sv-check/tests/fixtures/brakeman/app` whose
  output is kept beside it; fifteen ids appear in that run, and the guard cannot catch a swap between requirements that
  share vocabulary. Found on 24 September 2026 by the
  test-crediting mismatch check, firing on the example app written to demonstrate it. ASVS 5.0 `V1.2.1`
  is *output encoding for an HTTP response, HTML or XML document*. It is cited by `ast.sql-built-by-hand`,
  `ast.dynamic-code-execution`, bandit's `B608` and `B307`, gosec's `G201`/`G202`, and three Brakeman
  rules — none of which have anything to do with output encoding. Parameterized queries are **V1.2.4**;
  OS command injection is **V1.2.5**, not the `V1.2.2` that nine adapter rules cite (`V1.2.2` is URL
  encoding). The pattern repeats across the file: eight rules cite `V11.3.1` (block modes and padding)
  for weak hashes, which are `V11.4.1`; `G404` (`math/rand`) cites `V11.4.1` (hash functions) when
  unpredictable randomness is `V11.5.1`; `G304` (file paths) cites `V1.2.3` (JavaScript encoding) when
  it is `V5.3.2`; `G107` (SSRF) cites `V1.2.4` (database queries) when it is `V1.3.6`; `G402`/`B501`
  (TLS verification off) cite `V13.1.1`, which asks that communication needs be *documented*.

  This is the third time this class has been found here — five checkers citing `AC-NN` ids that did not
  exist, then every probe citation being semantically wrong — and it is the failure the whole product is
  most exposed to, because a wrong citation is not visibly wrong. It puts a finding, or a green line,
  against a requirement nobody examined, and the reader has no way to tell.

  Two things are needed, and the second matters more. Remap `data/adapters.json` and `data/ast-rules.json`
  by reading each requirement's text. Then write the guard that would have caught it without an example
  app happening to exist: every citation in the data files compared against the requirement it names, by
  shared vocabulary, the same comparison `suite.rs` already makes for tests. A citation nothing checks is
  a citation that drifts.

- ~~**Read the test runner's own report.**~~ Done on 24 September 2026. Left over: matching is an exact
  identifier match, so jest — which concatenates its `describe` blocks into the reported name — mostly
  will not match and its tests stay uncredited. A runner that reports a name unlike the declaration
  loses coverage silently rather than loudly. The parser understands JUnit XML only; TAP and the
  runners that emit their own JSON are not read.

- ~~**The MCP server.**~~ Done on 25 September 2026. `sv mcp --root DIR` speaks MCP over stdio
  (`crates/sv-cli/src/mcp.rs`, no SDK) with four tools: `securevibe_spec`, `securevibe_check`,
  `securevibe_explain` and `securevibe_write_report`. `securevibe_check` is `assemble_report`, the
  function `sv report` now calls too, so a model is told exactly what the written report says, gaps first.
  Every path is resolved against `--root` and refused outside it, `..` and symlinks included; a report is
  written only below the app. Starting the app and running other people's tools are not offered: each
  runs code, and that stays the person's decision at a terminal. Left over: MCP resources (the report
  files as resources rather than paths) and progress notifications for a long check.

## Decided, not yet written down as ADRs

**All three written down on 27 September 2026 by session securevibe-e8**, in a `docs/adr/` of `sv`'s
own, numbered after v1's so that a number always means one decision (`docs/adr/README.md`). Each one was
checked against the code and the history before it was written, and two were not quite true as stated here:

- ~~Corroboration only ever moves toward more requirements applying, never fewer.~~ **ADR-015.** True for
  every question the owner is asked. The derived conditions, which nobody is asked, are the exception: a
  scan that finds no XML or GraphQL library answers "no", and those requirements stop applying. The record
  says so rather than repeat the rule without it.
- ~~The OWASP data files are shared with v1, not copied.~~ **ADR-016.** True until 26 September 2026.
  Since the move there are two copies, `main`'s and the `v1` branch's, and a correction to one does not reach
  the other. Eight of the eleven files in `data/knowledge` are v1's alone, and editing them changes nothing
  `sv` does.
- ~~`sv` never writes application code.~~ **ADR-017.** True. It lists what `sv` does write into an app's
  folder (`security-notes.md`, its section of `AGENTS.md`, the reports), none of which the app runs.

The nine references to ADR-012, in `DESIGN.md` and in four files of three crates, now say it is v1's, and the
index says where it lives. **Not settled, and named in the index:** ADR-012 also ruled out SecureVibe writing
its own static-analysis rules for other languages. `sv` has since written them for fourteen, and no record
revisits that ruling. Whether one should is the owner's question.

**The owner answered on 27 September 2026:** the ruling needs updating. A superseding record covering
the decision that `sv` checks apps in many languages, with its own rules among the checks, is **claimed
the same day by session securevibe-e8** and drafted as ADR-018. **Accepted by the owner the same day**, and
done: `docs/adr/ADR-018.md`.
