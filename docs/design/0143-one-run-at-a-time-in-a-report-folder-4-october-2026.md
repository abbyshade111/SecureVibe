# One run at a time in a report folder (4 October 2026)

On family-hub (3 October) the owner and their AI coding tool each ran `sv report --run --tools` at about the same
time. Both wrote `securevibe-report`; the good run finished first, and the owner's, which failed, replaced its
report two minutes later with nothing to say so (BACKLOG, "What the owner hit building family-hub", item 2).

**A lock, taken before the run and held until its report is written** (`crates/sv-cli/src/report_lock.rs`).
`sv report` and the MCP server's `securevibe_write_report` both take `.securevibe-report.lock` in the report folder
before reading the app. A second run refuses at once, naming the run that holds the folder: its command, process
number, and when it started. It refuses rather than waits: a run takes minutes, and a command that sits silent
because of another run nobody remembers starting looks stuck. The folder checks that used to come at the end
(a link, someone else's files) now come first too, so a refusal comes before the wait rather than after it.

**A lock a killed run left does not block.** The lock is the operating system's own (`File::try_lock`), which it
lets go when the process ends, however it ends. The backlog suggested checking whether the holder's process number
is still running; the operating system's answer is better, since a process number can be reused, or belong to
another machine or container. The lock file still says who held it, so the next run says that run stopped before
it finished and that its report may be part-written. A disk that will not lock is said, and the run goes on.

**A report records when its run started and the hash of the `securevibe.toml` it read** (`run_record` in
`report.json` only; the pages for people stay the same from run to run). Before writing, a run reads the report it
would replace: if that came from a run that started later, it keeps the newer report, says so, and says whether the
two read the same file. With the lock this happens only where the lock could not hold: a disk without locks, or an
`sv` from before this. A `securevibe.toml` that changed while the run went on (family-hub's own start-command fix)
is said on the terminal and as a gap in the report.

**Found while testing:** a second run started as the first was writing its marker found the folder unmarked, with
the marker's part-written file in it, and called the folder someone else's. `sv`'s own part-written files
(`.report.json.sv-4321`) now count as `sv`'s, and the run holding the folder clears ones a stopped run left. And
taking the folder before the run made it, and marked it, before there was a report to put in it, so Ctrl-C during
`sv report --run` left an empty folder where it used to leave nothing (`interrupt.rs` caught it). A run that ends
without a report now takes away the marker it wrote and the folder it made, if nothing else is in it; Ctrl-C, which
leaves through `std::process::exit`, lets go first.

Tested with real processes of the real binary (`crates/sv-cli/tests/report_lock.rs`): a run kept going by `--run`
and a test command that sleeps, a second run at the same time, a `kill -9`, and an older report put beside a newer
one. These need a container backend; without one, the two-run tests say so. Each guard broken in turn was caught:
no lock (three tests), a leftover lock taken as a live one (two), no age check (one), no changed-file check (one),
the lock never removed (five), part-written files taken as someone else's (one), a failed run's folder left
(two), and Ctrl-C not letting go (one). Shared tool reports and container
names, which two runs at once also collide on, are S6 and S10, not changed here.
