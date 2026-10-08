# Tools' reports in a folder of the run's own (4 October 2026)

The deep review's S6. Each outside tool (Bandit, gosec, Brakeman, Semgrep, CodeQL) writes its findings to a file that
`sv` then reads. That file used to have a fixed name, `sv-bandit.sarif` and so on, in the computer's shared temporary
folder, and `sv` read whatever was there once the tool stopped, whatever exit code it stopped with. Somebody else on the
same computer could put a clean report at that name beforehand, in a way `sv` could not remove, and Bandit was recorded
as run with nothing found. Two checks run at once read each other's reports.

Now three things hold:

- **A folder of the run's own.** `run_all_in` makes a new folder for each run (`PrivateFolder`): readable by this user
  alone (mode 700), with a name drawn from the system's randomness rather than the process id and the time, and made
  with a call that fails on anything already there, a link included. It is removed with everything in it when the run
  ends. If it cannot be made, no tool runs and each is reported as not run, with the reason.
- **The tool's own exit codes.** Each entry in `data/adapters.json` lists `finished_exits`, the codes with which that
  tool says it ran to the end, found something or not, taken from its own source: Bandit 0 and 1, Brakeman 0 and 3,
  Semgrep 0 and 1, CodeQL 0. Any other code, or a tool stopped by a signal, is reported as not run, and its report is
  not read: a tool that stopped part way can leave a report that looks clean. Brakeman's 7 is the case that matters
  most: files it could not read, and nothing found. Gosec ends with 1 both when it finds something and when it fails,
  so for gosec the exit code cannot tell them apart, and the report still decides.
- **Only a report written in this run.** Anything already in the report's place is removed before the tool starts, and
  if it cannot be removed the tool is not run. Afterwards the report must be a plain file: a link in its place points at
  something that was there before.

Seven guards undone in turn (the fixed name in the shared folder, mode 700, the exit codes, a signal, removal of an
earlier report, the plain-file test, and removing the folder), and each was caught by its own unit test in
`adapters.rs`.

What this does not cover: the review's S7 (Bandit follows links `sv` refuses), S8 (a secret quoted in a tool's message),
and H7 (a file Bandit could not parse, with exit code 0) are their own items.
