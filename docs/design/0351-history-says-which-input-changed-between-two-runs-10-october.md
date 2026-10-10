# History says which input changed between two runs (10 October 2026)


Backlog 0230: ADR-083's decision 3, item C of the observability review's part 3 (backlog 0226). Built by session
securevibe-e2.

**The problem.** The dashboard compared two runs when they were the same kind of run, at the same level, from the same
`stackvet.toml`, by the same `sv`. The security notes and the design decisions also credit requirements, and `sv`'s
data says what applies and what each check knows, so an edit to any of them moved requirements while the page set the
two runs side by side as if the app had changed.

**What was built.** Each report's `run_record` carries `inputs` (`sv_report::RunInputs`): the SHA-256 of the
security notes and the design decisions as the run read them, `null` for one that was not there, and of `sv`'s data
folder, every file by its name (written with `/` on every system) and content, in name order, hashed once per run
(`report_lock::data_sha256`). A kept run (`dashboard::Run`, format 3) copies them. `not_comparable_with` names the
input that changed: "your security notes changed between them, and with them what they credit", the same for the
design decisions, and "the same sv was given different data". Data that could not be read in one of the two runs is
not held against the pair. A record from before format 3 is compared as before, and when something moved, the page
says whether those inputs changed is not known.

**Not hashed, on purpose.** There is no review seal file: a seal is a line in `stackvet.toml` or one of the two notes
files, already covered. The keys that check a seal live in the person's settings folder and are secret; no hash of
them is kept in the report or the history.

**Tests.** `crates/sv-report/src/dashboard/inputs_tests.rs` (5) and `crates/sv-cli/tests/history_inputs.rs` (2:
through the real `sv` with a home of its own, two runs with the notes edited and the decisions added between them, the
report's and the kept runs' hashes checked against the files and against the data folder the test finds, and the page
naming the notes as why the runs are not compared; and the data hash moving with a file's content or name).

**Broken on purpose, each put back:** the notes' hash not kept (1 red, end to end), the decisions' hash not kept (1
red, end to end), the notes left out of the comparison (2 red), the data never differing (1 red), the "not known"
sentence left out (1 red), and the file's name left out of the data hash (1 red).

**Left for later in ADR-083:** a record for a failed run (decision 2), what remains of decision 4, and `sv compare`.
