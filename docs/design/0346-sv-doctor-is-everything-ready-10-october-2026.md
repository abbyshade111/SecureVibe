# sv doctor: is everything ready? (10 October 2026)


Backlog 0217, part 3, narrowed as the owner chose on 9 October 2026 ("as recommended"). Built by session
securevibe-e2.

**The problem.** Setting up, a person finds out what is missing one failure at a time: the folder not in git, no
`stackvet.toml`, one that does not read, no start command in it, Docker not running. Each shows up only when the
command that needs it fails, worded for that command.

**What was built.** `sv doctor [PATH]` answers each of those in one plain line, marked *ready*, *not ready*, or
*can't tell*, in the order a person sets things up:
- which `sv` this is and where it reads its data (with no data, the command stops before it runs, as every command
  does under ADR-036, so that line can say *not ready* only when the code is reused elsewhere);
- whether the folder is in git, asked through the same guarded git as the checks (ADR-032);
- whether `stackvet.toml` (or the old name, said) is there and reads, with the reader's own error when it does not;
- whether it says how to start the app, by the run plan `sv run` builds, with that plan's own words for what is
  missing; *can't tell* when the file does not read;
- whether Docker can start the app, by `docker info` as `sv run` asks it. Inside StackVet's own container, Docker on
  the computer is not visible, so that line is *can't tell* and says `--run` needs StackVet on the computer itself.

It ends with how many things are not ready, or, when none is, that the setup is in place and that this says nothing
about whether the app is secure. It writes nothing and opens no network connection, so it does not say whether a
newer `sv` is out; the first line says so. The guide's install check names it.

**And through the MCP server**, in a second pull request the same day: `stackvet_status`, listed first, gives the
same answers, with what it quotes of the app (the folder's name and what `stackvet.toml` says) fenced (ADR-066, Later,
10 October 2026). Inside StackVet's container it does not ask Docker. Its tests are
`crates/sv-cli/src/mcp/status_tests.rs` (3); left unfenced, the fence test went red, and left out of the instructions,
the order test did.

**What it is worth.** Nothing, as evidence: it credits nothing. Each answer is only as good as the piece of `sv` it
asks, which is the piece the real run uses.

**Tests.** `crates/sv-cli/src/doctor/tests.rs` (7): a folder set up all the way, an empty one, a `stackvet.toml`
that does not read, one without a start command, the old name, inside the container (where Docker must not be
asked), and no data. `crates/sv-cli/tests/doctor.rs` (2) runs the real `sv` on an empty folder, and on a path that
is not a folder.

**Broken on purpose, each put back:** the git answer always *ready* (1 red), Docker asked from inside the container
(1 red), the closing line's "says nothing about whether the app is secure" removed (1 red), and a missing manifest
read as *not ready* to start rather than *can't tell* (2 red).
