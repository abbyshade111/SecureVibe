# An app listening on 127.0.0.1 is named as the likely cause (4 October 2026)

family-hub's first `sv report --run` waited a minute and said only that the app never answered on its health path.
The AI tool had copied the starter file's own example, `uvicorn app:app --host 127.0.0.1 --port $PORT`. Inside its
container an app listening on 127.0.0.1 answers only itself, and `sv` asks it from a second container on the fenced
network (BACKLOG, "What the owner hit building family-hub", item 1).

**The example.** The starter file now says `--host 0.0.0.0`, with a comment saying why. No other place `sv` tells an
app or an AI tool where to listen named 127.0.0.1 or `localhost`: `data/`, `docs/prompts/`, the MCP server's text, and
the example apps already say 0.0.0.0 or say nothing. A test reads the example out of the starter file and runs it
through the same test as the warning.

**The message.** "Never answered" now says that an app listening on 127.0.0.1 or `localhost` cannot be reached, and to
have it listen on 0.0.0.0 at the port in `$PORT`. When the start command itself names 127.0.0.1, `localhost`, or `::1`
(`sv_run::loopback_named_in`), the message names it as the likely cause; otherwise it is "one common cause". When the
app's own output already says why (a read-only file system), that is said instead of the guess.

**The warning, not a refusal.** Before waiting, `sv run` and `sv report --run` print a warning when the start command
names one of those addresses, and start the app anyway: the command line is not where the app really listens, and an
app may bind elsewhere than its command suggests, in either direction. Only the name as a whole counts, so
`127.0.0.10`, `notlocalhost`, and `fe80::1` are not taken for it. A command that names 127.0.0.1 for another reason
(a self-check with `wget`, say) is warned about too; the warning says it may be wrong.

Tested with a real container: a busybox app listening on 127.0.0.1, which first shows it is up by answering itself,
is warned about, never answers `sv`, and is named as the likely cause; the same app on 0.0.0.0 answers and is not
warned about. Five guards broken in turn, each caught: the example put back (the starter test), the general sentence
removed (the message test), the detector made to find nothing (the detector test and the container test), the warning
not printed, and the address not passed into the message (the container test each).
