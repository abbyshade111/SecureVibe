# `ast.download-piped-to-shell` flags a download read as data

**Status:** done, as its markers read on 8 October 2026

**Claimed on 28 September 2026 by session
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
