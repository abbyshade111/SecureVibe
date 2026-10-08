# Ctrl-C while an outside tool runs (8 October 2026)



From the review of 8 October 2026, item 1 (`docs/backlog/0188-from-the-review-of-8-october-2026-the-medium-and-low.md`). An outside tool run by `sv report --tools` or
`sv bundle --tools` leads a process group of its own, so the 30-minute limit can stop the tool and everything it
started. A side effect: Ctrl-C at the terminal reaches `sv` alone. Nothing on that path caught it, so `sv` ended where
it stood, and the tool ran on with no limit. The tools' private folder in the temporary folder and the report folder's
lock stayed behind, since a signal ends a Rust program without running any of its cleanup.

Now `sv` catches Ctrl-C (and a polite `kill`) before it runs any tool, with the handler `sv run` already uses
(`sv_run::catch_interrupts`), and tells the tool runner to ask it (`sv_check::adapters::stop_when`). Every program a
tool is made of starts in one function, `finish`. That function stops the program's whole group as soon as Ctrl-C has
been pressed, and once it has been, it starts nothing more, so no later tool starts, not even to say its version. When
the tools return, `sv` says "Stopped with Ctrl-C", lets go of the report folder, and ends with 130, the usual code for
Ctrl-C. Nothing is written, because what the tools got to is not a report of the app. The private folder is removed on
the way out, as after any run. A second Ctrl-C still ends `sv` at once, for somebody who would rather clean up by hand.
The MCP server never runs outside tools, so it is unchanged.

Tests: three in `crates/sv-check/src/adapters/interrupt_tests.rs` (a tool asked to stop ends with the program it
started; a tool nobody asks to stop runs to its end; nothing is started once Ctrl-C has been pressed, shown with a
program that is not there, whose start would fail), and one in `crates/sv-cli/tests/tools_interrupt.rs`. That test
runs `sv report --tools` with a stand-in Bandit that starts a five-minute program, sends Ctrl-C, and checks that `sv`
ends with 130 and says so, that the program is stopped, that the stand-in Semgrep after it is never asked to read the
app, and that neither the private folder nor anything in the report folder is left. Seven guards broken in turn, each
caught: no handler installed (1 test), the handler installed but the runner not told (1), no exit after the tools (1),
the report folder not let go of (1), the runner never asking (2), only the tool stopped and not its group (2), and a
program still started after Ctrl-C (1). The last needed a test of its own: a first version of the guard, in front of
each tool rather than each program, went red in no test, because `finish` already stopped the next tool's first
command the moment it started.
