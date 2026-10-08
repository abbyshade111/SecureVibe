# Outside tools run for at most half an hour, with only the environment they need (5 October 2026)

The deep review's improvement 3: `sv` started each outside tool with the owner's whole environment and waited for it
however long it took. A tool stuck on one file held `sv report` for ever, and every key in the owner's environment
reached a program reading somebody else's code (ADR-018, Later).

- **`finish`** runs a tool and stops it at its limit: half an hour for a run and for CodeQL's step before it
  (`TOOL_SECONDS`, or the entry's own `time_limit_seconds`), and a minute for asking a tool its version. A run that
  was stopped is not read, and says it was stopped; a version that did not come makes the tool broken, not missing.
  The tool leads a process group of its own on Unix, and the whole group is stopped, since Semgrep does its work in
  a second program. Its stderr is read as it comes, so a tool never waits on a full pipe.
- **`prepared`** clears the environment and hands on only `PASSED_ON`: where programs, the home folder, and the
  temporary folders are, the language, a proxy and certificates, and where Java, Go, and Python keep what they need.
  Then `GOTOOLCHAIN=local`, so a Go tool uses the Go installed here rather than fetching the one an app's `go.mod`
  names, and the adapter's own settings, such as Semgrep's `SEMGREP_ENABLE_VERSION_CHECK=0`.

What is not done: a tool that needs a variable not on the list fails, and says so through its own error; the list
grows when one does. Not run against the real tools in this session, none of which is installed here; the tests use
the stand-in scripts the adapter tests always have.

How it is held: `a_tool_that_does_not_finish_is_stopped_with_what_it_started_and_not_read`, with a tool that starts a
second program and hangs; `a_tool_is_handed_only_the_environment_it_needs`, with a tool that writes out its
environment; and `a_tool_that_does_not_say_its_version_is_broken_not_waited_for` (`crates/sv-check/src/adapters.rs`).
Six guards were undone in turn: the cleared environment, `GOTOOLCHAIN`, the stopped run not being read, the group
being stopped, the group being made, and the limit on the version. Each was caught.
