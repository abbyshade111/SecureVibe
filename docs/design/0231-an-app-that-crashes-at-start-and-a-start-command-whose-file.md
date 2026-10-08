# An app that crashes at start, and a start command whose file is not there (6 October 2026)

Two findings of the loop's item 6 (BACKLOG). Three Haiku apps crashed when they started, and each run said "Its last
output was: Traceback (most recent call last):", the first line, where Python says what went wrong on its last. The
hint after it, about an app listening on `127.0.0.1`, was beside the point. Two more builds wrote
`start = "python app.py"` with no `app.py`, and the preflight said nothing.

- **A crash is quoted by its error line** (`crash_line`, `crates/sv-run/src/docker.rs`): the last line of the app's
  output that names an error, read from the end past stack frames and what a runtime prints after them. A line names an
  error when it starts with an error's name (`KeyError:`, `sqlite3.OperationalError:`, Node's `Error:`), with Go's or
  Rust's panic, or ends with one in brackets, as Ruby writes it. An error's name ends in `Error`, `Exception`, or `Exit`,
  and its last part is capitalized, so a handler such as `server.onExit:` is not one. It is read by hand: `sv-run` has
  no pattern library and does not need one for this.
- **An app that did not crash is quoted by its last line**, not its first: one still running, or waiting, says the
  most there ("Running on http://127.0.0.1:5000").
- **A crash replaces the loopback guess.** `CannotRun::NeverReady` carries whether it crashed, and then the report says
  "That error is why: fix it, and run this again." in place of the guess about where the app listens.
- **The preflight names a start command's missing file** (`preflight`, `crates/sv-cli/src/preflight.rs`), the way it
  names a missing seed file, with "Look" as its answer. When the app has a build step, it adds that the step may make
  the file. Like the rest of the preflight, it credits nothing (ADR-035): the run stays the evidence.

How it is held:
- `a_crash_at_start_is_quoted_by_its_error_line` (`docker.rs`), with Python, Node, Go, Ruby, and a dotted Python
  name, and as controls a Flask app still running and two lines that only end in `Exit`.
- `an_app_that_never_answers_is_told_about_listening_on_loopback` (`lib.rs`), with a crash as its new case.
- `an_app_that_never_starts_is_not_assessed_rather_than_failed` (`crates/sv-run/tests/fence.rs`), in a real
  container: `false` prints nothing and is not said to have crashed; a start that prints a `KeyError` and exits is
  quoted by it and told that the error is why.
- `a_start_command_naming_a_file_that_is_not_there_is_said` (`preflight.rs`), with the build step and, as its control,
  the file present.

Nine guards were undone in turn, and each was caught. Three were missed the first time. The capital letter replaced a
check that the name begins with a letter, which nothing could break. A Docker case was added for `crashed` being
passed on, which only a real run reaches. The Ruby break did not compile, and the guard script now counts that.
