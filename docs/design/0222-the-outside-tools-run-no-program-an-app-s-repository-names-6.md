# The outside tools run no program an app's repository names (6 October 2026)

ADR-032 holds `sv`'s own `git` to running no program the app's repository names: `core.fsmonitor` in a planted
`.git/config` runs a program on every `git ls-files`. The second weekly review of the decision records asked whether
the outside tools `sv report --tools` runs in the app's folder keep to it too. Read on 6 October 2026: Semgrep runs
`git ls-files` for any folder it is given, and kept to the record only because `sv` hands it files one by one; Opengrep
runs no git in that kind of scan; whether the closed `codeql` program runs git is not known.

At the owner's word, every outside tool now starts with git's `core.fsmonitor` set off in its environment
(`git::ENV_OVERRIDES`: `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=core.fsmonitor`, `GIT_CONFIG_VALUE_0=false`), set last in
`adapters::prepared` so no adapter's settings undo it. Any git a tool starts inherits it, and a setting given this way
wins over the repository's, from git 2.31; an older git ignores it, and with it the guard.

The test runs a stand-in tool, `git ls-files` in a repository planted with `core.fsmonitor`, once started bare (the
program runs: the control) and once through `prepared` (it does not), and holds that no adapter sets a `GIT_`
variable. Broken on purpose three ways: the guard left out and the count set to 0 were each caught; the value set to
`true` was not, and is not a break, since `true` turns on git's own built-in monitor, which runs no program the
repository names. Not run with Semgrep or CodeQL themselves, which are not installed here.

**The program itself (8 October 2026).** The review of `sv` that day found the hole one step earlier: an adapter's
command is a plain name, a name is whatever `PATH` says, and the tools start in the app's folder with the owner's
`PATH` passed on. `source .venv/bin/activate` in the app before `sv report --tools` puts the app's own
`.venv/bin/bandit` first, and a relative entry (`.`, or an empty one between two colons) names whatever is in the
folder a program starts in, which for the tools is the app's. Either way `sv` would have run a program the app's
author put there, with the owner's rights, in place of the tool. Now `adapters::located` finds each program through
`PATH` first, the way the system would, follows links, and refuses one that is inside the app or reachable only
through a relative entry: the tool is reported as not run, saying which program and where, and what to do (install it
outside the app; put its folder on `PATH` in full). Not even its version is asked. A program found nowhere is run by
name as before, so a tool that is not installed still reads as not installed; on Windows, which finds programs
through `PATHEXT` too, nothing changes. Held by `program_tests` (`PATH` given rather than read, so the process's
own is untouched) and `a_program_inside_the_app_is_not_run_and_the_same_one_outside_is`, whose control runs the
same script from outside the app. Broken on purpose (the inside-the-app judgment switched off): both caught.

**Brakeman's settings file (8 October 2026).** The review of `sv` that day said the app's `config/brakeman.yml`,
which Brakeman reads on its own, could name Ruby files for Brakeman to load (`additional_checks_path`), and rated it
high. Tried with Brakeman 8.1.0 installed for the purpose: it could not. Brakeman has ignored that setting in a
settings file since 3.6.2 (May 2017) unless asked with `--allow-check-paths-in-config`, and a planted check file
that writes a mark was not loaded; the same file on the command line (`--add-checks-path`) was. So the finding was
wrong as rated, and what stood was smaller: the file can still turn checks off (`skip_checks`) with no trace in the
report, which is why a clean run was withheld whenever the app had one, and `-c /dev/null` had not helped because
Brakeman takes the first settings *file* it finds, `-c`'s before the app's, and `/dev/null` is not a file. Now the
entry passes `-c {config}`, a placeholder `sv` fills with an empty settings file (`--- {}`) written in the tool's
private folder for the run, so Brakeman reads that and the app's not at all; `switched_off_by` is gone from the
entry, and a clean run is credited whether or not the app has a settings file. Shown with the real Brakeman
(`crates/sv-check/tests/brakeman_settings.rs`, which says so and checks nothing where Brakeman is not installed):
the control run without `-c` over the fixture app with a planted `skip_checks: [CheckSQL]` reported no SQL
injection, and the run through `sv` reported it. Shown without it by a stand-in that exits 9 unless its `-c`
names a file outside the app holding exactly the empty settings (`a_tool_that_asks_for_a_settings_file_is_given_an_empty_one_of_svs_own`),
with the control being the same tool asked without one.
