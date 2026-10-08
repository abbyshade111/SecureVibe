# Semgrep without usage reporting, and Opengrep in its place (3 October 2026)

Semgrep is the one outside tool that connects to the internet: it downloads its rules from semgrep.dev each time it
runs. Measured on 3 October 2026, it also made a second connection on every run, to an Amazon server in Oregon. Three
runs each settled what it was. With `--metrics=off` the second connection was gone every time; with only
`SEMGREP_ENABLE_VERSION_CHECK=0` it was still there every time, and only the "a new version is available" notice went.
So it is semgrep's usage reporting, and the version check asks semgrep.dev, where the rules come from. Every one of
the twelve runs loaded the same 1,074 rules and found the same thing. The adapter now passes `--metrics=off` and sets
the version check off (`env` in its entry in `data/adapters.json`), so semgrep connects only to fetch its rules.
Connections were sampled about fifty times a second, which can miss a very short one.

When semgrep is not installed, Opengrep runs in its place (`stand_in`). It is the open-source fork of semgrep's
engine, and on 29 September 2026 it loaded the same rules, found the same things, and gave `sv` an identical report
(BACKLOG, "Evaluate Opengrep against semgrep"). The owner chose on 3 October to keep semgrep first and accept Opengrep
when semgrep is absent.

- **Only when semgrep is missing.** A semgrep that is installed and will not start is reported as that, with its own
  words, and Opengrep is not asked. A broken install is the owner's to fix, and running something else would hide it.
- **Its arguments are semgrep's, less what it refuses.** Opengrep stops at `--metrics=off` as an option it does not
  know (it has no usage reporting), so the entry names that argument in `leave_out`. The loader refuses a `leave_out`
  naming an argument semgrep is not given, since that would mean the stand-in is handed something no one checked it
  accepts.
- **The report says so.** The `examined` entry for `semgrep.` carries `stand_in`, a sentence naming Opengrep. A clean
  run is credited as "Opengrep (in place of Semgrep) over the code in this app", and a run that skipped part of the app
  says Opengrep skipped it. When neither is installed, the reason given names both.
- **The rules and the license are unchanged.** Opengrep runs the same registry packs from semgrep.dev, under the same
  Semgrep Rules License, so nothing about the owner's decision on that license changes.

`crates/sv-check/tests/stand_in.rs` plays both programs with two small scripts that write down how they were
started. It checks five cases: semgrep present, semgrep missing, neither present, Opengrep broken, and semgrep broken.
