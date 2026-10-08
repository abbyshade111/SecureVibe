# Bandit handed the app's own Python files, and a run that did not finish (4 October 2026)

S7 and H7 of the deep review, both about what `sv` takes from an outside tool as having been read.

**What Bandit is handed.** Bandit was given the app folder (`--recursive {dir}`), and read what it found there in
its own way: it followed a link out of the app and read the file the link pointed at, which `sv`'s own reading
refuses, and it read `vendor/` and the other folders of installed code `sv` leaves out (139 of family-hub's Bandit
findings were Flask's own code). It is now handed the app's Python files by name, from `sv`'s own listing, as
Semgrep already is (`-- {files}`, run in the app folder). `{files}` now gives a tool that reads one language only
the files of that language (`code_files_for`), so Bandit is never handed JavaScript to fail on; Semgrep, which reads
many, is still given every code file. An app with no Python is not handed to Bandit at all, and the report says
so. Brakeman still takes the folder: it reads a Rails application as a whole, not files one by one.

**A run its own report says did not finish.** A tool's SARIF can say that part of its run failed:
`executionSuccessful: false` on an invocation, or a notification at level `error` in `toolExecutionNotifications`
or `toolConfigurationNotifications`, usually naming the file. Bandit writes both when it skips a file it cannot
parse, and nothing read them, so a run that had skipped the file was credited as clean. Now any such report keeps
the run from counting as clean, for every outside tool: its findings still stand, the run is listed as partial,
and the report names what it could not get past (up to five, then a count). A warning does not count; a run marked
unsuccessful with nothing said does. The message for a partial run now says the tool did not look at all of the
app, which covers this and Semgrep's unread files, where it used to say the tool was told not to look.

Five guards broken in turn, each caught: every language's files handed over, the report's own word ignored,
warnings counted as errors, an unsuccessful run believed, and Bandit handed the folder again. Tested with stand-in
programs that write the reports and record what they were handed; Bandit itself was not installed where this was
written, so the first run of the real program on the new arguments is CI's or the owner's.
