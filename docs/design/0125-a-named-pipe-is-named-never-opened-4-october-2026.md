# A named pipe is named, never opened (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 1, S12) found that a named pipe in the app hung `sv`:
`sv_scan::files::Listing` listed anything that was not a folder or a link as a file, and the first check to read a
pipe waited for something to write into it, which nothing ever does. A socket or a device would have been read the
same way.

The walk now lists only regular files. Everything else, and an entry whose kind cannot be read, goes into
`Listing::special` and is never opened, and is said, the way links are: `sv check` prints it, the report lists it as
a gap ("not an ordinary file"), the checks that read the app's files say they read part of it, and `sv bundle`, whose
walk is its own, lists it as left out with the reason where before it dropped it without a word.

Tested with a real pipe (`mkfifo`), in the walk's own test and end to end through `sv check`, `sv report`, and
`sv bundle`, each run given a minute before the test fails, since the fault is a hang. Five guards broken in turn, each
caught; undoing the walk's guard hung all three commands again.
