# A preflight of the run settings (5 October 2026)

Item 5 of "The loop", and ADR-035. `sv run` can test an app only if the code gives it what `[stack.run]` says, and in
the trials it was the run, after the build, that found it did not. `sv preflight [PATH]` and `securevibe_preflight`
read the app's files against the settings, with nothing run, and answer for each thing the run will need: the start
command and image; listening on `0.0.0.0` and reading `PORT`; the seed's file, and the `SV_` accounts it is given
(the admin's only when there are admin pages); tables made by the app and not only by the seed; and every path and
sign-in field the settings name. Each answer is "looks right", "look at this", or "could not tell", and the result
opens by saying that "looks right" means the text was found, not that it works. It credits nothing.

**How it was checked.** Each of its eleven rules was broken in turn and the suite run; each was caught by the test
named for it. On the examples, `notes-with-users` has nothing to look at, and `flask-booking`, whose start command
binds `127.0.0.1`, has exactly that to look at. On the loop builds it found its own first mistake: two Sonnet builds
seed with `python app.py seed`, and it read that as tables made only by the seed; where the seed is the app's own
file, the answer is now "could not tell". What only describes the app (`securevibe.toml`, Markdown, plain text) is not
read, so a path named in prose does not count as found.

**What it cannot do.** A route built from parts reads as "look at this", and a name in a comment as "looks right";
each answer says what was looked for, so a person can judge. Whether builders use it, and whether it raises how many
builds `sv run` can test, is for the loop's next trial: item 3 ran on the pilot's `sv`, without it.
