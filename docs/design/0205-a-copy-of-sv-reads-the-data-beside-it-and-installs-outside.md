# A copy of `sv` reads the data beside it, and installs outside the build folder (5 October 2026)

BACKLOG, "A built `sv` cannot be moved", and its second form in my-first-app: `sv` read about twenty files of its own
from the folder it was built in, whatever `SV_DATA_DIR` said about the OWASP part, so a copy stopped working when its
build folder went, and so did the owner's `PATH` and the AI tool's settings, which named the build folder itself.
Recorded in ADR-036.

- **One place finds the data** (`crates/sv-frameworks/src/data.rs`), and every file `sv` reads at run time is found
  through it: `SV_DATA_DIR`, now the whole `data` folder; then beside the program, `data` or
  `../share/securevibe/data`, following a link to the program to where it really is; then the folder it was built
  from, which the Docker image keeps. A folder counts only when it holds the OWASP frameworks. A wrong `SV_DATA_DIR`
  is named, never passed over for another folder, and with no data folder at all every command stops at once and
  says each place it looked.
- **`sv --version` says which data it reads**, on a second line.
- **`tools/install.sh`** builds `sv` and puts it, with its data, in `~/.local/share/securevibe`, linked from
  `~/.local/bin/sv`. The owner's `PATH` and the AI tool's settings name the link, which does not change when the
  repository is rebuilt, moved, or removed. Run again after an update, it replaces the program and the data together;
  it never replaces a file at `bin/sv` it did not put there. `docs/GETTING-STARTED.md` and the README now install
  this way.
- **Not done: compiling the data into the program.** The loaders read files, and the owner edits rule data and
  expects the next run to use it; a program with its data beside it keeps both. A single file to download would need
  it.

How it is held: the six tests in `data.rs` and the four in `crates/sv-cli/tests/moved.rs` (above, in ADR-036), and
`the_version_names_the_build_and_its_commit`, which now reads the data line. Eleven guards were undone in turn and each
was caught; the one at first caught by nothing, following a link to the program, is caught by a test of its own,
since Linux already gives the program's real place and only macOS gives the link.

**8 October 2026 (backlog item 25(h)).** The install script builds with `--locked`, so the owner's copy is made from
the versions in `Cargo.lock` that the tests ran with (ADR-036, "Later, 8 October 2026"). The guide now says the
`target` folder the build leaves, 1 to 7 GB, can be deleted without stopping the installed `sv`, which is true
because of the copy described above. And the README's second paragraph sends somebody who is not a programmer to the
guide before the developer commands that follow.
