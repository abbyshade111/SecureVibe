# Files `sv` writes, never through a link and never over the app's own (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 1, S3 to S5) reproduced three ways `sv` wrote where it should not.
The MCP tools had refused links since "Writing nothing through a link"; the command line had not.

- **`sv rules` and `sv notes`** wrote `AGENTS.md` and `security-notes.md` with `std::fs::write`, which follows a
  link: one pointing outside the app had its target read in and then written over. Both now refuse a link at that
  name before reading it, and write through `write_without_following` (a new file, renamed into place). The check is
  in `write_notes` itself, so `sv notes`, `securevibe_notes_file`, and `securevibe_record_answer` all have it.
- **`sv bundle`** wrote its zip the same way, and worse, `bundle::resolve_for_writing` resolved links all the way
  to the file, so a link at `app-securevibe-bundle.zip` beside the app was turned into its target before anything
  could look at it. The function now resolves links in the folders on the way (why it exists: `/var` on a Mac) and
  never the file name, and the zip is refused if that name is a link, then written under a new name and renamed.
  This first fix missed the resolving; the test with the review's own fixture caught it.
- **A report given `out` "."** (or `--out` at the app) was written into the app, and on a disk that does not tell
  capitals apart its `security.md` replaced the app's `SECURITY.md`. `write_report_files` now refuses a folder that
  holds anything but the names `sv` writes, unless it carries `sv`'s marker; and refuses, marked or not, a folder
  holding a name that differs from one of `sv`'s only in capitals, since the marker can be planted. A folder from
  before the marker, holding only `sv`'s names, is still written to; so are new and empty folders, and the default
  `securevibe-report`.

Eleven guards were broken in turn; ten were caught, two of them only after a test was added (a marked folder
holding a file of the owner's, and an app holding a `README.md` a loose match would take for the marker). The
eleventh, writing the zip by rename rather than in place, only matters in the race below, which no test can stage. A
filter for staging files left by an interrupted run was taken out instead of tested: the marker is the first file
written, so such a folder is always marked.

What is still open: a write races with a link put at the name between the check and the rename, which
`write_without_following` closes by renaming over it (its own test); and S6 to S13 of the same review.
