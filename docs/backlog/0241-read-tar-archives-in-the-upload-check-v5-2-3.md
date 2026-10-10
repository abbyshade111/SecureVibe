# Read tar archives in the upload check (V5.2.3)

**Status:** open

From the open part of 0029, part 15. The compressed-bomb check reads zip and gzip, and a `.tar.gz` is already covered by the gzip reader. A plain `.tar` is not read. Build a small tar reader with no new dependency, as the zip and gzip readers were built (`crates/sv-check/src/signed_in/archives.rs`), and check it against Python's own `tarfile`. Refuse or judge it the way zip is judged: a tar whose stated sizes are false is a finding when accepted.
