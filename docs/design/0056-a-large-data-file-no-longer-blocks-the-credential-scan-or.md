# A large data file no longer blocks the credential scan or the MCP check (28 September 2026)

Found by a session on the owner's cato-pipeline project, which turns `sv report` into a plan of action
and closes an item when its finding stops appearing. cato vendors NIST's SP 800-53 catalog, 10 MB of
standards text in one JSON file, over the 2 MB `MAX_FILE_BYTES` every check reads. That one file left
the credential scan `partly` for the whole app, so a program reading `examined` could never treat a
missing `secrets.*` finding as fixed, and it left the MCP check unable to pass, since `mcp_servers`
read every JSON file and one it could not read stopped the clean result. Both were right by `sv`'s own
rules; the cost was that a file the owner knows to be data blocked two families for as long as it
was there, with nothing the owner could do. Three options were written up; **the owner chose the two
that do not rely on the manifest** (28 September 2026).

**Reading a file in pieces** (`Entry::in_pieces`, `sv-scan/src/files.rs`). A file over 2 MB and up to
256 MB (`MAX_PIECEWISE_BYTES`) can be read a piece at a time, holding one piece in memory. Each piece
has a part of its own (`keep`) and text around it: look-ahead, so a match that starts in the piece's
own part is whole, and look-behind, so a rule that asks what comes before a match (a word boundary)
sees the character the file has there, not the start of a piece. The owned parts tile the file: every
byte belongs to exactly one piece, and a match is reported by the piece where it starts. A character
cut by the end of a window waits for the next read instead of making the file "not text". Each piece
knows the line it starts on, so a finding gives the line an editor shows. The first version of this
had its overlap only as look-ahead, and the next piece's own part started after it: a strip of 64 KB
at every boundary belonged to no piece, and a key there would have been missed. The test that every
byte is owned exactly once was written to catch that, and it would have.

**The credential scan** reads a file over 2 MB in pieces of 1 MB overlapping by 64 KB, longer than any
credential shape or any line the assignment rule reads. The concern in `files.rs`, that a large file
is as likely to hold a hash as a key, is met by what is reported rather than by not reading: an
assignment the entropy rule finds in such a file is reported with low confidence, and a vendor shape
keeps its own, since a hash does not look like `AKIA` or `sk-ant-`. The clean result says how many
files were read in pieces. A file over 256 MB is still refused and named.

**The MCP check** already skipped every file whose text does not contain `command`: that is its rule
for a file it reads. A file over 2 MB is now searched for that word in pieces. Without it, the file
cannot start an MCP server by the check's own rule and counts as read; with it, the file stays unread
and named, "larger than 2 MB, and it mentions `command`", and the check says it could not finish, as
before. Nothing about a file's name or the manifest is trusted.

*Narrowed on 29 September 2026.* On cato the check still did not run: NIST's 10 MB catalog uses the
word "command" in its prose. The large file's pieces are now judged by the same pattern `launches_in`
applies to every file, a `command` key set to `npx`, `uvx`, `pipx`, `pnpm`, `yarn`, `bunx`, `pnpx`,
or `docker`, not by the word. A file with one stays unread and named ("larger than 2 MB, and it sets
`command` to a program that downloads what it runs"), since the server's arguments may lie across
pieces; one without counts as read. Going back to the word, or never finding the pattern, each turns
`a_large_data_file_that_never_says_command_does_not_block_the_mcp_check` red; the end-to-end
`a_large_data_file_leaves_the_credential_scan_and_the_mcp_check_finished` in `crates/sv-cli/tests/examined.rs`
now runs the catalog with the word in prose (finished) and with a `"command": "npx"` key (not run, naming the
file), and failed on the old rule.

On cato's reproduction (a `securevibe.toml`, an `app.py`, and a 3 MB JSON of plain text) the
credential scan is now `ran` and the MCP check is no longer not-run.

**Bundles follow.** `sv bundle` leaves out any file the credential scan could not vouch for, and a file
over 2 MB used to be one. Read in pieces, a clean one now goes into the bundle, and one with a key past
the 2 MB mark stays out as holding a credential, as any file with a key does. The bundle test's example
of an unread file was a 3 MB one; it now checks both sides.

**Broken on purpose eleven ways**, each restored from the bytes read before it, never from git. The
reader: no look-behind, caught by three tests; a strip at each boundary owned by nobody, four; lines
counted to the wrong place, four; a character cut by the window read as binary, two. The credential
scan: large files still refused, seven; a vendor match or an assignment counted outside its piece's
own part, two each; an assignment in a large file keeping its usual confidence, two; the clean result
not saying it read in pieces, two. The MCP check: a large file counted as read without looking, two;
a large file still blocking the check, two. The first pass found six of these caught by one test
each, and a second witness went in for every one: look-behind checked by the reader itself, a large
file of accented text, an assignment in the overlap on a line of its own (the assignment rule stands
aside for a vendor key on the same line, which is right, and which is why the first try at this
witness failed), the report's own words, and cato's reproduction run again with the word `command`
in the catalog, where the MCP check must still say it could not finish and name the file.
