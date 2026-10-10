# The MCP check still counts a large data file whose prose says "command"

**Status:** done, as its markers read on 8 October 2026

Noted on 29 September 2026 by the
cato-pipeline session: after the large-file work, `config.mcp-server-unpinned` is still not run on cato, because
NIST's 10 MB catalog uses the word `command` in its text, and a large file is counted as read only when it never
says `command`. That is the check working as written; narrowing it to a `command` key (`"command"` followed by `:`,
or `command =`) would let a prose file through while still catching a configuration. **Claimed on 29 September
2026 by session securevibe-e9**, at the owner's asking to continue with the backlog.
**Done the same day:** a large file's pieces are judged by the same `command`-key pattern every other file is
(`LAUNCHER` in `launch.rs`), not by the word. The catalog's prose counts as read and the check runs; a real
`"command": "npx"` in a large file still leaves it unread and named. Held by a unit test and the end-to-end one in
`crates/sv-cli/tests/examined.rs`, which failed on the old rule. See DESIGN, "A large data file no longer blocks
the credential scan or the MCP check", its "Narrowed" note.
