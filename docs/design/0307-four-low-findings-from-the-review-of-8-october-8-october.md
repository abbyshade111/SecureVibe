# Four low findings from the review of 8 October (8 October 2026)


From the review of 8 October 2026, item 6, its first four parts (`docs/backlog/0188-…`).

**A short value shown whole.** `Secret::redact` kept the first four characters of every value it masked, so a
four-character password in a web address was shown whole, and a six-character one nearly so. It now keeps at most a
third of the value, and never more than four characters: two of an eight-character value, none of a two-character
one. The length is still given, as it is the only way to tell two findings apart.

**Names a program prints a credential under.** `redact_text`, which masks text `sv` repeats and did not write (a
tool's message, a failing test's output), knew only the names the secrets scan uses for code. A token a failing test
printed as `Authorization: Bearer …` or `Set-Cookie: session=…` reached the report. It now also masks values under
`authorization`, `bearer`, `cookie`, `session`, `sessionid`, `otp`, `pin`, and `passcode`, each as a whole word of
the name (`x-session-id`, `otp_code`), so `spinner` and `mapping` are left alone, and the token after `Bearer` or
`Basic` in a header. The secrets scan of the app's code is unchanged: these names would make it report every session
id as a credential.

**A pipe named `securevibe.toml`.** The MCP server refused a link under the names it reads, and read anything else:
a named pipe there waited for ever for something to write to it, and with it the server's one thread for answering.
Anything under those names that is not an ordinary file or a folder is now refused, with the reason, before it is
read.

**A line break in a file name on screen.** `sv check` printed each finding's file and title as they were, so a file
named to end its line and start another put words of the file's choosing on a line of their own, reading as `sv`'s.
Both are now written on one line by `sv_report::one_line`, which the MCP server already used for the same reason,
its breaks shown as `\n`.

**Breaks.** Each failed a test: four characters shown whatever the length, the new names dropped, and the `Bearer`
pattern dropped (`crates/sv-check/tests/redact_printed.rs`); the pipe read (`crates/sv-cli/src/mcp/fifo_tests.rs`,
which waits 30 seconds for an answer rather than for ever); and the file name printed as it was
(`crates/sv-cli/tests/finding_lines.rs`). The title's `one_line` is not tested apart from the file's: no finding of
`sv`'s own has a line break in its title, and a tool's needs the tool.

**Still open in item 6:** header values quoted uncapped, IDN hosts in `sv probe`, the no-sidecar fallback, `image`
validation, the typed passphrase not zeroized, the DNS transaction id, a broken `adapters.json`, the exit without a
flush, the bundle's scratch folder, `report.html`'s Content-Security-Policy, and the install volume's cache key.
