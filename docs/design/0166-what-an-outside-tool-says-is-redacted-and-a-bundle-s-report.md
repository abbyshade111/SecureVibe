# What an outside tool says is redacted, and a bundle's report is scanned before it is zipped (4 October 2026)

The deep review of `sv` at `eff3f17` (part 1, S8) found a bundle that had left out the file holding a password, "so
the zip carries no secret", carrying the password four times inside `report/`. Bandit's B105 message quotes the value
it found ("Possible hardcoded password: '…'"), and a tool's words went into every report as the tool wrote them:
`secrets::redact_text` was used only for a failing test suite's output. Merging a tool's finding into one of `sv`'s
on the same line has not copied the tool's text since the merge kept `sv`'s words; a tool finding on a line of its
own, and anything a tool wrote to stderr, still came through whole.

**A tool's words are redacted as they are read** (`crates/sv-check/src/adapters.rs`). `run_all` and `run_all_in` now
take `sv`'s credential rules, and `run_one_in` redacts with them, through the same `redact_text` the test output
goes through: every finding's title, description, and fix (the tool's text) and its impact (`sv`'s, made from the
adapter's name, redacted anyway, since an unneeded redaction costs four characters and a missed one cannot be taken
back) (`redact_tool_text`); and every line of a tool's stderr a reason quotes, from the version question, the prepare
step, an exit code that means failure, and a run that wrote no report (`said`). Those lines were cut to 160 or 200
characters before; they are now redacted first and cut after, since a value cut short loses the quote that marks
where it ends, and with it its redaction. Everything downstream reads the redacted findings: report.json,
security.md, compliance.md, report.html, findings.sarif, the bundle, the MCP server's replies and resources, and
the terminal. `parse_sarif` stays a plain parser; redaction is the run's.

**A quoted value runs on past an apostrophe.** In a real report (family-hub under `--tools`) Bandit's B105 quoted a
message, `'Password changed. You've been signed out everywhere else.'`, and `redact_text` ended the value at
`You'`, leaving the rest showing; a password with an apostrophe in it would have shown its tail. A single quote
followed by a letter is now read as part of the value; a quote followed by anything else still ends it, so two
values side by side stay two.

**The bundle scans its own report before zipping it** (`refuse_a_credential_in_the_report` in
`crates/sv-cli/src/main.rs`), the review's suggested backstop. Every report file is read by the credential scan
(`scan_text`); anything it finds stops the bundle, and the refusal names the file, line, and rule, never the value.
It refuses rather than redacting the files, so a report in a bundle is always the one `sv` wrote. It also catches
what the report quotes of the app itself: a key in the app's name in securevibe.toml went into every report file,
while the bundle left securevibe.toml out for holding it; the message says to take the credential out of where it
was quoted from. For the scan to read `sv`'s own reports, `sv`'s redaction marker (`[redacted: Qv7r… (16 more
characters)]`, in exactly that shape) is now a placeholder rather than a value: before, the assignment rule read
`password: '[redacted: …]'` as a credential, and the first trial refused family-hub's bundle, naming 111 such lines.

**Tested.** `crates/sv-cli/tests/tool_messages.rs`: a stand-in Bandit (as `false_alarms.rs` makes one) reports
B105 on a line of its own, quoting a password in its message, its rule's description, and its help, and every other
tool `sv` knows is a stand-in that will not start and quotes the password as it says so. The password is built from
pieces at run time. The test first shows its search finds a planted copy, that the stand-in really quoted it, and
that both its finding and the other tools' words reached the report, then that the password is in no file
`sv report --tools` wrote, nothing it or `sv bundle --tools` printed, no entry of the bundle (which left
`config.py` out), no MCP resource or tool reply (`securevibe_check`, `securevibe_write_report`,
`securevibe_bundle`), and no zip the MCP server wrote. A second test shows `sv bundle` refusing a report that quotes
a key from the app's name, after showing the report really quotes it. Unit tests cover each stderr route with a
line long enough that cutting first would show eight characters of the password, the apostrophe, the marker read
back, and the backstop's refusal. With the real Bandit 1.9.4 and Semgrep, `sv bundle --tools` made bundles of
family-hub and another of the owner's apps, and family-hub's B105 message now reads `'[redacted: Pass… (53 more
characters)]'`; `sv bundle` without `--tools` made bundles of all five `examples/`.
Seven guards broken in turn, each caught: a tool's findings not redacted (two tests, the unit test and the end-to-end
one), its stderr not redacted (two), its stderr cut before redacting (one, the unit test: the end-to-end lines are too
short to be cut, and the unit test's are made to be), `sv`'s marker read as a credential (three: the unit test, the
backstop's, and the end-to-end test, whose bundle was then refused), an apostrophe ending a value (one), the backstop
never refusing (two), and the backstop not called (one, the end-to-end refusal).
