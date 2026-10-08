# A copy of another project's library is listed apart (6 October 2026)

Semgrep follow-up 1 (BACKLOG, the false-alarm research of 4 October). Of the 555 false alarms measured over 25 apps,
315 were in copies of libraries kept inside the app: jQuery, Bootstrap, Moment.js, DataTables and the like in
`public/`, `static/`, or `assets/`. None of the true findings was. The code is the library's, not the app's, and the fix
for a problem in it is a newer copy, or loading the library from its package, never an edit.

- **Known by the library's own file, as retire.js knows one** (`crates/sv-check/src/bundled.rs`): a string only that
  library writes, in its first 512 bytes (`jQuery v3.6.1`, Underscore's `define('underscore', …)`, `@license React`,
  and ten more), or the comment the file opens with when it names a version (`/*! FullCalendar v3.10.2`,
  `/** marked v18.0.13 - …`), a version without a `v` counting only in a comment marked `/*!`, `@license`, or
  `@preserve` and only with three parts. Not by the file's name, which says nothing about what is in it, and not by
  long lines, which the app's own built code has too. Only scripts and style sheets are looked at, their first 2 KB. An
  app's own bundle with a library further down is the app's, and so is RxJS's build, whose opening comment is the
  Apache license and names no library: missing a copy only leaves it where it was.
- **Listed apart, named, and still counted**, on test code's terms (ADR-023): `Finding::bundled_library` names the
  library and its version, the reports list such findings after the app's own under "in copies of other projects'
  libraries kept in the app" (or "in test or sample code, or in copies of other projects' libraries" when both are
  there), each says the fix is a newer copy, the summary at the top counts them apart, SARIF gives
  `inBundledLibrary`, and the MCP server lists them after the app's own. An app with no copy reads as it did.
- **Measured**: Rust's reading and a first version in Python agree on every file. Of the real library files at hand,
  Debian's jQuery 3.6.1 and Underscore (with and without its comment) and the browser builds in this repository's
  `node_modules` (React's nine, marked, URI.js, react-router's 32), every one with a banner or one of the strings is
  named; of the 661 JavaScript, TypeScript, and CSS files of this repository and v1, none is.

How it is held: three tests in `bundled.rs` (what is a library, what is not, the app's own bundle among them, and only
scripts and style sheets), two end to end in `crates/sv-cli/tests/bundled_apart.rs` (the copy's finding after the app's,
named, in SARIF and the summary; and a finding only in the copy still keeping V1.3.2 from being credited), and
`the_ai_tool_reads_the_apps_own_findings_before_those_in_a_copied_library` in `mcp.rs`. Fifteen guards were undone in
turn and each was caught; a sixteenth, skipping a version after the word "License" or "Version", carried no weight
beside the three-part rule and was taken out.
