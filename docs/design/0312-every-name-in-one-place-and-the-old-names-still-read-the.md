# Every name in one place, and the old names still read: the rename to StackVet, step 1 (8 October 2026)


The first of three pull requests that build ADR-062 (backlog item 218), asked for by the owner on 8 October 2026 once
`stackvet.dev` and `stackvet.app` were theirs. The order is by blast radius: this one touches the crates below
`sv-cli`, which nobody else was changing that night; the second changes `sv-cli` (the manifest's name, the MCP
server's and its tools' names, `sv init`'s template) once #1108, another session's change to the same file, has
merged; the third changes the documents and the image's name, and makes the record accepted.

**One module for every name.** `sv_frameworks::names` holds each name the product carries, new beside old: the
product, the manifest, the report folder with its marker and lock, the bundle's suffix and comment, the config
folder, the MCP server and tool prefix, the Docker labels, the coding-rules markers, the image, and the one name
with no old form, the signature namespace, with the reason it has none. Every constant that spelled a name in the
crates below `sv-cli` now reads it from there; `sv_scan::ecosystems::REPORT_MARKER` and its neighbors keep their
paths and take their values from the module.

**The old names still read, the new ones written.** Each with a test of its own:

- A report folder carrying the old marker, or named by the old default name, is `sv`'s own (`has_report_marker`,
  `claims_to_be_report`), and the old marker and lock count among the names `sv` writes, so such a folder holding
  nothing else is written to as before; one holding a file of the app's is refused as before
  (`crates/sv-scan/tests/old_report_names.rs`).
- A rules block between the old markers in `AGENTS.md` is found and rewritten between the new; one old marker
  without the other is refused as before (`crates/sv-check/tests/coding_rules_old_markers.rs`).
- The signing key's folder: `~/.config/stackvet` when it exists or when neither does; `~/.config/securevibe`
  while only it exists, with `Key::old_folder_in_use` saying so for the command to tell the person. Nothing moves
  a key (`crates/sv-check/tests/key_folder_old_name.rs`). The sentence `sv review` prints is the second pull
  request's.
- The leftover cleanup (ADR-025) lists containers and networks under the old owner label as well as the new, so a
  run stopped outright before the rename is still cleaned up after it. Not held by a test: listing needs Docker,
  and the fake backend the tests use does not answer `ps`.
- A bundle ending with the old comment is still `sv`'s own to replace; a stranger's zip is still refused
  (`crates/sv-cli/tests/bundle_old_comment.rs`, through the binary).
- The signature namespace is the old one and the command is `sv`, by test (`crates/sv-frameworks/tests/names.rs`),
  so neither can drift with a later edit of the module.

**What `sv` still writes under the old name after this pull request**, by design, until the second: the manifest
is read as `securevibe.toml` and the default report folder is written as `securevibe-report`, both spelled in
`sv-cli`. The marker inside that folder is the new one, which the first bullet makes harmless.
