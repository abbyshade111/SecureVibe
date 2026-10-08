# The MCP server in a folder, and one way to write a report folder (8 October 2026)

The architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October 2026", item 2,
second half) named two costs in `crates/sv-cli`. `mcp.rs` was 7,202 lines in one file, 62% of them tests, with seams
nobody had cut. And the sequence that writes a report folder (the folder claimed, the report built, a changed manifest
noted, an older report refused, the files written, the folder sealed, the claim released) was written out twice, in
`cmd_report` for `sv report` and in `write_report_into` for the MCP server's `securevibe_write_report`, so a guard added
to one and not the other was a silent difference between what the person gets at a terminal and what their AI coding
tool gets. Each of the lock (ADR-041), the seal (ADR-034), and the refusal of an older report had been added to both by
hand.

Three changes, none to what `sv` writes:

- **`mcp.rs` is the folder `mcp/`.** `mod.rs` keeps the server, its state, and the request dispatch; `protocol.rs` the
  JSON-RPC reading and replies; `confine.rs` the path confinement below the root; `resources.rs` the report folders
  offered as resources; `catalog.rs` the tool and prompt lists; `check_text.rs` the text of a check for the tool;
  `report_writing.rs` the `securevibe_write_report` tool; `tools.rs` the other tools; and `tests.rs` the tests, as they
  were. Nothing moved changed; the decision records that named `mcp.rs` name the new files.
- **One sequence for a report folder**, `report_folder::write_report_folder`, called by `sv report` and by the MCP
  server. What differs between the two is passed in: how the report is built, what the lock names the run, where a
  second run is told to write instead, and what is done with what `sv` says on the way (printed before the wait at a
  terminal, collected for the reply by the server). Its own tests show the claim is on the folder while the report is
  being built and gone once it is written, that a report from an older run does not replace a newer one, and that a
  build that fails leaves no folder behind. With the refusal of an older report removed on purpose, the second of these
  failed, and no test had before: the two copies had been held together by nothing but care.
- **One table of the five report files** (`report_files::REPORT_FILES`: each name, what kind of file it is, and how it
  is rendered), which `write_report` writes in order, the seal covers (`report_seal::SEALED`), and the MCP server offers
  as resources. The names were written out four times, held together by a test. `sv-scan`'s walk needs them too, to
  leave a report folder out, and that crate cannot see `sv-cli`, so the names are its (`REPORT_FILES` in
  `ecosystems.rs`, from which `REPORT_FOLDER_NAMES` is built) and the table in `sv-cli` is held to them by the compiler:
  a name that differs between the two does not build.

Also: `ReportOptions::reading_only(caller)` and `ReportOptions::asked_of(caller, ...)` replace the seven places that
each wrote the three "why not run" sentences and three `false`s by hand; the MCP server writes its three sentences, which
say what the person can do instead, over `reading_only`'s.
