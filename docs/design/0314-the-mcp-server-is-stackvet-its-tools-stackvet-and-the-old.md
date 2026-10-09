# The MCP server is stackvet, its tools stackvet_*, and the old names still answered (9 October 2026)


**What changed.** Step 2b of the rename (ADR-062): the names a user's AI coding tool and a user's own folders
carry, after the manifest (step 2a). The MCP server is `stackvet`, and its thirteen tools are `stackvet_*`; a
call by an old name, `securevibe_check` and the rest, is answered as the same tool, and the list names only the
new ones, so a tool that learned the old names keeps working while the `AGENTS.md` it reads is rewritten with
the new. History is kept in `~/.local/share/stackvet/history`, with the old folder used while only it exists,
as the config folder is (step 1), and nothing moved. `sv review` says once, before its first question, when the
key folder in use is the old one, and names the move. A new bundle is `<folder>-stackvet-bundle.zip`. The
installed copy's data is looked for under `share/stackvet` and then `share/securevibe`, and `tools/install.sh`
puts it under the new name. The help text, the MCP tool descriptions, the prose in the reports, and the product's
name in `sv`'s own words say StackVet.

**What keeps its name, and why.** The signature namespace (step 1, the record's point 6). The property names
`sv` writes into a bill of materials (`securevibe:complete`, `securevibe:manifest-disagrees:...`, and the rest):
they are read by whatever consumes the SBOM, as a wire format is, and a renamed property would silently stop
matching a consumer's filter. The record did not list them; this entry does, and the same reasoning as the
namespace applies. The repository's address in the SARIF file and in the false-alarm issue link stays until the
owner renames the repository (step 3).

**Held by.** `crates/sv-cli/src/mcp/old_names_tests.rs` (an old tool name answered as the new tool, a name that is
neither still refused, the list naming only the new, the server named `stackvet`),
`crates/sv-cli/tests/history_old_folder.rs` (neither folder, the old alone with a run in it, both),
`crates/sv-cli/tests/review_old_folder.rs` (on a pseudo-terminal: the note said once with the move, and nothing of
it when there is no old folder), and `tests/moved.rs` for the install script's new folder.
