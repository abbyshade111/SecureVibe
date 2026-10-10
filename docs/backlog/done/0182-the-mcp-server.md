# The MCP server

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026. `sv mcp --root DIR` speaks MCP over stdio
(`crates/sv-cli/src/mcp.rs`, no SDK) with four tools: `securevibe_spec`, `securevibe_check`,
`securevibe_explain` and `securevibe_write_report`. `securevibe_check` is `assemble_report`, the
function `sv report` now calls too, so a model is told exactly what the written report says, gaps first.
Every path is resolved against `--root` and refused outside it, `..` and symlinks included; a report is
written only below the app. Starting the app and running other people's tools are not offered: each
runs code, and that stays the person's decision at a terminal. Left over: MCP resources (the report
files as resources rather than paths) and progress notifications for a long check.
