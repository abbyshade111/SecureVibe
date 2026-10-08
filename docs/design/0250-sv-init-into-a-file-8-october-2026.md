# `sv init` into a file (8 October 2026)

`sv init` prints the starter `securevibe.toml` and then the instructions for the AI coding tool: the
specification, the coding rules, and the design-time prompts. That is what an AI coding tool should read, and it
is nothing like a file `sv` can read. The gap analysis (5.3) found the obvious thing an owner types,
`sv init > securevibe.toml`, wrote all of it into the file, and every later command refused the file.

When standard output is a file, `sv init` now prints only the starter, and says on the screen (standard error, so
not into the file) that the instructions were left out, and how to read them: `sv init` without `>`, or the
`securevibe_spec` tool. A terminal and a pipe get everything as before, so an AI coding tool that runs `sv init`
reads the same as it did. The starter alone is a file `sv scope` reads, with every answer still to give; that is
what the test checks, rather than only that the prose is gone. ADR-017 has the record ("Later, 8 October 2026").
