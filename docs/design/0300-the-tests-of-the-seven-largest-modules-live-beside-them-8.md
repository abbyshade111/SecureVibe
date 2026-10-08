# The tests of the seven largest modules live beside them (8 October 2026)

Item 11 of the architecture assessment of 8 October 2026 (BACKLOG, "From the architecture assessment of 8 October
2026"). The three merge conflicts of that day were all one shape: two sessions appending to the same place, a claim at
the top of the backlog's "Next" section, a test at the end of a module's `mod tests`, a paragraph on the same DESIGN
section. The backlog's rule is in CLAUDE.md now (append the claim at the end, merge it before building, a test in a
sibling file, a DESIGN section of its own). And the test modules of the seven modules over 3,000 lines, `ast.rs`,
`ai.rs`, `probes.rs`, `adapters.rs`, `secrets.rs`, `production.rs`, and `sbom.rs` (40 to 65% of each was tests), are
files of their own: `src/<module>/<name>.rs` for each `mod <name>` that was inside, declared where it was
(`#[cfg(test)] mod tests;`), its body moved verbatim and the code reindented by `rustfmt`. Nothing in a test changed:
`use super::*` means what it meant, since the module's place in the tree is the same. The seven files are 15,400
lines where they were 31,200.

What held it: `cargo test -p sv-check` (every test passes as it did), and the source-reading tests in `sv-cli`
(`moved.rs`, which since the MCP split knows a whole file can be a test module, and `decision_records.rs`, which names
tests by function, not by file). Not done: splitting `ast.rs` and `sbom.rs` along their own seams, which the item also
names; the tests out of the way is what makes that a smaller change.
