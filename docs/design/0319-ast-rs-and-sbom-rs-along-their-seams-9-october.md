# ast.rs and sbom.rs along their seams (9 October)

The architecture assessment of 8 October 2026 (item 11) asked for the two largest modules to be split where they
already divide, once their tests had moved out (done the same day). Two of its effects were the reason: a reader had
to hold 4,584 lines to find the part of `ast.rs` they meant, and two sessions changing different parts of one file
still had to bring each other's changes in.

The code moved and did not change. Each block went whole, with its comments, to a file beside its module:

| From | To | What it holds | Lines |
|---|---|---|---|
| `ast.rs` | `ast/html.rs` | Taking the script out of a page, the way a browser reads tags | 508 |
| `ast.rs` | `ast/fixed.rs` | What counts as fixed text, and the names bound to it | 1,188 |
| `ast.rs` | `ast/templates.rs` | Jupyter notebooks, and the templates of Astro, EJS, Svelte, and Vue | 798 |
| `sbom.rs` | `sbom/lockfiles.rs` | The readers of each lockfile and package manifest | 689 |
| `sbom.rs` | `sbom/cyclonedx.rs` | The bill of materials written as CycloneDX | 135 |

What stayed is each module's spine: in `ast.rs`, loading the rules, running them over a file, and the names and
callers a rule reads (2,087 lines); in `sbom.rs`, deciding which file to read for each ecosystem and what a bill of
materials missing something says (739 lines).

Items that were private became `pub(super)`, visible to the module and nothing outside it, and each module imports
its files back, so no caller and no test changed. ADR-018 and ADR-054 govern the new files as they governed the code
when it was in `ast.rs`. The census of credits names a file and a line, so it was run again after the move.
