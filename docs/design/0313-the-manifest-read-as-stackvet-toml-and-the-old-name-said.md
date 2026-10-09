# The manifest read as stackvet.toml, and the old name said once (8 October 2026)


**What changed.** Step 2a of the rename (ADR-062): the manifest. `sv init` writes `stackvet.toml`, and every command
reads that name first and `securevibe.toml` while only it exists, through one function, `sv_manifest::locate`,
which also refuses a folder holding both, with its reason: two manifests are two answers. The report carries the
file's name as read (`manifest_file` in `report.json`; an older report without it reads as the new name), the SARIF
file points its running-app findings at that name, and a finding the manifest's own answers made points at the file
by the name it has. When the old name was read, the report says so once, as the first entry of what was not
examined, and the terminal says the same sentence once: what was read, what to rename it to, and that the old name
is read until 1 January 2027 at the earliest.

**A wording decision, recorded on the ADR.** Some six hundred sentences across the crates name the manifest, most
of them in the checks of a running app ("`stackvet.toml` says the app should allow three wrong passwords in a
row"). Threading the file's actual name into each would touch every one of those functions for a name that differs
only during the window. So the sentences name the manifest by its new name, and the one note says, where a person
reads the report, that every such sentence means the file this app has. The alternative, the old name in every
sentence while the file keeps it, was set aside: it would teach the old name to every AI coding tool reading the
report, which is the opposite of what the window is for.

**What else moved with it.** The example apps' manifests are `stackvet.toml` now, so the verdict snapshots and
every test that copies an example exercise the new name, and the old name's path is held by its own tests; the
knowledge files under `data/` and the three tools that spell the name say the new one, since `sv init` and the
MCP spec write it; the list of `sv`'s own files, which an app made only of them counts as not read, holds both
names, as does the preflight's list of files that describe how the app runs, the running-app check's list of files
that are not the app's code, and the MCP server's list of files it refuses to read through a link.

**Held by.** `crates/sv-manifest/tests/locate.rs` (the four states of the two names, and the sentence),
`crates/sv-cli/tests/manifest_old_name.rs` (through the binary: the old name read and said once in the report and
at the terminal, with no finding pointing at a file the app does not have; both names refused with the reason and
nothing written; the new name alone with no note), and the whole suite, since every test that wrote
`securevibe.toml` into a scratch app now writes `stackvet.toml`.
