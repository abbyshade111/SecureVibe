# The report credits V15.1.2 for a lockfile it could not read

**Status:** done, as its markers read on 8 October 2026

**Done on 27 September 2026:** the
report carries the bill of materials' finding and credit, and the lockfile check is not assessed when
nothing could be read from the lockfile. See DESIGN, "A lockfile nobody could read is not an inventory". Found on 27 September 2026 by session
securevibe-e8 while tidying this backlog. **Claimed the same day by session securevibe-e8**, at the
owner's asking. Reproduced: an app with `pyproject.toml`, a
`poetry.lock` that holds no packages `sv` can read, and a two-line `securevibe.toml`. `sv report` marks
V15.1.2 (an inventory of every third-party library is maintained) **checked**, citing
`config.versions-pinned`, which passes because a lockfile exists. The same report lists "everything
Python installs" as a gap, because the bill of materials took nothing from that lockfile, and the
credit also counts toward threat T-27 (a dependency with a known vulnerability or a malicious update)
as checked in part. `sv check` on the same folder shows both the pass and the bill of materials'
`sbom.incomplete` finding against V15.1.2, which contradict each other. The report never shows the
finding: `assemble_report` in `crates/sv-cli/src/main.rs` builds the bill of materials and does not
add `sbom::incompleteness_finding` or `sbom::completeness_verified`, as `cmd_check` does. Likely fix:
report both, so the finding outranks the pass; and settle whether `config.versions-pinned` should
credit V15.1.2 at all when the bill of materials could read nothing from the lockfile. A pinned
`requirements.txt` with no lockfile is not affected: both checks flag it.
