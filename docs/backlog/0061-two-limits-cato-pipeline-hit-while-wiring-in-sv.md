# Two limits cato-pipeline hit while wiring in `sv`

**Status:** partly done: 3 of 4 parts done, 0 claimed, 1 open, as its markers read on 8 October 2026

Found on 28 September 2026 by a session on the owner's
cato-pipeline project, while integrating `sv` (cato's ADR 0009), with `sv` built from `main` at `5117b0a`, and
written up for this backlog. Session securevibe-e10 checked each claim about `sv`'s code against `main` the
same day before adding it here; the reproductions below are cato's and were not rerun. Both are honest,
fail-closed behavior; the cost is in what they block. **Each numbered item can be claimed on its own.**
1. **`requirements.lock` beside `pyproject.toml` is not read.** For a Python project with a `pyproject.toml`,
   `sv` looks only for `poetry.lock`, `pdm.lock`, or `uv.lock` (`crates/sv-scan/src/ecosystems.rs`, the
   `pyproject.toml` entry; checked). A hash-pinned `requirements.lock` beside it is ignored, though it is the
   file `uv pip compile pyproject.toml -o requirements.lock` writes and the name Rye uses.
   `requirements.lock` is already a known lockfile, but only for the `requirements.txt` manifest (checked), and
   `from_pinned_requirements` in `crates/sv-check/src/sbom.rs` already skips `--hash` lines and reads
   `name==version`. As a result `config.versions-pinned` (medium) says there is no lockfile, which is untrue;
   the bill of materials lists no Python packages (`sbom.incomplete`, the gap "everything Python installs");
   and `examined` has `advisory.` as `partly`. Seen on cato's own repository: `sv sbom` listed 0 components;
   the same file renamed `requirements.txt` listed 41. Reproduce:
   `printf '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["PyYAML>=6.0"]\n' > pyproject.toml`,
   then `uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock`, then `sv sbom .`.
   **The owner's decision, as cato's write-up records it: fix it here.** Fix: add `"requirements.lock"` to the
   `pyproject.toml` entry's lockfiles. Two decisions come with it: which lockfile is read when several are
   present, said in the report as it is for other ecosystems; and environment markers, since a universal lock
   has lines like `colorama==0.4.6 ; sys_platform == 'win32'`, which the parser lists even where it would not
   be installed (the safe side for an advisory comparison; the bill of materials then says slightly more than
   is installed, which the report could say, or the marker could be read). Test: a `pyproject.toml` project
   with a hash-pinned `requirements.lock`, `--hash` lines and one marker line included, gives components, no
   `config.versions-pinned` finding, and `advisory.` as `ran` when the database covers PyPI; remove the new
   entry and it goes red. **Claimed on 28 September 2026 by session securevibe-e2**, at the owner's asking to
   pick a backlog item, in branch `claude/securevibe-e2-pyproject-lock`.
   **Done the same day:** `requirements.lock` is the last of the `pyproject.toml` lockfiles, so a `uv.lock`,
   `pdm.lock`, or `poetry.lock` beside it is read first. A platform condition is not read, so such a package
   is listed everywhere, and a line is now cut at its `;` whether or not a space comes before it, which fixes
   `requirements.txt` as well. Three tests (the reader, which lockfile counts, and the report end to end); each
   guard, broken in turn, turns its own test red. See DESIGN, "A `requirements.lock` beside `pyproject.toml`".
   One correction to the entry above: no ecosystem's report says which lockfile was read when several are
   there, so this one does not either. That is the next item.
2. **One large data file blocks two checks for the whole app.** `MAX_FILE_BYTES` (2 MB,
   `crates/sv-scan/src/files.rs`; checked) is the largest file any check reads. cato vendors NIST's SP 800-53
   catalog at `oscal/catalogs/nist-800-53-rev5/catalog.json`: 10 MB of standards text, no code, no
   credentials. That one file leaves the credential scan `partly` ("1 file(s) were not read"), so a program
   reading `examined` can never treat a missing `secrets.*` finding as fixed anywhere in the app. It also
   leaves `config.mcp-server-unpinned` not assessed for the whole app: `mcp_servers` in
   `crates/sv-check/src/launch.rs` reads every file `may_start_servers` selects, JSON included, and one it
   cannot read means the check can never pass (checked; it still reads every other file and still reports an
   unpinned server it finds, so it blocks the clean result, not the findings). Both are right by `sv`'s own
   rules and `examined` reports them correctly; the problem is that a file the owner knows to be data blocks
   two families permanently, with nothing the owner can do. Reproduce: a folder with a `securevibe.toml`, an
   `app.py`, and `python3 -c "import json; json.dump({'text': 'x'*3_000_000}, open('catalog.json','w'))"`,
   then `sv report . --out out`. **Options, for the owner to choose:**
   (a) read large files in pieces for the credential scan, since its rules are line-oriented, so `secrets.`
   can be `ran`, meeting the concern in `files.rs` (a large file is likelier to hold a hash than a key) by
   giving findings there *possible* certainty rather than by not reading them; (b) stop one unrelated file
   from blocking the MCP check: a file that starts an MCP server is small, so for one over the limit first
   check whether it can be an MCP configuration at all (by name, or by scanning for `"mcpServers"` or
   `"command"`), or report the check as `partly` naming the file; (c) let the manifest name data files, such
   as `[repository] data = ["oscal/catalogs/**"]` with a reason, each listed in the report, which relies on a
   manifest an AI tool may write and so would need the visibility `not-the-app` has. cato's write-up
   recommends (a) and (b) together, which clear it without asking anyone to trust the manifest. Tests: a
   3 MB plain-text JSON and no MCP configuration leaves the MCP check run, or `partly` and naming the file,
   never not assessed; a key planted past the 2 MB mark of a large file is found and `secrets.` is `ran`;
   each guard removed in turn turns its test red. **The owner's decision, 28 September 2026: (a) and (b)
   together. Claimed the same day by session securevibe-e10**, in branch `claude/large-data-files`.
   **Done the same day:** a file over 2 MB and up to 256 MB is read in pieces for credentials (an
   assignment found in one is reported with low confidence), and the MCP check counts a large file as
   read when it never says `command`, its own rule for any file. On cato's reproduction the credential
   scan is `ran` and the MCP check is no longer not-run. See DESIGN, "A large data file no longer
   blocks the credential scan or the MCP check".
3. **The report does not say which lockfile was read when a project has more than one.** Found on 28 September
   2026 while doing item 1. `find_lockfile` in `crates/sv-scan/src/ecosystems.rs` takes the first name in each
   ecosystem's list that exists and says nothing about the rest, for every ecosystem (`poetry.lock` and
   `requirements.lock` beside `requirements.txt`, `uv.lock` and `requirements.lock` beside `pyproject.toml`,
   `package-lock.json` and `yarn.lock`, and so on). If the two disagree, the bill of materials and the advisory
   comparison describe one of them and the owner is not told which. The bill of materials could carry a note
   naming the file read and the ones passed over. **Claimed on 29 September 2026 by session securevibe-e2**, at
   the owner's asking to pick a backlog item, in branch `claude/securevibe-e2-which-lockfile`.
   **Done the same day:** one lockfile is still read, in the same order, and the others are named in the bill
   of materials (a CycloneDX property), in `sv sbom`'s output, and in the report as a gap. `advisory.` is
   `partly` in `examined`, and the clean "nothing found" claim is withheld, so `sv audit` exits 2 rather than
   0. Six tests; each of eight guards, broken in turn, turns its own test red. See DESIGN, "Two lockfiles of
   one kind".
