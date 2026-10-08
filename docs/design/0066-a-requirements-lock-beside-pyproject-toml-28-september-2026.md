# A `requirements.lock` beside `pyproject.toml` (28 September 2026)

cato-pipeline, wiring `sv` into its own pipeline, found that a Python project with a `pyproject.toml` and a
`requirements.lock` beside it was told it had no lockfile. `requirements.lock` is the file
`uv pip compile pyproject.toml -o requirements.lock` writes, and the name Rye uses, but `sv` only looked for it
beside a `requirements.txt`. Three things followed from that one missing name: `config.versions-pinned` said, wrongly,
that nothing pinned the app's packages; the bill of materials listed no Python packages; and known vulnerabilities in
them were never compared. It is now one of the `pyproject.toml` lockfiles (`crates/sv-scan/src/ecosystems.rs`), and it
is read the same way as beside `requirements.txt`: each `name==version` line, with `--hash` lines and comments left out.

**Which lockfile, when there are several.** The first one found in the list is read, and `requirements.lock` is last.
A project that has `uv.lock` or `poetry.lock` as well is read from that one, because it is the tool's own record and a
`requirements.lock` beside it is usually an export made from it. The report does not say which lockfile was read when
more than one was there. That is true of every ecosystem, not only this one: the backlog entry expected the report to
say it "as it is for other ecosystems", and it does not for any. It is left as its own backlog item rather than
widened into this change. (Done the next day: see "Two lockfiles of one kind".)

**Platform conditions.** A universal lock has lines such as `colorama==0.4.6 ; sys_platform == 'win32'`, for
packages installed only on some computers. The condition is not read: the package is listed wherever the app is
installed. For the comparison with advisories that is the safe side, since a vulnerable package is never left out;
the cost is a bill of materials that can say slightly more than one computer installs. Writing the condition with no
space before the `;` used to leave it glued to the version (`306;sys_platform=='win32'`), which matches no advisory
anywhere; the reader now cuts every line at its `;` first. That fix reaches `requirements.txt` too.

**How it was checked.** Three tests, each at its own level: the reader
(`a_requirements_lock_beside_pyproject_is_read_hashes_and_markers_included`, in `sbom.rs`), which lockfile counts
(`a_requirements_lock_pins_a_pyproject_project_and_a_tools_own_lockfile_comes_first`, in `sv-scan`'s `scan.rs`), and
the report end to end (`a_pyproject_app_locked_by_requirements_lock_is_compared_in_full`, in `sv-cli`'s
`examined.rs`: an advisory about `pyyaml` is found, there is no `config.versions-pinned` finding, and `advisory.` is
`ran`). Each guard was broken in turn across the whole workspace. Taking `requirements.lock` out of the list turns all
three red. Putting it before `uv.lock` turns only the order test red. Reading the line without cutting at `;` turns
only the reader test red, which is the one test that has a condition written without a space.
