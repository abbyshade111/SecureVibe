# Three faults found scanning the owner's family-hub, reported 3 October 2026

**Status:** done, as its markers read on 8 October 2026

Sent by the cato-pipeline session
at the owner's asking. It found them on family-hub (Python and Flask, built with `sv` in the loop) with `sv` at
982f97e and 45b6d71, and checked all three were still there on `main` at 9573c0d. **Each can be claimed on its
own.**
1. **A fully hash-pinned `requirements.txt`, and a `pylock.toml`, are not read as a lockfile.** family-hub pins
   every package with `==` and `--hash`, and has a `pylock.toml` (PEP 751) beside it. `sv` still reports
   `config.versions-pinned` ("no lockfile beside it"), `sbom.incomplete`, and an incomplete package list for the
   advisories. `crates/sv-scan/src/ecosystems.rs` knows `poetry.lock`, `Pipfile.lock`, and `requirements.lock`
   only. Read `pylock.toml` and `pylock.*.toml` as a Python lockfile, for `requirements.txt` and `pyproject.toml`.
   Treat a `requirements.txt` in which every requirement is `name==version` with at least one `--hash` as a lock:
   pip refuses anything else under `--require-hashes`. One line without either means it is not.
   **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline
   session, in branch `claude/securevibe-e9-python-locks`.
   **Done the same day** (DESIGN, "A Python project pinned by `pylock.toml`, or by a hashed `requirements.txt`").
   Both pin a Python project now. On the way: the manifest comparison read the backslash that carries a line on
   to its `--hash` as part of the version, which is fixed. Tried end to end on a folder of family-hub's shape.
   **Part status:** done, 4 October 2026
2. **Python pre-release versions (PEP 440) cannot be compared.** `compare` in `crates/sv-check/src/advisories.rs`
   follows semver, where a pre-release comes after `-`. PyPI writes `2.0.0rc1`, `1.0a1`, `3.0.0.dev0`, and
   `1.0.post1`, which do not parse, so an advisory whose range starts at `2.0.0rc1` goes unanswered. family-hub's
   werkzeug 3.1.9 was left "could not be compared" for three of them. Compare PyPI versions by PEP 440 (epoch,
   release, pre, post, dev, local ignored), and keep semver for the other ecosystems.
   **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline
   session, in branch `claude/securevibe-e9-pep440`.
   **Done the same day** (DESIGN, "Python versions compared as pip compares them"). PyPI ranges follow PEP 440's
   order and the rest keep semver. Checked against `packaging` 24.0 on 101,481 pairs, with one deliberate
   difference: a local label (`+cu118`) is ignored, so a local build of an affected release stays affected.
   **Part status:** done, 4 October 2026
3. **A report does not say which `sv` made it, and the published image does not know its commit.** `report.json`
   has no version or commit, and `sv --version` in the published image prints "commit unknown", because
   `SV_GIT_COMMIT` is not set when the image is built. Write `"sv": {"version", "commit"}` into `report.json` and
   the SARIF's `tool.driver`, show it in `report.html`, and pass the commit to the image build.
   **Claimed on 4 October 2026 by session securevibe-e9**, at the owner's asking through the cato-pipeline
   session, in branch `claude/securevibe-e9-report-provenance`.
   **Done the same day** (DESIGN, "A report names the `sv` that made it"). Every form of the report names the
   version and commit, and the image is built with its commit (`--build-arg SV_GIT_COMMIT`), which the CI image
   job's smoke test checks.
   **Part status:** done, 4 October 2026
