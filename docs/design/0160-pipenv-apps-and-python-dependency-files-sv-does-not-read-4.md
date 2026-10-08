# Pipenv apps, and Python dependency files `sv` does not read (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H9) found that a Python app with only `Pipfile` and
`Pipfile.lock` had no Python at all as far as `sv` could tell. Only `requirements.txt` and `pyproject.toml` counted as
Python manifests (`crates/sv-scan/src/ecosystems.rs`), so a `Pipfile.lock` was read only when one of those sat beside
it. Django 2.2.0 in the lockfile was never compared with its advisory, and the comparison of the rest of the app was
credited as V15.2.1. A `setup.py`, a `setup.cfg`, or a `requirements-dev.txt` went the same way: what they install was
neither listed nor named as left out.

**`Pipfile` is a manifest, with `Pipfile.lock` its lockfile.** The lockfile is read as before, from every section
rather than `default` and `develop` only, since a `Pipfile` may add package categories of its own and `pipenv lock`
locks them all; `_meta` is the one key that holds no packages. Development packages are listed, as they are from every
other ecosystem's lockfile. `Pipfile` is held to its lockfile like the other manifests (`manifest_lock::compare`), so
a `Pipfile` that asks for another Django than the lockfile has is named, and its names are read for the technology
scan (`deps::from_pipfile`).

**Nothing in a `Pipfile.lock` is dropped without a word.** A package Pipenv installs from a repository or a folder is
locked by its commit or path, with no version. It is named, as `pylock.toml`'s are, and the list counts as incomplete.
The one entry left out is the app's own folder (`"path": "."`, written by `pipenv install -e .`), which is the app and
not something it depends on. This is H21 for this reader only; pnpm and Yarn are still as H21 describes.

**A `Pipfile` without its lockfile is read as other manifests are.** A package pinned to one version (`"==2.2.0"`) is
listed at that version, marked as asked for rather than installed, so the list is incomplete. A package asking for a
range or for any version (`"*"`) is named and not listed, since no version in the file is the one installed.

**Python dependency files `sv` does not read are found and named** (`ecosystems::python_declarations_in`):

- A requirements file under another name (`requirements-dev.txt`, `dev-requirements.txt`, any `.txt` in a
  `requirements/` folder). One that pins and hashes every package is a lockfile in its own right, as
  `requirements.txt` is, and is read as one; any other is named. A lockfile beside it says nothing about it, since
  `requirements-dev.txt` is usually the very list a lockfile beside it leaves out. `requirements.in` is not named: it
  is what `pip-compile` turns into the requirements file beside it.
- `setup.py` and `setup.cfg` that name packages to install (`install_requires`, `extras_require`; one that could not
  be read counts as naming them). They are named unless a Python lockfile in the same folder was found, which is made
  from what the project asks for, `setup.py` included (`pipenv install -e .`, `pip-compile setup.py`), and so stands
  for it. A `setup.cfg` that only configures a tool is not a declaration.
- A Conda `environment.yml`, always: its packages come from Conda's channels, which nothing here reads and PyPI's
  advisories do not describe.

Each named file leaves the bill of materials incomplete, so the advisory comparison is not credited (V15.2.1) and
`sv audit` exits "not assessed". `sv audit` now prints each reason the list is incomplete, beside "the list itself is
incomplete", rather than sending the owner to `sv sbom` to learn which file. The report's gap row says "part of what
Python installs" when other Python packages were listed, rather than calling a list with Django in it empty; before,
every unread reason was worded as an empty list, which was already wrong for `pylock.toml`'s packages with no version.

What is still not done: a `requirements.txt` read without a lockfile still lists its exact pins and leaves a range
(`flask>=2`) out without naming it (the list is marked incomplete by its declared versions, but the range is not
named); an app whose only Python file is a `setup.py` is not reported by the pinning check as pinning nothing; and a
`Pipfile.lock` with no `Pipfile` beside it is not found. (The first two were done on 5 October 2026; see the next
section. The third is still open.)

**Tested.** Unit tests in `sbom.rs`, `manifest_lock.rs`, and `deps.rs`, detection tests in
`crates/sv-scan/tests/scan.rs`, and end to end (`crates/sv-cli/tests/pipenv.rs`): a locked npm app whose clean
comparison is credited (the control) gains a `Pipfile` and `Pipfile.lock` with Django 2.2.0, and `sv audit` and
`sv report` find the advisory; with Django past the fix, both credit V15.2.1; and each of `worker/setup.py`,
`worker/setup.cfg`, `requirements-dev.txt`, a `Pipfile` alone, and a `Pipfile.lock` with a package from a repository
makes the audit "not assessed", leaves V15.2.1 not verified, and names the file in both. Eleven guards broken in turn,
each caught: `Pipfile` not a manifest (eleven tests), the other declarations not read (four), a package with no
version in `Pipfile.lock` dropped (two), a `Pipfile`'s ranges dropped (two), the gap always called empty (one), a
`setup.py` named beside a lockfile (one), a `Pipfile` package from a folder held to the lockfile (one), only `default`
and `develop` read (one), the app's own folder named (one), a hashed `requirements-dev.txt` not read (one), and every
`setup.cfg` counted (one).
