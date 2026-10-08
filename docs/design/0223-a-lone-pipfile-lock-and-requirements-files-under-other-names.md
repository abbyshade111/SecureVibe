# A lone `Pipfile.lock`, and requirements files under other names (6 October 2026)

Deep review H9's last done note left two gaps open, and both are closed here.

**A `Pipfile.lock` with no `Pipfile` beside it.** `pipenv sync` and `pipenv install --ignore-pipfile` install from the
lockfile alone, so an app can be shipped with only that file. Nothing found it: the Pipenv entry in `ECOSYSTEMS` is keyed
on `Pipfile`, so such an app had no Python as far as `sv` could tell. Its packages were never compared with an
advisory, and the pinning check said "no package manifest". `Pipfile.lock` is now also an entry of its own, a lockfile
that stands as its own manifest. It is skipped wherever another manifest in its folder already lists it as a lockfile
(`read_as_lockfile_beside`): beside a `Pipfile` or a `requirements.txt` it is theirs, read once, as before. A
`pyproject.toml` does not list it, so beside one both are projects and the lockfile is read. The manifest name it
carries is the lockfile's own, which the manifest comparison and the declared-names reader do not know, so they pass it
by, as they should: there is no second file to compare it with.

**A requirements file under another name.** `requirements-dev.txt` or `requirements/prod.txt` without hashes was
named as unread by the bill of materials and judged by nothing else. So the pinning check passed on a lockfile beside
it that leaves it out, and said "no package manifest" when it was alone. `setup_only_in` becomes
`declared_elsewhere_in`. It still offers a `setup.py` or `setup.cfg` with no Python lockfile beside it as a project
with no lockfile. It now also offers each requirements file under another name, as its own lockfile when it pins and
hashes every package (`fully_hash_pinned`, the test `requirements.txt` already meets), and as having none otherwise,
whatever lockfile is beside it. That is the bill of materials' own reasoning: such a file is usually the very list a
lockfile beside it leaves out. A Conda `environment.yml` is still not judged: no reader here knows how Conda pins, and
the bill of materials names it as unread. The pinning finding for such a file says it does not pin and hash every
package, rather than "there is no lockfile beside it", which could be untrue, and its fix names `pip-compile
--generate-hashes`.

Broken on purpose eleven ways, each caught: the new entry removed (3 tests); the folder rule never skipping (3),
ignoring whether the other manifest is there (3), or ignoring which lockfiles it lists (1); requirements files never
their own lockfile (2), always their own lockfile (2), or not judged at all (2); a Conda file judged (1); a `setup.py`
beside a lockfile judged (1); the pinning check leaving the declared files out (2); and the new wording never chosen (1).
The rule that checks which lockfiles the other manifest lists is caught by one test only, which was written to catch
it: a `pyproject.toml` beside a lone `Pipfile.lock`, which must leave both projects in place.
