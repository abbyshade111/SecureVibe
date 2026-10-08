# A Python project pinned by `pylock.toml`, or by a hashed `requirements.txt` (4 October 2026)

family-hub pins every package in `requirements.txt` with `==` and `--hash`, and has a `pylock.toml` beside it. `sv`
still said there was no lockfile, listed the packages "at the version asked for", and called the package list
incomplete. The owner had done what `sv` asks, and the report said the opposite. The cato-pipeline session reported
it.

- **`pylock.toml` is a Python lockfile.** It is PEP 751's lockfile, written by `pip lock`, and a project may keep one
  per environment as `pylock.<name>.toml`. Both now count for `requirements.txt` and `pyproject.toml` projects, after
  the tools' own lockfiles and before `requirements.lock`. A named one beside the plain one is said to be passed over,
  as any second lockfile is.
- **It is read as TOML.** Each `[[packages]]` entry gives a name, and a version when the package comes from an index.
  A package installed from a folder, a repository, or an archive may have no version. Such packages are named, and
  the list is marked incomplete, rather than left out without a word.
- **A `requirements.txt` that pins and hashes everything is its own lockfile.** Every requirement must be
  `name==version` with no wildcard and at least one `--hash`, and there must be at least one requirement. Lines that
  only set where pip looks (`--index-url` and the like) or turn on `--require-hashes` may stand beside them. Anything
  that installs from elsewhere (`-r`, `-e`, a path, an address) means it is not a lock. Neither does one line with
  no pin or no hash, since pip would install it without either. It only counts when no separate lockfile is there.
- **A fault found on the way.** The manifest and lockfile comparison read `blinker==1.9.0 \` (a line carried on to
  its `--hash`) as asking for version `1.9.0\`, so a hashed `requirements.txt` beside any lockfile disagreed with it
  on every line. The backslash is now dropped.

Tried end to end on a folder of family-hub's shape:
- `sv check` gave the "commit the lockfile" finding before, and passes `config.versions-pinned` after.
- `sv sbom` lists the three packages as installed and marks the list complete.

**Break tests.** Each of these was caught:
- a hash not required;
- a wildcard version allowed;
- `-r` and `-e` allowed;
- the backslash kept.

Reading `pylock.toml` line by line was caught only by the test of a package with no version. TOML puts a
package's own keys before its sub-tables, so a wheel's `name` cannot be taken for a package; dropping an unversioned
package is the real cost, and that test guards it.
