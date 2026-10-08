# What a `requirements.txt` leaves out is named, and a `setup.py` with no lockfile does not pin (5 October 2026)

The rest of H9 of the deep review: two places where `sv` stayed quiet about Python packages it had not checked.
The second is recorded as ADR-037, at the owner's asking.

**A `requirements.txt` read without a lockfile.** Only the lines that pin one version (`stripe==7.8.0`) say which
version is installed, so only they are listed, marked as asked for. Every other line was dropped without a word: a
range (`flask>=2`), a name alone (`gunicorn`), a wildcard (`requests==2.*`), a package from an address or a folder
(`pkg @ https://…`, `-e git+https://…#egg=helper`), and another requirements file pulled in (`-r base.txt`). The list
was marked incomplete, but nothing said what it left out, so it read like everything the file asks for. Each of them
is now named in the reason the list is incomplete, which `sv audit` prints and the bill of materials carries in its
`securevibe:unread:Python` property, in the same words the `Pipfile` reader already used. The file is read as pip reads it: a line ending in `\` goes on on the next,
a comment after a space is left out, and `-e .` (the app itself), a constraints file (`-c`), and the lines that only
say where pip looks install nothing and are not named. A requirements file that pins and hashes every package is
still read as a lockfile, as before.

**A `setup.py` or `setup.cfg` with no lockfile beside it.** `pip install .` resolves what `install_requires` asks for
afresh each time, as `pip install -r requirements.txt` does without a lockfile, which the pinning check (V15.1.2)
already reports as not pinning. A `setup.py` was not one of the manifests the check looked at, so an app declared
there alone was told it had no package manifest, and one beside a locked npm app had its pinning credited on npm's
lockfile alone. Each `setup.py` or `setup.cfg` that names packages, with no Python lockfile in its folder, is now
judged as a project with no lockfile (`ecosystems::setup_only_in`), by the pinning check and in the scan's own list of
unpinned projects, which `sv check` prints. A lockfile in the same folder still stands for it, and one that names no
packages still declares nothing. A folder whose `requirements.txt` and `setup.py` both pin nothing is named once.

**Not done.** A requirements file under another name (`requirements-dev.txt`) without hashes is named as not read by
the bill of materials, as before, but is not judged by the pinning check, and a `Pipfile.lock` with no `Pipfile` beside
it is still not found.

Twelve guards broken in turn, each caught: a `setup.py` not judged by the pinning check, not in the scan's list of
unpinned projects, or judged though a lockfile is beside it; one folder's Python named twice; what is not listed not
named (two tests); an included file not named; an address's `#egg=` not read; a scheme with `+` taken for a package's
name; a wildcard taken for a version; continued lines not joined; a comment after a requirement kept; and `-e .`
named as a package.
