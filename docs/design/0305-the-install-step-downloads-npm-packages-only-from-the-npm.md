# The install step downloads npm packages only from the npm registry (8 October 2026)


From the review of 8 October 2026, item 2 (`docs/backlog/0188-…`). With `install = true`, `sv run` installs an app's
packages in a container of their own that can reach the internet, before the app runs inside the fence (ADR-052).
For Python, `requirements.txt` was already held to exact versions from PyPI. For Node it was not: `npm ci` downloads
each package from the address `package-lock.json` gives it, and nothing looked at those addresses. A lockfile is a
text file anyone can edit, so an app could have that container fetch from any server, the owner's own network
included. The dependency files were also found with `is_file`, which follows a link, so a `package-lock.json` that
was a link to a file elsewhere on the owner's computer was copied into that same container.

**What changed.** Before anything runs, `install::plan` reads the lockfile and refuses it, naming up to three
packages, unless every package comes from `https://registry.npmjs.org/` and carries an `integrity` fingerprint
(SHA-256 or stronger) that npm checks the download against. The address is compared with the registry's whole
prefix, slash included, so `https://registry.npmjs.org.example.com/` and `http://registry.npmjs.org/` are refused. A
git or file address, a package with no address, and a local folder (`link`) are refused; a package bundled inside
another's download (`inBundle`) has nothing of its own to fetch and is passed. Version 1 lockfiles are read through
their nested `dependencies`, and a lockfile `sv` cannot read is refused rather than taken as clean. A
`requirements.txt`, `package.json`, or `package-lock.json` that is a link is refused before it is read.

**Breaks.** Each failed `crates/sv-run/tests/npm_sources.rs`: the address not checked, the registry compared without
its slash, the fingerprint not checked, SHA-1 accepted, bundled packages not passed, links followed, version 1 not
read, and a lockfile with nothing readable taken as clean.

**Not done.** A package's `version` is not compared with the address it is fetched from: an address on the registry
for another package, or another version, still passes, and npm's own check is of the fingerprint the same lockfile
gives. What the lockfile names is the app's choice; that it comes from the registry, unaltered, is what this holds.
