# When a manifest and its lockfile disagree (3 October 2026)

`sv` reads a project's lockfile when it has one, because it says what is installed. Nothing compared it with the
manifest beside it. On 23 September a dependency bot raised `pyjwt` in `examples/flask-booking/requirements.txt` and
left `requirements.lock` alone; for ten days GitHub, which reads the manifest, and `sv`, which reads the lock,
described two different apps, and nothing noticed until a person asked (BACKLOG, "Say when a manifest and its
lockfile disagree"). Whoever installs from the manifest runs versions the report never looked at, so a vulnerability
in what is really installed can go unreported, or one be reported in versions nobody runs.

**What is compared** (`sv-check`, `manifest_lock`). Each package the manifest asks for is held to every version the
lockfile has for it. It agrees when one of them is allowed: npm can install two copies of a package, and the manifest
governs only one. A package the lockfile does not have at all disagrees, unless its line in `requirements.txt` has a
platform condition (`; sys_platform == "win32"`), since a lock made on another platform rightly leaves it out. Python
names are compared as the package index compares them (`Flask_Login` is `flask-login`).

Two manifests are read: `requirements.txt`, with Python's version clauses (`==`, `!=`, `>=`, `<=`, `>`, `<`, `~=`,
`===`, and `==1.2.*`), and `package.json`, with npm's ranges (`^`, `~`, `x`, comparators, hyphen ranges, and
`||`). Versions are compared as plain release numbers. What cannot be compared that way is listed as not compared,
never as agreeing: a pre-release or post-release on either side, a link or a path instead of a version, a tag such as
`latest`, a platform condition with nothing locked, or a range written in a form not read here. The other manifests
were added later the same day (see the end of this section), and Gradle's after them.

**Where it is said.** In the same places as "Two lockfiles of one kind", since it is the same doubt from the other
side: the list describes a file the app may not be installed from.

- **The bill of materials** (`Sbom::disagreements`): the list is still the lockfile's, and still complete in the sense
  the document uses. The CycloneDX document carries a `securevibe:manifest-disagrees:<project>` property naming
  each package that differs, as the manifest writes it, with what the lockfile has (at most five, then a count). Packages
  not compared go in a `securevibe:manifest-not-compared:<project>` property.
- **`sv sbom`** names them, and no longer ends with "so this is what is installed".
- **The report**: a gap, "whether npm is installed from `package-lock.json` or `package.json`", saying to bring
  the two back into step; and in `report.json`'s `examined` list, `advisory.` is `partly`. Packages not compared
  get a gap of their own, "whether `package.json` and `package-lock.json` agree about every package".
- **The clean claim** (`advisories::audit_against`): "every package compared, nothing found" is withheld while the
  manifest asks for something the lockfile does not have, and `sv audit` says so and exits 2 (not assessed). A
  vulnerability found in the lockfile is still reported. Packages that could not be compared do not withhold it: the
  list is still a full reading of the lockfile, as it was before anything was compared.

**Not a finding.** A disagreement shows the inventory may be wrong, not that one is missing, so it is not reported
against V15.1.2 or anything else, and no requirement is cited for it.

**How it was checked.** Twelve tests: eight of the comparison itself (the case that was found; each file the older
one; a range the lock satisfies staying quiet; a package missing from the lock, and one for another platform; names
as the index compares them; what cannot be compared; two copies of a package; 27 Python and 46 npm cases of what a
range allows), the bill of materials and its document (a Python project and an npm project in a folder below, and
the two in step saying nothing), the clean claim (with an only-not-compared control that keeps it), `report.json`
(in step, disagreeing, and not compared), and `sv sbom` and `sv audit` (in step and disagreeing). Nineteen guards
broken in turn, each caught: a missing package taken as agreeing; a platform condition ignored; only the first locked
copy looked at; what cannot be compared taken as agreeing; names not normalized; `^0.x` and `~` read too wide;
`~=` without its prefix; a pre-release read as a release, on either side; a comparison that found nothing recorded
anyway; the clean claim not withheld; the document's property, the report's two gaps, and the `examined` reason
each left out; and `sv sbom`'s line, its closing sentence, and `sv audit`'s line each left out.


**The other manifests, added later the same day.** Five more, each read with the range rules its package manager
documents, because the same characters mean different things in each:

- **`pyproject.toml`**: the project's own list (`[project] dependencies`, PEP 621), read as `requirements.txt` lines
  are; its extras and `[dependency-groups]`, which may rightly be missing from a lock; and Poetry's tables, where
  `^1.2` is `>=1.2,<2`, `~1.2` is `>=1.2,<1.3`, and a bare `1.2.3` is exactly that version. Poetry's `python` entry
  is the Python, not a package; one with `git`, `path`, or `url` is not compared, whatever version it also names.
- **`Cargo.toml`**: a bare `1.2` means `^1.2`, not exactly 1.2 as in npm; `=1.2.3` is exact; comma-joined
  requirements must all hold. A workspace's shared `[workspace.dependencies]` are compared where they are written,
  and a member's `workspace = true` is not compared again; `path` and `git` crates are not compared. A crate renamed
  with `package =` is looked up by its real name. Optional crates and crates for one platform may be missing.
- **`composer.json`**: `~1.2` means `>=1.2,<2.0`, unlike npm's and Poetry's `<1.3`; a bare `1.2` is exactly
  `1.2.0`; `|` and `||` both mean "or". PHP itself and its extensions are not packages. Stability flags (`@beta`),
  branches (`dev-main`), and aliases are not compared. Names are compared without regard to case, as Composer does.
- **`Gemfile`**: the quoted constraints after a gem's name, with `~> 7.1` meaning `>=7.1,<8`. A gem from `git:`,
  `github:`, or `path:` is not compared; one inside a `platforms` or `install_if` block, or with a `platforms:`
  option, may be missing. `Gemfile.lock`'s platform suffix (`1.16.0-x86_64-linux`) is set aside.
- **`go.mod`**: each `require` names one exact version, held to the versions `go.sum` lists for that module. A module
  `replace`d by another or by a folder is not compared. A required module missing from `go.sum` is not compared
  rather than disagreeing, because `go.sum` may hold only the hash of its `go.mod`, which the bill of materials
  does not list, for a module nothing imports. A `go.sum` holding only other versions of it does disagree.

Run on this repository, a Cargo workspace, every crate agrees with `Cargo.lock`, and nothing is said.

Six more tests, one per manifest and one through the bill of materials, with 21 Poetry, 14 Cargo, 22 Composer, and 12
RubyGems cases of what a range allows. Thirty guards broken in turn, each caught. The first run left three uncaught. A
Poetry folder dependency that also names a version, and a commented-out line in `go.mod`, each got a case. Composer's
check for stability flags, branches, and aliases was removed: every one of them already fails to read as a version,
so the check carried no weight. Two more showed a check for `platforms` that the shorter check for `platform` already
covered; it was removed, and the `install_if` block got a case.


**Gradle, added last.** `build.gradle` and `build.gradle.kts` are read for coordinates written out in full, as
`'group:artifact:version'` or as `group: 'g', name: 'a', version: 'v'`, in either language, and held to
`gradle.lockfile`. A plain version is not exact in Gradle: it is the least Gradle will use, and it picks the
highest version anything in the build asks for, so a lockfile holding a newer version agrees and only an older one
disagrees. `1.2.3!!` is exact, `1.2.+` is a prefix, and `[1.0,2.0)` is a range, as Maven writes them. The words after
a version's number (`33.0.0-jre`, `5.3.2.Final`) must be the same on both sides to be compared, case aside; other
words cannot be put in order, so they are not compared. A version from a variable (`$v`), a word such as
`latest.release`, a version catalog entry (`libs.okhttp`), and another project in the build are not read. Which
configurations are locked is the project's choice, so a dependency missing from the lockfile is not compared rather
than disagreeing.

Two tests, a Groovy and a Kotlin build file, and 20 cases of what a version allows. Thirteen guards broken in turn,
each caught. A check for versions from a variable or `latest.` carried no weight, since neither reads as a number,
and was removed.
