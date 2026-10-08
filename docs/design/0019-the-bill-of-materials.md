# The bill of materials

`sv sbom ./app` writes CycloneDX 1.5 JSON to standard output and everything else to standard error, so
`sv sbom ./app > sbom.cdx.json` gives a clean file and still tells the person what it is worth.

An SBOM is worth exactly the completeness of its list. The whole reason to hand one to somebody is that
they can ask "is the compromised version of that library in here?" and trust the answer, so a partial one
is more dangerous than none. Two things follow, and both are recorded on the document rather than only in
the terminal — a caveat that stays behind in a terminal is not a caveat.

**A range is not a version.** A lockfile says what is installed; a manifest says what was asked for, and
`^4.18.0` is a different thing on a different day and a different machine. Components read from a manifest
are marked `declared`, the count appears in `metadata.properties`, and `flask>=2.0` produces no component
at all — listing it as though the range were a version is the failure this module is arranged around.

**An ecosystem that could not be read is named.** `poetry.lock` is a format `sv` cannot parse yet, so it
appears in the document as an unread ecosystem rather than being silently dropped. An SBOM that quietly
omits a whole ecosystem reads exactly like one that had nothing to omit.

Lockfile readers so far: `package-lock.json` (v1 and v2/v3 shapes), `Cargo.lock`, `composer.lock`,
`Gemfile.lock`, `go.sum` and exact `==` pins in requirements files. `Gemfile.lock` indentation matters —
specs are indented four spaces and their own dependencies six, and reading both would invent packages the
app does not ship.

Where the list is not complete, `sv check` says so as a medium finding, because the gap is the point: asked
whether a compromised library is in this app, nobody could answer from an incomplete document.

### The report asks the bill of materials, instead of reasoning about dependencies itself

Two commands on the same app — a `package.json` with `"react": "18.0.0"` and no lockfile — said different
things, and the report was the one that was wrong:

    sv sbom    npm is in use but nothing readable says which versions are installed,
               so none of its packages are listed
    sv report  package.json pins no versions, so the list of dependencies is what was
               asked for rather than what is there

There is no list. No version in a `package.json` is read at all, so npm's bill of materials is *empty*, and
a reader was told it was approximate. "What was asked for" is a description of a list that exists.

The report built that row from `scan_report.unpinned`, which knows exactly one thing: whether an ecosystem
that pins with a lockfile is missing one. One sentence was then written for every ecosystem, and one
sentence covering every ecosystem is wrong about some of them. Rewording it would have moved the error
rather than removed it — pip is the counter-example, where the versions really were read and really are
what was asked for.

It was wrong about pip too, in the other direction: `flask==3.0.0` pins a version, and the row said
`requirements.txt` "pins no versions". Both halves of one sentence, each true of one ecosystem and false of
the other.

`sv sbom` had drawn this distinction correctly all along and had no reader inside `sv`. The report now
builds an SBOM and asks it, so there are two gaps where there was one:

| what the bill of materials holds | what the report says |
|---|---|
| an ecosystem in `unread` | **everything npm installs** — the reason the SBOM gives, and that this is an empty list, not an approximate one |
| components marked `declared` | **which Python versions are really installed** — read from a manifest rather than a lockfile |
| components marked `locked` | nothing: there is no gap to report |

The third row is as much of the fix as the first. A gap row for an app whose lockfile was read reads as a
hole where there is none, and it is what a fix that simply always printed something would produce; three
tests hold it, one of them over a document with a locked ecosystem beside an unreadable one.

Building the SBOM in the report path reads manifests and lockfiles and opens no network connection, which
is what made it safe to add. Left over: the report still does not carry the SBOM's own incompleteness
finding or run the advisory comparison — the other half of the backlog entry this shares a root with, and
its own piece of work.

### A lockfile nobody could read is not an inventory (27 September 2026)

The gaps were only half of what the bill of materials knows, and the other half was missing. `sv check`
already reported it: incomplete is a finding against V15.1.2 (`sbom.incomplete`), complete is evidence
for it, and exactly one of the two speaks. `sv report` read the gaps and left both of those out, so
V15.1.2 was decided by `config.versions-pinned` alone, and that check passed any lockfile it found.

Put together, on an app whose `poetry.lock` held nothing `sv` could read, the report marked V15.1.2
*checked* ("an inventory catalog of all third-party libraries is maintained"). Beside it, the gaps said
"everything Python installs" was an empty list, and threat T-27 counted the credit as *checked in part*.
`sv check` on the same folder printed the pass and the `sbom.incomplete` finding one under the other.

Two changes, one for each half:

- **The report carries the bill of materials' finding and credit,** as `sv check` does. A finding
  outranks a pass, so the requirement reads *needs attention*.
- **The lockfile check asks the bill of materials** before passing. A lockfile it could take nothing
  from leaves the question *not assessed*, with the bill of materials' own reason. That covers a
  format `sv` cannot read, and a file that parsed and held no packages. A lockfile being there is not
  the same as its versions being known.

Its old test passed with `{}` as the `package-lock.json`, which is exactly the case this refuses; it now
holds a package. Breaking each of the three changes on purpose turns a test red: the report's finding
(one test), the report's credit (the control, where a readable lockfile must be credited by both
checks), and the lockfile check (two tests).
