# Advisories: Python names, nested npm copies, and declared packages (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 1, H8, H10, and H11) found three ways the advisory comparison
could miss a known vulnerability and still credit V15.2.1, the requirement that the app contains no component past its
fix time frame.

- **H8, Python names.** PyPI reads `jupyter_server`, `Jupyter.Server`, and `jupyter-server` as one package (PEP 503).
  The comparison matched names letter for letter, ignoring only case, so a lockfile and an advisory that spelled one
  name two ways never met. Python names are now compared through `manifest_lock::python_name`, the normalizer the
  manifest-and-lockfile comparison already used. Other ecosystems are compared as before: in npm, `lodash_x` and
  `lodash-x` are two packages, and a test holds that.
- **H10, nested npm copies.** A `package-lock.json` of version 1 keeps a second version of a package under the package
  that needs it. Only the top level was read, so an old copy installed underneath, the kind an advisory is usually
  about, was never compared. Every level is read now, and each copy is listed by its own name and version.
- **H11, packages known only from a manifest.** The clean claim required every lockfile to be read, but not every
  package to come from one. A package listed only by the version its manifest asks for is not known to be what is
  installed. The claim now requires the package list to be complete (`Sbom::is_complete`), the same test the SBOM
  uses before calling itself complete. A comparison that finds something still reports it, with medium confidence,
  as before.

Each fix was broken in turn and the new test for it went red: comparing Python names without normalizing them,
checking only for unread lockfiles, and not reading below the top level. In each case one test caught it, the one
written for it; no earlier test did, which is how the three got through. A first version had its own normalizer, and
breaking its joining of separator runs or its lowercasing was caught by the same test; it was replaced by the shared
one, which `manifest_lock`'s own test holds.
