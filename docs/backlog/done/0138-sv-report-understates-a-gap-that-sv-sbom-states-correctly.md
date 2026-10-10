# `sv report` understates a gap that `sv sbom` states correctly

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 by
session securevibe-e9. The report builds an SBOM and asks it, instead of reasoning about dependencies
from `scan_report.unpinned`: an unreadable ecosystem is now reported as an empty list rather than an
approximate one, a manifest-declared one as what was asked for, and a fully locked one as no gap at
all. The sentence was also wrong about pip in the other direction — `flask==3.0.0` does pin a version,
and it said `requirements.txt` "pins no versions". See DESIGN, "The report asks the bill of materials".
Left over: the report still does not carry the SBOM's incompleteness finding or run the advisory
comparison, which is the other half of the entry this shares a root with.

As originally found, on 25 September 2026 while reviewing the nested-manifest walk. For an ecosystem
whose manifest versions `sv` cannot
read, the report says the list holds what was asked for, when the list holds nothing at all. The two
commands on the same app — a `package.json` with `"react": "18.0.0"` and no lockfile:

    sv sbom    npm is in use but nothing readable says which versions are installed,
               so none of its packages are listed
    sv report  package.json pins no versions, so the list of dependencies is what was
               asked for rather than what is there

`sv sbom` is right, and puts a `securevibe:unread:npm` component in the CycloneDX document so a
downstream reader sees it too. `sv report` builds its gap from `scan_report.unpinned` with one
sentence for every ecosystem, and that sentence is true of pip — `flask==3.0.0` really is the version
asked for — and wrong of npm, where no version in a `package.json` is read at all and that
ecosystem's bill of materials is empty. A reader is told the list is approximate when it is absent.

Same root as the entry about `sv report` not running the bill of materials or the advisory
comparison: the report reasons about dependencies from the scan alone and never asks the SBOM, which
already knows the difference and says it well. Rewording the sentence is probably the wrong fix — one
sentence covering two ecosystems will be wrong about one of them again. **Claimed on 25 September
2026 by session securevibe-e9.**
