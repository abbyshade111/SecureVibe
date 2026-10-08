# Folders the manifest says are not the app (27 September 2026)

On `sv`'s own repository, the example apps and the fixture apps inside its tests were read as part of
`sv`. Their dependencies are evidence the corroborators trust, and corroboration only ever adds, so an
example's `authlib` overruled "auth = false" and switched on the sign-in requirements for a tool nobody
signs in to: 19 answers overruled, and 547 findings from code that is not `sv`.

**The manifest can name them.** `[repository] not-the-app = ["examples", "crates/*/tests"]` lists folders
from the app folder, where `*` stands for one whole folder name. Matching is by whole names: `examples`
holds `examples/shop/app.py`, not `examples.md` or `my-examples/`. An entry that names the whole app
(`.`, an empty string, `*`), reaches outside it (`..`, an absolute path), or uses `*` inside a name is
refused, and the report says so.

**Still read, never evidence about the app.** `sv_scan::scan_app` leaves those folders out of what the
scanner treats as the app: the files it looks in for technologies, the languages, the declared
dependencies, and the ecosystems and unpinned lockfiles. Every command reads the app through one helper
(`scan_for`), so `sv scope`, `sv report`, `sv notes`, and `sv questions` agree. Nothing else changes: the
code rules, the credentials scan, the bill of materials, and every other check still read those folders,
their findings still count toward their requirements, and each is listed with test and sample code
(`mark_not_the_app`), as the section above describes.

**Said in the report.** Moving evidence out of view is the kind of thing that must be visible, since a list
that named the app's own `src` would hide what the app uses. The report's "What was not examined" names
the folders that were set apart, any named that are not in the app, and any entry refused, and says to take
the app's own code off the list. Unlike a finding set aside, the list does not need a person's name: it
hides nothing, since every finding in those folders is still listed and counted. What it can take away is
evidence that more requirements apply, which is why the report shows it.

`sv`'s own `securevibe.toml` uses it, at the owner's asking: `crates/*/tests`, `examples`, `tools`, and
`docs`, the four the v2 self-assessment left out of its "product code only" run. That file is the one the
self-assessment's repository run used, so a rerun of that run now differs from what the assessment records.
