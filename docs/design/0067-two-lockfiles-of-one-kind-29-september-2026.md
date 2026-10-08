# Two lockfiles of one kind (29 September 2026)

A project can hold two lockfiles for the same package manager: a `package-lock.json` beside a `yarn.lock` left
from before a switch, or a `uv.lock` beside the `requirements.lock` exported from it. `sv` reads the first one in
the ecosystem's list and, until now, said nothing about the other. The two can disagree, and the one not read may be
the one the app is installed from, so the bill of materials and the comparison with advisories could describe
versions the app does not ship, with nothing in the report to say which file they came from.

`sv` still reads one of them, in the same order, and now names the rest wherever the versions are used. Reading
both and listing every version from either was considered, as the safe side for advisories, as platform conditions
are handled; it was not done, because two lockfiles that disagree are a fault in the app for its owner to settle,
and a list that silently merges them hides the fault rather than showing it.

- **Detection** (`sv-scan`, `DetectedEcosystem::passed_over`): the other lockfiles of the same kind in the folder
  the one read came from.
- **The bill of materials** (`Sbom::passed_over`): which file was read and which were not, and in the CycloneDX
  document a `securevibe:lockfile-passed-over:<project>` property. The list is still *complete* in the sense the
  document already uses, a full reading of a lockfile, so `securevibe:complete` does not change; `sv sbom` no
  longer ends with "so this is what is installed" when it is only what one of two files says.
- **The report**: a gap, "which lockfile npm is installed from", naming both files and saying to remove the one not
  in use. In `report.json`'s `examined` list, `advisory.` is `partly`, naming the file not read beside the one that
  was: a finding that stops appearing because a different lockfile was read is not a fixed finding.
- **The clean claim** (`advisories::audit_against`): "every package compared, nothing found" is withheld, as it is
  for an incomplete list, since the question is whether the app ships anything vulnerable and the list may not be
  what it ships. `sv audit` then exits 2 (not assessed) rather than 0, and says which file was not read. A
  vulnerability found in the file that was read is still reported.

**How it was checked.** Six tests: detection (`scan.rs`, three lockfiles beside one manifest and one below that has
only one), the document (`sbom.rs`), the clean claim (`advisories.rs`, with the one-lockfile control), `sv sbom`'s
terminal (`dependency_gap.rs`), `report.json` (`examined.rs`, with the one-lockfile control), and `sv audit`'s
status (`audit_two_lockfiles.rs`, 0 with one lockfile and 2 with two). Each of eight guards was broken in turn across
the whole workspace: detection finding nothing turns three red; the note left out of the bill of materials, two;
each of the document's property, the report's gap, the `examined` reason, the claim, the `sv audit` line, and the
`sv sbom` wording turns at least its own test red. No example app in the repository has two lockfiles of one kind, so
no report of theirs changes.
