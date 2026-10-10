# Clean coverage from the remaining checks

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 24 September 2026. Every check that can find
something now also reports what it examined and found nothing wrong, each failing closed on its own
coverage. Left over: `sv report` does not run the bill of materials or the advisory comparison at all
— they live in `sv check` and `sv audit`, the latter because it needs an offline database path — so a
report says nothing about dependencies either way. That is a bigger change than this item and is not
what this entry asked for, but a reader of the reports would not guess it. **Since then:** the report
runs the advisory comparison with `--advisories` (DESIGN, "In the report too") and asks the bill of
materials for its gaps (DESIGN, "The report asks the bill of materials"). It still leaves out the bill
of materials' own finding, and that turned out to matter: see "The report credits V15.1.2 for a lockfile
it could not read" under Next.
