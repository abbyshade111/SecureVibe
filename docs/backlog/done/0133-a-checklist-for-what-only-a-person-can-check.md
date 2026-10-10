# A checklist for what only a person can check

**Status:** done, as its markers read on 8 October 2026

Asked for by the owner on 26 September 2026,
after the report readability work: *"perhaps a checklist for the checks that have to be verified by
a human, with a short description of how to verify them."* **Claimed on 26 September 2026 by
session securevibe-e8.** Measured against a real report first, because two earlier estimates of the
size were wrong: 98 applicable requirements can only be settled by a person — 40 ASVS (7 at level
1, 33 at level 2), 21 Secure by Design, and 37 AISVS. Of the ASVS ones, 20 have no plain-language
question yet; the security notes and design questions already cover the other 20. So the new
writing is `data/human-checks.json` with one how-to-verify line each, and a report section that
gathers all three sources, level 1 first. The 58 Secure by Design and AISVS controls get a group
explanation rather than 58 lines: those standards are checklists already, and 58 more rows is the
wall of text this work exists to remove. Nothing here credits anything — each stays unverified with
the instruction beside it. **Done on 26 September 2026.** `data/human-checks.json` (20 entries),
`crates/sv-check/src/human.rs` gathering all three catalogs, and a "What only you can check"
section above the tests, level 1 first. See DESIGN, "What only you can check". Left over: the 58
design-review controls are counted rather than explained, which is deliberate, and the 33 ASVS
level 2 entries could use the same treatment as the level 1 ones if the owner wants them broken
out.
