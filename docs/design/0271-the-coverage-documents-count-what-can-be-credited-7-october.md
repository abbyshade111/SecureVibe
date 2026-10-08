# The coverage documents count what can be credited (7 October 2026)

The gap analysis (`docs/GAP-ANALYSIS.md`, 1.8) found that `docs/COVERAGE.md`'s headline, "can settle" 49% of ASVS,
counted 50 requirements that a check can only ever find failing. A check can show the control missing, and finding
nothing does not show it present, so no clean run credits them. `docs/REQUIREMENTS.md` called them "Can be checked".
Those are the numbers people quote.

- **A column of its own.** The summary, the ASVS level table, and both chapter tables gain **Can be credited**: of
  the requirements a check can settle, the ones a check can mark *checked*. For ASVS that is 119 of 345 (34%) beside
  169 that can be settled, and 43 of the 70 at level 1, beside 57.
- **The ASVS sentence.** The AISVS section already said how many of its settled requirements can only be marked
  *needs attention*. ASVS now has the same sentence under its level table: 50 of 169.
- **A label of its own.** In `docs/REQUIREMENTS.md`, such a requirement reads **Can only be found failing**, not
  "Can be checked", and each framework's and level's count says how many there are.
- **Held to a second reading.** `credited` decides the column. `data/reach.json` was written separately, from the
  checks that can credit each requirement. `tools/coverage.py` stops when the two name different requirements.
  Counting every requirement a check can settle as creditable stopped it, naming the 16 that differ.
- **Not changed.** The paper's figure (`docs/paper/figure-security.html`) quotes "can settle" as of 3 October, with
  its own definition. It is a dated measurement in the paper's hands, so it is left as it is. The backlog notes the
  credited share for whoever next updates it.
