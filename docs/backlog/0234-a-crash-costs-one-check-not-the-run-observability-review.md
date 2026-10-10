# A crash costs one check, not the run (observability review, part 3, F)

**Status:** open

The owner's word, 10 October 2026, asked with the three other open decisions of that day: yes (part 3, F, of backlog 0226).

A check that crashes costs that check, not the run: each stage of `sv report` run so that a panic in one is caught,
recorded as "not assessed: the check crashed", with the place, and the rest of the report written. A new reason for
not assessed, so its record is written with the build. Medium.
