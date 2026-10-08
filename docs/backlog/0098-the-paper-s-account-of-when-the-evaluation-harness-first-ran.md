# The paper's account of when the evaluation harness first ran disagrees with the first session's transcript

**Status:** done, as its markers read on 8 October 2026

Found on 27 September 2026 while tracing, at the owner's asking, where the harness came from. **Claimed on
28 September 2026 by session admiring-murdock-875699**, at the owner's asking. **Done the same day:** `TIMELINE.md`
says where the harness came from and gives Day 0 its recorded times (the commits' own, from the v1 bundle), and
`METHODOLOGY.md` notes that its quotation's date is UTC.
The transcript (the first session, "Vibe-coding application builder") and `securevibe-reasoning.md` in the
owner's paper folder show:
- At 19:48 Eastern on 17 September, the owner asked about optimizations "for example, build out/refine a
  harness and/or orchestrated agentic workflow".
- At 19:49, Claude proposed "An evaluation harness" with "golden apps (five or six profiles covering the feature
  combinations)".
- At 19:58, the owner chose it: "…and the evaluation harness and golden apps".
- At 20:37, the harness was designed, and at 20:42 its first run found template bugs.

Two places in `docs/paper/` say otherwise:
- `METHODOLOGY.md` says its first run was "on 18 September 2026". 20:42 Eastern on the 17th is 00:42 UTC on
  the 18th, so the date is probably UTC.
- `TIMELINE.md`'s Day 0 table puts the harness in the commit at "~20:15" (`af6b83f`). The harness did not exist
  until after 20:37.

Correct both to Eastern time, as the rest of `TIMELINE.md` is, and say in `TIMELINE.md` who introduced the idea
and who chose it, with the quotations above.
