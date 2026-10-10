# Changing and deleting another user's record can be credited when the request never reached a route

**Status:** done, as its markers read on 8 October 2026

Found on 8
October 2026 by the second documentation review: `update` and `delete` under `owned` are POSTed as forms unless they
say otherwise, and the specification does not say they can (`method`, `json`). For an app whose route is `PUT` or
`DELETE`, the second user's request answers 405, the first user's record is unchanged, and that is read as a refusal,
so V8.2.2 is credited in full (`crates/sv-check/src/signed_in/admin.rs`, ADR-053). A refusal should count only when
the same request, sent by the record's owner, does change or delete it. **Claimed on 8 October 2026 by session
paper-facts**, at the owner's word ("go ahead with ... the deep scrub and review of the documentation"), in branch
`claude/owned-control`, with a Later entry on ADR-053. Read on `main` just before this claim: no other session had
claimed it.
**Done the same day** (ADR-053, Later): the first user sends the same request at a second record of their own, and
the second user's request counts as refused only when the owner's own changes or deletes theirs; otherwise V8.2.2 is
checked in part, naming the request and `method`. The specification says how to give `method`, `json`,
`token-field` and `id-field`.
