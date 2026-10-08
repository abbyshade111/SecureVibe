# An unanswered question excludes requirements when a corroborator found nothing

**Status:** done, as its markers read on 8 October 2026

Done on 26 September
2026 (see the end of the entry). Found on 26 September 2026 reviewing the new manifest questions. `ci-cd` and `iac` are claim
conditions — `securevibe.toml` asks about them — and when the manifest does not answer, a
corroborator that looked and found nothing answers `false` for it, which marks requirements *not
applicable* rather than *not assessed*. On a manifest holding only `manifest-version` and
`[app] name`, that excludes twelve requirements, eleven of them AC.12's CI/CD pipeline hardening.

The report says in the same breath that this is not valid. Its own note for that state reads:
*"Taken on the manifest's word. `sv` looked and found nothing, which for this is not the same as
finding it absent."* There was no manifest word to take, and the sentence says why finding nothing
should not settle it.

The two states are also indistinguishable in the outcome. With `ci-cd` unanswered the claim is
`unverifiable`; with `ci-cd = false` written down it is `confirmed` and *"the manifest and the code
agree"* — and both exclude the same twenty-eight requirements. Meanwhile `hosted-scm` and
`outside-contributors`, claim conditions with no corroborator, correctly stay *not assessed* and say
so: *"Nobody has said. Requirements that turn on this are not assessed rather than excluded."* So the
same silence is handled two ways depending on whether a corroborator happens to exist for it.

`resolve` is where it comes from: `(None, Some(false)) => Some(false)`. That is right for the derived
conditions — no GraphQL library in the lockfile really does answer `graphql`, and the manifest never
asks — and wrong for a claim condition, where absence of a `.github/workflows` folder in an uploaded
app is exactly the case the note describes. Sixteen of the twenty-eight exclusions on that manifest
are derived and sound; the twelve from `ci-cd` and `iac` are not.

This is the direction `sv init` calls the one that matters: "A capability present but denied is the
one mistake that matters — it is how a real requirement gets marked not applicable."

**Claimed on 26 September 2026 by session securevibe-e8**, at the owner's asking, before the
threat-model citations, the mock identity provider, and the real browser. **Done the same day.**
An unanswered claim now stays unanswered whatever the scan found; the twelve are AC.12.1–AC.12.8,
AC.7.3, AC.7.4, AC.9.1, and SBD-AC-07 (eight of them AC.12, not eleven), and all twelve are now
not assessed. See DESIGN, "Finding nothing does not answer for the owner".
