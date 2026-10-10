# `probe.cors-any-origin` asks only the health path

**Status:** done, as its markers read on 8 October 2026

Found on 7 October 2026 by session paper-facts, in the recipe
trial: the stranger `Origin` goes to `/` alone (`crates/sv-check/src/probes.rs`, the `cors` request), so a JSON API
that lets any site read it, the case the check exists for, is never asked. Ask the app's listed private pages and
API addresses too, signed in where they need it.
**Claimed on 7 October 2026 by session paper-facts**, at the owner's word ("go ahead with the next steps from the recipe
trial"), in branch `claude/two-samples`, with ADR-055 `Status: proposed`. Read on `main` just before this claim: no other session had claimed it.
**Done the same day** (ADR-055, accepted): each `private` page asked as the first user, signed in.
