# `probe.action-done-twice` reports a booking that went through once as twenty

**Status:** done, 10 October 2026

Found on 4 October 2026 by
session securevibe-e2, testing the design-time prompts. The check sends the `once` action 20 times at the same
instant, all as the first test user, and counts the answers carrying the `completed` text. The build made with the
"actions that must happen once" prompt took the seat in one conditional UPDATE, and answered a repeat from the member
who already held it with "Booked" again, changing nothing: what that prompt asks for ("safe to repeat"). The check
counted 20 bookings and raised the finding against a correct app (the trial in `docs/prompts/design-time.md`). An app's own
answer cannot tell "taken now" from "already yours". Ways out, for the owner to choose: send the copies as two or more
users, so only one of them can be told it went through; or read the effect, from a page `once` names that shows how
many were taken, rather than the answers. Until then the finding can accuse exactly the app it should credit, which
is the kind of false alarm that makes the tool rewrite correct code.
**The owner's decision, 5 October 2026:** send the copies as two or more users. **Claimed the same day by session
securevibe-e2**, at the owner's word, in branch `claude/securevibe-e2-done-twice-users`.
**Done the same day** (DESIGN, "Later, 5 October 2026: two users, not one"). The copies go half as A and half as B;
the action going through for both is the finding, and a repeat the holder is told went through is not. Credit needs
both users shown signed in and holding the token, and the refused user still signed in afterwards, so a refusal for
being signed out never counts. Ten guards broken in turn, each caught. Not yet run against a real app in a
container: no `once` example exists, and this environment has no Docker; the script itself was run with the
sidecar's busybox.

**Checked against origin/main, 10 October 2026:** code built: `crates/sv-check/src/signed_in/once.rs` sends the copies half as user A and half as user B. A run against a real app with a `once` example is not on main.
