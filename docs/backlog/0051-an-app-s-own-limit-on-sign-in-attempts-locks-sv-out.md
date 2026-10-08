# An app's own limit on sign-in attempts locks `sv` out

**Status:** done, as its markers read on 8 October 2026

Found on 5 October 2026 by session paper-facts, in the
loop trials and trial 3 before them: an app that limits sign-ins answered `sv`'s admin sign-in with 429, and the
signed-in checks had nothing to work with. A correct limit is what the owner wants; `sv` signs in many times in a
run from one address. The spec could say how many, so a builder can set the limit to allow them in a test copy, or
`sv` could say which sign-in hit the limit and stop counting the checks it blocked as unanswered.
**The owner's decision, 5 October 2026:** both. **Claimed the same day by session securevibe-e2**, at the owner's word, in branch
`claude/securevibe-e2-signin-limit`.
**Done on 5 October 2026 by session securevibe-e2.** The spec's `[stack.run.users]` says `sv` signs in up to 60
times in one run from one address, before the guessing check's wrong passwords (the scripted runs make 13 to 50, and
a test holds them and the spec to the number). A sign-in the limit still refuses after waiting is named in one gap,
as the limit working rather than the app failing, with what to change; the first user's no longer reads as a mistake
in securevibe.toml. Not tested against a real app with a sign-in limit. DESIGN, "Later, 5 October 2026: a sign-in the
app's limit refuses is named, and the spec says how many there are".
