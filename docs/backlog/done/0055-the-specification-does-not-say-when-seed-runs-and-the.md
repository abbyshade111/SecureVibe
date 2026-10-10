# The specification does not say when `seed` runs, and the prompts trial's brief says the opposite of what `sv` does

**Status:** done, as its markers read on 8 October 2026

Found on 5 October 2026 by session paper-facts, running the third prompts trial. `sv run` runs `seed` inside
the app's container after the app has answered its health path (`sv-run/src/docker.rs`, `seed`). The spec says only
"creates them"; `docs/prompts/trial/brief.md` says "when run once before the app starts". An app that makes its
tables only in its seed crashes on the first page `sv` asks for, and the run is reported as could not start: three
Haiku builds in the trial did. Ways out, for the owner: say in the spec that the seed runs once the app is up, so
the app must make its own tables; or run the seed before the health check. Either way, correct the brief.
**Claimed on 5 October 2026 by session paper-facts** with item 1 of "The loop", above, in branch
`claude/loop-confounds`: the spec will say when the seed runs, and how `sv` runs it is not changed (running it
earlier would break apps that make their tables when they start). Changing when it runs stays the owner's to choose.
**Done the same day**, as said: the spec and the plan say when the seed runs, and the brief is corrected. How `sv`
runs it is unchanged.
**The owner's decision, 5 October 2026:** leave when the seed runs as it is.
