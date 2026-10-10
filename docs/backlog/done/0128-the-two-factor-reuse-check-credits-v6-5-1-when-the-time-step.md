# The two-factor reuse check credits V6.5.1 when the time step rolls over mid-check

**Status:** done, 10 October 2026

Found on
26 September 2026 reviewing the TOTP probes (#129). **Claimed on 26 September 2026 by session
securevibe-e9, and done the same day:** the check keeps clear of a step's last ten seconds, looks at
the clock again after the second use and tries the pair once more in the new step, says V6.5.1 is
not assessed if the step ends twice, and the V6.5.5 credit now says the 30-second bound was not
shown. `totp_checks` in
`crates/sv-check/src/signed_in.rs` reads the step once, at the top, and computes `current` from it.
Three sign-in attempts later, that code is given again to see whether the app takes it twice. If the
30-second step has ended in between — the run starts at a uniformly random point inside its step, so
this is ordinary, not rare — the app is refusing a code that is *stale*, not a code that is *used*,
and the probe reads the refusal as the app doing the right thing.

Reproduced rather than argued. A fake app with `totp_reusable` switched on, a clock that moves on
with every request, and a run starting four seconds before a step boundary:

| seconds per request | V6.5.1 |
|---|---|
| 0, 1 | finding, correctly |
| 2 | not assessed: *"The current code ... did not sign the two-factor account in ... Check `totp` in securevibe.toml, and that `seed` enrolled the account"* |
| 3 | **credited as verified**, and the steps line reads *"the same code again: refused"* |

An app that reuses codes is reported as one that does not. The two paths differ in which side of the
boundary the *control* lands on; the 2-seconds row is only noise, but it blames the owner's manifest
for something that is not wrong with it.

It needs an app that accepts the current step alone, with no drift tolerance either side — which is
what V6.5.5's own sentence asks for, a 30-second lifetime. So the apps that are strictest about
V6.5.5 are exactly the ones whose V6.5.1 failure is hidden. The existing tests cannot show it: the
fake app's clock stands still except during `wait`, so no test run ever crosses a boundary.

The fix is small — read the step again after the reuse attempt, and when it is not the step
`current` was computed for, report V6.5.1 not assessed (or recompute and try once more) rather than
crediting it. The same reasoning as the ordering fix the same pull request already made: a refusal is
only evidence when it can have no other cause.

**Also worth saying, smaller:** V6.5.5 says a TOTP has "a maximum lifetime of 30 seconds", and the
probe shows a code from five steps back being refused. That demonstrates *a defined lifetime*, which
is the requirement's first clause, and not the 30-second bound. The suite's correct app accepts one
step either side, so an app accepting 60-second-old codes is credited with V6.5.5 today. Tolerating
drift is the right engineering call; the evidence line should say which of the two clauses was shown.

**Checked against origin/main, 10 October 2026:** built: `totp.rs` keeps clear of the last 10 seconds, retries once in the new step, and reports unsure when the step ends twice; V6.5.1 is not assessed and V6.5.5 says the 30-second bound was not shown.
