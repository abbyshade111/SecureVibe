# `a_run_killed_outright_is_cleaned_up_by_the_next_one_and_said_to_be` failed once on CI

**Status:** done, as its markers read on 8 October 2026

Seen on 29 September
2026 by session securevibe-e2, on the pull-request run of #447 (a change to this file alone), while the push run of
the same commit passed. `crates/sv-cli/tests/killed_run.rs:177`: the killed run was listed as leaving
`sv-<pid>-0-app`, `-net`, and `-probe`, and the next run's message named the app and the network but not the probe
sidecar; nothing was left afterwards. The sidecar runs `sleep 900` with `--rm`, so why it was listed and then not
named is not known; a guess, marked as one: the next run's leftover listing, or its removal, can miss a container
that is starting or already being removed. Needs a container backend to reproduce. **Claimed on 30 September
2026 by session securevibe-e2**, at the owner's asking to pick another backlog item, in branch
`claude/securevibe-e2-killed-run`. **Done the same day; the fault was in the test, not in `sv`.** A run removes
the sidecar once its questions are asked, and on CI the questions took less than the three seconds the test
waits before killing it, so the kill could land while `docker rm -f` of the sidecar was running. Killing `sv`
does not stop the `docker` calls it started: that removal finished on its own, after the test had listed the
sidecar as left behind and before the next run looked, so the next run rightly did not name it. Reproduced here
with a `docker` wrapper that holds the sidecar's removal for a second and the kill moved into it: 4 failures in
12 runs, the same message as CI. The test now waits, after the kill, until no `docker rm -f` or `docker network
rm` naming the killed run is still going, then lists what it left (a `docker exec` of the suite is not waited
for, since it runs for minutes and removes nothing). The same setup then failed 0 times in 22 runs, the wait was
seen catching a removal in flight in both halves of the test, and a kill moved into the suite still passed.
