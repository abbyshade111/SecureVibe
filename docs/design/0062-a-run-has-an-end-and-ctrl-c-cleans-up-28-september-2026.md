# A run has an end, and Ctrl-C cleans up (28 September 2026)

Review item 2 found that nothing bounded `sv run`: every Docker call waited as long as it took, the app's own
test command included, so a suite that hung hung the whole run. And Ctrl-C left the run's containers and network
behind, because a signal ends a Rust process without unwinding, so the teardown in `Teardown`'s `Drop` never ran.
Both are fixed in `crates/sv-run/src/lib.rs`.

- **Every Docker call has a limit: 20 minutes.** That is generous on purpose. `docker run` downloads an image it
  does not have, which takes minutes on a slow connection; the point is that a run never waits forever, not
  that it hurries. A call that runs out of time is stopped and reported like any other failed call.
- **The app's own tests get 10 minutes.** A suite stopped at the limit credits nothing, whatever it printed. The
  report says it was stopped and after how long, not that it failed, and shows the last lines it printed, which is
  where a hung suite shows how far it got.
- **Stopping a command stops what it started.** Each command runs in a process group of its own, and the whole
  group is stopped. Stopping only `sh -c` left its children running, still holding the output open, so the
  run waited for them anyway; the first test of the limit found this.
- **Ctrl-C is caught once a run begins.** It stops the Docker command in progress and refuses the next, so the
  run returns and its teardown removes the containers and the network. The teardown's own calls still run after
  Ctrl-C. `--slow`'s long waits end at Ctrl-C too. `sv` then says it was stopped, writes no report (what a run
  got to before it was stopped is not a report of the app), and exits with 130, the usual code for Ctrl-C. A
  second Ctrl-C ends `sv` at once, for someone who would rather clean up by hand than wait.

**Later the same day: the two gaps above, closed** (session securevibe-e2, at the owner's asking):

- **The test limit can be set.** `[stack.run] test-time-limit` is the number of seconds the suite may run; left
  out, or 0, it is ten minutes. A suite that needs longer is not stopped for it.
- **A run ended by something that cannot be caught is cleaned up by the next one.** Everything a run creates
  carries the label `org.securevibe.owner=<machine>:<process>` (`sv_run::cleanup`). Each run first removes what
  carries this machine's name and the id of a process that has ended, and says what it removed, on the
  terminal and in the report. It leaves alone what another running `sv` owns, what `sv` on another machine
  sharing the Docker daemon owns, and anything unlabeled. The machine's name is in the label because `sv` in a
  container has process ids of its own: without it, a host `sv` could read a container's live run as ended.
  Where a process cannot be asked about, it counts as running, so nothing is removed on a guess. Tested against
  real containers: a run killed with `kill -9` leaves its app and network (the control), and the next
  `sv run`, and the next `sv report --run`, each remove them and name them.

**Later still: a run that fails says what it removed as well.** The removal happens before the app is started,
so it has happened whether or not the app then answers. At first only a run that succeeded said so; one that
failed afterwards (an app that never answered, a Docker that refused) gave its reason and nothing else, and
containers and a network had gone from the owner's computer without a word. Seen on the owner's Mac, where a
failing test run had quietly cleaned up. A failed run is now a `RunFailed`: the reason, and what was removed
first, and its explanation gives both, so `sv run` and `sv report --run` say it on either path.
