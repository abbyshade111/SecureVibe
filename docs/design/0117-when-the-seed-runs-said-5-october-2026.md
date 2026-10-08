# When the seed runs, said (5 October 2026)

`sv run` runs `[stack.run.users] seed` inside the app's container once the app answers on its health path, and again
in the second copy it starts for an AI kill switch (`sv-run/src/docker.rs`, the signed-in stage). The spec said only
that the seed "creates" the accounts, and the trials' brief said it ran "before the app starts"; in the third prompts
trial three builds that made their tables only in the seed crashed on the first page. The spec now says when it runs
and what follows (the app makes its own tables; the seed works on a fresh database), the plan's line for `seed` says
the same, and the brief is corrected with a note. How `sv` runs the seed is not changed: running it before the health
check would break the apps that make their tables when they start, which every Sonnet build did.

`the_spec_says_the_seed_runs_after_the_health_check_and_it_does` (`sv-run`) holds the sentence to the order in the
code: the health wait comes before the signed-in stage, and that stage runs the seed. It reads the code's text, so it
catches the call moved, not a run that behaves otherwise; removing the sentence, and putting the stage's call ahead of
the health wait, each turned it red.
