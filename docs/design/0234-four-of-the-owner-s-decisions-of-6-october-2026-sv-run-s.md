# Four of the owner's decisions of 6 October 2026: `sv run`'s exit status, one word of a prompt, a builder with no owner, and the live site's ciphers

Each was put to the owner with a recommendation, and each was decided as recommended (BACKLOG, the documentation
review's items 4 and 8, "Builders told the owner is away still stop to ask", and "More probes", item 8).

- **`sv run` exits 2 when the app could not be run** (ADR-029, Later, 6 October 2026). It printed "Not assessed" and
  exited 0, which a CI job reads as a run that went well. Now 0 means the app ran, whatever was found; 2 that it could
  not be started or never answered; 3 that `sv` itself failed. `sv run --help` and `sv --help` say so.
- **"It creates" becomes "it prints"** in the shown "settings file first" prompt (`data/prompts.json`,
  `docs/PROMPTS.md`), since `sv init` prints the file. Nothing else in a prompt shown to work was changed, and
  `docs/PROMPTS.md` says the one word changed after its trial. Its advice to delete a line when unsure stays: like
  `sv init`'s "say true", it leaves nothing excluded.
- **A stronger sentence for a build with no owner** (the loop protocol's amendment 5, and `NO_OWNER` in
  `docs/prompts/loop-pilot/loop_trial.py`): "do not stop to ask me anything", and "keep going until the app is built
  and runs", for every arm of every trial after item 6.
- **V12.1.2, the live site's cipher suites, stays unchecked by `sv`**, since it takes dozens of handshakes and
  `sv probe` keeps to four. The report's "how to check it yourself" list (`data/human-checks.json`) now says so, and
  names testssl.sh and SSL Labs' online test, with what a good result looks like.

How it is held: the loopback tests in `crates/sv-cli/tests/loopback_start.rs` check exit 2 for an app that never
answers, with a container backend and without one, and exit 0 for one that ran, its control (setting the not-assessed
return to 0 turns the first red); `the_help_says_what_each_status_means` now covers `sv run`; and
`the_live_sites_ciphers_are_left_to_a_scanner_the_owner_runs` (`crates/sv-check/tests/human_checks.rs`) holds the
instruction, with V12.1.1, which `sv probe` does ask about, as its control.
