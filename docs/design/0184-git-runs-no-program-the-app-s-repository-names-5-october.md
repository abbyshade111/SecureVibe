# Git runs no program the app's repository names (5 October 2026)

Found while looking at how `sv` runs outside programs, and not in the deep review. The committed-secrets check runs
`git ls-files` in the app's folder, on the owner's computer and outside the fence. Git reads the repository's own
`.git/config`, written by whoever wrote the app, and `core.fsmonitor` there names a program git runs to learn which
files changed. Reproduced: plain `git ls-files` ran it. An app handed to the owner to check could have run anything
during `sv check` (ADR-032).

- **One place runs git, `git::ls_files`** (`crates/sv-check/src/git.rs`), with `core.fsmonitor=false` given on the
  command line, which wins over the repository's own setting.
- **Only what was shown to run is overridden.** A planted `core.hooksPath` with `post-index-change` and
  `reference-transaction` hooks was tried too; `ls-files` runs neither, so nothing is given for them. An override
  for them was built and then taken out, since undoing it was caught by nothing.

How it is held: `a_program_the_app_s_repository_names_is_not_run` (`git.rs`) and
`checking_an_app_runs_no_program_its_repository_names` (`crates/sv-cli/tests/git_config.rs`), through `sv check`, each
with a control in which plain git runs the planted program. Undoing the override was caught by both, and reading the
files with git directly again, as before, by the second.
