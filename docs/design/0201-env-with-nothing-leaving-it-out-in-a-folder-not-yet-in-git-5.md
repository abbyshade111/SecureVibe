# `.env` with nothing leaving it out, in a folder not yet in git (5 October 2026)

In the loop pilot every build was flagged `config.gitignore-covers-env` (high) by `sv report` on a copy that
`prompt_trial.py` had made a git repository, while the `sv check` during the build, in a plain folder, did not say
so: with no `.gitignore` and no repository the check answered "not assessed, nothing to read". A builder who checks
before `git init` never heard it, and then `git init` and `git add .` commit the `.env` that is sitting there.

Whether a `.gitignore` leaves `.env` out needs no repository: since H23 the file is read the way git reads it
(`gitignore_ignores`). The repository was needed only for one case, a folder with no `.gitignore` at all, where the
check had no file to read and so did not decide. That case is now decided from the folder's own files
(`gitignore_covers_env`, `crates/sv-check/src/config.rs`):

- **Not a repository, no `.gitignore`, an environment file at the root** (`.env` or `.env.*`, not a template such
  as `.env.example`): a finding, at the environment file, worded for a folder not yet in git: when it becomes one,
  the usual first commit (`git add .`) would save the file, unless a git ignore file kept outside the folder (a
  global one on that computer) leaves it out, which `sv` does not read. That one case cannot be decided from the
  app's files, and the finding says so rather than claiming more.
- **Not a repository, no `.gitignore`, no environment file**: still not assessed, now saying there is no `.env`
  either and to add a `.gitignore` before adding one. A folder with nothing to commit is not flagged.
- **Not a repository, with a `.gitignore`**: decided as before (it already was); a failing one now says the folder
  is not a repository yet.
- **In a repository**: unchanged, wording included, as is `config.secrets-file-committed` (what is already committed).
  A subfolder of a larger repository with no `.gitignore` of its own is still not assessed, because the one that
  matters may be in a folder above.

`sv check`, `sv report`, and the MCP server's `securevibe_check` all call `check_dir_in`, so they say the same.

How it is held: in `config.rs`,
`a_folder_not_yet_in_git_with_an_environment_file_and_nothing_leaving_it_out_is_a_finding`,
`a_folder_not_yet_in_git_with_no_environment_file_has_nothing_to_read` (no file, a template only, and a folder
called `.env`), and `in_a_repository_the_environment_file_check_is_unchanged`; and
`an_environment_file_in_a_folder_not_yet_in_git_is_said_by_all_three` (`crates/sv-cli/tests/env_plain_folder.rs`),
which asks `sv check`, `sv report`, and the MCP server over stdio about one plain folder with a `.env`, then with a
`.gitignore` covering it, then with neither. Each setup asserts the folder is outside any repository. Four guards
were undone in turn and each was caught: deciding nothing in a plain folder (the old behavior) failed the first
`config.rs` test and the three-way test; counting `.env.example` failed the no-file test; giving a plain folder's
failing `.gitignore` the repository's wording failed the first test; and taking the plain-folder path in a
repository failed the repository test, which is the only test of a repository with no `.gitignore`.
