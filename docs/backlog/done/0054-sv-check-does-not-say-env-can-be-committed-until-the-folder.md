# `sv check` does not say `.env` can be committed until the folder is a git repository

**Status:** done, as its markers read on 8 October 2026

Found on 5 October 2026
by session paper-facts, in the loop pilot: every build was flagged `config.gitignore-covers-env` (high) by
`sv report` on a copy that had been made a repository, and the `sv check` during the build, in a plain folder, said
nothing. A builder that checks before `git init` never hears it. Either say it in a plain folder too, or say that it
was not looked at.
**Claimed on 5 October 2026 by the cato-pipeline session**, at the owner's asking to take one of the pilot's
findings, in branch `claude/env-plain-folder`.
**Done the same day** (DESIGN, "`.env` with nothing leaving it out, in a folder not yet in git"): it is said. A
`.gitignore` is read the way git reads it (H23), so only a folder with no `.gitignore` needed a repository; now a
plain folder with no `.gitignore` and a `.env` or `.env.*` at its root is a finding, worded for a folder not yet
in git, and naming the one thing `sv` cannot read (a global git ignore file on the computer). With no environment
file it is still not assessed. Repositories are unchanged. Tested in `config.rs` and through `sv check`,
`sv report`, and the MCP check together (`tests/env_plain_folder.rs`); four guards undone in turn were each caught.
**Seen working on 6 October 2026** in the loop's item 6: in five loop builds `securevibe_check` named the
`.gitignore`, the builder wrote one, and the final report did not find it.
