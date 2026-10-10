# `git ls-files` runs a program the app's repository names

**Status:** done, as its markers read on 8 October 2026

Found on 5 October 2026 by session securevibe-e9,
while looking at how `sv` runs outside programs. The committed-secrets check runs `git ls-files` in the app's
folder (`crates/sv-check/src/config.rs`), and git honors the repository's own `.git/config`. A `core.fsmonitor`
there is a program git runs: reproduced, `git ls-files` ran it. So an app someone hands the owner to check could
run anything on the owner's computer, outside the fence, during `sv check`. In the Docker image, which trusts every
repository (`safe.directory '*'`), the same. Fix: run git with the settings that run programs overridden on its
command line, which wins over the repository's; a test that plants one.
**Claimed on 5 October 2026 by session securevibe-e9**, at the owner's asking to keep working off the backlog,
in branch `claude/securevibe-e9-git-config`.
**Done the same day** (DESIGN, "Git runs no program the app's repository names"; ADR-032): git is run through
one place, with `core.fsmonitor` overridden on its command line, and a test plants one and checks it never runs.
