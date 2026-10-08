# The preflight does not check that the start command's file is there

**Status:** done, as its markers read on 8 October 2026

Found on 6 October 2026 by session
paper-facts, in item 6: two builds wrote `securevibe.toml` with `start = "python app.py"` and no `app.py`, and `sv
run` could not start them. `securevibe_preflight` names a seed file that is missing; the start command's file should
be named the same way (ADR-035).
**Claimed on 6 October 2026 by session securevibe-e9**, with the crash's last line above, in branch
`claude/securevibe-e9-start-failures`.
**Done the same day** (same DESIGN section): the preflight names the start command's missing file, and adds that a
build step may make it.
