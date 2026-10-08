# When an app crashes at start, `sv` quotes the first line of the error, not the last

**Status:** done, as its markers read on 8 October 2026

Found on 6 October 2026
by session paper-facts, in the loop's item 6: three Haiku apps crashed when they started, and each run said "Its last
output was: Traceback (most recent call last):". `never_ready_detail` (`crates/sv-run/src/docker.rs`) quotes
`first_line` of the logs, and a Python error says what went wrong on its last line. The hint that follows, about an
app listening on `127.0.0.1`, is beside the point when the app crashed. Quote the last lines (the exception), and
give the loopback hint only when nothing crashed.
**Claimed on 6 October 2026 by session securevibe-e9**, with the preflight's start file below, at the owner's word
("Please continue to work off the backlog"), in branch `claude/securevibe-e9-start-failures`.
**Done the same day** (DESIGN, "An app that crashes at start, and a start command whose file is not there"): a
crash is quoted by its error line, and is told the error is why in place of the loopback guess; an app that did
not crash is quoted by its last line.
