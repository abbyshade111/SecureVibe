# The headline counts what was set aside (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 1, R2) found a report whose only finding had been set aside as a
false alarm opening with "Nothing here found a problem". A false alarm leaves the report's findings when it is set
aside, and `bluf::headline` counted the findings alone. With R1 (an AI tool can write `by = "owner"` on its own
review), that line is the one a reader would take away from an app whose problem was waved off.

`headline` now counts false alarms beside the findings. With nothing still open it says how many were found and set
aside, and where they are listed, before saying that nothing being open is not the app being sound; beside open
findings it adds how many more were set aside. It says they were set aside "in securevibe.toml", not by a person:
`sv` cannot tell who wrote the entry, which is R1's question, not settled here. An accepted risk stays among the
findings, so it is not counted twice. Three guards broken in turn, each caught, two of them also by the end-to-end
review test, which now reads the headline in both `compliance.md` and the HTML page.
