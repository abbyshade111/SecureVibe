# The build-loop record read a line at a time, and said when full (9 October 2026)

Backlog 226 (the observability review), part 1, items 3 and 7, built by session stackvet-e9. Both are places where
the record of the build loop (ADR-076) said less than it knew, and the report then said something untrue.

**One bad byte.** `read_at_most` read the record with `read_to_string` and ignored its error. On text that is not
UTF-8 that call leaves the buffer empty, so `summarize` saw no line at all and the report said "Nothing shows that sv
was used", about an app whose record held every call. ADR-076 says a line that cannot be read is counted and said.
The record is now read as bytes and split on newlines; each line is decoded on its own, and one that is not UTF-8
counts as unreadable like a line that is not JSON. `summarize` takes bytes for that reason.

**The size limit.** `record` stops writing at `MAX_BYTES` (4 MB), and `MAX_BYTES`'s comment said a report "says the
rest was left out", but nothing did: `BuildLoop` had no field for it, so "the last check came to …" named the last
check written, which may be long before the last made. `BuildLoop` now has `full`, set when the file has reached the
limit, and the report's paragraph adds that later calls were not written down and the last check named is the last
one written. `full` is left out of `report.json` when false, so a report written before it reads and is sealed the
same. Reading stops at the limit too, and the line the cut falls through was written whole by `sv`: it is dropped,
not counted as unreadable, since saying "one line could not be read" about a line `sv` wrote well would be its own
small untruth.

**Tests.** `build_loop/limit_tests.rs` writes a record with a byte that is not UTF-8 between two good lines (two
calls and one unreadable line, where the old reading gave none), a record past the limit (full, no further line
written, no half line counted), and one short of it (not full). `mcp/build_loop_limit_tests.rs` writes a report
over each: the page does not say `sv` was never used, and `report.html` and `compliance.md` say the record reached
its limit. With the old reading put back and `full` never set, four of the five fail.
