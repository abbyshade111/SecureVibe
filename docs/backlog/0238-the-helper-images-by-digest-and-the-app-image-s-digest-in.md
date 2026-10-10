# The helper images by digest, and the app image's digest in the report (observability review, part 3, K)

**Status:** open

The owner's word, 10 October 2026, asked with the three other open decisions of that day: yes (part 3, K, of backlog 0226).

The helper images `sv` runs (`busybox`, `mailpit`, `node`, the headless browser) named by digest, not by tag, and the
app image's digest said in the report, so a run is repeatable and a moved tag cannot change what runs. Changes what
`sv` runs, so its record is written with the build. Small.
