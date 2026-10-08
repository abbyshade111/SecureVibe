# `sv check` reads securevibe.toml when it is there (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 5.1). `sv check` at a terminal never read securevibe.toml, so a file the
AI coding tool wrote and `sv` could not read got no word and exit 0, while `sv report` and `securevibe_check` refused
it. Between 15 and 34 percent of Haiku's builds in the loop trials wrote such a file.

- **What changes.** When the file is there, `sv check` reads it before anything else and stops on one it cannot read,
  with the reader's own message and exit 3 (ADR-029, "Later, 7 October 2026"). With no file it runs as before: the
  credential scan, the code rules, and the configuration checks need none.
- **What it is for.** Only that: nothing `sv check` reports depends on the file. Its help now says it is a narrower
  scan than `sv report` or `securevibe_check`, saying nothing about requirements, and reads the file only to stop on
  one it cannot read.
- **The coding rule.** "After each feature, run `securevibe_check` (or `sv check` in a terminal)" pointed an AI tool at
  the narrower scan as if it were the same thing. It now names `sv report` as the terminal's form, and says `sv check`
  is a narrower scan.

One guard broken, and caught: with the file not read, the test's two broken files (bad syntax, a misspelt section)
finish with 0 and the scan runs.
