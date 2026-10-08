# Semgrep skips some folders by default and does not say so

**Status:** done, struck through in the old file, as its markers read on 8 October 2026

Done on 25 September 2026 by
session securevibe-e8. Semgrep is handed the app's code files by name, which it reads whatever any
ignore file says, and the list of files it writes (`--json-output`) is checked against the list it
was given; a file it was given and did not read, or no list at all, withholds the clean-run credit.
`docs/DESIGN.md`, "Semgrep is named the files". Left as it was: `build/`, `dist/`, `vendor/` and
the rest of `SKIP_DIRS` are not handed to it, because no check in `sv` reads them. If built output
can be what ships, that is a question about `SKIP_DIRS` for every check at once, not about semgrep.
