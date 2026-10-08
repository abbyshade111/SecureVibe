# One file per design entry (8 October 2026)


Asked for by the owner on 8 October 2026 (BACKLOG, "One file per design entry, so two pull requests stop colliding in
`docs/DESIGN.md`"; `docs/adr/ADR-060.md`). Every session added its section to the end of `docs/DESIGN.md`, so any two
open pull requests changed the same lines, and that afternoon five of one session's pull requests were each put in
conflict there four or five times by the others' merges, stalling auto-merge each time.

The 296 sections of `docs/DESIGN.md` are now the files `docs/design/0001-…` to `0296-…`, numbered in the order they were
written and named by their headings, which are unchanged, so every `DESIGN, "Section title"` reference still finds its
entry. This is the first entry written as a file of its own, by `tools/design_entry.py new`. `docs/DESIGN.md` keeps its
opening and says where the entries are and how to add one, and holds no list of them: a list each entry added a line
to would put the conflicts back. `python3 tools/design_entry.py list` prints the entries in order, and the
documentation pages (`tools/docs_page.py`) list them under a heading of their own.

A branch written before the split conflicts in `DESIGN.md` once it merges `main`; the script's opening gives the three
steps, and `move` turns the branch's own sections into entries. A section whose title is an entry already and whose text
differs, a later note added to an old section, is named and left for a person rather than written twice or dropped.

Tests: `crates/sv-check/tests/design_entries.rs` runs the script's check and its self-test. Broken in turn, each caught:
a section appended to `DESIGN.md`, an entry misnamed, two entries with one title, and the script reading a `## ` inside
a code block as a heading. The split itself was checked by rebuilding the old file from the entries: identical but for
blank lines at the end of each section.
