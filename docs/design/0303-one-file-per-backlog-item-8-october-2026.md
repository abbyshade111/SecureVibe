# One file per backlog item (8 October 2026)


Asked for by the owner on 8 October 2026 ("can you please go ahead with the one file per backlog item when you're
ready?"), from the proposal made that evening after the backlog was measured: 149 items in "Next", 82 done and never
moved, 31 with parts in more than one state, and no "Done" section. The record is ADR-061, written as proposed with
the claim and accepted here.

**What was done.** `tools/backlog.py move` split the old file into 211 items under `docs/backlog/`, numbered in the
order they stood and named by their titles, unchanged, so every `BACKLOG, "title"` citation still finds its item by
a search of the folder; 47 of them were struck-through entries the old file had never marked, and one title was
shared by two entries, the first a self-declared duplicate, which is renamed so both are files. Each file's third
line is its status, read once from its markers at the split and dated as such: 21 open, 16 claimed, 37 partly done
with their counts, 137 done. `docs/BACKLOG.md` is now the rules and the roadmap, with no item and no list of items.
The script reads and writes the status lines (`list`, `summary`, `show`, `new`, `claim`, `done`, `--check`, and
`move` for a branch from before the split), and `claim` refuses an item another session holds or that is done, which
is the conflict two sessions used to have with everyone turned into one they have with each other.

**How it was checked.** The items put back together in order, with their titles made bold leads again, equal the
old file's two sections under whitespace normalization, but for the strike marks and the period each title ended
with. The self-test breaks each rule of the layout in turn and watches `--check` name it; an item left in the real
`docs/BACKLOG.md` was caught by the check on the real folder before the file was replaced.

**What changed around it.** `CLAUDE.md`'s claim rule, `docs/ARCHITECTURE.md`'s "where to look" line, `README.md`,
the documentation pages (the items are a section of their own, as the design entries are), and the opening of
`tools/merge_main.py`, which has the backlog's conflict no longer to settle. A branch written before the split
conflicts in `docs/BACKLOG.md` once it merges `main`; the steps to mend it are at the top of the script, and an item
such a branch only edited is named for a person to carry over, since its note's place is now a status line.
