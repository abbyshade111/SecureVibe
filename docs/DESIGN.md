# StackVet (`sv`) — design

> **This is the dated record, not the map.** Every entry in `docs/design/` was written when its decision was made,
> numbered oldest first, and none is rewritten afterward; what `sv` is today is the sum of them. For the ten-minute map of the crates,
> the stages of a run, and where each rule is held, read `docs/ARCHITECTURE.md` first; for the decisions that matter
> most, with the files each governs, `docs/adr/`. The opening entries were written while `sv` was a second
> version beside v1 in `agnostic/`. On 26 September 2026 `sv` became the top of the repository and v1 moved to the
> `v1` branch; paths written `agnostic/…` below are now at the repository root (`agnostic/data/…` is `data/…`,
> `agnostic/Dockerfile` is `Dockerfile`), and `../data` is `data/`.

A second version of SecureVibe. It keeps the workflow, the checks, the compliance engine and the reports, and
changes two things:

* **No wizard.** The user builds their app in whatever AI coding tool they like, with the back-and-forth that gets
  the app right. `sv` picks the code up afterwards.
* **No language.** Nothing in the pipeline assumes Node, Express or the SecureVibe template.

Written in Rust, a memory-safe language (`docs/adr/ADR-020.md`). The OWASP data files were shared with v1 rather than copied until the move; since then
there are two copies (`docs/adr/ADR-016.md`).

**Where the entries are.** Until 8 October 2026 every entry was a section of this file, added to its end. Each is now
a file of its own under `docs/design/`, named by a number that keeps the order they were written in and by its title
(`docs/design/0001-what-carries-over-unchanged.md` is the first), with the title unchanged as its heading. A reference
of the form `DESIGN, "Section title"`, in the code or the documents, names an entry by that title: search
`docs/design/` for it. `python3 tools/design_entry.py list` prints them all in order. The record of why is
`docs/adr/ADR-060.md`: with every session adding to the end of one file, any two open pull requests changed the same
lines, and each merge left the others in conflict.

**Adding an entry.** Write a new file, never a section here: `python3 tools/design_entry.py new "Its title (8 October
2026)"` makes `docs/design/NNNN-its-title.md`, numbered one past the highest, with the title as its first line; write
the entry below it. Two pull requests open at once may take the same number, which harms nothing. A later note on an
older decision goes at the end of that entry's own file, under a heading of its own, as before. This file holds no
section and no list of entries, and a test fails when it does (`crates/sv-check/tests/design_entries.rs`): a list every
entry adds a line to would bring the conflicts back.

**A branch written before the split** that added a section here conflicts in this file once it merges `main`. The
steps to mend it are at the top of `tools/design_entry.py`: keep `main`'s copy of this file, and move the branch's own
sections into entries with `python3 tools/design_entry.py move`.
