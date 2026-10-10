# Each numbered part of a backlog item gets a status line of its own

**Status:** done, 10 October 2026

Decided by the owner on 9 October 2026, after asking for "a better overview of what's done from the backlog and what
isn't", since the board "is clearly not tracking things properly": "yes, please add that change when it fits into your
workflow. And this can be part of the dashboard work whenever we get to that." Recorded in ADR-061 ("Later, 9 October
2026: a status line for each numbered part, proposed"). **Claimed on 9 October 2026 by session paper-facts**, at the
owner's word, to be built when it fits after the session's open work.

**What is wrong.** An item's own status is its third line, set by `tools/backlog.py`, and reads true. Its numbered parts
have none: `part_counts` guesses each from words in its prose (`DONE`, `NOT_DONE`, `CLAIMED` in `tools/backlog.py`), and
the board in the documentation set (`tools/docs_page.py`) shows those guesses. Three ways it goes wrong, each seen on
`main` that evening:

- **A claim or done note written at the end of an item is counted under no part.** 0226 read "o20 c0 p0 d0" (twenty
  parts open) with parts 1 and 2 done and 3, 4, 7, 8, 9, and 10 claimed, every note being at the item's end.
- **Words vary.** "done the same day", "overtaken", "**Part 1, item 1 done**" are not among the words read.
- **A part's prose that mentions what is not done reads as partly done.** 0085 read seventeen of its parts as partly done.
- And an item's status line and its parts can disagree: 0187 read `done` with four parts open or partly done.

**What to build.**

1. **A status line under each part.** A status line under each numbered part, in the item file's one form: `Status: open`, `claimed by <session>,
   <date>`, `done, <date>`, `partly done: <what remains>`, set by `backlog.py claim 226.3 --by <session>` and `done
   226.3`, which refuse a part another session holds, as for items.
   **Part status:** done, 9 October 2026
2. **The board and `list` read only those lines.** The board and `backlog.py list` read parts only from those lines, never from prose, and show each item with its parts
   under it: how many are done, claimed and by whom, and open.
   **Part status:** done, 9 October 2026
3. **`--check` holds parts to their lines.** `backlog.py --check` fails when a part has no status line, when one is not in the form, and when an item's own status
   disagrees with its parts (`done` with a part open); and when a note at the end of an item names a part ("part 1, item
   3 claimed", "items 3 and 7 done") that its line does not agree with.
   **Part status:** done, 9 October 2026
4. **A one-time conversion.** A one-time conversion of every item: each part's line set from what can be read without doubt; where the prose leaves
   it unclear, `partly done: unclear, needs a look` rather than a guess, so the board is honest from the first day and
   says where a person must look.
   **Part status:** done, 9 October 2026
5. **The rules say so.** The rules in `CLAUDE.md` and `docs/BACKLOG.md` saying to claim and finish a part with the tool, as for an item.
   **Part status:** done, 9 October 2026

6. **A `done` folder.** When an item is done, `backlog.py done` moves its file to `docs/backlog/done/`, keeping its
   number and name, so the folder lists only live work (about 44 files of 229 that evening); the tool, the board, and
   a search by title read both. References to a moved file's path are kept true.
   **Part status:** done, 10 October 2026

7. **Each finding of a future review is an item of its own.** A review keeps its write-up and lists its findings by
   number, each an item file, so two sessions working on two findings never write to one file; the big items already
   written stay as they are, their parts kept honest by the lines above. A rule in `CLAUDE.md` and `docs/BACKLOG.md`.
   **Part status:** done, 10 October 2026

8. **A soft size warning.** `--check` names an item past about 300 lines, as one to split before it grows into
   another 0006 (890 lines that evening); a warning, not a failure.
   **Part status:** done, 10 October 2026

**The owner's decision on 6 to 8, 9 October 2026,** after asking for "additional suggestions for keeping the backlog
more manageable" and remembering a done area that had never been built: "yes, I agree with all those fixes, thank
you". Built after 1 to 5, in a pull request of their own.

**Showing it** belongs to the observability dashboard (0227), at the owner's word: the board's view of parts, and how
far each item has come, is built there. This item makes the data true; 0227 decides how a person sees it.
