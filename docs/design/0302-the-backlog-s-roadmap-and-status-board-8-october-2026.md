# The backlog's roadmap and status board (8 October 2026)


Asked for by the owner on 8 October 2026, after the end-of-day write-up: the backlog had grown past what a person
can read ("it's hard for me to parse what's done and not done"), and the write-up's roadmap lived only in a file on
the owner's side. Measured that evening with the script this entry adds: 146 items in "Next", 82 of them done and
never moved, 31 with parts in more than one state, 8 partly done, no "Done" section, and 237 open parts in all,
among them the 41 findings of the two reviews of the code merged 1 to 6 October, none claimed, which the write-up
had not counted because it knew only the day's two documents.

**The roadmap** is a section at the top of `docs/BACKLOG.md`, before "Next": five phases and a process line, each
naming items by title and sub-items by number, with why each comes where it does, and one rule for a session with no
word from the owner (take the first unclaimed sub-item in that order, claim it, land it before the next). It is the
order of work and not its record: claims and done notes stay on the items, and the section is rewritten only when
the order changes, with the date. The order: what is known to be broken first (the two code reviews, the 8 October
review's medium findings in the order the fence needs, the MCP hardening list, the documentation review's finds, and
the older reviews' leftovers), then the assessment's remaining shape items, then the owed records, then the product
(the loop trials' comparison arm first, since it is the paper's central claim), then what waits for an idle session.
Several items are marked "verify on `main` first": later work overtook them and they want a done note, not a build.

**The status board**, `tools/backlog.py`, reads the "Next" section and prints each item's line, status, sub-item
counts, claiming sessions, and title, with `--open`, `--claimed`, `--done`, and `--mixed`, and `summary` for the
counts. The status is a reading of the markers the items already carry (`**Claimed`, `**Done` and its kin, "Not
done") and nothing else, which the script's opening says; a marker written another way reads as open, so the board
errs toward showing work rather than hiding it. Its self-test holds the reading to a sample of every kind, and
`crates/sv-cli/tests/backlog_board.rs` runs that and the board on the real file. Breaking it on purpose (the done
marker made unmatchable) failed the self-test on every done item's status.

**Proposed, not built**: one file per backlog item with a status line, as ADR-060 did for the design record and as
gap item 33 asked for in another form. It is the owner's decision and has its own item, which says the shape, what it
buys (status as data; a claim as an edit of one file, so two sessions claiming the same item conflict with each
other; nothing left for the merge script to settle), and what it costs. The three items the write-up proposed that
had none here (ideas for `sv`, the process items, and that proposal) are appended at the end of "Next".
