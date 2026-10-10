# One file per backlog item, with a status line

**Status:** done, 8 October 2026
Proposed on 8 October 2026 by session securevibe-review after
measuring this file (146 items in "Next", 82 done and never moved, 31 mixed, no "Done" section), and asked for in
another form by gap item 33 ("move done items to a file of their own"). The owner's decision: an ADR, `Status:
proposed`, written by whoever claims this, and accepted in the pull request that builds it. The shape, as ADR-060
gave the design record: each item a file under `docs/backlog/`, numbered in the order written and named by its
title, whose second line is `**Status:** open` or `claimed by <session>, <date>` or `done, <date>` or `partly
done: <what remains>`, kept by hand as the markers are today; sub-items keep their numbers inside the file, so
"gap item 13(c)" and "backlog 32, step 2" still resolve; `docs/BACKLOG.md` becomes the roadmap and the rules, with
no list of items (a list every item adds a line to would bring the conflicts back); `tools/backlog.py` reads the
status lines instead of the prose, gains `new`, `claim`, and `done`, and its `move` splits this file once, using
the parser it has today, with the 31 mixed items settled by a person. What it buys: what is open becomes data; a
claim is an edit of one file, so two sessions claiming the same item conflict with each other, which is the right
outcome, and the merge script has nothing left to settle; the documentation pages list the items apart. What it
costs: the 300-odd citations of the form `BACKLOG, "title"` in the code and the documents still resolve by a search
of `docs/backlog/`, as the design citations do, and the paper names this file at commits that still hold it; the
other two asks of gap item 33 are not recommended (GitHub issues would move the record out of the repository the
paper cites; CI refusing a double claim comes free with one file per item).
**The owner said yes the same evening** ("can you please go ahead with the one file per backlog item when you're
ready?"). **Claimed 8 October 2026 by session securevibe-review**, in branch `claude/securevibe-review-backlog-files`;
the record is ADR-061, `Status: proposed`, to be accepted in the pull request that builds it.

**Built the same day** (ADR-061 accepted; design entry "One file per backlog item"): the 211 items of the old file
are `docs/backlog/0001` to `0211`, in the order they stood, each with its status read once from its markers at the
split and dated so; the rebuilt text of the files equals the old file under whitespace normalization; `docs/BACKLOG.md`
is the rules and the roadmap; `tools/backlog.py` reads and writes the status lines (`list`, `summary`, `new`,
`claim`, `done`, `show`, `--check`, `move`), and `crates/sv-cli/tests/backlog_board.rs` runs its self-test and the
check on the real folder.

