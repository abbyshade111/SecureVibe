# Backlog management: a roadmap at the top, a status board, and the proposal of one file per item

**Status:** done, 10 October 2026

Asked for by the
owner on 8 October 2026 ("do you have suggestions for managing the backlog better? ... it's hard for me to parse what's
done and not done" and "ensure the backlog has the sequencing and details needed from your roadmap"), after the
end-of-day write-up. Measured that evening: 145 items in "Next", about 100 of them done and never moved, 20 partly
done, no "Done" section, and the two reviews of the code merged 1 to 6 October holding 41 findings with none claimed,
which the write-up's roadmap had not counted. To build now, without changing the file's shape: a `## Roadmap` section
at the top, ordered by phase, naming each item by its title and the sub-items by number, with why each comes where it
does and how the section is kept current; `tools/backlog.py list`, a status board read from the items' own markers
(`**Claimed`, `**Done`, "Not done"), per item and per numbered sub-item, with `--open`, `--claimed`, `--done`, and a
self-test a test runs; the items the write-up proposed that had none here (ideas for `sv`, process), appended at the
end of "Next"; and a `CLAUDE.md` line that a session with no word from the owner takes the roadmap's next unclaimed
item. To propose, not build: one file per backlog item with a `**Status:**` line, as ADR-060 did for the design
record and gap item 33 asked for, so that what is open becomes data rather than a reading of prose, and a claim is an
edit of one file (two sessions claiming the same item then conflict, which is the right outcome). That is the
owner's decision: an ADR, `Status: proposed`, with the claim that builds it.
**Claimed 8 October 2026 by session securevibe-review**, at the owner's word, in branch
`claude/securevibe-review-backlog`.
**Built the same day** (the `## Roadmap` section at the top of this file; `tools/backlog.py`, with its self-test run by
`crates/sv-cli/tests/backlog_board.rs`; the three items appended just above this one; `CLAUDE.md`, the roadmap
bullet and the tools list; design entry "The backlog's roadmap and status board"). The one-file-per-item layout is
proposed in its own item above, not built.

**Built 10 October 2026:** the status board, as `python3 tools/backlog.py board` (Markdown, read from the status lines alone, with the claims that need the owner's check flagged) and `board --html FILE` (one page for a browser or phone). The roadmap section of `docs/BACKLOG.md` was left as it was: its order is unchanged, and it is a reading of the items, not a list of them.
