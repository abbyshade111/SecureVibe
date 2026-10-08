# A merge script, and the merging rules in `CLAUDE.md`

**Status:** partly done: see its done note; what remains is not yet written, as its markers read on 8 October 2026

Asked for by the owner on 8 October 2026 ("go ahead with
the merge script and CLAUDE.md lines please"), from the end-of-day write-up of session securevibe-review (its
section "Pull requests and merging"), after ADR-060 took the `DESIGN.md` conflicts away. What remains is the
backlog: every claim and every done note is an addition to this file, so two open pull requests still meet here, and
on 8 October each such conflict was resolved by hand the same way (both sides kept, `main`'s first) at the cost of a
ten-minute CI round, with one pull request of this session refused three times because another merge landed
between its green run and its own. To build: `tools/merge_main.py`, which merges `origin/main` into the branch and
settles a conflict in a Markdown file when, and only when, both sides added text at the same place (the merge base
holds nothing there), keeping `main`'s side first; any other conflict is left for a person, named, and the script
fails. A self-test that builds a repository with both kinds of conflict, run by a test in `crates/sv-cli/tests`.
And five lines in `CLAUDE.md`: turn auto-merge on when a pull request is opened and bring `main` in with the script
when GitHub reports a conflict; one open build pull request per session; `main` red after your merge is yours to
mend within the hour; before a review or an assessment, read the day's write-ups in this file; and the script's
name in the tools list. No decision: nothing changes what `sv` runs, writes, or concludes.
**Claimed 8 October 2026 by session securevibe-review**, at the owner's word, in branch
`claude/securevibe-review-merge-script`.
**Done the same day** (`tools/merge_main.py`, with its self-test run by `crates/sv-cli/tests/merge_main.rs`;
`CLAUDE.md`, four bullets after "Git is pre-approved" and the tools list; design entry "A merge script for the
backlog's conflicts, and four merging rules"). The script settles a conflict in a Markdown file only when every
block's merge base is empty; a Rust file, or a block where both sides changed the same lines, is left as Git
left it, named, and the script fails. It never commits: the merge is staged for the session's own commit.
