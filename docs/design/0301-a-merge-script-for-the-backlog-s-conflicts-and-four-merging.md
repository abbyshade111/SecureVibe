# A merge script for the backlog's conflicts, and four merging rules (8 October 2026)


Asked for by the owner on 8 October 2026 from the end-of-day write-up of session securevibe-review, after ADR-060
had made each design entry its own file. The conflict that remained was the backlog's: every claim and every done
note is an addition to `docs/BACKLOG.md`, and two open pull requests add at the same place. On 8 October each such
conflict was resolved by hand the same way, both sides kept and `main`'s first, at a ten-minute CI round each, and
one pull request of this session was green three times and refused three times because another merge landed
between its green run and the merge by hand.

**The script.** `tools/merge_main.py` fetches and merges `origin/main` into the current branch with Git asked to
show the merge base in each conflict (`diff3`). A conflict in a Markdown file is settled only when every block's
base is empty, which is the one case where nobody changed anything and both only added: `main`'s text is kept, then
the branch's, with a blank line between when the branch's text starts a list item or a heading. Any other
conflict, in any file, is left exactly as Git left it and named, and the script fails, so a person resolves it. The
script never commits: the merge stays staged for the session's own commit, with its message and trailers. It refuses
to start on `main` or over uncommitted changes. Its self-test builds a repository with a both-added backlog
conflict, a Markdown line both sides changed, and a Rust file both sides added to, and holds the script to settling
the first alone; `crates/sv-cli/tests/merge_main.rs` runs it.

**The rules**, in `CLAUDE.md` after "Git is pre-approved": turn auto-merge on when a pull request is opened and bring
`main` in with the script when GitHub reports a conflict; one open build pull request per session; `main` red after
your merge is yours to mend within the hour, forward or by a new commit, never a force-push; and before a review or
an assessment, read the day's write-ups in the backlog. The tools list names the script.

**Not built.** A merge queue, which is the only way never to merge a combination that was not tested; it is a
repository setting of the owner's and costs one more CI run per pull request. The write-up suggests trying
auto-merge alone first, and the queue only if `main` goes red from an untested combination more than once a week.
