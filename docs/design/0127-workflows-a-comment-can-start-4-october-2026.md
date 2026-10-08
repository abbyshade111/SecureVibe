# Workflows a comment can start (4 October 2026)

The deep review of `sv` at `eff3f17` (BACKLOG, part 2, H4) found a workflow started by `issue_comment` that checked
out the pull request's code with the repository's secrets credited AC.12.1. `PRIVILEGED_TRIGGERS` in
`crates/sv-check/src/workflows.rs` named only `pull_request_target` and `workflow_run`; a comment trigger runs with
the secrets and a token that can write whenever anybody who can comment starts it, which on a public repository is
anybody, and the usual "/test" bot checks out `refs/pull/<n>/head` or runs `gh pr checkout`.

`issue_comment` and `discussion_comment` are now privileged triggers, and the finding and the not-assessed reason name
whichever trigger it was rather than the first two. A comment bot that checks out nothing is not assessed for AC.12.1,
as the labeler under `pull_request_target` already was: `sv` cannot follow a commit the workflow looks up itself.

Not added, and why. `workflow_dispatch` and `repository_dispatch`: only somebody with write access, or a token, can
start one, so the finding's premise does not hold. `pull_request_review_comment` and `pull_request_review`, which the
review proposed: whether GitHub gives these the secrets when the pull request comes from a fork could not be checked
against GitHub's documentation from this session, and a guess either way is a claim. They stay open in the backlog.
Three guards broken in turn, each caught. (Settled on 5 October 2026: next section.)
