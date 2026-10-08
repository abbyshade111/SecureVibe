# The review triggers run as `pull_request` does (5 October 2026)

The rest of H4. The deep review proposed adding `pull_request_review` and `pull_request_review_comment` to the
privileged triggers, beside `issue_comment`, and the question left open was whether GitHub runs them with the
repository's secrets when the pull request comes from a fork. GitHub's documentation, "Events that trigger workflows"
(docs.github.com, read 5 October 2026), answers it in the section of each:

- Both run on the pull request's merge branch (`refs/pull/<n>/merge`), as `pull_request` does, where `issue_comment`
  runs on the default branch.
- Under "Workflows in forked repositories", both say, in the words used for `pull_request`, that with the exception
  of `GITHUB_TOKEN` secrets are not passed to the runner when a workflow is triggered from a forked repository, and
  that `GITHUB_TOKEN` is then read-only.

So a workflow started by a review of a stranger's pull request has neither the secrets nor a token that can write,
and checking out the pull request's code there is what `pull_request` does every day. They are not privileged, and
`sv` judges them as it judges `pull_request`. That was already what it did; what changes is that the reason is now
known rather than missing, in `PRIVILEGED_TRIGGERS`' comment in `crates/sv-check/src/workflows.rs`, and that a test
holds it: the same workflow, checking out the pull request's head with a secret in its environment, comes out the
same under `pull_request` and under each review trigger, and is found under `issue_comment`
(`the_review_triggers_are_judged_as_pull_request_is`).

Not covered: a private repository whose owner turns on "Send secrets to workflows from pull requests" or "Send
write tokens to workflows from pull requests" (GitHub, "Managing GitHub Actions settings for a repository", read the
same day; private repositories only). These live in the repository's settings, which `sv` cannot see from its files,
and they give fork pull requests' `pull_request` workflows the secrets too, so they are not a gap the review triggers
open on their own. Whether they reach the review triggers as well, GitHub's page does not say.

Two guards broken in turn, each caught by that test: `pull_request_review` made privileged, and
`pull_request_review_comment` made privileged.
