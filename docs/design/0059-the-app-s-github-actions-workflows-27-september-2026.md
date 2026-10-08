# The app's GitHub Actions workflows (27 September 2026)

A workflow is code that runs with the repository's credentials, and the dangerous shapes are few and
well known. Appendix C names them, and the coding rules already tell the AI tool not to write them;
this is `sv` checking whether it did. `crates/sv-check/src/workflows.rs` reads every file in
`.github/workflows` and runs beside the other configuration checks.

| Check | What it finds | Requirement |
|---|---|---|
| `config.workflow-runs-fork-code` | A workflow started by `pull_request_target` or `workflow_run` that brings in the pull request's own code, through `actions/checkout`'s `ref` or `repository`, or a `run:` step fetching it | AC.12.1 |
| `config.workflow-secrets-with-fork-code` | The same, in a job that also reads a secret other than the job's own token, or passes `secrets: inherit` | AC.12.3, **finding only** |
| `config.workflow-checkout-keeps-token` | A checkout without `persist-credentials: false` | AC.12.2 |
| `config.workflow-token-permissions` | No `permissions:` for the workflow or for a job, or `write-all` | none |
| `config.workflow-hands-out-all-secrets` | `toJSON(secrets)`, `secrets: inherit`, or a secret in the workflow-wide `env:` (added 7 October 2026) | V13.3.2, **finding only** |
| `config.workflow-untrusted-text-in-run` | A stranger's text (`${{ github.event.pull_request.title }}`, `github.head_ref`, and the like) in a `run:` line or `github-script`'s `script:` (added 7 October 2026) | AC.12.1 under a trigger that runs with secrets, else none; **finding only** |
| `config.workflow-action-not-pinned` | Another organization's action named by a tag or branch rather than a commit (added 7 October 2026) | none |

**What a clean reading earns, and what it does not.** AC.12.1 is credited only when every workflow
was read and none is started by either trigger. A privileged trigger with no checkout `sv` recognizes
is *not assessed*, not clean, because a workflow can also run what it downloads from the pull
request's own run, which is the pull request's code in another form. AC.12.2 is credited when every
checkout turns its token off. The credit says, in its own words, what no file shows: a repository
setting that sends secrets to pull requests from forks, and credentials kept on the runner some other
way. AC.12.3 is never credited, because what it asks for is an approval before a job gets secrets,
and that is a repository setting.

**No requirement for the token's permissions.** The backlog entry proposed citing AC.7.4 for a
missing or broad `permissions:` block. AC.7.4 names those blocks, but what it asks is that changes to
them get dual control and a security-team review, which a file cannot show. The finding is still
worth making, and it is made citing nothing, like the missing SECURITY.md.

**Anything a plain reading cannot settle leaves every workflow unread.** That covers a parse error, a
second YAML document in one file, an anchor, an alias, or a tag, and it also covers a pipeline of
another kind beside the workflows (`.gitlab-ci.yml`, a `Jenkinsfile`, and five others). While
anything is unread, AC.12.1 and AC.12.2 are *not assessed*, and the reason names the file. A clean
result for the files that were read is not a clean pipeline.

**The files are read with tree-sitter's YAML grammar** (`tree-sitter-yaml` 0.7, MIT, from the
tree-sitter-grammars project), not with a YAML crate. The established serde crate is archived (see
"pnpm, and a dependency not taken"), and tree-sitter is how `sv` already reads code (ADR-018). The
grammar gives the file's structure. A short conversion keeps only mappings, lists, and plain or
quoted text, each with its line, and refuses everything else by name.

**Broken on purpose, thirteen ways, each caught.** These were: triggers written as a map ignored,
the anchor guard off, the parse-error guard off, a second document accepted, the checkout's `ref`
not read, fetch commands not read, `persist-credentials` ignored, other pipelines ignored, a
privileged trigger with no checkout credited, the job's own token counted as a secret,
`secrets: inherit` ignored, unread files not blocking credit, and `write-all` not noticed. Two were
caught by nothing at first:

- **The anchor, alias, and tag guard.** It is redundant with the conversion, which already refuses a
  value with more than one part. Its only effect is the reason the owner reads, so the test now checks
  the reason, and a tag-only fixture was added.
- **The second-document guard.** The first mutation was wrong: it replaced the guard with a call that
  also failed. Written correctly, the break is caught.

This is the static reading that "Appendix C in a section of its own" expected. A workflow finding, or
a credit for a workflow found clean, keeps its AC.12 requirement in the app's own counts, because that
split moves out only the Appendix C requirements that nothing has reached.

`tools/coverage.py` learned the same distinction the report makes. A check written in Rust can now be
findings-only (`RUST_FINDINGS_ONLY`), and `sv`'s own findings-only checks are counted among the
Appendix C requirements that can only ever be marked *needs attention*. Appendix C goes from 0 to 3
of 68 that a check can speak to, and one of the three is that kind.
