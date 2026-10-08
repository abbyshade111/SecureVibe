# A CI workflow that hands every secret to a job (V13.3.2, 7 October 2026)

V13.3.2 asks that access to secrets follow least privilege. The one place that access is written down in most apps'
own repositories is their GitHub Actions workflows, and there are three common ways a workflow gives a step more than
it needs. `config.workflow-hands-out-all-secrets` (`crates/sv-check/src/workflows.rs`; medium, high confidence, only
ever a finding) reports each, once per file, at the first line that does it.

- **`toJSON(secrets)` anywhere.** Every secret in the repository turned into one piece of text and handed on, however
  it is spaced or capitalized. High, rather than medium, because one slip then sends every secret at once, and a
  secret of several lines is changed by the conversion, so GitHub may not recognize it to hide it in the logs.
- **`secrets: inherit`** on a job that calls a reusable workflow. Every secret the caller can read goes to the called
  workflow, whatever it needs.
- **A secret in the workflow-wide `env:`.** It reaches every step of every job, including actions written by others and
  packages installed from outside. The finding names the variables and leaves out plain settings beside them. The job's
  own token (`secrets.GITHUB_TOKEN`) is not counted, as elsewhere in this file. A workflow with only one step in it is
  not reported, because there is nobody else for the secret to reach.

**What it does not do.** It never credits V13.3.2: workflows that hand out each secret with care say nothing about who
else can read the secrets, in the repository's settings, the cloud, or the app itself. The proposal's other half,
cloud permission files that let the app read every secret (IAM policies on `Resource "*"`, Kubernetes roles reading all
`secrets`), is not built. A secret read as `secrets['NAME']` rather than `secrets.NAME` is not recognized in the `env:`,
as it is not in the rest of this file. Other pipelines, such as GitLab's, are not read, as before.

Nine guards broken in turn, each caught:
- `toJSON(secrets)` not looked for;
- matched only as written, not however it is spaced;
- `secrets: inherit` not looked for;
- the workflow-wide `env:` not looked for;
- a one-step workflow reported too;
- every `env:` setting named, not only the secrets;
- the job's own token counted as a secret, which `config.workflow-secrets-with-fork-code`'s test catches too;
- `toJSON(secrets)` reported as medium;
- a clean run credited.

`crates/sv-cli/tests/workflow_secrets.rs` is the end-to-end witness: a real `sv report` on an app whose workflow passes
`secrets: inherit` shows V13.3.2 needing attention. With the inherit check broken, it falls back to not verified.
