# V13.3.2: a CI workflow that hands every repository secret to a job

**Status:** partly done: see its done note; what remains is not yet written, as its markers read on 8 October 2026

From `docs/PARTIAL-CHECKS.md` (V13.3.2,
level 2, "reads the code, finding only"), which no check speaks to yet. In `.github/workflows`, `${{ toJSON(secrets) }}`
anywhere, `secrets: inherit` on a call to a reusable workflow, and secrets placed in the workflow-level `env:`, where
every step of every job can read them, rather than in the one step's that needs them. The proposal's cloud permission
files (IAM and Kubernetes roles that read all secrets) are left for later. Only ever a finding, citing V13.3.2:
finding none says nothing about how secrets are handed out elsewhere.
**Claimed on 7 October 2026 by session securevibe-e9**, at the owner's word ("feel free to pick your next backlog
item whenever you're ready"), in branch `claude/securevibe-e9-workflow-all-secrets`. A new check that only ever
raises findings changes no requirement's status, so no ADR is proposed.
**Done the same day** (DESIGN, "A CI workflow that hands every secret to a job"):
`config.workflow-hands-out-all-secrets`, citing V13.3.2. Only ever a finding.
