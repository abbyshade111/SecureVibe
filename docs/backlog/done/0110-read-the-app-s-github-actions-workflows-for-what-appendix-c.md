# Read the app's GitHub Actions workflows for what Appendix C warns about

**Status:** done, as its markers read on 8 October 2026

Found on 27 September
2026 while moving Appendix C out of the headline numbers: the coding rules tell the tool not to
write these, and `sv` could see whether it did. When `.github/workflows/` exists, a static rule
over each workflow file for a `pull_request_target` or `workflow_run` trigger that checks out the
pull request's code (AC.12.1), a checkout without `persist-credentials: false` (AC.12.2), secrets
reachable from a job that runs a fork's code (AC.12.3), and a missing or broad `permissions:` block
(AC.7.4). Findings when present; credit only for a workflow read in full and found clean, per rule,
as the other static rules do. **Claimed on 27 September 2026 by session securevibe-e8.** One change
of scope on reading the requirements: AC.7.4 asks that changes to trigger settings get dual control
and a security-team review, which a workflow file cannot show, so a missing `permissions:` block is
not cited as AC.7.4. **Done the same day:** `crates/sv-check/src/workflows.rs`, four checks, with
AC.12.1 and AC.12.2 credited only for workflows all read and found clean, AC.12.3 finding-only
(approvals are repository settings), and the token's permissions a finding citing nothing. See
DESIGN, "The app's GitHub Actions workflows".
