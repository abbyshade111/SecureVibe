# The deep review of `sv` at `eff3f17`

On 4 October 2026 the cato-pipeline session, at the owner's asking, reviewed `sv`'s own code in depth: `main` at
`eff3f17` (Merge PR #546, 09:08 Eastern), 107,029 lines of Rust in 142 files across `sv`'s seven crates, tests
included. It found 58 problems. This document counts them, says how they were found, and says what had been done
about each by the cut-off. One row per finding is in `review.csv`; the figure is `figure-review.html`. The record runs
to `main` at `157ddc3` (Merge PR #564, 4 October 2026, 11:37 Eastern), two and a half hours after the commit the
review read.

The review came the day after the comparison study (`STUDY.md`), whose ten issues were all fixed before `eff3f17`,
and it was run by the same session.

## Method

- **Six reviewers, one area each:** dependencies; static code, secret, and configuration checks; running and probing
  apps; files, outside tools, and bundles; the manifest, requirements, and reporting; and the MCP server and command
  line.
- **Harmless fixtures.** Each reviewer read the code and tried each suspected fault on a small made-up folder: a file
  named `..\outside\deploy_key.txt`, a symbolic link where `sv` writes `AGENTS.md`, a test password, nine deliberate
  SQL injections. Fixtures ran on a build of `eff3f17`, or on the published image of `45b6d71`; in the second case the
  reviewer checked that the same code was still there at `eff3f17`. Nothing in the SecureVibe repository was changed.
- **Three labels for how sure each finding is.** *Reproduced*: a reviewer ran it and saw it happen. *Read*: confirmed
  from the code, not run. *Plausible*: likely, not shown.
- **Re-verification.** Before the report was written, the most serious findings were checked again by the session
  itself: twelve by reading the code (the bundle's path mapping, the review signer check, the folder-hiding marker,
  the `AGENTS.md` write, the HTTPS-redirect and HSTS credits, the privileged workflow triggers, the session-cookie
  choice, the package-name comparison, the npm v1 reader, the V15.2.1 credit, and the Python manifest list) and one
  by running a test: the network fence, on Colima.
- **Severity.** Each finding has a severity of critical, high, medium, or low. Where the review gives two ("medium to
  high"), it counts the lower, by its own rule, and so does this document.

The review was sent to the SecureVibe sessions in three parts, which the backlog took in as three entries: part 1
(S1 to S13, R1, R2) in PR #553 at 10:04 Eastern, and parts 2 and 3 in PR #556 at 10:23.

## The 58 findings

| Part | Critical | High | Medium | Low | Total |
|---|---|---|---|---|---|
| S. Safety of `sv` itself (isolation, files written or read outside the app, bundles) | 1 | 7 | 4 | 1 | 13 |
| H. Honesty: false cleans and coverage overclaims | — | 15 | 9 | 1 | 25 |
| A. Accuracy: false positives and noise | — | — | 3 | 3 | 6 |
| R. Reviews, reports, and exit codes | — | 4 | 6 | 4 | 14 |
| **Total** | **1** | **26** | **22** | **9** | **58** |

**42 were reproduced, 14 read, and 2 are plausible.** Three were found by two reviewers independently (S3, H6, R1).

**A correction to the review's own table.** The review's summary table gives part R as 4 high, 7 medium, and 3 low.
By its own rule, R12 ("medium to low") counts as low, which makes R 4, 6, and 4. Its table then sums to 23 medium and
8 low, while its stated totals, and the Word report's, are 22 medium and 9 low. The totals are right; the table's R
row is off by one finding.

By the area of `sv` each finding sits in (assigned for this document from the code each names; the review does not
say which reviewer found which):

| Area | Findings |
|---|---|
| Running and probing apps | 11 |
| Static code, secret, and configuration checks | 11 |
| Dependencies | 10 |
| Manifest, requirements, and reporting | 10 |
| Files, outside tools, and bundles | 9 |
| MCP server and command line | 7 |

## What the findings say

**"Checked" claimed on a narrow test.** The largest group, all 25 of part H. A requirement is marked *checked*, or a
check *ran*, where `sv` looked at much less than the claim implies:

- the SQL rule misses the usual vulnerable calls in five languages and still marks V1.2.4 checked (H1);
- Svelte and Vue templates are never read (H2);
- a Python package written `jupyter_server` never matches the advisory for `jupyter-server` (H8);
- a redirect to plain HTTP is credited as "sends the browser to HTTPS" (H12);
- HSTS with `max-age=0` is credited (H13);
- any 4xx answer counts as rate limiting (H15).

Each says *checked* where `sv` should say *not verified*, which is the failure `sv` is built to avoid. The 25 are the
review's own grouping. `TOP10.md` counts 30 of the 58 as verdicts that failed open (part H, with S6, R2, R3, R6, and
R12); `TESTS-AND-FAULTS.md`, which gives each fault one kind and leaves out H16 as plausible, counts 24 (part H less
H16, H22, H24, and H25, which it classes otherwise, plus A4, R1, and R12).

**`sv` did not yet treat the folder it reads as hostile.** The one critical finding, S1: a file named with
backslashes let `sv bundle` read and zip files from outside the app, and the test bundled the Mac's `/etc/hosts`.
The network fence let the app under test reach the host through the bridge's gateway (S2, reproduced on Colima).
`sv notes`, `sv rules`, and the bundle wrote through symbolic links (S3, S4), a report written into the app replaced
its `SECURITY.md` (S5), and a marker file could hide a folder from every check (H6).

**The line between a person and an AI tool rests on a label.** Any `by` other than two spellings of "AI tool" counts
as a person, so an AI tool could clear its own findings (R1) and the report would then say "Nothing here found a
problem" (R2).

**The study's false-alarm pattern has one cause.** The SQL, redirect, and file-path rules cannot tell a constant or an
already-checked value from input (A1). That is why seven of family-hub's eight SQL findings in the comparison study
were false alarms. The study's seven unmatched reviews are R3.

**What held up.** `report.html` escapes everything; the requirement data is consistent; unanswered questions are never
read as "does not apply"; `sv`'s own file walker never follows links; the MCP server stays inside its root; helper
containers are locked down; and `sv`'s regular expressions cannot be made to run away.

## What had been done by the cut-off

| Status at `157ddc3` | Findings | Which |
|---|---|---|
| Fixed on `main` | 1 | S1 (critical): PR #555, merged 10:16 Eastern (`47ec409`) |
| Claimed, fix in an open pull request | 4 | S2 (PR #558); S3, S4, S5 (PR #562) |
| Claimed, no fix yet | 1 | S12 (claimed in PR #563) |
| Not claimed | 52 | the rest |

**One of the 58 was fixed by the cut-off.** S1, the only critical finding, was claimed in the same pull request that
entered part 1 in the backlog and fixed 12 minutes later. The fix holds three ways, each tested by breaking it on
purpose: paths are built from their parts, the bundle leaves out and lists such names, and the zip refuses any entry
that is not a plain path inside the bundle. Its backlog entry is the only one of the 58 marked done at the cut-off.

**Five more were being worked on.** The fix for S2 (close the gateway, and refuse to run when it can be reached) and
the fix for S3 to S5 (write `sv`'s own files never through a link and never over the app's) were in open pull requests
at the cut-off; S12 was claimed. All six are in part 1, the order the review asked for: S1, then S2, then S3 to S6,
then R1 and R2.

**Fixed before the review.** The review lists six earlier issues as already fixed at `eff3f17`: PEP 440 pre-release
versions, a hash-pinned `requirements.txt` read as a lock, the trailing `/.` path, a missing tool reported as "would
not start", the blank template's `{new_password}`, and `last_affected` (with H18 still open). All six are among the
study's ten issues (`STUDY.md`) and are not counted in the 58.

**Not part of the 58.** The review also lists seven improvements that are not faults, such as a shared helper that
treats constants as constants, time limits for outside tools, and scoring CVSS v4 records. The backlog keeps them with
part 3.

## Limits

- **One reading of one commit.** The review read `eff3f17`. It does not say what was missed, and a finding labeled
  *Read* or *Plausible* was not shown to happen.
- **Fixtures, not apps.** Reproductions used made-up folders. Whether any of the 58 affected the five apps in the
  comparison study has not been re-checked; a re-run of the study on a fixed `sv` would show it.
- **A two-and-a-half-hour window.** The cut-off fell the morning the review arrived. The status above says what was
  done by then, not what will be.
- **The record.** The sessions that took the review in (`securevibe-e2`, `securevibe-e9`) are not on this machine,
  so from 28 September the record is git, pull requests, and the backlog only. Claims and fixes here are from those.

## Sources

The review itself, `~/code/sv-study/sv-review-2026-10-04.md` (also in the Word report's appendix C). `docs/BACKLOG.md`
at `157ddc3`, its three deep-review entries. The pull request record (`prs.json`, fetched 4 October 11:39), PRs #546
to #564. `git log 157ddc3`. Lines of Rust: every `.rs` file under `crates/` at `eff3f17`, counted with `wc -l`.
