# Decision records

A decision record ("ADR", architecture decision record) writes down one decision: what was decided, why, what
else was considered, and what it costs. It is kept so that nobody has to reconstruct the reasoning later from
code, and so that undoing the decision is a choice made knowingly.

## When a record is written, and how it stays true

Since 4 October 2026, at the owner's asking, a record is written with the change that makes the decision, not after
it. (`sv`'s first eleven were each written one to seven days after the decision, and only when a review noticed;
`docs/paper/ADRS.md`.)

- **What needs one.** A change to what counts as evidence or at which tier, to what `sv` runs or connects to, to what it
  writes into someone's folder, to the network fence, a new or removed dependency, a default that changes what a report
  concludes, and every choice the owner makes when a session asks. A change that does none of these needs none.
- **When.** In the same pull request as the decision. For anything substantial, first: the backlog claim adds the
  record as `Status: proposed`, and the pull request that builds it makes it accepted and says where the build
  differs from the plan. A change to an existing decision is a dated "Later" entry on its record, or a new record that
  replaces it; nothing in a record is quietly rewritten.
- **Governs.** Each record lists the files whose change can change its decision. The "Decision records" check
  (`.github/workflows/decision-records.yml`, `tools/adr_check.py`) fails a pull request that touches one of them and
  neither changes the record nor says, on a line of its description, `ADR-0NN: unchanged, because ...` with a reason.
  The reason is the point: it is the moment somebody reads the record against the change.
- **References.** `crates/sv-cli/tests/decision_records.rs` fails when a record names a test or a file that no longer
  exists, governs a pattern that matches nothing, or when any record number cited in the code or the documents has no
  record, or a record is missing from the index below.
- **Required.** The owner decided on 4 October 2026 that "Decision records" is a required check on `main`, so a pull
  request that owes a record does not merge.
- **The weekly review** stays as the safety net: once a week a scheduled session reads every record against the
  week's merged pull requests, and reports how many days each new record came after its decision.

## Numbering

One sequence runs across both versions of SecureVibe, so a number always means one decision.

- **ADR-001 to ADR-014 are v1's.** They moved with v1 to the `v1` branch on 26 September 2026 and are at
  `docs/adr/` there, and at the tags `v1-paper` and `v1-final`. ADR-014 is the file named `ADR-011.md` there,
  whose title calls it ADR-014; v1 has no other file for either number.
- **ADR-015 onward are `sv`'s**, and are here.

## v1's records that `sv` still cites

Two of v1's decisions are rules `sv` keeps. `DESIGN.md` restates both among "the rules that carry over" (the
evidence-tier rule without its number), and ADR-012 is also cited by number in `DESIGN.md`, in three source files, and in two tests:

- **ADR-006, evidence tiers.** AI review alone is never a pass, and a requirement only a person can check
  never passes on its own.
- **ADR-012, what "SecureVibe checks this app" means in another language.** Written after the first app from
  outside, a Python one, was told it was missing `package-lock.json`. `sv` cites it for the rule it drew from
  that incident: a check that does not apply is not a check that failed, a scan that did not run is not a
  clean result, and a wrong statement in a report is worse than a gap in it.

  ADR-012 also ruled out SecureVibe writing its own static-analysis rules for other languages. `sv` later
  wrote such rules for fourteen languages, fifteen counting shell on 30 September 2026 (`DESIGN.md`, "Rules
  that read the code"). ADR-018 replaces that ruling, and the rest of ADR-012 stays in force.

## `sv`'s records

| Record | Decision |
|---|---|
| [ADR-015](ADR-015.md) | What the owner says can add requirements and never remove one, and silence is not a "no" |
| [ADR-016](ADR-016.md) | The OWASP data files: one copy while both versions lived here, and two since |
| [ADR-017](ADR-017.md) | `sv` never writes the app's code |
| [ADR-018](ADR-018.md) | `sv` checks apps written in any language, with rules of its own among the checks (replaces ADR-012's ruling against such rules) |
| [ADR-019](ADR-019.md) | `sv` runs the app in a container on a network with no way out (replaces v1's ADR-010 choice, for `sv`) |
| [ADR-020](ADR-020.md) | `sv` is written in Rust, a memory-safe language (replaces v1's ADR-001 choice, for `sv`) |
| [ADR-021](ADR-021.md) | A crash's or a rate limiter's answer is never read as the app refusing |
| [ADR-022](ADR-022.md) | Whose word counts, and at which tier (extends v1's ADR-006, for `sv`) |
| [ADR-023](ADR-023.md) | False alarms and accepted risks a person records, and test code's findings listed apart |
| [ADR-024](ADR-024.md) | An unanswered data list holds the app to ASVS level 2 |
| [ADR-025](ADR-025.md) | `sv run` has an end: time limits, Ctrl-C that cleans up, and leftovers removed by the next run |
| [ADR-026](ADR-026.md) | The owner's word counts only when `sv review` recorded it (changes part of ADR-022 and ADR-023) |
| [ADR-027](ADR-027.md) | `sv probe` asks only public addresses, and only the ones it checked |
| [ADR-028](ADR-028.md) | Decide before you build: the design comes first, and nothing is credited for it |
| [ADR-029](ADR-029.md) | Exit codes: 2 only when a check could not run, 1 only when asked, 3 when `sv` failed |
| [ADR-030](ADR-030.md) | A plan before any code: `sv plan` and `securevibe_plan`, crediting nothing |
| [ADR-031](ADR-031.md) | A `not-the-app` list that would set apart all of the app's code is not used |
| [ADR-032](ADR-032.md) | Git, run in the app's folder, runs no program the app's repository names |
| [ADR-033](ADR-033.md) | CVSS v4 scores, computed with FIRST's own tables |
| [ADR-034](ADR-034.md) | A report is offered as `sv`'s only when its seal shows `sv` wrote it |
| [ADR-035](ADR-035.md) | A preflight of the run settings, read from the code and never run |
| [ADR-036](ADR-036.md) | `sv` finds its data beside itself, and an install does not live in a working folder |
| [ADR-037](ADR-037.md) | A Python project with no lockfile does not pin, `setup.py` and `setup.cfg` included |
| [ADR-038](ADR-038.md) | The SQL injection probe only reads, only on `sv`'s own copy of the app, and only ever finds |
| [ADR-039](ADR-039.md) | The sign-in token checks, and which key addresses they may name |
| [ADR-040](ADR-040.md) | A credential name over a sentence is reported low, and says so |
| [ADR-041](ADR-041.md) | One run at a time in a report folder, held by a lock file `sv` writes there |
| [ADR-042](ADR-042.md) | The test model answers in the shape the app asked for, and a wrong shape refused is credit for C7.1.1 |
| [ADR-043](ADR-043.md) | A seal is a signature any computer can check, against keys the owner chose to trust |
| [ADR-044](ADR-044.md) | The coding prompts shown to work reach the AI tool when it builds what they are for |
| [ADR-045](ADR-045.md) | The app's own tools are called in a loop only when the owner marks them read-only |
| [ADR-046](ADR-046.md) | Compressed archives sent to the upload, to the limits the owner states |
| [ADR-047](ADR-047.md) | V3.4.3 is credited only for a Content-Security-Policy with the directives it names |
| [ADR-048](ADR-048.md) | The weak password-derivation rule cites storing passwords as well as making keys |
| [ADR-049](ADR-049.md) | `sv` reads the AI coding tool's own files in the project folder, apart from the app's grade |
| [ADR-050](ADR-050.md) | The app's own tests are a tier of their own, below an automated check |
| [ADR-051](ADR-051.md) | The tests must pass before a pull request merges into main, and every commit on main is tested |
| [ADR-052](ADR-052.md) | Packages installed before the run, outside the fence, in a container that sees only the dependency files |
| [ADR-053](ADR-053.md) | Another user's records are checked for reading, listing, changing, and deleting, and one read alone is "checked in part" |
| [ADR-054](ADR-054.md) | Templates and notebooks are read for what they can hold, and never pass silently |
| [ADR-055](ADR-055.md) | Two checks stop resting on one sample: cross-site access asks the private pages, and a common password is three |
| [ADR-056](ADR-056.md) | An error answer is credited only when the app was made to give one, and it was clean |
| [ADR-057](ADR-057.md) | A dashboard for `sv`, optional, with history kept only when the owner asks, outside the app's folder (proposed) |

## Where v1's records disagree with what v1 built

v1's records are archived on the `v1` branch and are not edited; the owner chose on 30 September 2026 to record
their corrections here instead (BACKLOG, "Records that disagree with what was built"). Each was checked against
the `v1` branch and its history on that day.

- **ADR-001** cites V15.1.2 (keep an inventory of third-party components) for choosing "TypeScript everywhere
  with a single npm install". A language choice is not an inventory; ADR-007, which ships the inventory, cites
  the same requirement correctly. For `sv`, ADR-020 replaces this record's choice.
- **ADR-008** lists three AI providers: `anthropic`, `null`, and `scripted`. OpenAI and Google providers were added
  on 18 September 2026 (`7ecb4c3`, `71fae08`), with a choice of service for each step (`4b947ac`), and the record
  was not updated.
- **ADR-010** says generated code's network access is not restricted, and lists macOS `sandbox-exec` among the
  alternatives set aside. On 18 September 2026, two days after it was accepted, v1 fenced the network of the code
  it ran (`27b85e2`, `pipeline/net-fence.ts`): loopback only, through `sandbox-exec` on macOS and a network
  namespace on Linux, as v1's `docs/CONTRACTS.md` describes. The record was not updated, and v1's `README.md`
  still says "Network access is **not** restricted". For `sv`, ADR-019 replaces this record's choice.
- **ADR-012** cites "ADR-011's sibling change". No record carries the number ADR-011 (the file named `ADR-011.md`
  is ADR-014, as above). The change it means is `dca2e6c`, "Say what was read, and stop scoring code nobody read".
- **ADR-013** says its PDF writer "lays it out on A4 pages", and its consequences, updated by `2ef4149`, say the
  paper size is a setting with US Letter the default and A4 the other choice. The consequences are what v1 does.
