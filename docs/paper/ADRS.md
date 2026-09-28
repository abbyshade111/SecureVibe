# The architecture decision records

An architecture decision record (ADR) writes down one decision: what was decided, why, what else was considered, and
what it costs. This looks at every record the project kept across both versions: when each was written, what
happened to it afterwards, what the later evidence says about it, and how v1's decisions carried into `sv`. The
figure is `figure-adrs.html`.

## The records

Twenty records in three places, and one feature that wrote them:

- **v1's own: 13 files**, `docs/adr/ADR-001.md` to `ADR-013.md` at tag `v1-final`. The file named `ADR-011.md` is
  titled ADR-014, so the numbers in use are 001 to 010 and 012 to 014; no record is titled ADR-011.
- **`sv`'s own: 4**, ADR-015 to ADR-018 in `docs/adr/` on `main`, with an index (`docs/adr/README.md`). One number
  sequence runs across both versions, so a number always means one decision.
- **The template's: 3**, "ADR 1" to "ADR 3" in `templates/secure-web-app/docs/adr/` at `v1-final`, shipped in every
  generated app. They are the defaults, generated from the template's own code, and repeat v1's ADR-002, ADR-003,
  and ADR-004 in the app's terms.
- **v1 also wrote decision records for each app it built:** the same eight decisions for every app (authentication,
  sessions, encryption and keys, uploads, the AI boundary, deployment, logging, and dependencies), each worded from
  that app's answers (`server/src/design/adrs.ts`). When a decision's text had not changed, its original date was
  kept, "so re-deriving does not rewrite history". In a generated app they replace the template's three.

## When they were written

| Record | Decision | Written | Part of the record |
|---|---|---|---|
| ADR-001 to ADR-010 | v1's foundations: TypeScript, server-rendered apps, no native modules, the hardened template, the local UI's own protection, evidence tiers, scanners, AI providers, AISVS Appendix C applied to SecureVibe, and running generated code | **16 September**, two days before the first surviving commit | only through `c85c174`, the restore after the iCloud eviction |
| ADR-014 | A file that cannot be checked for malware is refused, not stored | 20 September, amended the same afternoon | `52625fb`, `cb5d5f1` |
| ADR-012 | What "SecureVibe checks this app" means in another language | 20 September | `7e81ada` |
| ADR-013 | Reports as PDF files, written by SecureVibe | 25 September, amended the same afternoon | `5f44d3d`, `2ef4149` |
| ADR-015 | What the owner says can add requirements and never remove one, and silence is not a "no" | decided with `sv`'s design (from 22 September) and narrowed on 26 September; **written 27 September** | `c4649b1` |
| ADR-016 | The OWASP data files: one copy while both versions lived here, and two since | first part decided with `sv`'s design, second part on 26 September; **written 27 September**, amended the same day | `c4649b1` and later |
| ADR-017 | `sv` never writes the app's code | decided with `sv`'s design; **written 27 September** | `c4649b1` |
| ADR-018 | `sv` checks apps written in any language, with rules of its own among the checks | in practice from 23 September, when `sv` wrote its first rules; **written and accepted 27 September** | `62fc96a`, `fec8522` |

**Two patterns:**

- **v1 decided first and wrote it down as it went.** Ten foundational records on one day, before any code in the
  surviving record, and three more on the day each decision was made.
- **`sv` decided in the code and wrote the records afterwards,** all four on its last day, one to five days after
  the decisions. Session securevibe-e8 checked each against the code and the history before writing it. Two of the
  three decisions carried in the backlog were "not quite true as stated" (`docs/BACKLOG.md`, "Decided, not yet
  written down as ADRs"):
  - "corroboration only ever adds requirements" missed the derived conditions, where a scan that finds nothing does
    answer "no";
  - "the data files are shared" had stopped being true at the move.

## What happened to each decision

| Record | In v1 | In `sv` |
|---|---|---|
| ADR-001 TypeScript everywhere | held | **reversed without a record**: `sv` is written in Rust, and `DESIGN.md` gives no reason |
| ADR-002 Server-rendered generated apps | held | not applicable: `sv` builds no apps |
| ADR-003 No native modules | held | not applicable |
| ADR-004 Hardened template; the AI only extends it | held | replaced by ADR-017: `sv` writes no app code at all |
| ADR-005 The local UI's token, host check, and CSRF | held | not applicable: `sv` has no UI; its MCP server speaks over standard input and output |
| ADR-006 Evidence tiers; AI never counts as verified | held | **kept**, cited by `sv`, and listed in `DESIGN.md` among "the rules that carry over word for word" |
| ADR-007 Built-in scanners, outside tools when present | held, but for its first four days semgrep read no files and reported clean (`7e81ada`) | **kept in spirit**: outside tools run when installed and are reported as *not run* when not |
| ADR-008 AI provider abstraction | **went stale on 18 September**: OpenAI and Google were added (`7ecb4c3`), and the record still lists three providers | not applicable: `sv` makes no AI calls |
| ADR-009 AISVS Appendix C applied to SecureVibe | held: v1's self-assessment has an Appendix C section | kept in part: `sv`'s self-assessment reports Appendix C, and hands 13 of its 19 requirements to the AI tool as rules |
| ADR-010 Node's permission model, not a container; network not restricted | **went stale on 18 September**: the network fence used `sandbox-exec`, an alternative the record had rejected (`27b85e2`) | **reversed without a record**: `sv` runs apps in Docker, the other rejected alternative. `DESIGN.md` argues it and says what changed, and no record names the reversal |
| ADR-012 Other languages: three tiers, no rules of SecureVibe's own | held in v1 | **contradicted from 23 September, superseded in part on 27 September** by ADR-018. Its rule on honest reporting stays in force |
| ADR-013 PDF reports | held; the record contradicts itself on paper size since its same-day amendment | not carried: `sv` writes HTML, Markdown, JSON, and SARIF |
| ADR-014 Unscannable files are refused | held, and amended the same day to say what SecureVibe's fenced checks can and cannot show | not carried |
| ADR-015 to ADR-018 | — | held; ADR-016 amended the day it was written, when the eight v1-only data files were removed |

**By the numbers, for v1's 13:**
- **Held in v1: 11.** 2 went stale within two days of being written, ADR-008 and ADR-010, and were never updated.
- **In `sv`: 2 kept** (ADR-006, and ADR-012's reporting rule), and **3 replaced or reversed**:
  - ADR-012's ruling, replaced by ADR-018, with a record;
  - ADR-001, reversed without one;
  - ADR-010, reversed without one.
- **The rest do not apply to a tool that builds nothing and has no UI.**

## The records against the later evidence

Several decisions were tested by what happened after they were written:

- **ADR-006, evidence tiers.** The comparison of 20 September is its test. An uploaded copy of v1's own app got an AI
  review of 45 requirements and verified none. The rule that AI review alone is never a pass is what kept that
  from reading as success (`figure-three-arms.html`).
- **ADR-007, outside tools when present.** Its promise, "say so in the coverage table", failed quietly: semgrep ran,
  exited successfully, and scanned zero files in twenty runs. The fix made the tool read files and made the report
  say what was read. `sv` kept the promise and turned it into a rule: a tool that did not run is *not run*.
- **ADR-010, running generated code.** It disclosed that the network was not restricted, and two days later the
  project restricted it. The decision improved within two days; the record never caught up.
- **ADR-014, refusing unscannable files.** The golden apps showed on the day it was written that SecureVibe's own
  fence keeps apps away from the scanner, so every upload was refused inside a check. The record was amended to
  separate what a check can show (the app refuses what it cannot scan) from what it cannot (that uploads are scanned).
- **ADR-015, silence is not a "no".** A review finding on 26 September (#128) showed that the rule had one exception
  too many: a scan that found nothing answered for a silent owner on two questions and excluded twelve requirements.
  The rule was narrowed (#133) the day before it was written down.
- **ADR-012, no rules of SecureVibe's own.** `sv` found the ruling wrong for a tool that must check an app even when
  no outside tool is installed. It wrote its own rules, and ADR-018 records why. The part of ADR-012 that survived is
  the part about honesty.

## The records against the Top 10 analyses

Several records are defenses against the risks in `TOP10.md` and `AGENTIC.md`. These placements are judgments,
like those in `AGENTIC.md`:

| Record | Defends against |
|---|---|
| ADR-002, ADR-005 | A05 Injection (auto-escaping), A01 Broken Access Control (CSRF, a host check against DNS rebinding) |
| ADR-003 | A04 Cryptographic Failures (password hashing), A08 Software or Data Integrity Failures (install scripts disabled) |
| ADR-004, ADR-017 | ASI02 Tool Misuse and ASI10 Rogue Agents: v1's agent writes only in allowed paths, and `sv` has no agent writing code |
| ADR-006 | ASI09 Human-Agent Trust Exploitation: an AI's verdict is never taken as a pass |
| ADR-010 | ASI05 Unexpected Code Execution: generated code runs confined |
| ADR-014 | A06 Insecure Design: uploads of unchecked content |
| ADR-012, ADR-015, ADR-018 | A10 Mishandling of Exceptional Conditions: a scan that did not run, or a question nobody answered, is never read as clean or as "no" |

The last row has the most records, and it is the fault `TOP10.md` found most particular to a security checker: a
verdict that fails open. Three records address it, across both versions, and `TOP10.md` records eight such verdicts, some before the records were written and some after.

## Citations

Ten of v1's records cite ASVS or AISVS requirements, 16 citations in all. Each was checked against the standard's own
text in `data/frameworks`. **15 fit their decisions.** One does not: ADR-001 cites V15.1.2, keeping an inventory of
third-party libraries, for the choice of one programming language. ADR-007 cites the same requirement correctly,
since it ships the inventory. `sv`'s four records cite requirements in their text rather than in a list, and have no
`Related` line to check.

## Inconsistencies, now in the backlog

At the owner's request, every inconsistency found here is recorded in `docs/BACKLOG.md` ("Records that disagree with
what was built, or are missing, found by the ADR analysis"), so that each gets fixed:

1. ADR-012 cites "ADR-011", a number no record carries.
2. ADR-010, and v1's `README.md`, say the network is not restricted, when the fence restricted it from 18 September.
3. ADR-008 lists three AI providers, when there were five.
4. ADR-013 says A4 in its decision and US Letter by default in its costs.
5. `sv`'s README says it opens no network connection, while `sv probe` has `curl` contact the address the owner types.
6. `DESIGN.md` quotes ADR-006 "word for word" in statuses `sv`'s reports do not have.
7. ADR-001's citation of V15.1.2.
8. `sv`'s Rust and Docker choices: each reverses a v1 decision, and neither has a record.

Items 1 to 4 and 7 are in v1's records, which are archived on the `v1` branch. The backlog says where a fix belongs.

## What this shows

- **The records that held were rules, not technology choices.** Evidence tiers, honest reporting, and "silence is
  not a no" carried from v1 into `sv`, some word for word. The technology choices (language, runtime, UI, sandbox)
  either did not apply to `sv` or were reversed.
- **Decisions drifted from their records fastest when they got better.** ADR-008 and ADR-010 went stale within two
  days, both times because the project did more than the record said: more AI providers, and a network fence the
  record said would not exist. An out-of-date record that understates a protection is still wrong, and in a paper it
  undersells the work.
- **A reversal with a record is the exception.** ADR-018 replaced ADR-012's ruling openly: it named what changed,
  what stays in force, and why. ADR-001 and ADR-010 were reversed by `sv` with no record. And for five days, from
  23 to 27 September, `main` did the opposite of what ADR-012 said.
- **Writing a decision down after the fact is a check, and it finds things.** When `sv`'s decisions were written down
  on 27 September, checking them against the code corrected two of three. The same checking, done here, found eight
  more inconsistencies.
- **Most of v1's foundation was decided before the record began.** Ten of its thirteen records are dated
  16 September and survive only through the restore commit. They are the evidence of what the first two days
  decided, as `TIMELINE.md` notes.

## Limits

- **This reads the records and checks them against the code and history.** It does not re-argue whether each
  decision was right.
- **The Top 10 placements are judgments,** and each record defends against more than the row shows.
- **Owner involvement is counted only where a record says so.** It says so for ADR-012, ADR-013, ADR-014, ADR-016's
  later part, and ADR-018. v1's first ten records name no one.
