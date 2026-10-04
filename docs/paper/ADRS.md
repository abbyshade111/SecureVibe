# The architecture decision records

An architecture decision record (ADR) writes down one decision: what was decided, why, what else was considered, and
what it costs. This looks at every record the project kept across both versions: when each was written, what
happened to it afterwards, what the later evidence says about it, and how v1's decisions carried into `sv`. The
figure is `figure-adrs.html`.

It runs to the cut-off, `main` at `157ddc3`, 11:37 Eastern on 4 October 2026. It was first written at 16:43 on
27 September, when `sv` had four records; where a count has changed since, both are given. Times are Eastern. Several
records date themselves in UTC, four hours ahead, so a record "written on 4 October" was committed at 21:02 on
3 October, and the owner's choices "on 30 September" were made on the evening of 29 September.

## The records

Twenty-seven records in three places (twenty when this was first written), and one feature that wrote them:

- **v1's own: 13 files**, `docs/adr/ADR-001.md` to `ADR-013.md` at tag `v1-final`. The file named `ADR-011.md` is
  titled ADR-014, so the numbers in use are 001 to 010 and 012 to 014; no record is titled ADR-011. They are
  archived on the `v1` branch and are not edited; since 29 September their corrections are kept in `sv`'s index,
  `docs/adr/README.md`.
- **`sv`'s own: 11**, ADR-015 to ADR-025 in `docs/adr/` on `main`, with that index (4 when this was first written).
  One number sequence runs across both versions, so a number always means one decision.
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
| ADR-017 | `sv` never writes the app's code | decided with `sv`'s design; **written 27 September**, amended the same evening | `c4649b1`, `60879b4` |
| ADR-018 | `sv` checks apps written in any language, with rules of its own among the checks | in practice from 23 September, when `sv` wrote its first rules; **written and accepted 27 September** | `62fc96a`, `fec8522` |
| ADR-019 | `sv` runs the app in a container on a network with no way out | with `sv run`'s design, 22 to 24 September; **written 27 September at 18:06**, because the analysis below found no record of it | `60879b4` (#312) |
| ADR-020 | `sv` is written in Rust | when `sv` began, 22 September; **written 29 September at 21:39**, from the owner's reason given that day, memory safety | `55d31b7` (#463) |
| ADR-021 | A crash's or a rate limiter's answer is never read as the app refusing | 28 September (#412, #416, #418, #420); **written 3 October** | `5220460` (#541) |
| ADR-022 | Whose word counts, and at which tier | 26 and 27 September (#175, #239, #242), and 3 October (#539); **written 3 October** | `5220460` (#541) |
| ADR-023 | False alarms and accepted risks a person records, and test code's findings listed apart | 27 September (#297, #303, #316); **written 3 October** | `5220460` (#541) |
| ADR-024 | An unanswered data list holds the app to ASVS level 2 | 27 September (#265); **written 3 October** | `5220460` (#541) |
| ADR-025 | `sv run` has an end: time limits, Ctrl-C that cleans up, and leftovers removed by the next run | 27 to 29 September (#332, #336, #369); **written 3 October** | `5220460` (#541) |

**Three patterns:**

- **v1 decided first and wrote it down as it went.** Ten foundational records on one day, before any code in the
  surviving record, and three more on the day each decision was made.
- **`sv` decided in the code and wrote the records afterwards,** every one of its eleven, from one to seven days
  after the decision: five on 27 September, one on 29 September, and five on the evening of 3 October. Session
  securevibe-e8 checked the first four against the code and the history before writing them. Two of the three
  decisions carried in the backlog were "not quite true as stated" (`docs/BACKLOG.md`, "Decided, not yet written
  down as ADRs"):
  - "corroboration only ever adds requirements" missed the derived conditions, where a scan that finds nothing does
    answer "no";
  - "the data files are shared" had stopped being true at the move.
- **From 27 September, records were written because something looked for missing ones.** ADR-019 and ADR-020 came
  from this analysis (backlog item 8 below). ADR-021 to ADR-025 came from the first weekly review of the records,
  which the owner asked for on 27 September and session securevibe-e2 carried out on the evening of 29 September
  (#464): it read every record against the 441 merges of the previous eight days and listed seven decisions with no
  record. The owner chose on 3 October (dated 4 October in the backlog) to write five of them, fold a sixth into
  ADR-019 as a line, and leave the seventh. All six were done that evening.

## What happened to each decision

| Record | In v1 | In `sv` |
|---|---|---|
| ADR-001 TypeScript everywhere | held | **reversed**: `sv` is written in Rust. For seven days nothing said why; since 29 September **ADR-020 replaces it for `sv`**, from the owner's reason, memory safety |
| ADR-002 Server-rendered generated apps | held | not applicable: `sv` builds no apps |
| ADR-003 No native modules | held | not applicable |
| ADR-004 Hardened template; the AI only extends it | held | replaced by ADR-017: `sv` writes no app code at all |
| ADR-005 The local UI's token, host check, and CSRF | held | not applicable: `sv` has no UI; its MCP server speaks over standard input and output |
| ADR-006 Evidence tiers; AI never counts as verified | held | **kept**, cited by `sv`, and **extended for `sv` by ADR-022** on 3 October, in `sv`'s own statuses |
| ADR-007 Built-in scanners, outside tools when present | held, but for its first four days semgrep read no files and reported clean (`7e81ada`) | **kept in spirit**: outside tools run when installed and are reported as *not run* when not |
| ADR-008 AI provider abstraction | **went stale on 18 September**: OpenAI and Google were added (`7ecb4c3`), and the record still lists three providers | not applicable: `sv` makes no AI calls. The correction is recorded in `sv`'s index since 29 September |
| ADR-009 AISVS Appendix C applied to SecureVibe | held: v1's self-assessment has an Appendix C section | kept in part: `sv`'s self-assessment reports Appendix C, and hands 13 of its 19 requirements to the AI tool as rules |
| ADR-010 Node's permission model, not a container; network not restricted | **went stale on 18 September**: the network fence used `sandbox-exec`, an alternative the record had rejected (`27b85e2`) | **reversed**: `sv` runs apps in Docker, the other rejected alternative. Since 27 September **ADR-019 replaces it for `sv`**; the correction to v1's record is in `sv`'s index since 29 September |
| ADR-012 Other languages: three tiers, no rules of SecureVibe's own | held in v1 | **contradicted from 23 September, superseded in part on 27 September** by ADR-018. Its rule on honest reporting stays in force, and ADR-021 cites it |
| ADR-013 PDF reports | held; the record contradicts itself on paper size since its same-day amendment | not carried: `sv` writes HTML, Markdown, JSON, and SARIF. The correction is recorded in `sv`'s index since 29 September |
| ADR-014 Unscannable files are refused | held, and amended the same day to say what SecureVibe's fenced checks can and cannot show | not carried |
| ADR-015 to ADR-018 | — | held. ADR-016 amended the day it was written, when the eight v1-only data files were removed; ADR-017 the same evening, to name `sv probe` as the one network exception; ADR-015 and ADR-018 on 29 September, when the weekly review found a count out of date in each (35 facts, not "about twenty-five"; 18 rules, not twelve) |
| ADR-019 | — | amended three times: on 29 September, when the weekly review found one sentence untrue (the app's own container was not read-only); on 3 October, when the owner chose to make it true (#496); and that evening, with the line the weekly review asked for, that the release build must keep unwinding. On 4 October the deep review found its title untrue in another way (below) |
| ADR-020 to ADR-025 | — | held at the cut-off. ADR-020 had one slip, fixed the same evening; ADR-021 gives its count of passes twice, 29 when built and 36 when written |

**By the numbers, for v1's 13:**
- **Held in v1: 11.** 2 went stale within two days of being written, ADR-008 and ADR-010, and were never updated in
  v1. Their corrections, and those for ADR-001, ADR-012, and ADR-013, are kept in `sv`'s index since 29 September.
- **In `sv`: 2 kept** (ADR-006, extended by ADR-022, and ADR-012's reporting rule), and **3 replaced or reversed, each
  now with a record**:
  - ADR-012's ruling, replaced by ADR-018 on 27 September;
  - ADR-010, replaced for `sv` by ADR-019 on 27 September, three to five days after `sv run` was built;
  - ADR-001, replaced for `sv` by ADR-020 on 29 September, seven days after `sv`'s first Rust code.

  When this was first written, the last two had no record.
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
- **ADR-019, the fence, tested twice.** The first weekly review found that "the only writable place is a small
  in-memory folder" was not true of the app's own container. The owner chose to change the code rather than the
  record: since 3 October the app runs read-only, with no capabilities, as every helper did, checked before and after
  on every example app. This is the first record in either version that made the code catch up with it. The second
  test is the deep review of 4 October (finding S2): on Colima, a container on the fenced network reached the
  virtual machine's own services through the network's gateway, while the internet stayed blocked. On Linux with
  Docker itself, the gateway is the owner's own computer. The record's title, "a network with no way out", and its
  "nothing on it can reach anything outside it" are not true while that stands. S2 was claimed at the cut-off and
  not yet fixed. It was fixed that afternoon (#558), and the record now says so in a "Later" entry.
- **ADR-021, a crash is not a refusal.** Built after a rate limiter's answer was found credited as the app's refusal. When it was written down, the table of passes that rest on a refusal had grown from 29 rows to 36, and
  the record says both.
- **ADR-022 and ADR-023, whose word counts.** Both records say their cost plainly: "`sv` cannot tell who typed a
  name", and "trust rests on the name in `by`". The deep review (R1) showed what that costs: an AI tool that wrote
  `by = "owner"` cleared its own findings, and the report then said a person had set them aside. The records were
  honest about the limit; the review asks for a stronger decision, which would be a new record.

**After the cut-off.** The owner took that decision the same afternoon, and it is the twelfth record: ADR-026, "The
owner's word counts only when `sv review` recorded it", written down that evening with "Later" entries on ADR-022 and
ADR-023. Unlike the eleven, it was written the day it was built. The counts in this document stay those of the
cut-off; `SINCE-THE-CUTOFF.md` has what followed.

## The records against the Top 10 analyses

Several records are defenses against the risks in `TOP10.md` and `AGENTIC.md`. These placements are judgments,
like those in `AGENTIC.md`:

| Record | Defends against |
|---|---|
| ADR-002, ADR-005 | A05 Injection (auto-escaping), A01 Broken Access Control (CSRF, a host check against DNS rebinding) |
| ADR-003 | A04 Cryptographic Failures (password hashing), A08 Software or Data Integrity Failures (install scripts disabled) |
| ADR-004, ADR-017 | ASI02 Tool Misuse and ASI10 Rogue Agents: v1's agent writes only in allowed paths, and `sv` has no agent writing code |
| ADR-006, ADR-022, ADR-023 | ASI09 Human-Agent Trust Exploitation: an AI's verdict is never taken as a pass, and an AI tool's answer or review counts only as its own |
| ADR-010, ADR-019 | ASI05 Unexpected Code Execution: generated code, or the app being checked, runs confined |
| ADR-014 | A06 Insecure Design: uploads of unchecked content |
| ADR-012, ADR-015, ADR-018, ADR-021, ADR-024 | A10 Mishandling of Exceptional Conditions: a scan that did not run, a question nobody answered, or an answer the app never gave is never read as clean, as "no", or as a refusal |

ADR-020 (Rust) and ADR-025 (a run has an end) are not placed: the first is about the checker's own memory safety,
the second about cleaning up after it, and neither is one of the risks those analyses count.

The last row has the most records, five of the eleven in `sv` (three when this was first written), and it is the
fault `TOP10.md` found most particular to a security checker: a verdict that fails open. `TOP10.md` records 43
such verdicts to the cut-off (eight to 27 September), some before the records were written and some after.

## Citations

Ten of v1's records cite ASVS or AISVS requirements, 16 citations in all. Each was checked against the standard's own
text in `data/frameworks`. **15 fit their decisions.** One does not: ADR-001 cites V15.1.2, keeping an inventory of
third-party libraries, for the choice of one programming language. ADR-007 cites the same requirement correctly,
since it ships the inventory. `sv`'s index has recorded that correction since 29 September.

`sv`'s eleven records cite no requirement as met. Two name requirements, and say why: ADR-020 names V1.4.1 to V1.4.3
(memory-safe copies, integer overflow, freed memory) "only to say what the language does and does not give", and
ADR-021 names V8.2.1 only as the false pass that was found. All four ids exist in `data/frameworks` and fit what
they are named for.

## Inconsistencies, all resolved

At the owner's request, every inconsistency found here was recorded in `docs/BACKLOG.md` ("Records that disagree
with what was built, or are missing, found by the ADR analysis"), so that each got fixed. By the cut-off the backlog
marks every one done:

1. ADR-012 cites "ADR-011", a number no record carries.
2. ADR-010, and v1's `README.md`, say the network is not restricted, when the fence restricted it from 18 September.
3. ADR-008 lists three AI providers, when there were five.
4. ADR-013 says A4 in its decision and US Letter by default in its costs.
5. `sv`'s README says it opens no network connection, while `sv probe` has `curl` contact the address the owner types.
6. `DESIGN.md` quotes ADR-006 "word for word" in statuses `sv`'s reports do not have.
7. ADR-001's citation of V15.1.2.
8. `sv`'s Rust and Docker choices: each reverses a v1 decision, and neither has a record.

| Items | How | When |
|---|---|---|
| 5, 6, and the Docker half of 8 | `README.md`, ADR-017, and `CLAUDE.md` name `sv probe` as the one exception; `DESIGN.md` restates the evidence rule in `sv`'s terms; ADR-019 is written | 27 September, 18:16 (#312), 83 minutes after this analysis was merged |
| 1 to 4, 7, and the Rust half of 8 | the owner chose a note in `sv`'s index over new commits on the `v1` branch; the index gained "Where v1's records disagree with what v1 built", each item checked again against the `v1` branch; ADR-020 is written from the owner's reason | 29 September, 22:17 (#463) |

v1's records themselves are unchanged, as archived records should be: the corrections live beside them, in `sv`'s
index. The Rust half of 8 waited two days because only the owner could give the reason; nothing in the code or the
history recorded one.

## What this shows

- **The records that held were rules, not technology choices.** Evidence tiers, honest reporting, and "silence is
  not a no" carried from v1 into `sv`, some word for word. The technology choices (language, runtime, UI, sandbox)
  either did not apply to `sv` or were reversed.
- **Decisions drifted from their records fastest when they got better.** ADR-008 and ADR-010 went stale within two
  days, both times because the project did more than the record said: more AI providers, and a network fence the
  record said would not exist. An out-of-date record that understates a protection is still wrong, and in a paper it
  undersells the work.
- **A reversal with a record was the exception, and became the rule.** When this was first written, only ADR-018 had
  replaced a v1 ruling openly; ADR-001 and ADR-010 were reversed by `sv` with no record, and for five days, from 23 to
  27 September, `main` did the opposite of what ADR-012 said. By 29 September each of the three reversals had a
  record naming what it replaces.
- **Writing a decision down after the fact is a check, and it finds things.** When `sv`'s decisions were written down
  on 27 September, checking them against the code corrected two of three. The same checking, done here, found eight
  more inconsistencies, and the first weekly review found two counts out of date, one untrue sentence, and seven
  decisions with no record.
- **A record can move the code, not only follow it.** ADR-019's untrue sentence was settled by making the app's
  container read-only rather than by editing the sentence.
- **Checking the records is not checking the code.** Every review of the records read them against what was built,
  and none tried the fence from inside. The deep review did, and found a way out of it that ADR-019's title denies (fixed
  after the cut-off, #558).
- **Most of v1's foundation was decided before the record began.** Ten of its thirteen records are dated
  16 September and survive only through the restore commit. They are the evidence of what the first two days
  decided, as `TIMELINE.md` notes.

## Limits

- **This reads the records and checks them against the code and history.** It does not re-argue whether each
  decision was right.
- **The Top 10 placements are judgments,** and each record defends against more than the row shows.
- **Owner involvement is counted only where a record or the backlog says so.** It says so for ADR-012, ADR-013,
  ADR-014, ADR-016's later part, ADR-018, ADR-019's change of 3 October, ADR-020, ADR-024, and the choice of which
  owed records to write. v1's first ten records name no one.
- **From 28 September the sessions that wrote `sv`'s later records left no transcript on this machine.** What is
  said here about them comes from the records, the commits, the pull requests, and the backlog.
