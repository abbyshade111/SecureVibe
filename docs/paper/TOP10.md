# The project's vulnerabilities against the OWASP Top 10:2025

What went wrong, security-wise, over SecureVibe's life (16–27 September 2026), and where each item falls in the
OWASP Top 10. There are three different things to count, kept apart below because they answer different questions:

1. **Weaknesses in SecureVibe's own code**: faults in v1 or `sv` that an attacker, or a mistake, could have used.
2. **SecureVibe's verdicts failing open**: places where a check reported "clean" or "passed" when it had not looked. For a security checker this is the fault that matters most, because nothing else notices.
3. **What SecureVibe found in other code**: in the apps it checked, and in each version when it checked itself.

The figure is `figure-top10.html`.

## Method

- **Edition.** OWASP Top 10:2025, the current edition. Each category's mapped CWEs were read from its page on
  `top10.owasp.org/2025` on 27 September 2026. The list sizes match what OWASP states for each category, for example
  40 for A01 and 24 for A10.
- **Mapping.** An item is placed in a category only through a CWE on that category's official list. Some CWEs come
  from the source itself (v1's self-check records one per finding). Others are chosen here from what the source says
  happened, and are marked *(chosen)*. When an item has CWEs in two categories, the one describing the main harm is
  used, and the other is named.
- **Items with no category.** Some CWEs are on no category's list, for example CWE-835 (an infinite loop), CWE-843
  (type confusion), CWE-1333 (a slow regular expression), and CWE-1059 (missing documentation). Those items are
  shown as *no category* rather than forced into the nearest one.
- **Sources.** Every item names a commit, pull request, or file in this repository. v1's files are read at tag `v1-final`.
- **Changes since 2021** that matter here:
  - Server-side request forgery (CWE-918), path traversal (CWE-22), link following (CWE-59), and open redirect
    (CWE-601) now count as A01, Broken Access Control.
  - A10, Mishandling of Exceptional Conditions, is new and includes failing open (CWE-636).
  - Letting a package's install scripts run (CWE-829) counts as A08, Software or Data Integrity Failures.

## 1. Weaknesses in SecureVibe's own code

Twenty were recorded. One (a name collision between two runs, `7287d85`) is a reliability fault rather than a
security one, and one (a dependency check that could never pass on this account, `6f468ac`) is a process problem.
That leaves 18 weaknesses.

| Category | # | What was wrong | Version | CWE | Found by | Record |
|---|---|---|---|---|---|---|
| A01 Broken Access Control | 3 | `sv`'s MCP tool that writes the report followed a symlink inside the app, so all five report files could be written anywhere. Its test passed while the guard was broken | sv | 59, 22 | review | #77 (`2ed3da6`) |
| | | The first zip reader accepted `/etc/passwd` as `etc/passwd`, because the relative-path helper drops a leading slash | v1 | 22, 36 | a unit test, before merge | #38 (`0b89a37`) |
| | | The runtime probes' HTTP client accepted any address and switched off certificate checks; it was safe only because of who called it | v1 | 918 (and 295, A07) *(chosen)* | self-check triage | #28 (`f5c8b68`) |
| A03 Software Supply Chain Failures | 2 | After the move: the Dockerfile's base images were unpinned, CodeQL scanned only Rust and not `sv`'s JavaScript, and there was no security policy | sv | 1104 *(chosen)* | review of `main` | #228 (`e15f641`) |
| | | Dependency updates (tree-sitter, hmac, sha1, the CodeQL action); none names an advisory | sv | 1104 *(chosen)* | Dependabot | #256 |
| A04 Cryptographic Failures | 2 | The API key prefix in the template shipped to every generated app used `byte % 62`, which is not uniform ("never a way in") | v1 | 330 | CodeQL | `828dd89` |
| | | Secrets could come only from `.env`, and keys never rotated; a rotation script was added, and the secret-manager requirement stays reported as unmet | v1 | 324 (and 798, A07) *(chosen)* | a compliance control | `a341c59` |
| A05 Injection | 4 | The prompt fence neutralized the delimiter around untrusted data with a nested replace instead of one global one | v1 | 116 | CodeQL (the one real alert of 27) | #19 (`c39bddd`) |
| | | Markdown report cells escaped the pipe but not the backslash, so scanner output, file names, or the owner's text could push content into the next column; four copies | v1 | 116, 74 | CodeQL (2 real of 51 open) | `828dd89` |
| | | A generated JavaScript string escaped the quote but not the backslash | v1 | 116 | CodeQL | `828dd89` |
| | | Finding references and the AI service's console address were drawn as links even when they were not http(s), so a `javascript:` link was possible | v1 | 79 *(chosen)* | self-check | `9dc8140` |
| A06 Insecure Design | 2 | Generated code that SecureVibe ran could reach the network; an operating-system fence (loopback only) was added | v1 | 653 *(chosen)* | design | `27b85e2` |
| | | When no sidecar could start, `sv`'s fallback probe container ran without `--read-only`, `--cap-drop ALL`, or `no-new-privileges` | sv | 269 *(chosen)* | review | #77 (`45d8125`) |
| A09 Security Logging and Alerting Failures | 2 | An opt-in AI scanner charged the owner's API key, then reported "skipped", hiding the spend | v1 | 223 *(chosen)* | cross-review | `a4e4fbf` |
| | | `sv`'s tests about keeping credentials out of output printed the value under test when they failed | sv | 532 | CodeQL | #229 (`90201dd`) |
| No category | 3 | `mkdirSync(recursive)` loops forever on a path like `/proc` | v1 | 835 | a CI hang | `a562749` |
| | | CodeQL type confusion on the uploaded body passed to the zip reader | v1 | 843 | CodeQL | `b3e22ed` |
| | | The fence test counted any failure as "blocked", so it could pass without proving the fence held (see also section 2) | sv | 1164 *(chosen)* | running the suite | #148 |

**Not found in the record:** cross-site request forgery, session or cookie flaws, or a leaked key in SecureVibe's own
code. Push protection appears only as a lesson about test data (`8132920`), and gitleaks found only planted test
fixtures (`d5d5719`).

## 2. SecureVibe's verdicts failing open (A10)

A security checker's own failure mode is reporting "clean" when it did not look. Each item below did exactly that,
passed the automated suites, and was caught another way. Under Top 10:2025 all of them are A10, Mishandling of
Exceptional Conditions, through CWE-636, "Not Failing Securely ('Failing Open')" *(chosen)*.

| What happened | Version | Caught by | Record |
|---|---|---|---|
| Semgrep scans only files tracked by git, and no app folder was ever a git repository. So across twenty runs on five apps it scanned zero files, exited successfully, and was recorded as "ran, 0 findings" | v1 | noticing that every run was zero | `7e81ada` |
| A Python app's seven `.py` files went unread; the report scored "0 of 106 verified" on the two files that were read | v1 | the owner | `dca2e6c` |
| A line marked `# nosec` made bandit report nothing, and `sv` credited the silence as a clean run | sv | review | #73 → #79 |
| An unanswered manifest question excluded twelve requirements instead of leaving them open | sv | review | #128 → #133 |
| The two-factor reuse check could pass an app that reuses codes when the 30-second step rolled over mid-check | sv | review | #132 → #152 |
| A leaky rate limiter reversed the spoofed-address check both ways, with identical evidence text for the true and the false result | sv | review | #134 → #144 |
| The fence test passed with `nc` missing from the image | sv | running the suite on the owner's Mac | #148 |
| v1's self-check reported a critical "protected route open to anonymous visitors" on a route that had answered 429: the rate limiter spoke before the route did | v1 | reading the evidence | `9dc8140` |

The last one failed the other way: a false alarm, not a false pass. It is here because it is the same fault, a
check that did not handle an unexpected answer, and because v1's committed self-check report (made at 19:28) still
shows it as an open critical. The fix landed one minute later (19:29).

## 3. What SecureVibe found in other code

### v1 checking itself (20 September)

195 findings: 4 critical, 113 high, 45 medium, 30 low, 3 info. v1 records a CWE and a triage status for each, so the
mapping below is mechanical (`artifacts/self-assessment/security-report.json` at `v1-final`).

| Category | Flagged | False alarm | Accepted, by design | Open |
|---|---|---|---|---|
| A01 Broken Access Control | 95 | 95 | — | — |
| A03 Software Supply Chain Failures | 3 | 1 | 2 | — |
| A04 Cryptographic Failures | 3 | — | 3 | — |
| A05 Injection | 48 | 33 | 13 | 2 |
| A06 Insecure Design | 2 | 2 | — | — |
| A07 Authentication Failures | 14 | 10 | 3 | 1 |
| A08 Software or Data Integrity Failures | 3 | — | — | 3 |
| A10 Mishandling of Exceptional Conditions | 1 | 1 | — | — |
| No category | 26 | 18 | — | 8 |
| **Total** | **195** | **160** | **21** | **14** |

Notes:
- **17 of the A01 findings** also carry CWE-73 (A06). They are counted once, under A01.
- **The A01 column is almost entirely rules that assume an app built from v1's own template:** 62 "route outside
  the registry", 17 "file path from the user", and 11 "path join". Once those rules were left out of the
  self-check (#40), 103 findings from four such rules went with them. Thirteen of those were the "accepted" process
  spawns, and the rest were false alarms (`86ddf82`).
- **"Accepted" means SecureVibe does these on purpose:** it spawns scanners (13, A05), and it talks to the app under
  test on 127.0.0.1 with certificate checks off (6, A04 and A07).
- **The two open A05 findings** were fixed that evening (`9dc8140`).
- **The open A07 finding** is the 429 false alarm in section 2.
- **The three open A08 findings** are install scripts allowed in dependencies. Seven of the uncategorized open
  findings are missing documentation, and one is a slow regular expression.

### `sv` (v2) checking itself (27 September)

`sv` run on its own product code, with every finding triaged by hand. The full account, including the run on the
whole repository, is `SELF-ASSESSMENT-V2.md`, and every verdict is in
`self-assessment-v2/product-only/triage.json`. `sv` records a CWE for each finding, so this mapping is also mechanical.

| Category | Flagged | False alarm | Accepted, by design | Open |
|---|---|---|---|---|
| A01 Broken Access Control | 212 | 159 | 53 | — |
| A04 Cryptographic Failures | 20 | 19 | 1 | — |
| A05 Injection | 4 | — | 4 | — |
| A07 Authentication Failures | 16 | 13 | 3 | — |
| **Total** | **252** | **191** | **61** | **0** |

Notes:
- **The A01 row is one rule,** "a file path built from a value" (CWE-22 and CWE-73). All 212 findings also carry
  CWE-73 (A06) and are counted once, under A01. The 159 false alarms are test code inside `sv`'s own source files.
  The 53 accepted are `sv` reading files inside the app it was pointed at. The MCP server, the one place paths arrive
  from outside, has none outside its tests.
- **The A04 row** is 18 `ws://` findings in `sv`'s own `ws://` rule and its tests, one SHA-1 in a test, and the
  browser driver talking to 127.0.0.1 inside the fence.
- **The A05 row** is `sv` running fixed tools with their arguments as a list, which is what it is for.
- **The A07 row** is test passwords, a template placeholder, and three passwords `sv` deliberately sends to apps under test.
- **Run on the whole repository instead,** `sv` flagged 804 findings. The 547 extra come from its tests, its
  deliberately vulnerable fixture apps, its example apps, and its maintenance scripts, and none of them is a weakness
  in `sv`.

Against v1's self-check: 195 findings, 2 real and fixed that evening. For `sv`: 252 findings and none real. Both are
mostly false alarms, from the same kind of cause: v1's rules assumed an app built from its own template, and `sv`
reads its own test code as the product.

### The apps SecureVibe checked (the comparison of 20 September)

From `docs/paper/findings.csv`: 38 findings across three arms. The CSV records no CWE, so each rule's CWE is
chosen here from what it detects. Where v1 records a CWE for the same rule elsewhere, that one is used.

| Category | Arm A: SecureFit, built by v1 | Arm B: same code, uploaded | Arm C: a Python app, uploaded |
|---|---|---|---|
| A01 Broken Access Control | 3 failing authorization tests (V8.2.1 ×2, V8.3.1) | `.env` not ignored by git (538) | `.env` not ignored by git (538) |
| A03 Software Supply Chain Failures | — | — | unpinned versions, no engine pin (1104), 2 |
| A04 Cryptographic Failures | — | recovery codes hashed with HMAC rather than a password hash (916), info | — |
| A05 Injection | — | SQL built by joining text (89), 2 | `innerHTML` set from data (79), 5; inline scripts without the page's nonce (79), 3 |
| A06 Insecure Design | protected template files changed (693), 2 | several writes with no transaction (362) | a sensitive value in a URL parameter (598) |
| A07 Authentication Failures | a default admin credential in `FIRST-LOGIN.txt` (1392), info | — | — |
| A08 Software or Data Integrity Failures | — | npm install scripts allowed (829) | — |
| Not a vulnerability | a misnamed test; a failing theme test | no `.env.example`; "no evidence of human review of AI code"; an unchecked end time | seven "not documented"; no `.env.example`; no run instructions |

Arm A's failing tests are its own security tests catching real access-control gaps. That is strong evidence, and
it exists only because v1 built and ran the app. Arms B and C found injection only by reading code, and nothing
there was confirmed by running the app.

### Not mappable

- **v1's golden-app baselines** (`evals/baselines/*.json`) record only counts by severity, not which rule fired.
- **The friend's health app** survives only as "at risk on AC-02 and MT-06". AC-02 and MT-06 are v1's compliance
  control ids, and the record gives no findings.
- **The owner's first app built with `sv`** is recorded for `sv`'s faults, not the app's. The two findings it names
  (a regular expression's `exec` reported as a shell command, and a test's `query` reported as hand-built SQL) were
  false alarms, and both were fixed (#220).

## What this shows

- **The largest groups of SecureVibe's own weaknesses were in handling untrusted text (A05, 4) and paths and
  addresses (A01, 3).** Every one was fixed, most within a day, except the secret-manager requirement, which is still
  reported as unmet. CodeQL found six of the 18. Review, the self-check, a unit test, Dependabot, and design work found
  the rest. No authentication, session, or leaked-key flaw in SecureVibe's own code appears anywhere in the record.
- **The weakness most particular to a security checker is A10: a verdict that fails open.** Eight are recorded, in
  both versions, and none was caught by a test failing. Two A09 items are the reporting cousin of the same fault,
  among them the scan that charged the owner's credit and said "skipped".
- **Checking itself, each version flagged the most under A01, and it was noise both times.** v1: 95 findings, every
  one a false alarm, because the rules assumed v1's own template; tuning the rules removed 103 findings at once, 90 of
  them false alarms. `sv`: 212, 159 of them its own test code and the rest the job it is for. Neither self-check found
  a real access-control weakness, and v2's found no real weakness at all.
- **In the apps checked, only running the app produced access-control evidence.** Arm A's three failing
  authorization tests are the only A01 results that were not configuration. Reading the code found injection-shaped
  problems (A05) in Arms B and C that nothing confirmed.
- **A02 and A09 never appear in the checked apps' findings.** Those three apps were checked by v1 on 20 September.
  `sv`'s catalog, written afterwards, has checks aimed at every category, for example a cross-origin rule that allows
  any site and cookie flags (A02), and missing violation reports and security events absent from the log (A09).
  `docs/COVERAGE.md` counts that reach by ASVS requirement rather than by Top 10 category.

## Limits

- **This counts what was written down.** A fault fixed without a note is not here.
- **Chosen CWEs are judgements.** Each is marked, and a different reader could place a few items in a neighboring
  category. The v1 self-check mapping uses the CWEs v1 recorded and involves no judgement.
- **Top 10 categories are broad**, and several of these items touch two. Counts use one category per item and name
  the second.
- **The checked-app findings come from one day's comparison of three apps.** They describe those apps, not apps in
  general.
