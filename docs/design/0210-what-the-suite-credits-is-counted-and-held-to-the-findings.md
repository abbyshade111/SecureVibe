# What the suite credits is counted, and held to the findings-only lists (6 October 2026)

Running-app checks item 1 left one thing undone (BACKLOG). `docs/COVERAGE.md` had counted 21 checks as able to credit
their requirements when none ever did, found on 3 October by reading the code. Nothing would catch the next one,
because a check gives credit through helpers and tables of rules as often as by name.

- **Every credit is written down.** In a debug build, which is what the test suite runs, `Verified::new` adds one
  line to the file `SV_CREDIT_LOG` names: the check, its requirements, and the place in the code that gave it
  (`#[track_caller]`). A release build has none of this, so `sv` itself writes nothing new anywhere.
- **The census reads it** (`python3 tools/coverage.py --credits LOG`). A credit made in a test, in a test module, or in
  a file that is a test of its own is a test building its own evidence and is left out, by the same line
  `coverage.py` already draws (everything before a file's first `#[cfg(test)]` ships). It fails when a check listed as
  only ever a finding (`RUST_FINDINGS_ONLY`, or `findingsOnly` on a tree-sitter rule) was credited; when one never
  credited is not listed, which means it is findings-only or no test reaches its credit; and when a credit names a
  requirement the check does not cite.
- **CI runs it** after the tests, in the same job (`.github/workflows/rust.yml`).

The first census found three more:

- `probe.password-hints` (V6.4.2) only ever raises a finding.
- `secrets.credential-assignment` (V13.2.3) never credits under its own name. A clean scan is credited as
  `secrets.scan`, which names the requirements of `data/secret-rules.json`, and V13.2.3 is not one of them.
- `probe.cors-any-origin` (V3.4.2) does credit, but no test reached it.

### And what it withholds (8 October 2026)

A check is known to work when it says no with the thing it guards broken, and the census above shows only that
each says yes (backlog item 32, `docs/GAP-ANALYSIS.md`, 7.4). Its first step, measuring:

- **Every finding a check makes is written down too.** Each of the 45 places in the code that ships where a check
  makes a finding hands it through `finding::found`, which in a debug build adds a line, the check and the place in
  the code, to a file beside the credits (`SV_CREDIT_LOG` plus `.withheld`), so CI needs no change. A helper that
  builds findings is `#[track_caller]`, so the place is the one that called it; a finding a test builds for itself
  is left out by the same line as a credit. A release build writes nothing.
- **`python3 tools/coverage.py --withheld LOG`** lists every check the suite saw credit and never saw withhold. It
  fails nothing. Two checks name each finding after what it found, `advisories` (`advisory.<id>`) and `sbom`
  (`sbom.<what>`), and are counted under those names (`WITHHELD_UNDER`).

The first count: 125 checks seen giving credit, 115 seen withholding, 10 not. Each of the ten withholds by design
without a finding: the four log checks (`probe.authentication-logged`, `probe.authorization-failure-logged`,
`probe.log-common-format`, `probe.log-line-metadata`), `probe.clear-site-data`, the two AI logging checks
(`probe.ai-call-log-session`, `probe.ai-injection-logged`), `probe.oidc-issuer-not-checked`, and the two
password-change checks say "not assessed", or simply give no credit, when what they look for is missing. Each of
the ten already has a test asserting it is not credited when it should not be; the census cannot see a credit not
given. So the next step is the census seeing that, not new tests: each of those checks marks the branch where it
withholds, and the gate follows once the list is empty. Breaks: `found` writing nothing, and the census counting a
finding a test built, each failed `crates/sv-check/tests/withheld_log.rs`.

**Step 2: a credit not given is written down too (8 October 2026).** Each of the ten calls
`verified::unless_credited(check, &verified)` where it has run, once: when no credit from it is among them, it
withheld, and a debug build writes that to the same `.withheld` log, with the place that called it. It decides
nothing and changes nothing in a release build. The place is after the check's own branches, never inside one,
so it cannot be skipped by the branch that withholds; a check that never ran (a setup it needed was missing)
returns before it and is not counted as withholding. The gate this leads to is ADR-059, proposed.

The first two are now listed, so `docs/COVERAGE.md` and `docs/REQUIREMENTS.md` mark them as "only ever as a finding".
The third has its test (`an_app_that_names_its_own_origin_is_credited_and_one_that_says_nothing_is_not`). The census
agrees with every tree-sitter rule's flag as it was. No report changes: the reports never credited any of these.

How it is held: `a_credit_is_written_down_with_the_place_that_gave_it` (`crates/sv-check/tests/credit_log.rs`) holds
the line, and in CI it also writes a credit for a findings-only check from a test into the suite's own log, which the
census must leave out. `the_census_of_credits_counts_only_what_a_check_gave` (`coverage_doc.rs`) feeds the census small
logs whose answer is known. Ten guards were undone in turn, and each was caught by one or both.
