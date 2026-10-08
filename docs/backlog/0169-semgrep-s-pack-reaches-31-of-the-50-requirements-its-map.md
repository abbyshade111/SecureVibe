# Semgrep's pack reaches 31 of the 50 requirements its map names

**Status:** partly done: 1 of 12 parts done, 0 claimed, 11 open, as its markers read on 8 October 2026

Done on 26 September 2026: the honest
count, the AI pack for apps that use AI, and option B (`p/default` beside `p/security-audit`) after the owner
reviewed the rules' license; the coverage count reaches 46 of the 50. What stays open is the separate entry
"Later, and not a priority" below. Found on 26 September 2026 by the registry run (session
relaxed-nobel-27acfa). The adapter runs `p/security-audit`,
which loads 225 rules, 162 of them mapped. The map has 1,022, and `docs/COVERAGE.md` counts all of
them, so it credits semgrep with 19 requirements no rule the adapter loads can reach: all eight
AISVS ones and V1.3.6, V1.3.12, V3.3.2, V3.5.5, V4.4.1, V9.1.1, V9.2.1, V11.3.3, V11.4.2, V11.4.3,
and V16.2.5. Measured by loading each pack over the fixture app:

| Packs | Rules loaded | Requirements reached (of 50) |
|---|---|---|
| `p/security-audit` (today) | 225 | 31 |
| and `p/ai-best-practices` | 252 | 37 |
| and `p/default` | 1,087 | 41 |
| and `p/default` and `p/ai-best-practices` | 1,114 | 46 |
| and all of those, `p/owasp-top-ten`, and `p/secrets` | 1,185 | 47 |

Two ways to make the coverage document true, and the owner's to choose: run more packs (more
findings, a slower run, and the same network fetch), or count only the rules the adapter really
loads. The two are not exclusive. Either way, the packs are the registry's, and they change without
`sv` changing, so whatever is chosen should be re-measured when the map is regenerated.

**For every session working on `sv`: these rules are not being run.** Since step 1 below,
`docs/COVERAGE.md` no longer counts them and lists them by name. Before it, the instruction was to treat a
requirement that semgrep reaches only through its map as *not checked*, whatever `docs/COVERAGE.md`
said, and not to build on the 19 listed above as if semgrep covered them. That includes the eight
AISVS requirements "AISVS, beyond applicability" credited to semgrep's AI rules; none of those rules
is in `p/security-audit`.

**Recommendations.** Each session adds its own below, under its name, as its own commit, and the
owner decides. Asked for by the owner on 26 September 2026.

- *Session relaxed-nobel-27acfa.* Three steps, in this order:
  1. **Make the count honest first, and without changing what runs.** Keep a dated snapshot of the
     rule ids each pack loads (`data/semgrep-packs.json`), written by a script like
     `tools/pwned_passwords.py` on a machine that can reach semgrep.dev, and have `coverage.py`
     credit semgrep only with mapped rules in a pack the adapter runs. A test holds the adapter's
     `--config` list to the packs in the snapshot, so adding a pack without measuring it fails.
     This is cheap, changes no finding, and stops the document claiming 19 requirements nobody checks.
  2. **Then add `p/ai-best-practices`.** 27 rules, six more requirements (31 to 37), most of them
     the AISVS ones the map was built for, and Semgrep only runs a rule on files in its language, so an
     app without AI code pays almost nothing. It is where the AI rules actually live.
  3. **Then decide on `p/default` with numbers from the evaluation harness, not from me.** Adding it
     reaches 46 of the 50. Measured over the example apps and v1's app template (197 files), it
     added about 3 seconds and 3 findings, all on the template, and all three are false alarms:
     `detect-non-literal-regexp` on patterns built from the app's own settings and route names, not
     from anything a visitor types. Three mistaken findings on one app is small, but the owner reads
     every finding, so it should be counted over the golden apps with `npm run eval` before adopting.

  Not recommended: `p/owasp-top-ten` and `p/secrets` on top. They add one requirement between them
  (V11.3.3), and `sv` already has its own secret scanner.

- *Session securevibe-e8.* Agreed on the order, with three things to know before each step:
  1. **The overstatement is in `docs/COVERAGE.md`, not in anybody's report.** A report already
     credits a clean semgrep run only with rules its own SARIF says were loaded, and only for a
     language the app is in (`credit_loaded_only`, `crates/sv-check/src/adapters.rs`), so no app has
     been credited with the 19. Step 1 is fixing the document and what sessions plan from it, and it
     can be done now. When it is, `coverage.py` should also keep "can credit" apart from "can only
     find": a rule's `findings_against` is never credited by a clean run.
  2. **`p/ai-best-practices` adds findings for the AISVS requirements, not credit.** All eight are
     mapped as `findings_against`, deliberately: no user input reaching a system prompt is not an
     enforced instruction hierarchy. So the pack's value is catching the mistakes, and the coverage
     count should show those eight as "finding only", not as settled. Still worth adding, for that.
  3. **Prefer the mapped rules to the whole of `p/default`.** A result from a rule the map does not
     know still reaches the owner, as a finding with no requirement (`adapters.rs`, module notes),
     so every unmapped rule in a pack is one more thing a non-programmer may have to read and
     dismiss; `p/default` adds about 835 rules to reach four more requirements. Semgrep takes a
     registry rule by id (`--config r/<rule-id>`, repeatable), so the adapter could add just the
     mapped rules those four need beside the two packs. Whether that resolves and how long it takes
     has to be measured on a machine that reaches semgrep.dev, which this session cannot. If it
     does not work, the evaluation harness decides, as above.

  Not decided by any of this: which packs change is the owner's, and so is whether three false alarms
  on one app is too many.

- *Session securevibe-e9.* The same three steps in the same order, with one correction to how bad
  the problem is and one more option to measure before step 3.
  1. **The per-run report is already honest; the document is what overstates.** Semgrep's adapter
     reads more than one language, so `clean_run_evidence` counts a rule only when the SARIF says
     it was loaded. A clean run of `p/security-audit` has never credited any of the 19, and the
     eight AISVS rules are `findings_against`, which credit nothing even when loaded. What is wrong
     is `docs/COVERAGE.md` and anything a session built on it. So step 1 is a documentation fix
     and should be judged as one: `coverage.py` reading the same loaded-rule snapshot the adapter
     is held to, as relaxed-nobel-27acfa proposes, with a test that fails when the two disagree.
     Worth doing first, and no report changes.
  2. **`p/ai-best-practices`: yes, and it carries little risk.** Its rules only ever raise findings
     (`findings_against`), so adding it cannot make any credit look stronger than it is. The only
     cost is more findings, and those are what the AISVS map was written to produce.
  3. **Before deciding on `p/default`, measure a fourth option: the pinned `semgrep-rules` commit
     the map was generated from (`a84ff9c`), run as a local `--config` folder limited to the mapped
     rules.** The loaded set would then equal the map by construction, so the count cannot drift
     when the registry changes a pack, and a run needs no fetch from semgrep.dev. It may be slower
     and noisier than `p/default`, which is why it is a thing to measure and not a recommendation
     yet. Whichever option wins, adopt it by default only if its extra findings over the golden
     apps are mostly real. Otherwise offer it as an opt-in (`--tools` taking a thoroughness level),
     so an owner who wants the 46 can have them without every owner reading the false alarms.

- *Session keen-meninsky-691a27.* Checked first, before recommending:
  **no run has ever overclaimed any of the 19.** `clean_run_evidence` (`crates/sv-check/src/adapters.rs`)
  takes a rule as evidence only when `loaded.contains(rule_id)`, and that gate is on for any adapter
  whose `language` is `*`, which semgrep's is. So a clean semgrep run already credits only the 162
  mapped rules the SARIF says were loaded, and the 19 stay *not assessed* in every report. The defect
  is confined to `docs/COVERAGE.md` and `tools/coverage.py`. That is worth saying plainly, because
  "19 requirements are never checked" reads like a live false claim to an owner and it is not one;
  nothing shipped needs correcting and nothing needs doing in a hurry.

  Given that, in order:

  1. **Make the count honest — but not by subtracting 19.** The document is wrong because it counts
     the map while the engine counts the loaded rules: two sources of truth for one question, which is
     why they drifted. Record the loaded-rule list from the registry run as a fixture and have
     `tools/coverage.py` intersect the map with it, the same set `clean_run_evidence` uses. One input,
     regenerable, and stale in a way somebody can see. A hand-subtracted 31 is right today and wrong
     the next time the registry edits a pack, silently, which is how this started.
  2. **Then add `p/ai-best-practices`.** It is by far the cheapest row in the table above — 27 more
     rules for six more requirements, against 862 more rules for four in `p/default` — and it is the
     pack aimed at code that calls a model, which is where the eight AISVS requirements live. Whether
     it reaches all eight is not something the table separates, and it should be stated when measured
     rather than assumed.
  3. **Leave `p/default` to the eval harness**, as relaxed-nobel says. Note it changes *findings*, not
     only coverage, so it needs baseline updates in the same change and should not ride along with a
     documentation fix.

  One caution for whatever is chosen: a pack's contents are the registry's and change with no change
  to `sv`, so today's number goes wrong without anything here moving. Whatever lands should carry the
  date it was measured and the `semgrep-rules` commit beside it, the way the map already records
  `a84ff9c 2026-09-22`, and re-measuring belongs in regenerating the map rather than in somebody
  remembering.

- *Session relaxed-nobel-27acfa, answering keen-meninsky's question.* Which of the six
  `p/ai-best-practices` reaches is already measured: C2.2.1, C9.1.2, C9.3.1, C9.5.4, and C10.4.2
  (five of the eight AISVS requirements), and V1.3.6. C2.1.6, C7.1.2, and C7.3.1 are in no pack
  measured here. As securevibe-e8 notes, the five AISVS ones are `findings_against`: the pack can
  find them failing and never credit them.

**The owner, on 26 September 2026:** leaning toward that order, and toward keeping the AI pack
separate, so that `p/ai-best-practices` only runs against apps that use AI (the `ai` condition).
**Step 1, the honest count, claimed on 26 September 2026 by session securevibe-e8**, from the
registry run's own list of the rules `p/security-audit` loaded
(`crates/sv-check/tests/fixtures/semgrep/semgrep-registry-1.176.0.sarif`); what runs is not changed.
Steps 2 and 3 are not claimed: both need a machine that reaches semgrep.dev to measure.
**Step 2, `p/ai-best-practices` for apps that use AI, claimed on 26 September 2026 by session
relaxed-nobel-27acfa**, at the owner's asking; step 3 is not claimed. **Step 2 done the same day:**
adapters can carry `conditional_args`, and semgrep adds the AI pack unless the app is known not to
call a model; when nobody has said, it runs, because its rules only ever find something. AISVS goes
from 2 to 6 by the honest count, 5 of them findings only, plus V1.3.6. See DESIGN, "The AI pack, for
apps that may call a model".
**Step 1 done the same day:** `data/semgrep-packs.json` (written by `tools/semgrep_packs.py`) records
what each pack loads, and `coverage.py` counts semgrep only through those rules, lists the rest, and
refuses a pack nobody has measured. Level 1 is 52 of 70 and Level 2 is 62 of 183 by the honest
count. See DESIGN, "Counting semgrep by what it runs".

**The owner's answer, 26 September 2026:** measure the fourth option too — the pinned
`semgrep-rules` commit the map was generated from, run as a local folder — beside `p/default`,
before deciding.
**Step 3's measurements, the pinned rules beside `p/default`, claimed on 26 September 2026 by
session relaxed-nobel-27acfa**, at the owner's asking. The decision stays the owner's.
**Measured the same day.** Four options, each over ten targets with semgrep 1.176.0: the fixture
app (one of each kind of fault, on purpose), the example apps, v1's app template, and the code of the
owner's six built apps in `workspace/projects` (copied without `.env`, data, or keys). The runs are
outside the repository; only these numbers are kept.

| Option | Rules | Requirements (of 50) | Owner's apps, per app | Fixture findings | Owner's apps and template, findings |
|---|---|---|---|---|---|
| A. `p/security-audit` and `p/ai-best-practices` (today) | 252 | 37 | 2.7 s | 13 | 0 |
| B. A and `p/default` | 1,114 | 46 | 4.8 s | 28 | 10 |
| C. The pinned rules: `semgrep-rules` a84ff9c, only the 1,022 mapped | 1,022 | 50 | 40.5 s | 30 | 148 |
| D. A and the 26 registry rules (`r/<id>`) that reach B's nine extra requirements | 278 | 46 | 11.0 s | 13 | 9 |

What the numbers say:

- **B finds real faults that A misses.** On the fixture, `p/default` added 15 findings (14
  distinct): SQL injection, SSRF, path traversal, command injection, and two TLS settings, all among
  the fixture's own planted faults. A missed every one, because `p/security-audit` holds the pattern rules and `p/default` holds the rules
  that follow data from a request to where it is used. The "requirements reached" count hides this,
  since SQL injection's requirement was already reached by other rules.
- **On the owner's apps, B's extra findings were all false alarms.** Nine were
  `detect-non-literal-regexp` on patterns built from the app's own settings and route names, not
  from anything a visitor types. All nine fall on three lines of v1's template
  (`scripts/setup.ts:37` in every app, `src/features/ai/screening.ts:49`, and
  `src/features/apikeys/index.ts:44`), so it is three fixes in the template, not nine. The tenth was
  `missing-integrity` on an icon written inline as a `data:` address.
- **D adds the requirements and none of the catches.** It aims only at requirements not yet
  reached, so it leaves out exactly the injection rules that made B worth having. It is also slower
  than B, because each rule is fetched separately.
- **C matches the map by construction, and it costs a lot.** Semgrep loaded exactly the 1,022 mapped
  ids, when each rule file sits in a folder of its own lowercased name and each top-level folder is
  passed relative to the rules folder. But it took about 40 seconds an app, against 5 for B, and
  gave 148 findings on the owner's apps and template. The ones read were false alarms:
  `generic-api-key` on the file hashes in `securevibe.provenance.json`, `var-in-href` on `<%= appName %>`
  in a link's text, and `html-in-template-string` on an error message containing `<id>`. One was
  real and is `sv`'s own secret scanner's business: `FIRST-LOGIN.txt`, the one-time password v1
  writes into the app folder. Not traced: `innerHTML` in one app's `static/app.js`, which fills
  dashboard tiles and may or may not include text a person typed.
- **C also runs into the rules' license.** The Semgrep Rules License v1.0
  (https://semgrep.dev/legal/rules-license) allows use "only for your own internal business
  purposes" and does not allow distributing the rules. So a pinned copy cannot be kept in this
  repository or shipped with `sv`; each owner's machine would have to fetch the commit itself. It
  would be a fetch from GitHub instead of semgrep.dev, which is no less network. Whether an owner
  fetching them for their own app counts as their internal use is a question for the owner, not a
  measurement. A related one: two test fixtures
  (`crates/sv-check/tests/fixtures/semgrep/*.sarif`) keep rule descriptions exactly as semgrep wrote them,
  and "any portion of those rules" is in the license's definition of the rules.

**Recommendation from session relaxed-nobel-27acfa: B.** About 2 seconds an app buys the rules that
find injection through a request, which A is blind to. Its false alarms on these apps were one line
of v1's template and one inline icon. Fix those template lines at the source, and measure `p/default`
into `data/semgrep-packs.json` in the same change. D is not worth it. C is not worth it as the
default: ten times slower, far noisier, and the license stands in the way of pinning it here. Its one
real benefit, a count that cannot drift, is already covered by the dated pack snapshot and its test.
The evaluation harness was not run; these numbers come from six apps v1 actually built, which is
what it would build, and it can still be run before adopting. The decision is the owner's.

**The owner, on 26 September 2026:** leaning toward B, and wants the Semgrep Rules License looked
at before anything more is built on semgrep's rules: both whether `sv` running them over an owner's
own app is the owner's internal use, and the two SARIF fixtures that keep rule descriptions word for
word. Not decided yet; B is not claimed. (Both settled later the same day: B was chosen, and the license was
reviewed and judged acceptable. See "The owner, on 26 September 2026, on the license" below.)

**The local-folder half was also claimed the same day by session securevibe-e8**, on its own
branch; the claim reached `main` after relaxed-nobel's, so the two crossed. It was already measured
by then, and is kept below relaxed-nobel's fuller run as a second, smaller measurement of option C.
**securevibe-e8's measurement, the same day.** Semgrep 1.176.0 and `semgrep-rules` at `a84ff9c`, every rule the map
names copied into one file with its registry id, so nothing is fetched from semgrep.dev:

| Rule set | Rules | Requirements reached (of 50) | Findings on the examples and v1's template (174 files) | Time |
|---|---|---|---|---|
| `p/security-audit`, rebuilt from the commit | 225 | 31 | 3 | 5 s |
| the map's own rules | 1,022 | 50 | 20 | 20 s |

- **The local copy is the registry's.** The 225 `p/security-audit` rules rebuilt from the commit gave
  exactly the registry run's 13 results on the fixture app, rule, file, and line.
- **What loads is the map, by construction.** The SARIF listed 1,022 loaded rules, the same ids as
  the map; none was missing from the commit. So the coverage count could not drift from what runs.
- **The 17 extra findings are all on v1's template, and on reading, none is a real fault.** Six
  `var-in-href` on links the server builds itself (navigation, the checkout link, the authenticator
  link), six `html-in-template-string` on error messages that contain no HTML, four
  `detect-non-literal-regexp` on patterns from the app's own settings and routes, and one
  `unsafe-dynamic-method` on `router[method]` from a fixed list. The example apps got none. For
  comparison, `p/default` added 3 false alarms on a similar set (relaxed-nobel-27acfa, above): the map
  holds audit rules that `p/default` leaves out, and they are noisier.
- **The rules' license** could not be read from this session; relaxed-nobel-27acfa's could, and
  what it says is above.
- **A detail for whoever builds it:** semgrep puts the rule file's folder in front of each id, as a
  path relative to where it was started, so it must be started in the folder holding the file.

Smaller than relaxed-nobel's run and consistent with it: on the owner's six built apps option C was
twice as slow again, and far noisier, than on the examples and template alone.

**The owner's decision, 26 September 2026:** B, `p/default` beside the two packs, for now. (An
earlier "19 more requirements definitely seems worth it" was made on securevibe-e8's smaller numbers
before relaxed-nobel-27acfa's run and license reading reached the owner, and is replaced by this.)
Adopting B, as relaxed-nobel-27acfa proposed: add `p/default` to the adapter, measure it into
`data/semgrep-packs.json` in the same change (which needs a machine that reaches semgrep.dev), and
fix the three lines of v1's template that make its regular-expression false alarms. **Claimed on
26 September 2026 by session relaxed-nobel-27acfa**, at the owner's asking, template fix included.
**Done the same day:** `p/default` runs beside `p/security-audit` and is measured into
`data/semgrep-packs.json`; the coverage count reaches 46 of the 50. Two of the three template lines
are fixed at the source (`scripts/setup.ts`, and the API-key route matching, now
`src/lib/route-path.ts`). The third, the prompt-injection ruleset in `src/features/ai/screening.ts`,
stays, because its patterns come from the operator's own data file and not from a visitor; apps with
the AI feature show that one false alarm. See DESIGN, "`p/default` beside `p/security-audit`".
The owner's condition above still holds: the license questions are looked at before B is built. (Met the
same day: see the next paragraph.)

**The owner, on 26 September 2026, on the license:** reviewed the Semgrep Rules License and judged
this use acceptable. The license allows use for one's own purposes, personal or a company's own, and
not reselling, and nothing here is monetized or sold, which the owner says will not change. The
answer came to both questions above, running the rules and the fixtures' rule descriptions, so the
condition on B, that the license is looked at first, is met. If selling or licensing `sv`, or
bundling it into something sold, is ever raised, semgrep's rule map is the first thing to
re-examine: it is the largest single piece of borrowed work here, and this condition governs all of
it.

**The golden apps, at the owner's asking, the same day.** The evaluation harness built all five
golden apps without AI (all built, 0 regressed against their baselines), and the four options ran
over each app's code:

| Option | Per app | Findings across the five apps |
|---|---|---|
| A. Today's two packs | 3.0 s | 0 |
| B. A and `p/default` | 5.3 s | 8 |
| C. The pinned rules | 39.0 s | 148 |
| D. A and the 26 rules | 10.9 s | 8 |

B's eight are the same three template lines as before (`scripts/setup.ts:37` in all five,
`src/features/ai/screening.ts:49` in two, `src/features/apikeys/index.ts:44` in one), so there are no
new kinds of false alarm, and fixing those lines clears all of them. D found the same eight. C's are
the kinds already read: `var-in-href` 68, `generic-api-key` 57, `html-in-template-string` 10, the
same eight regular expressions, and `unsafe-dynamic-method` 5. None of the options found a real
fault in the golden apps. That fits apps built from a hardened template; it is also why B's value
shows on the fixture's planted faults rather than here. The recommendation stands: B, with those
three template lines fixed at the source.
