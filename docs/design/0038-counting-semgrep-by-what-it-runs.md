# Counting semgrep by what it runs

`docs/COVERAGE.md` credited semgrep with every requirement its map names, about a thousand rules'
worth, but the adapter runs one registry pack, `p/security-audit`, which loaded 225 of them in the
registry run of 26 September 2026 (session relaxed-nobel-27acfa). Nineteen requirements were counted
through rules nothing runs. No report was ever wrong this way: a clean run is credited only with the
rules its own SARIF lists as loaded, and only in the app's languages. The document, and whatever a
session planned from it, was.

`data/semgrep-packs.json` now records which rules each pack the adapter runs loads, with the date and
semgrep's version, written by `tools/semgrep_packs.py` from a run (on a machine that reaches
semgrep.dev) or from a SARIF already made; today's entry comes from the registry run's own file in
the semgrep fixture. `tools/coverage.py` counts a semgrep rule only when it is in a pack the adapter
runs, refuses to write the document when the adapter names a pack the file has not measured, and
lists what the map names but nothing runs, under "Semgrep: rules in its map that are not run". The
list it produces is the nineteen the registry run found, arrived at independently.

The honest count: ASVS 129 to 125 settleable, Level 1 from 54 to 52 of 70, Level 2 from 64 to 62 of
183, and AISVS from 8 to 2. The other ASVS requirements among the nineteen are still reached, by
CodeQL or another tool. Nothing about what runs changed.

Held by two tests beside the coverage document's own: the snapshot must equal the rules the registry
run lists, and every pack in the adapter's `--config` must be in the snapshot. Each of the three was
broken in turn: counting the whole map again, a snapshot missing one rule, and a pack added to the
adapter without measuring; every one was caught, the last two by two tests each.

Next, the owner's lean: `p/ai-best-practices` as its own entry, run only for apps that use AI, and a
decision on `p/default` from measurements. Both need semgrep.dev, and both will be refused by
`coverage.py` until the pack is measured, which is the point.

### The AI pack, for apps that may call a model

Done on 26 September 2026 (session relaxed-nobel-27acfa), at the owner's asking. `p/ai-best-practices`
is where semgrep keeps most of its rules about code that calls a model, and none of them is in
`p/security-audit`. Adding it to every run would be harmless, but the owner asked that it run only for
apps that use AI, and one adapter entry is the right shape for it. The rules share semgrep's map,
its SARIF, and its install line, and a second entry would duplicate all three.

So an adapter can now carry `conditional_args`: arguments added to its run unless a condition is known
not to hold, placed just before its `--`. Semgrep's entry adds `--config p/ai-best-practices` for `ai`.
The load refuses an unknown condition, a placeholder in the added arguments, and an adapter with no
`--` to put them before, because after it the pack's name would be read as a file to scan.

**Only a known "no" leaves it out.** The `ai` answer comes from the manifest and the code together,
and the code wins: an app whose manifest says no AI and whose code imports OpenAI still gets the pack.
When nobody has settled it, the pack runs. Its rules only ever find something (the AISVS ones are
`findings_against`), and on code that calls no model they find nothing, so leaving it out there would
hide mistakes in exactly the apps nobody checked, and gain nothing. Seen through the real binary with
a wrapper recording semgrep's arguments: an app calling OpenAI with nothing said got both packs and a
finding against C2.2.1 (`openai-missing-moderation`). An app without AI code whose manifest says no got
`p/security-audit` alone, and the same app with nothing said got both.

The pack is measured in `data/semgrep-packs.json` (27 rules, semgrep 1.176.0). `tools/semgrep_packs.py`
and `coverage.py` read conditional packs, and the coverage document says which packs run only for apps
that may call a model. By the honest count, semgrep now reaches C2.2.1, C9.1.2, C9.3.1, C9.5.4, and
C10.4.2, as findings only, and V1.3.6, which a clean run can credit, but only for an app the pack ran
on. AISVS goes from 2 to 6 requirements with a check, 5 of them only ever *needs attention*. C2.1.6,
C7.1.2, and C7.3.1 stay out of reach of any pack measured.

Regenerating the document showed two faults in its AI section that had been there since it was
written, and that no AI rule had ever exercised: it printed rules as Python tuples, and it called every
rule semgrep's, including CodeQL's `js/system-prompt-injection`, which it also said "settled" C2.1.6 with
an explanation that belongs to credential scans. Each rule is now named with its own tool, and a tool
whose rules only ever find a requirement failing is no longer listed as settling it.

Four breaks, each caught: leaving the pack out when nobody has settled `ai`; putting the pack after
the `--`, which passed every test until the test was made to look for it; an unmeasured conditional
pack, which the measured-packs test did not read until it was extended; and an unknown condition in
the data.


### `p/default` beside `p/security-audit`

Adopted on 26 September 2026 (session relaxed-nobel-27acfa), the owner's choice among four measured
options (backlog, "Semgrep's pack reaches 31 of the 50 requirements its map names"). `p/security-audit`
holds semgrep's pattern rules; `p/default` holds the rules that follow data from a request to where it
is used. With the first alone, the fixture app's planted SQL injection, request forgery, path
traversal, and command injection went unreported. With both, `sv report --tools` on the fixture gives
28 semgrep findings, each with its requirement (`tainted-sql-string` against V1.2.4, `ssrf-requests`
against V1.3.6, `path-traversal-open` against V5.3.2, `subprocess-injection` against V1.2.5). It costs
about two seconds an app. The pack is measured in `data/semgrep-packs.json` (1,074 rules), and the
coverage count now reaches 46 of the 50 requirements the map names. Only C2.1.6, C7.1.2, C7.3.1, and
V11.3.3 are left, and V11.3.3 has its own backlog item as a rule of `sv`'s own.

Its false alarms on apps built by v1 fell on three lines of the template, all
`detect-non-literal-regexp`: a regular expression built from a string at run time. Two were fixed at
the source rather than hidden. `scripts/setup.ts` reads a `.env` value by its line, and the API-key
middleware matches route patterns segment by segment (`src/lib/route-path.ts`, always present, with
its own test), matching the same paths as before except a parameter mid-segment, which no route uses.
The third, in `src/features/ai/screening.ts`, compiles the prompt-injection ruleset from
`data/injection-patterns.json`, which SecureVibe copies into the app and whoever runs the server may
update. A pattern there is not something a visitor can shape, and turning it into code would lose the
point of the file, so it stays, and an app with the AI feature shows that one false alarm. Hiding it
with a suppression comment would make `sv` report that semgrep was told to look away, which is worse.

Checked by building the five golden apps with the changed template (all built, 0 regressed; each app
has four more passing tests, the route-pattern ones) and running the three packs over them: `p/default`'s
false alarms went from eight to two, both the prompt-screening line, in the two apps with the AI
feature. The template's suite passes with every feature on (228 passed, 0 failed) when run the way
SecureVibe runs it, `tests/**/*.test.ts`. Its own `npm test` runs only `tests/security/` and
`tests/features/`, so the root-level tests, the new one among them, are not part of it; that gap is
older than this change and is its own piece of work.
