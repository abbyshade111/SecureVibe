# The language's own tool

Four tree-sitter rules across four languages is a start, not a security review. Every ecosystem already
has a tool that knows its own traps, and the useful thing `sv` can do is run it and read the result
rather than re-implement a hundred rules badly in Rust. `data/adapters.json` describes bandit, gosec,
brakeman, semgrep, and CodeQL; adding another is a data change. `sv report --tools` runs the ones that suit the
app, opt-in for the same reason as `--run` and one more: one of them fetches its rules over the network
the first time it runs, and that is stated in the file rather than discovered from a firewall log.

Three decisions, each a way of not lying:

- **A tool that is not installed reports *not run*, with how to install it.** Never a clean pass. This
  is the whole reason the adapters are a data file with a gap attached rather than a shell script: a
  script that skips a missing binary produces a report identical to one where the tool ran and found
  nothing, and the second is the one everybody assumes.
  Until 8 October 2026 that *not run* was only in the reports: with no tool installed, `sv report
  --tools` printed nothing about them and exited 0, the default (ADR-029). It now says on screen which tools
  did not run and why, each once, whatever the exit status (backlog item 25(c)). The hint reads as a
  sentence either way: "To install it, run `pip install semgrep`; then run this again", and for CodeQL,
  whose install is steps in words, "To install it, download the CodeQL bundle …" rather than a quoted
  command that is not one (`install_step` in `crates/sv-check/src/adapters.rs`).
  The hint is the one for the computer `sv` is running on, where a tool has one (`install_on` in
  `data/adapters.json`, `Adapter::install_hint`): `pip install` is refused by the Python Homebrew installs
  on a Mac and by recent Debian and Ubuntu (PEP 668), so a hint that worked nowhere the owner works was no
  hint. On a Mac, Semgrep and gosec come from Homebrew, and Bandit from `pipx` with its SARIF formatter
  added (`pipx inject`), since Homebrew's Bandit lacks the formatter; on Linux, Bandit and Semgrep come
  from `pipx`. Each was checked to exist where it says (Homebrew's own formula files, 8 October 2026).
  Brakeman and CodeQL keep the general hint: Homebrew has no Brakeman, and its CodeQL is the command alone,
  without the query packs `sv` runs from the bundle. In `sv`'s own container the computer is not the
  person's, so the general hint is given there. Nothing a hint says is evidence of anything; it only
  decides whether the person can follow it.
- **SARIF and nothing else.** One output parser that is trusted is worth more than five that are nearly
  right. A tool that cannot emit SARIF is not listed yet rather than parsed by guesswork — which is why
  bandit's install line names two packages, since its SARIF formatter is a separate one.
- **Rule ids map to requirements one at a time, and each says what it detects.** Crediting everything a
  tool knows about to every run of it would make one clean bandit run look like an assessment of
  injection, secrets, weak hashing and debug mode at once. A finding whose rule id is not in the map
  carries no requirement, which is a fair thing to be and is shown as such. Each entry's `what` is
  prose, and it is not decoration — see *The citations were all wrong* below.

Running it is what taught it the distinction it was missing. Semgrep is installed on the machine this
was written on and cannot start under the sandbox, and the first version reported it as *not installed*
and told the owner to install a tool they already had. `presence` now tells **missing** from **here and
will not start**, and prints what the tool said instead of an install line that would not help. The same
run showed adapter findings carrying absolute paths while `sv`'s own are relative: a report is something
an owner may send on, and the layout of their home directory is not part of what they meant to share.

Against a small Flask app with bandit and semgrep installed, `bandit.B608` lands on the same line as
`sv`'s own SQL rule — two independent tools agreeing, which is worth more than either alone — while
`bandit.B104` and a semgrep rule are reported carrying no requirement, because nothing has mapped them.

### Semgrep: a thousand rules, mapped by rule rather than by hand

Semgrep's findings carried no requirement at all until 25 September 2026, because its map was empty.
The other tools' maps were written one entry at a time, which works for Brakeman's forty codes and not
for the 1,321 security rules in semgrep's own repository. So the map is generated, by
`tools/semgrep_rule_map.py` from a checkout of `semgrep/semgrep-rules`, and the judgment went into
how it decides rather than into each entry.

**Two keys, both required.** A rule is mapped only when its CWE is one of a class's and its id says the
same thing in words: CWE-89 and an id about SQL, CWE-601 and an id about a redirect. Neither key is
enough alone, and reading the result showed why. semgrep tags Go's `dangerous-exec-cmd` as code
injection when it runs an operating system command, the AI rules about user input in a system prompt as
OS command injection, and Flask's and Django's tainted-SQL rules as type conversion and mass
assignment. Words alone fail the other way, because `exec`, `template` and `load` each belong to
several classes. Where the keys disagree the rule stays unmapped, and its finding carries no
requirement, which is a fair thing for it to be.

**Every class's members were read**, except the 224 generic secret detectors
(`generic.secrets.*`, one per credential format), which were checked as a group. That found 88 rules the two keys put in the wrong class or in a
class they do not belong to: key sizes filed as unapproved ciphers (they are V11.2.3's), SSLv3 filed as a
cipher, `hashids-with-django-secret` filed as a weak hash, `XMLDecoder` filed as XXE when it
deserializes. Each is an entry in `OVERRIDES` with its reason, and the script refuses to run if an
override names a rule that no longer exists, which is how fourteen mistyped ids were caught. Configuration
rules (Terraform, GitHub Actions, Kubernetes, Dockerfiles) are left out: they are about deployment, not
the requirements an application's code is checked against. The result is 998 rules across 39
requirements, and every `what` passes the citation guard.

**The ids were measured, and one thing could not be.** Semgrep names a rule differently by how it was
loaded. From a folder it prefixes the rule's own id with the folder, so the file's name drops out:
`use_of_weak_crypto.yaml`'s `use-of-DES` is `go.lang.security.audit.crypto.use-of-DES`. The registry
names it by the file's path and the id together,
`go.lang.security.audit.crypto.use_of_weak_crypto.use-of-DES`, and that is what the map is keyed on,
since the adapter runs the registry pack `p/security-audit`. The registry could not be reached from where
this was written, so the kept SARIF was made by putting each rule file in a folder of its own name,
which makes semgrep's own prefixing produce the registry's form. Semgrep did the matching; only the
folder layout was arranged. A run against the registry on a machine that can reach it is the one check
still owed, and the fixture's README says how.

**The registry run, done on 26 September 2026** (session relaxed-nobel-27acfa, Semgrep 1.176.0,
`--metrics=off`). It confirmed the form: all 12 rules that fired are keys in the map, as written. It
also showed one thing the reproduction got wrong, and one thing nobody had measured.

* **The registry lowercases the path.** `detect-pseudoRandomBytes.yaml` is
  `javascript.lang.security.detect-pseudorandombytes.detect-pseudoRandomBytes`: the path is
  lowercased, and the rule's own id keeps its capitals (`use-of-DES`). None of the 225 loaded ids has
  a capital before its last part. Three map keys did (that rule, a C# X.509 rule, and a Scala Slick
  rule), so a finding from any of them would have carried no requirement. The generator now
  lowercases the path, and the three keys are corrected. Only the first can be witnessed, because the
  other two are not in this pack; that they follow the same rule is inferred, not seen.
* **The pack is a quarter of the map.** `p/security-audit` loads 225 rules, and 162 of them are in the
  map. The map has 1,022 (the first pass's 998 and 24 AI rules), so the other 860 are never loaded by
  the adapter's command and can never fire. Counted by requirement, the map names 50, and the pack's
  rules reach 31. The other 19 are reachable
  only through rules the pack does not load: all eight AISVS requirements from semgrep's AI rules
  (C2.1.6, C2.2.1, C7.1.2, C7.3.1, C9.1.2, C9.3.1, C9.5.4, C10.4.2), and V1.3.6, V1.3.12, V3.3.2,
  V3.5.5, V4.4.1, V9.1.1, V9.2.1, V11.3.3, V11.4.2, V11.4.3, and V16.2.5. `docs/COVERAGE.md` counts the
  whole map, so it credits semgrep with those 19. The kept fixture hid this, because it was made with
  every rule loaded; 22 of its 35 results, from 20 of its 32 rules, come from outside the pack. Which packs to run instead
  is a decision about what `sv` runs, and it is in the backlog with the numbers.

The run is kept beside the first one as `semgrep-registry-1.176.0.sarif`, with tests that every rule
it reported is mapped and that no map key differs from a registry id only in its capitals. Putting the
old spelling back fails the second, and only it, because that rule did not fire in the fixture app.

Against that run, over a Flask app and a Go program with one of each fault, every one of the 29
security findings lands on a requirement, sixteen of them checked against the fault written to
produce them, while semgrep's best-practice and
correctness rules, which fire too, carry none.

**What a clean run is credited with, corrected the same day.** A tool that runs and finds nothing is
credited with every requirement its map names. With semgrep's map empty that credited nothing; with 998
rules mapped, a clean run marked 39 requirements checked for any app at all, including zip slip on an
app with no Go in it, where the only zip-slip rule is Go's, and requirements whose rules are not in the
pack that ran. The same fail-open the per-rule language claim closed for `sv`'s own rules, reopened by
an adapter, and found by counting what a clean run claims while writing the coverage analysis.

For a tool that covers several languages and runs a pack, a clean run now counts a rule only if the
report lists it among the rules it loaded (semgrep's SARIF lists every rule it ran, found or not) and it
is written for a language the app is in; each mapped rule carries its languages for that. Against the
kept run: 9 requirements for a Python app, 5 for a Go app, none for a Ruby app, where it was 39 for all
three. A report that lists no rules credits nothing. Bandit, gosec and Brakeman are unchanged: each runs
every check it has over its one language, whatever its report lists.

**A tool told to look away, corrected again.** That last sentence was true only of a tool nobody had
told to skip anything, and the app can tell it. Found by the other session and verified by running the
tools, each of the four in the version named:

- Bandit 1.9.4 skips a line marked `# nosec`, or one check on a line marked `# nosec B608`, and its
  SARIF then holds no result, only two counts in `runs[0].properties.metrics._totals` (`nosec` and
  `skipped_tests`). A `.bandit` file in the app can switch checks and folders off, and nothing in the
  report says so at all. A search that joined user input into SQL on a `# nosec` line was credited as
  V1.2.4 checked.
- gosec 2.29.0 leaves a `#nosec` line out of its SARIF and says nothing, unless asked with
  `-track-suppressions`, when the issue is there and marked as suppressed.
- Semgrep 1.178.0 keeps a `// nosemgrep` result in its SARIF, marked as suppressed.
- Brakeman 8.0.6 keeps a warning listed in `config/brakeman.ignore`, marked as suppressed and naming
  that file. `skip_checks` in `config/brakeman.yml` hides a check with no trace, and
  `--config-file /dev/null` does not stop Brakeman reading the file. (Since 8 October 2026 it is given an empty
  settings file of `sv`'s own instead, and reads the app's not at all: see below.)

Where a tool can be made to look anyway, it is: bandit runs with `--ignore-nosec` and `--ini /dev/null`,
gosec with `-track-suppressions`. What any tool reports as suppressed is shown as a finding, and says it
was marked to be ignored and where, since a finding somebody chose to hide is still a finding until
somebody has looked at why. That is the owner's decision to make with the finding in front of them, not
one `sv` makes for them by agreeing to look away. What is left, a clean run whose report still counts
skipped lines (and, until 8 October 2026, an app with a Brakeman settings file: `switched_off_by` in `adapters.json`,
which no entry uses now), is not
credited, and the report says why in the gaps.

The same measurement turned up a neighbor that is not fixed here: semgrep, by default, skips files
under `tests/`, `test/`, `build/`, `dist/`, `vendor/` and a few others, and its SARIF says nothing about
it. It is in the backlog.

**Semgrep is named the files.** Measured with semgrep 1.178.0, given a folder it leaves out, and says
nothing in its SARIF about leaving out:

- `tests/`, `test/`, `build/`, `dist/`, `_build/`, `vendor/`, `node_modules/` and `.venv/`, from its
  built-in ignore list, when the app has no `.semgrepignore` of its own;
- whatever the app's own `.semgrepignore` names, which replaces that list, so an app can hide any
  folder with one line;
- anything `.gitignore` covers, in a git repository (`--no-git-ignore` lifts only this one).

Nothing turns the built-in list off, and naming a folder on the command line does not help: the ignore
rules apply inside it. Naming files does. Every file named is read, including one in `.gitignore`, one
the app's `.semgrepignore` excludes, one in `tests/`, and one over the 1 MB size limit. And
`--json-output` writes, beside the SARIF, the list of files it read (`paths.scanned`).

So semgrep is now started inside the app and handed `-- ./file ...` for every code file `sv` itself
would read: everything outside `SKIP_DIRS` whose extension is a language `sv` knows, without following
links, since a tool reads whatever it is named. The list it writes is checked against the list it was
given, and a clean run is credited only when every file was read; otherwise the report names how many
were not, and the first few. A list left by an earlier run is removed first, so it cannot vouch for this
one. An app with no code to name is not run (named no files, semgrep reads the folder, ignores and
all), and an app with more names than fit on a command line (256 KiB of them, about three thousand
files) is reported as not run rather than handed a folder.

What is not handed to it is what no check here reads: `build/`, `dist/`, `vendor/` and the rest of
`SKIP_DIRS`. Checked against a real run through `sv report --tools`, with a rule loaded from a file:
a shell command built from input in `tests/helpers.py` was not reported at all with the folder, and is
reported with the files.

### AISVS from semgrep's AI rules: evidence against, never for

Until 25 September 2026 one AISVS requirement had a check, C9.5.4, through the credential scan.
Semgrep's `ai/ai-best-practices` folder holds 107 security rules about applications that call a
model, and 33 were already mapped, all to ASVS: a hard-coded key is V13.3.1 and model output passed
to `eval` is V1.3.2 wherever it appears. None named AISVS.

Reading the two side by side, the rules and AISVS meet in one direction only. A rule that finds user
input in an OpenAI system prompt has found a system where user instructions are not kept below
system ones, which is exactly what C2.1.6 asks for. The same rule finding nothing has not found an
instruction hierarchy: it has found that one way of breaking it is absent, in one vendor's SDK, in two
languages. Every AISVS pair turned out this way. AISVS asks for controls (a classifier scores every
prompt, output is bounded by length limits and termination controls, tools run in a least-privilege
sandbox) and a pattern can show one missing but never present.

The map had no way to say that: a mapped requirement was carried by a finding and credited by a clean
run, both. So a rule now has two lists. `requirements` are both, as before. `findings_against` are
carried by a finding and never credited: `clean_run_evidence` does not read them, the loader refuses a
requirement in both lists, and a test runs the widest clean run there could be (every rule loaded, six
languages) and asserts no AISVS id comes out of it. The citation guard reads `findings_against` the
same as `requirements`.

Nine families, 24 rules, eight AISVS requirements:

| Requirement | Found failing by |
|---|---|
| C2.1.6 instruction hierarchy | user input in the system prompt: OpenAI, Anthropic, Gemini, Cohere, Mistral |
| C2.2.1 every prompt scored by a content classifier | OpenAI and Mistral completions with no moderation call, or its verdict unchecked |
| C7.1.2 output bounded by length limits | OpenAI and Anthropic calls without `max_tokens` |
| C7.3.1 classifiers block harmful content | Cohere with its safety mode turned off |
| C9.1.2 per-execution budgets | a model called inside `while True` with no way out |
| C9.3.1 tools isolated in a least-privilege sandbox | LangChain's `PythonREPL`, `BashProcess` and relatives run (also V1.3.2) |
| C9.5.4 secrets kept out of the model's context | an MCP tool that returns a credential |
| C10.4.2 tool responses screened for indirect prompt injection | an MCP tool returning an outside response as is, or a tool description with hidden instructions |

Left out on purpose, each with its reason in `tools/semgrep_rule_map.py`: the rules about the
developer's own tooling in the repository (Claude Code and Cursor settings, hooks, `SKILL.md`, IDE
settings), which are about the machine the app was written on rather than the app; the rules that flag
a missing system prompt or safety setting, which is a provider's default and not the absence of a
control; and the hard-coded key rules, since a key in the source is not a key in the model's context.

Checked against a real run: semgrep 1.178.0 with eleven of the 24 rules, over a small help-desk
assistant written with each fault, in Python and again in part in JavaScript, and the same calls written
carefully (`crates/sv-check/tests/fixtures/semgrep-aisvs`). Twelve findings, all in the faulty files,
each on the requirement it is about; the other thirteen rules are the same patterns for other
vendors. Through `sv report --tools` with AISVS in scope, all seven AISVS requirements
and V1.3.2 read *needs attention*, including C9.5.4, which a clean credential scan had marked
*checked* while an MCP tool handed its key to the model.

What `sv`'s own code rules could add was looked at and not written. Every one of these is a flow from
one place to another (a request value into a system prompt, a response into a tool's return value),
and the code rules match a call and its arguments. A rule that fired on any string reaching
`messages` would mostly report the user message, which is where user input belongs.

### CodeQL: following a value, which no rule here could

Every rule `sv` writes, and nearly every semgrep rule, matches a call: `eval(...)`, a query built with
`+`. None of them follows a value from where it enters the app to where it is used, and that is what
several requirements are really about: a regular expression built from what somebody typed (V1.2.9),
a parameter that arrives as an array where the code assumed a string (V15.3.5), a property name from
the request that reaches an object's prototype (V15.3.6), input written to a log unencoded (V16.4.1).
CodeQL does follow it (taint tracking), and it already runs in this repository's own CI.

Two entries, `codeql-javascript` (which also reads TypeScript, so its `language` names both) and
`codeql-python`, each running the bundle's `security-extended` suite offline. CodeQL works in two steps,
so an adapter can now have a `prepare` step before `run`, with a `{database}` folder that passes between
them, made fresh for each run and removed afterwards. A database that cannot be built means the tool did
not run, in the words CodeQL used; a database left by an earlier run is removed first, because analyzing
it would report on somebody else's code.

Three things about reading its reports, each found by running it rather than from its documentation:

- **Severity and weakness are on the rule, not the result.** CodeQL's results carry neither a level nor
  tags. The rule has a `security-severity` score, read on the CVSS bands (9.8 is critical), and tags
  written `external/cwe/cwe-079`, read as `CWE-79`. Every adapter now falls back to the rule's own.
- **A clean run is credited only with the rules its report says ran** (`credit_loaded_only`). The suite
  is chosen, not everything CodeQL has, so the map can know rules that did not run.
- **A run that read no code is not clean.** CodeQL reports the lines of the app's own code it extracted;
  zero means it read nothing, and a report with no findings is then recorded as not a clean result.

The map follows the same vocabulary as the other tools, so the citation guard reads it the same way:
49 JavaScript and 32 Python queries. A query that fits no requirement cleanly (`js/missing-rate-limiting`,
say) is left unmapped, and its finding is still shown with no requirement attached. Two are only ever
findings: `js/incomplete-url-scheme-check` shows half of V1.2.2 missing and a clean run says nothing about
URL encoding, and `js/system-prompt-injection` is evidence against AISVS C2.1.6 exactly as semgrep's
rule is. Level 1 goes from 51 to 52 of 70 and Level 2 from 49 to 53 of 183, each with `--tools` and
CodeQL installed.

Tested with a stand-in that plays both steps and replays reports from a real CodeQL 2.27.1 run, and once
against the real tool when it is on the PATH, which here it was: it built the database, analyzed it,
and found the cross-site scripting it was given, in 29 seconds.

### Three more wrong citations, in the place the guard could not see

The citation guard reads `adapters.json` and `ast-rules.json`. Citations hard-coded in Rust were
guarded by nothing, and there were three of them, all pointing at **V1.3.5** — *sanitizing
user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL
stylesheets*:

| check | cited | should be |
| --- | --- | --- |
| the bill of materials is incomplete | V1.3.5 | V15.1.2, an inventory catalog of third-party libraries |
| a dependency matches a known advisory | V1.3.5 | V15.2.1, components within documented remediation time frames |
| the ecosystem pins no versions | V1.3.5 | V15.1.2 |

The third one is the worst of them, and shows why this class matters. Its citation was attached to
the *passing* outcome as well as the failing one, so an app that committed a lockfile earned a green
line against template sanitization — a requirement nothing had looked at.

So the guard now has a second half that reads the Rust sources. It is deliberately narrow about what
counts as a citation, and each restriction is a false positive it hit on the way in:

- **`src/` only.** A test may name an id precisely *because* it does not exist — `V1.2.9` stands in
  for a typo in the suite tests — and flagging those makes the guard something people switch off.
- **Not comments.** `probes.rs` explains in a comment that it once cited `V14.4.1`, "which is not a
  requirement at all". That comment is the record of the fix. Reading it as a live citation reports
  the fix as the bug.
- **Quoted, and three parts.** `V6.2` in a doc example is a section scope, and scopes are
  legitimate; `"V15.1.2"` in a literal is a citation.

That half only checks that an id resolves — the `AC-NN` class. It would not have caught any of the
three wrong citations above, because `V1.3.5` is a perfectly real requirement. The semantic half is
what catches those: it is built by calling the real code and comparing the finding's own words with
the requirement's, so a citation cannot drift from the finding it travels with. Breaking it is what
showed the lockfile check was still unguarded after the first attempt — putting `V1.3.5` back
produced no failing test at all, because the semantic half only reached the bill of materials. It caught the replacement wording immediately: the clean
bill-of-materials claim read *"1 package listed at the version actually installed"*, which shares no
vocabulary with a requirement about an *inventory* of *third-party libraries*. The citation was
right and the sentence was written in the wrong words, which is the third time that exact thing has
happened and the reason the guard compares words at all.

### The citations were all wrong

The mapping from a rule to the requirement it is evidence about is the whole product. A finding whose
citation is wrong is not a smaller finding — it is a green line, or a red one, against a requirement
nobody examined, and the report gives its reader no way to tell. On 24 September 2026 nearly every
citation in `data/adapters.json` and `data/ast-rules.json` was found to be wrong.

ASVS 5.0 `V1.2.1` is *output encoding for an HTTP response, HTML document, or XML document*. It was
cited for SQL injection and for `eval` by seven rules. `V1.2.2` is *URL encoding*; nine rules cited it
for OS command injection, which is `V1.2.5`. Eight cited `V11.3.1` — *insecure block modes and weak
padding* — for MD5 and SHA1, which are `V11.4.1`. `G404`, Go's non-cryptographic random number
generator, cited the hash-function requirement rather than `V11.5.1`. `G304`, a file path built from
user input, cited the JavaScript-encoding requirement rather than `V5.3.2`. `G107`, server-side request
forgery, cited the *database query* requirement. Parameterized queries — the thing half the map is
actually about — are `V1.2.4`, and nothing cited it.

How this survives is the interesting part, and it is not carelessness. The ids are plausible: they sit
in the right chapter, in the right family, one or two digits from correct. Nothing in a report looks
wrong, because the requirement text is not printed next to the rule that cited it. And the tests were
written *from the map* rather than from the requirement — `a_rule_the_map_does_not_name_carries_no_requirement`
asserted `B608 -> V1.2.1` and passed for as long as the map said so, which is a test that checks the
code against itself.

It had been found twice before, both times by accident: five checkers citing `AC-NN` ids that did not
exist, then every runtime probe citation. The third time was an accident too — an example app written
to demonstrate test crediting tripped the test-name comparison, which reported that a test named for
`V1.2.1` shared no words with it. The comparison was right and the example was wrong.

So that same comparison now runs over the data files. `crates/sv-check/tests/citations.rs` reads every
citation in both files and checks two things: that the id resolves to a loaded requirement, and that the
rule's own description shares at least one substantive word with the requirement's text. For the second
to be possible at all, each adapter rule now carries a `what` in prose — a bare id-to-id mapping gives a
guard nothing to compare, which is precisely why nothing checked it for so long.

The guard is deliberately weak: one word in common, not agreement. It cannot catch a swap between
neighboring requirements that share vocabulary — `V1.2.4` cited where `V1.2.7` belongs would pass, both
being about parameterized queries — and it is stated here so nobody reads a green run as more than it
is. What it catches is a citation pointing at a different subject altogether, which is every mistake
actually made here across three occasions. A check that is weak and runs beats a check that is strict
and gets turned off.

It earned its keep immediately, on the work that introduced it: three of the replacement descriptions
shared no words with the requirement they cited. All three were correct citations described in the
wrong vocabulary — "subprocess started with `shell=True`" against a requirement that says *operating
system command* — and the fix was to describe the rule in the terms the requirement uses, which is the
discipline the guard exists to impose.

One thing it cannot check, and which is now written down rather than assumed: Brakeman's rule ids in
`adapters.json` come from its documented warning codes and have never been seen in a real SARIF run,
because Brakeman cannot be installed in this sandbox. An id that is simply wrong maps nothing, so it
shows as a finding carrying no requirement rather than as a wrong one — the safe direction, but not a
verified one.

### The threat model's citations, and the bridge phrases already written

The threat model (`data/knowledge/threats.json`, shared with v1) cites requirements too: 115 pairs across 42
threats, 101 distinct requirements. It was the fifth citation surface and the only one outside the guard.
Comparing each threat's description with the requirements it cites flags 52 of the 115 — and every flagged
pair that was read is right. A threat is written for somebody who is not a programmer and ASVS for somebody
who is, so "someone denies having signed in" and "all authentication operations are logged" share no word.

The fix looked like it needed a bridge phrase per pair, as the Secure by Design crosswalk has. It was already
there: every citation in the file carries a `because` — "guessing a short password" for T-01 against
V6.2.1 — and measured with the guard's own comparison, all 115 share vocabulary with both the requirement and
the threat. The guard had only ever been pointed at the descriptions. So `citations.rs` now reads the threat
citations through their `because`, like every other citation, and a second test holds each `because` against
its threat, so a phrase cannot join any threat to any requirement. Nothing in `threats.json` changed.

Breaking it found one more hole, in the crosswalk as well: `shares_no_words` treats a text with no substantive
word as agreeing with everything, which is right for a test name and wrong for a bridge. A `because` removed,
or reduced to "the app", passed both guards. A third test now requires every bridge phrase, in both files, to
carry a word the comparison can use. Five breaks, each caught by a general guard and not only by the fixture
test: a wrong subject, an id that does not exist, a phrase matching the requirement alone, and a `because`
removed or emptied — the last two on T-02 and on a crosswalk pair, so the fixture's own pair could not
catch them by accident.

### A report from a run

`sv report --run` starts the app behind the same fence `sv run` uses and folds what it answered into the
report. Opt-in, not automatic: everything else `sv report` does reads files, and this starts somebody's
code. Both commands go through one `probe_the_running_app`, because two call sites each deciding when an
app is runnable would drift, and the one that drifts quietly is the report.

What changes when it runs is not only that findings appear. The standing gap — *the app was never
started* — is replaced by the probes' own list of what asking it could not reach: authorization, session
handling, CSRF, anything that needs data sent into a form. An app that ran is not an app fully examined,
and the gap list has to say which of the two happened. The app's declared tests are folded in the same
way, under the rule below.

### Whether the app was started, in one line

The counts in `sv report`'s summary move a long way with `--run` (on the owner's first build from
scratch, requirements checked went from 9 to 23), and nothing in the summary said which had
happened: the AI coding tool reading it for the owner worked it out from the counts. So the first
line after the list of files written is now one of three:

- *The app was not started*, and how to start it.
- *--run was given, and the app could not be started*, and the reason the runner gave: what
  securevibe.toml leaves out, no container backend, or the app never answering.
- *The app was started with* its image *and answered N of the M requests sent to it without signing
  in*, whether it was then asked more as test users, and whether its own tests passed, failed (the
  report then shows their last lines), or were not declared.

`report.json` carries the same as `run_status`, by name (`state` is `not-asked`, `could-not-start`,
or `started`) rather than by sentence, for a tool that reads the file instead of the terminal.

Tested with seven breaks (the line not printed, printed after the counts, a failed start reported as
not asked, an exit code of zero read as failure, any exit code read as a pass, the state named the
way Rust names it, the signed-in half dropped), each turning two to four tests red; the two states
that need no container are tested through the binary, and the third was seen end to end: *started
with python:3.12-slim and answered 29 of the 29 requests*, its tests failing.

### What the app's own tests are evidence about

A passing test suite is the largest source of positive evidence here and the easiest place in the whole
workspace to overclaim, so the rule is narrow and stated once: **a test counts only for a requirement it
names, and only when the suite it belongs to actually passed.**

Matching tests to requirements by their words was the obvious design and is refused. A test called
`test_login` might be about authentication, or sessions, or neither; crediting a requirement on the
strength of a name somebody chose for other reasons is how a compliance report becomes fiction. `sv init`
therefore asks the app's author to write the id into the test — `def test_V1_2_4_search_uses_bound_parameters`
or `# covers V1.2.4` on the line above — and `suite.rs` reads that back. A test that names nothing is not
evidence about anything in particular, which is a perfectly fair thing for a test to be; most tests are.

Three things have to hold before one requirement is credited, and each of them is a way the credit would
otherwise be wrong:

1. **The suite passed.** A failing suite credits nothing at all, not even the tests in it that passed,
   because `sv` sees one exit code and cannot say which tests it came from. This is also the limit of the
   feature: reading a test runner's own report would let a partly-passing suite credit its passing half,
   and that is on the backlog rather than guessed at here.
2. **The id resolves.** An id outside the loaded frameworks is a typo, and crediting it would put a green
   line against a requirement nobody has.
3. **The id is in a test file.** The same `# covers V1.2.1` in `app.py` is somebody's note about an
   intention. The path test is deliberately generous about naming conventions — `tests/`, `spec/`,
   `__tests__/`, `*_test.go`, `*.spec.ts`, `test_*.py` — and deliberately strict about the separator,
   because without it `latest.go` is a test file and the walk starts reading the application code.

Two details cost a run each. Go only runs a function called `TestXxx`, so `TestV1_2_1` runs a letter
straight into the id; the word-boundary rule rejected it, which would have meant reading nothing in any Go
suite while looking like it worked. And crediting per line rather than per file counted a test twice when
its docstring repeated the id, then reported the docstring as not matching the requirement — one honest
test producing one duplicate claim and one false flag.

What this cannot check is whether the test does what it names. v1's comparison is ported as it was: the
test's wording against the requirement's, reporting where they share nothing, at Info and Low confidence
because about a third of those flags are honest tests phrased differently. It reports and never withholds
credit, for the reason v1 gives — a check that takes credit away from a third of real work is a check
people turn off.

Running it found a fault in the report itself. The probes verified three requirements that are above the
fixture's target level, so every one of those positive claims fell outside the applicable table and
disappeared — the count read *0 checked* on a run where the probes had just checked three things, and a
reader would have concluded they never ran. Findings already had a section for this case; satisfied
checks did not. A vanishing positive claim is safer than a vanishing finding and still tells the reader
something untrue.

### A suite that mostly passed

`suite.rs` credited a requirement only when the *whole* suite passed, because a run sees one exit code
and cannot say which tests it came from. One broken test anywhere therefore credited nothing at all,
however many of the other forty named a requirement and passed — which is a fair reading of one exit
code and a poor reading of what the suite established.

Every runner in the languages the manifest knows can write JUnit XML, so `securevibe.toml` gains
`test-report` and the run reads what lands there. Three things make it safe rather than merely useful.

**The rule is strictly additive.** A suite that passed outright does not consult the report at all, so
it credits exactly what it credited before — reading a report can only ever *add* a claim, never remove
one. A suite that failed credits only tests the report names and says passed, matched on an exact
identifier read off the declaration. Anything unmatched stays uncredited, which is precisely where it
stood before any of this. jest concatenates its `describe` blocks into the reported name, so jest tests
mostly will not match, and that costs coverage rather than correctness.

**The parser fails closed, and that is its whole design.** No XML crate is cached in this environment
and adding a dependency to a security tool to read a test report is not a trade worth making, so it is
hand-written — and hand-written XML is wrong in the direction that matters here, reading a failed case
as passed. So anything surprising refuses the *entire* report rather than returning what it managed to
understand: an unclosed tag, an entity it does not know, an element it has never heard of. A refused
report falls back to the exit code, which is where this started. Every weakness of the parser becomes
lost coverage instead of a false claim. Ten refusals are tested, and the one worth naming is a CDATA
section holding what looks like `</testcase><testcase name="invented"/>` — a naive reader invents a
passing test out of captured output.

A skipped test is not a passing test. It did not run, so it established nothing, and crediting one
would put a requirement green on the strength of a test nobody executed.

**A stale report must never read as a pass.** One left over from an earlier run — committed into the
repository, or baked into the image — would be read as this run's result. So it is deleted before the
suite runs and must be there afterwards, or nothing is read. This is the adapters' rule again: absent
never reads as clean.

#### The read-only mount, which made the first version impossible

The first version had the runner write its report into the app folder, and it could never have worked:
the app is mounted `:ro`, deliberately, because `sv` reads code and does not let the code it is checking
rewrite itself mid-check. So the file was never written, and the feature reported *the test runner wrote
no report* — correctly, and uselessly, every single time.

Nothing about that was visible from reading the code; it took running it against an app whose suite
really fails. The container now gets a `--tmpfs` at `/sv-reports`: writable, in memory rather than on
the owner's disk, gone when the container goes, and read out with `exec` like everything else. A
relative `test-report` resolves there, and `sv init` says so, because an owner who writes
`reports/junit.xml` by habit would otherwise hit exactly the same wall.

### What a failing suite printed

A suite that fails under `--run` is worth what its runner's report says still passed, and its exit
code says only that something did not. Which test, and why, is in the last lines the runner prints,
where every common runner puts its summary. On the owner's first build from scratch one test failed
under `sv`'s Node 22 image and not under the owner's Node 26, and the report could not say which: the
AI coding tool rebuilt `sv`'s environment by hand to find it. So when the suite fails, the report
(all three pages, and `report.json` as `test_output`) and `sv run`'s terminal output carry the last
30 lines it printed, under a sentence saying how many there were in all.

- **As a terminal showed them.** Color codes and other control sequences are taken out, a line a
  runner redrew in place (a progress bar) is its last state, and blank lines at the end do not count
  as the end.
- **Never a credential.** A runner that prints its environment, or a request it made, prints the keys
  in it, and a report may be handed to somebody. Everything the credential rules match, and any value
  given to a name that says it is a credential (`API_KEY=…`, `"password": "…"`, quoted or not,
  whatever its entropy), is cut to what a finding shows of it, its first four characters. A cut that
  was not needed costs a reader four characters; one that was missed cannot be taken back. The
  sentence says how many were cut. Placeholders (`changeme`, `${TOKEN}`) are left, because cutting one
  hides the mistake it points at.
- **Text, whatever it holds.** The HTML page escapes it, and the Markdown fence is longer than any run
  of backticks in it, so a runner's own markup or code fence cannot end the block around it.
- **Nothing for a suite that passed**, even one that printed a failure on its way to passing.

Tested with each of twelve breaks (a rule's matches not cut, named values not cut, placeholders cut,
the first lines kept, colors kept, redraws kept, trailing blanks kept, a passing suite's output kept,
the HTML not escaped, a fixed fence, the block left out, the count of cuts dropped), each caught by
two tests; and end to end with `sv run` and `sv report --run` on a Python app whose suite prints 45
lines, a key among them, and fails: the last 30 were shown, and the key's tail was in none of the
five report files.

### Saying a check looked and found nothing

A finding is a claim about something that is there. `Verified` is the mirror: a claim about something
that is *not*, which is only worth the coverage behind it, and which fails in a direction nobody
notices — a green line in a report is not something a reader goes back to question.

Three rules hold wherever one is produced. **Fail closed**: a check says nothing unless it read
everything it would have needed to. **Say the scope**, in a person's words, beside the claim, because
"checked" means nothing without "over what". **Claim no more than the check tests**: the requirement ids
are the same ones it cites when it fails, which is the one direction this must never move in.

What that rules out is more interesting than what it allows:

- No rule that reads code says anything at all while a language present in the app goes unparsed. The
  injection it looks for could be sitting in the Ruby nobody read, so a clean Python scan of a
  Python-and-Ruby app has established nothing about that app.
- A rule says nothing about a language it never saw. A SQL rule that never met a line of Python has not
  shown the app builds no queries by hand.
- A credential scan that skipped one file claims nothing. "Forty-eight of fifty-two files were clean"
  belongs in the gap list, not beside a requirement, and the skipped one is exactly where a key would
  be. An empty folder claims nothing either: reading no files is the one case where "found no
  credentials" is true and means nothing.
- An app that set **no cookie** is not credited with setting good ones, and an app that sent **no
  `Access-Control-Allow-Origin`** is not credited with checking origins. Both rules return "no finding"
  for the careful app and for the app that was never really asked, and reading that as correctness hands
  a green line to every app that does neither.

The probes are the only place anything here observes the app doing the right thing rather than failing
to catch it doing the wrong one, and a probe with no answer credits nothing — otherwise a run against an
app that would not start reads as a run against an app that passed.

**On screen too (8 October 2026, backlog item 25(g)).** The reports already credited nothing for a folder
none of whose files was read, but `sv check` still printed its config checks that found nothing under
"Checked and fine", five of them for an empty folder, each "0 files: none …". When no file of the app was
read, it now prints one line instead: none is listed as checked and fine, because the checks that found
nothing had nothing to look in (`Gaps::read_nothing` in `crates/sv-cli/src/exit.rs`). The same run showed a
finding about an absence, no SECURITY.md, at `SECURITY.md:1`, a line of a file that is not there; a finding
whose file is missing is now shown as `SECURITY.md (not there)`. Only what `sv check` prints changed: the
finding's location in the JSON reports, SARIF, and fingerprints is as it was.

### What the reports found in the checks themselves

Building the first one turned up two faults that nothing else could have shown, because both were
invisible until something tried to resolve a citation:

Five checkers cited `AC-05`, `AC-08`, `AC-09`, `AC-10` and `AC-13` — Appendix C *family* ids, written
with a hyphen and a leading zero instead of a dot, matching no requirement at all. Worse, they were not
near-misses in meaning either: `config.secrets-file-committed` cited the family for *Explainability &
Traceability of Code Suggestions*, and had the spelling been right, a .gitignore would have marked an
AI-explainability family as looked-at.

Every probe citation was wrong in the same way. `security_headers` cited Strict-Transport-Security for a
rule that checks CSP, nosniff, framing and referrer policy — over plain HTTP, where there is no TLS
policy to have. `cookie_attributes` cited the CORS and CSP requirements. `trace_enabled` cited HSTS when
V13.4.4 names TRACE outright. They were invented rather than looked up. They are now the ids the rules
actually test, and `every_requirement_a_check_cites_is_a_requirement_that_exists` walks both `crates/`
and `data/` and fails on any citation that resolves to nothing.

That guard was itself wrong twice before it was right, which is the useful part. Its first version
scanned for anything id-shaped and reported ninety failures, none of them citations — the probes name
whole ASVS chapters in prose when saying which ones they cannot reach. Its second version read only
`crates/`, found fourteen ids, and passed, while every id in `ast-rules.json` and `secret-rules.json`
went unchecked. A guard that silently covers half of what it names is worse than none, because the half
it misses now looks guarded. It ends by asserting it reached a Rust source and both JSON rule files by
name, rather than by counting.

### The two checks that said nothing when they found nothing

The credential scan, the rules that read code, the probes and the app's own tests all report what
they examined and found nothing wrong. The bill of materials and the advisory comparison did not:
they produced findings when something was wrong and were silent when nothing was, and silence reads
exactly like a check that never ran.

Both now speak, and both fail closed on their own coverage. The bill of materials may call itself a
complete inventory only when nothing was unread *and* there is something in it — an app with no
dependencies `sv` could find is far more often an app whose manifests were never parsed than an app
with no dependencies, and that is the easiest false green line in the whole area. Exactly one of the
two sentences is ever said, so a document is never reported as both an incomplete list and a good
inventory.

The advisory comparison may say it found nothing only when all five of these hold, and each is a way
a clean answer would mislead:

- **The database held records.** An empty one compares every package against nothing. This one is
  belt-and-braces and is labeled as such in the code: an empty database covers no ecosystem, so the
  next condition already stops the claim, and breaking this one alone turns no test red. A condition
  that carries no weight should say so rather than look load-bearing.
- **There were components to compare.** Nothing examined is not nothing wrong.
- **Every ecosystem present was covered.** A database that says nothing about npm did not check the
  npm packages; it skipped them.
- **Every version could be compared.** A version no range can place — a git hash, a date, a build
  tag — is a component whose status is unknown, not clear.
- **The component list was not known to be short.** A clean answer about the packages `sv` could see
  is an answer to a question nobody asked: they asked whether the app ships anything vulnerable.

`sv audit` now says two different sentences depending on which of those held. "Nothing in what was
compared matches a record in this database" is true either way and is exactly what a reader skims
past, so the claim is only made when there is nothing left over to qualify it.
