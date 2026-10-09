# What is in `data/`, and what reads it

Everything `sv` knows that is not code lives here: the OWASP standards, the questions it asks, and its rules. Most
files are read each time `sv` runs, so editing one changes `sv`'s behavior without rebuilding it. The exceptions are
marked below. A test (`crates/sv-cli/tests/data_readme.rs`) fails when a file here is not listed in this page, so
the list stays complete.

`sv` reads every file here through one place (`crates/sv-frameworks/src/data.rs`, ADR-036), which looks in
`SV_DATA_DIR` (a whole copy of this folder), then beside the program (`data`, or `../share/stackvet/data`), then
in the repository it was built from (`crates/<crate>/../../data`), which is what the Docker image uses.
`tools/install.sh` puts a copy beside the program it installs.

## The standards (`frameworks/`)

The requirements themselves, as published. Read by `sv-frameworks` and counted by `tools/coverage.py`.

| File | What it is |
|---|---|
| `frameworks/asvs-5.0.0.json` | OWASP ASVS 5.0 |
| `frameworks/aisvs-1.0.json` | OWASP AISVS 1.0 |
| `frameworks/aisvs-1.0-appendix-c.json` | AISVS Appendix C, the rules for AI coding tools |
| `frameworks/sbd-checklist-0.5.0.json` | The Secure by Design checklist |

## Which requirements apply

| File | Read by | What it is |
|---|---|---|
| `knowledge/applicability.json` | `sv-frameworks` | Which requirements apply to which apps, and the `manualOnly` list: requirements only a person can settle. |
| `applicability-v2.json` | `sv-cli`, `sv-manifest` | `sv`'s rules laid over the file above, replacing rules whose reasons described v1's own template. |
| `level-hints.json` | `sv-check` | What the report looks for in an app held to level 1 that would make it level 2: sign-up routes, and field names for health, financial, card, and identity information. A match is a question under the level line, never a finding. |
| `sbd-asvs-crosswalk.json` | `sv-cli` | Which ASVS requirements each Secure by Design control corresponds to. |
| `knowledge/threats.json` | `sv-cli`, `sv-report` | The threat model's rules. |
| `atlas-references.json` | `sv-report`, **compiled in** | MITRE ATLAS references for the threat model. Written by `tools/atlas_references.py`; rebuild `sv` after changing it. |

## What `sv` asks the owner and the AI coding tool

| File | Read by | What it is |
|---|---|---|
| `security-notes.json` | `sv-check`, `sv-cli` | The questions answered in writing, in the security notes file. |
| `design-questions.json` | `sv-check`, `sv-cli` | The design questions answered in `stackvet.toml`. |
| `human-checks.json` | `sv-check`, `sv-cli` | How to check by hand what no automated check can settle. |
| `coding-rules.json` | `sv-check`, `sv-cli` | Rules the AI coding tool follows while it writes the app. |
| `prompts.json` | `sv-check`, `sv-cli`, `tools/coverage.py`; `docs/PROMPTS.md` is written from it by hand | Prompts for the AI coding tool, each with the check that shows whether it worked and the result of trying it. |
| `design-prompts.json` | `sv-check`, `sv-cli`, `tools/coverage.py`; `docs/prompts/design-time.md` is written from it by hand | Design-time prompts from the Secure by Design checklist, in `prompts.json`'s shape, with the checklist controls each helps a person answer. |
| `design-decisions.json` | `sv-check`, `sv-cli` | The sections of `design-decisions.md` that count toward a Secure by Design control, read as the security notes are, each with the heading its design-time prompt writes and what a written section does not show. |
| `feature-briefs.json` | `sv-cli` | The features `sv brief` and `stackvet_before` write a brief for: the conditions and requirements each brings, its design-time prompts, and the `stackvet.toml` settings `sv run` needs to test it. |

## How `sv` reads an app

| File | Read by | What it is |
|---|---|---|
| `tech-signatures.json` | `sv-cli` | Signs in the code that a technology is used. |
| `claim-corroborators.json` | `sv-cli` | Signs in the code that back up, or contradict, what `stackvet.toml` says. |
| `ast-rules.json` | `sv-check`, `sv-cli` | `sv`'s own rules for reading code, in each language. |
| `secret-rules.json` | `sv-check`, `sv-cli` | The formats of keys and passwords the secrets scan looks for. |
| `adapters.json` | `sv-check`, `sv-cli` | The outside scanners `sv` can run (semgrep, bandit, and others), and which requirements their rules speak to. |
| `reach.json` | `sv-report`, through `sv report`; `sv-cli`, through `sv explain` | For each requirement a check can settle, the kinds of run with a check that can credit it. Written by `tools/coverage.py` (a test fails while it is out of date); the short version uses it to say how many requirements only a kind of run that did not happen could reach. Its `checks` part lists, for every requirement a check speaks to, each check, the kind of run it needs, what it looks for, and whether it is only ever a finding, for `sv explain`. |
| `semgrep-packs.json` | tests and `tools/coverage.py` | Which rules each semgrep pack really loads, as measured by `tools/semgrep_packs.py`. |
| `codeql-suites.json` | tests | Which queries each CodeQL suite the adapters run really selects, as measured by `tools/codeql_suites.py`. |

## The fields of a rule in `ast-rules.json`

Each rule is one entry in the file's `rules` list. `sv` refuses to load the file when a rule has a field not named
here, so a misspelled field stops the run rather than being ignored. A test
(`crates/sv-check/tests/ast_rule_schema.rs`) fails when this list and the fields `sv` accepts differ, in either
direction. "Per language" means an object whose keys are language names (`python`, `javascript`, `typescript`, `go`,
`java`, `kotlin`, `csharp`, `php`, `ruby`, `rust`, `swift`, `dart`, `c`, `cpp`, `shell`). A pattern is a regular
expression. The code's own comments on `AstRule` (`crates/sv-check/src/ast.rs`) give each field's reasons at length.

A query marks parts of what it matches with names, and the fields below read them: `@fn` is the called name, `@mod` the
object or module the call is on, `@arg` the argument judged, `@kw` a keyword argument's name, `@hash` a hash the call
names, and `@hit` the place the finding points to (the first part matched, when there is no `@hit`).

Every rule has these:

- `id` (text): the rule's name, used in findings and in the report.
- `title` (text): one line saying what was found.
- `severity` (`critical`, `high`, `medium`, `low`, or `info`): how bad it would be.
- `confidence` (`high`, `medium`, or `low`): how sure the rule is, kept apart from how bad.
- `requirementIds` (list of text): the requirements the rule speaks to, the same whether it finds something or not.
- `cwe` (list of text): the weakness numbers (CWE) a finding names.
- `description`, `impact`, `fix` (text): what the finding means, what it allows, and how to put it right.
- `queries` (per language, text): one tree-sitter query per language. A language with no query is one the rule says
  nothing about.

What a match must look like to be reported, each optional (per language unless it says otherwise):

- `functionPatterns`: what `@fn` must match.
- `modulePatterns`: what `@mod` must match.
- `argumentPatterns`: what `@arg` must match. A match with no `@arg` is not reported.
- `argumentPatternsByHash` (per language, pattern to pattern): for a call that names its hash, what `@arg` must match
  for each hash that `@hash` matches, in place of `argumentPatterns`.
- `argumentPositions` (per language, pattern to number): calls whose argument that matters is not the first, with
  its position counted from 0.
- `argumentsForCommonNames` (per language, pattern to pattern): calls with a name too common to report on alone, and
  what their argument must look like to be reported.
- `keywordPatterns`: what `@kw` must match. A match with no `@kw` is not reported.
- `enclosingFunctionPatterns`: what the name of the function around the match must match, written as lower-case
  words joined by `_`.
- `valueNamePatterns`: what one of the names given to the value at `@hit` must match, written the same way.
- `safeArgumentPatterns`: an `@arg` known to be safe, so the call is not reported.
- `literalArgumentIsSafe` (true or false, false when left out): a call whose `@arg` is plain fixed text is not
  reported.
- `safeArgumentPiecesRead` (true or false): an argument pieced together is safe when every piece is fixed text or
  matches `safeArgumentPatterns`.
- `argumentNamesRead` (true or false): `argumentPatterns` also matches through a name set, in the function around
  the call, to text the pattern matches.
- `functionNamesRead` (true or false): `functionPatterns` also matches through the name `@fn` begins with, read as
  what the function around it sets it to.

What a finding says, each optional and false when left out:

- `boundParametersLowerConfidence`: a plain name with values passed after it lowers the finding's confidence, and
  the finding says why.
- `saysWhenReadFromDatabase`: an argument built from fixed text and values read back from the app's database says so.
- `saysWhenChecked`: an argument passed through a function whose name says it checks it names that function.

What a clean result says, each optional:

- `looksFor` (text): what the rule looks for, in plain words, shown beside a clean result.
- `looksForIn` (per language, text): where the rule looks for something narrower than `looksFor` says.
- `nothingToFind` (per language, text): languages with nothing for the rule to find, each with the reason. A language
  cannot have both this and a query.
- `findingsOnly` (true or false, false when left out): the rule can show the fault present and never its absence, so
  finding nothing credits nothing.
- `jsxQuery` (text): patterns added to the `typescript` query for files that may hold JSX (`.tsx`, `.astro`).
- `unreadPackages` (per ecosystem, package name to text): packages that build queries through calls of their own the
  rule does not read, each with those calls in a few words. Ecosystems are named as the bill of materials names them
  (`npm`, `Python`, `Go`, `PHP`). While the app ships one, the rule claims nothing, and the report names the package.

## Passwords

| File | Read by | What it is |
|---|---|---|
| `knowledge/common-passwords.txt` | nothing at run time | The most common passwords, 96,517 of them, one per line. `sv`'s sign-up checks use four entries from it, written into the code (`signed_in/passwords.rs`): three from the top 3000, all of which must be refused (ADR-055), and one far down the list for the breached-password check; `tools/pwned_passwords.py` samples it. |
| `breached-password-evidence.json` | `sv-check`, **compiled in** | Evidence that the password `sv` tries at sign-up for the breached-password check is in known breaches. Written by `tools/pwned_passwords.py`; rebuild `sv` after changing it. |
| `common-passwords-breach-sample.json` | nothing at run time | How much of the common-password list is breach data, from a sample. Written by `tools/pwned_passwords.py`. |

## v1's files

Eight more files in `data/knowledge/` were v1's and never read by `sv`: the wizard's wording, its sample apps, its
glossary, and the like. They were removed from `main` on 27 September 2026 at the owner's decision. v1 keeps its own
copy on the `v1` branch and at the tags `v1-paper` and `v1-final` (see `docs/adr/ADR-016.md`).
