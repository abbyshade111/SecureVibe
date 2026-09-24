# SecureVibe Agnostic (`sv`) — design

A second version of SecureVibe. It keeps the workflow, the checks, the compliance engine and the reports, and
changes two things:

* **No wizard.** The user builds their app in whatever AI coding tool they like, with the back-and-forth that gets
  the app right. `sv` picks the code up afterwards.
* **No language.** Nothing in the pipeline assumes Node, Express or the SecureVibe template.

Written in Rust. The OWASP data files are shared with v1 rather than copied.

## What carries over unchanged

`data/frameworks/*.json` (ASVS 5.0, AISVS 1.0, AISVS Appendix C, SbD checklist) and `data/knowledge/*.json` are
pure data with no Node in them. `sv` reads the same files from the same place. One source of truth for ASVS
across both products; an ASVS correction fixes both.

The rules that carry over word for word:

* Evidence tiers are honest. AI review alone is `ai-assessed`, never `pass`.
* A check that does not apply is not a check that failed (ADR-012), and a scan that did not run is not a clean
  result, and a requirement that was not assessed is not a failed one.
* A checker that knows which requirements it verifies says so in `Evidence.requirementIds`.

## The part that actually needed designing

`shared/src/profile.ts` opens by saying the wizard answers are "the ONLY input to every security decision
SecureVibe makes". Delete the wizard and every security decision loses its input. The applicability engine
reduces a design to about twenty-five booleans — `auth`, `uploads`, `payments`, `ai-actions`, `multi-tenant`,
`tls`, `internet` and so on — and those booleans decide which requirements apply *at all*. Get one wrong in the
permissive direction and the report says "not applicable" about a requirement the app needed.

Inferring them from the code is guessing, and guessing is the thing this project refuses to do elsewhere.

### Claims, and what corroborates them

The user's AI tool writes a `securevibe.toml` during the build — `sv init` prints the spec to hand it. Every
capability in that file is a **claim**, not a fact. `sv` then tries to corroborate each claim against the code,
and each one ends in one of four states:

| State | Meaning | What it does to the requirements |
|---|---|---|
| `confirmed` | Claim says yes, and the code agrees | They apply, evidence recorded |
| `contradicted` | Claim says no, and the code says otherwise | **They apply anyway**, plus a finding |
| `unsupported` | Claim says yes, nothing in the code shows it | They apply; the claim is not treated as evidence |
| `unverifiable` | No corroborator exists for this claim | They apply; reports say "asserted, not verified" |

**Corroboration only ever moves toward more requirements applying, never fewer.** A manifest cannot switch a
requirement off that the code says applies. This is the same constraint v1 puts on the second opinion and the
follow-up questions — they may only move an answer toward the safer side — and it is what stops a careless or
over-confident manifest from turning into an over-stating report.

The asymmetry is deliberate and it is the whole safety argument: a wrong claim costs the user a requirement they
did not need to meet, never a requirement they needed and were told they did not.

### A thing v2 can answer that v1 could not

`buildConditionContext` hardcodes `oauth`, `webrtc`, `jwt`, `rag`, `mcp`, `multi-tenant` and `training` to
`false`, because the wizard never asked and the template never emitted them. Whole ASVS chapters — V10 (OAuth),
V17 (WebRTC) — are switched off for every app v1 has ever built. Real code from a real tool uses those things, so
in `sv` they are claims like any other, with corroborators, and those chapters come alive.

## Shape

```
sv-cli          the `sv` binary: check, init, report, explain
sv-manifest     securevibe.toml — parse, validate, the spec `sv init` prints
sv-frameworks   loads the OWASP JSON; the applicability engine
sv-corroborate  claims vs. code; the four states above
sv-scan         language-agnostic scanners: secrets, config, lockfiles/SBOM, tree-sitter AST rules
sv-adapters     per-language tooling, driven by a data file and not by Rust
sv-compliance   evaluation, evidence tiers, traceability, test-name matching
sv-run          the container runner and the DAST probes
sv-report       compliance and security reports, SARIF
```

### Why the adapters are a data file

Adding Python support should be adding a manifest entry, not writing a crate. An adapter says what tool to run,
how to recognise it is installed, how to parse its output into the common finding shape, and which ASVS
requirements its findings bear on:

```toml
[[adapter]]
id = "ruff"
ecosystem = "Python"
detect = { file = "pyproject.toml" }
probe = ["ruff", "--version"]
run = ["ruff", "check", "--output-format", "json", "."]
parse = "ruff-json"
stage = "lint"
```

A tool that is not installed is reported as **not run**, never as a clean pass. That is the ADR-012 rule applied
to tooling instead of to ecosystems.

### Running the code

v1 gets its strongest evidence by running the app: seeded users, DAST probes, the generated test suite. Keeping
that across arbitrary stacks means the manifest declares build/start/test, and `sv` runs them in a container with
the network fenced to loopback, exactly as `pipeline/net-fence.ts` does for a child process today.

A container backend is available on this machine as of 22 September 2026: Colima 0.10.3 with Docker 29.8.1,
serving a linux/aarch64 daemon on two CPUs and 2 GB of memory. Those are Colima's defaults and they are modest —
an app whose test suite wants more will need `colima start --cpu 4 --memory 8`, and `sv-run` should say that a
run was resource-starved rather than report it as a failing one.

`sv-run` is still built behind a trait, because a machine with no backend is the normal case for anyone else
running `sv`. Where none is present, every dynamic requirement reports `not assessed` — not `pass`, and not
`fail` — and the reports say which applied, as v1's do.

## Handover

`sv check ./my-app` is the primitive: any tool, any editor, CI. An MCP server wrapping the same core comes
second, so an AI coding tool can run the checks mid-conversation and work the findings without the user leaving
the chat. The CLI is what makes it tool-agnostic; MCP is what makes the loop tight.

## What is deliberately gone

`templates/secure-web-app`, `generator/`, the recipes, the wizard, the React UI, the upgrade path. `sv` never
writes application code, so the generation agent and its fence go with them. Uploaded apps in v1 are "only ever
scanned, never run"; in `sv` every app is that app, except that a declared run command lets it be run in a
container the user consented to.

## What the first run found

Running the ported engine against the real OWASP data with a Python/Flask manifest (604 requirements loaded,
254 applicable at level 2) surfaced something the port was not looking for.

**76 of the 197 exclusions — 39% — are not about the app at all.** They come from the 39 rules in
`applicability.json` that use the `never` condition, whose reasons are statements about v1's template:

* "JNDI is a Java technology; this app is written in TypeScript for Node.js and does not use it."
* "all data lives in its own SQLite database file"
* "The AI model is hosted and maintained by the vendor (Anthropic)."
* "There is no CI/CD pipeline in a local build, so there are no pipeline trigger settings to protect."
* "There are no pull requests from outside contributors; the only code the AI reviews is the code it
  generated for you on this computer."

Every one of those is true of a v1 app and unknowable about someone else's. For a Java service they are wrong;
for a repo with GitHub Actions and outside contributors, `AC.12` and `AC.13` being switched off is the difference
between a report and a misleading one. This is ADR-012 exactly — a wrong statement in a report, which an owner
would act on — and it would have reached v2 silently, because the rules load and resolve without complaint.

So `NotApplicable` carries the condition that excluded it, `sv` counts the inherited ones and refuses to repeat
their reasons, and `crates/sv-frameworks/tests/real_data.rs` pins that they stay distinguishable. The test
asserts they are *identifiable*, not that there are 76 of them: a frozen count would only pin today's data file.

Those 76 are the v2 backlog's first item. Each needs one of three things:

1. **A real condition** — `ci-cd`, `outside-contributors`, `graphql`, `websockets`, `xml`, `ldap`,
   `self-hosted-model` — claimed in the manifest and corroborated from the code, exactly like `auth`.
2. **A language condition** — V1.3.8 (JNDI) genuinely does not apply outside the JVM, and V1.4 (memory safety)
   genuinely does not apply to a memory-safe language. These are answerable from the detected ecosystem, which
   `ecosystems.ts` already does well enough to port.
3. **Nothing** — and then they report *not assessed*, which is honest, rather than *not applicable*, which
   is a claim `sv` has not earned.

### How that was resolved

All three, as it turned out — and the third barely applies.

**Thirty of the seventy-six are one question.** C3, C4, C6.*, C11, C12.3, C12.5 and AC.6 all say some version
of "the model is Anthropic's, and Anthropic hosts it". That is a single claim, `self-hosted-model`, plus the
`training` condition that **already existed** and was bypassed. Likewise V6.8, V7.6 and V7.1.3 — seven
requirements about external identity providers — all mean `oauth`, which also already existed. v1 hardcoded it
`false`, so the rules reached for `never` instead.

**Eleven are technology questions** the dependency manifests answer without anyone's word: LDAP, XPath, XML,
LaTeX, JNDI, memcache, format strings, unmanaged code, WebSockets, GraphQL, postMessage. One of those was
actively misleading rather than merely unknowable — V1.3.10's reason reads "Node.js does not have C-style
format strings that user input could exploit", and Python's `%` formatting makes that false for the very
example app this was tested against.

The replacements live in `agnostic/data/applicability-v2.json`, which replaces the rule at a scope rather than
merging with it: a wrong reason surviving next to a right one is still a wrong reason that can be printed. Two
of the 39 are deliberately left alone — V15.4 and C5.1, whose `never` reasons say "this is ASVS level 3", which
is honest and has nothing to do with v1.

### Two things this forced, which are the real result

**A fourth bucket.** Every rule now states where its answer comes from — `claim` (securevibe.toml says) or
`derived` (the dependencies say) — and a condition that *nothing has answered* produces **not assessed**, not
"does not apply". v1 never needed this, because the wizard asked about every condition it had. `sv` is handed a
repository and cannot assume, and "this does not apply to you" versus "nothing here has checked" is exactly the
distinction this project exists to keep.

**Silence is not a no.** Every claim is `Option<bool>`. `serde(default)` turning an absent `ci-cd` line into
`false` would have quietly excluded ten requirements on an answer nobody gave — the same failure as the
inherited reasons, arriving through the type system instead of the data file. An explicit `false` from the
owner is their own deliberate statement and is honoured; silence is not converted into one.

Breaking the not-assessed branch failed exactly **one** test at first. Under this project's rule that means the
coverage was accidental, so two more were added that fail for different reasons — a realistic partly-answered
app, and the general property that every exclusion rests on a condition something actually answered. Three fail
now.

### What the example app looks like afterwards

Before: 254 apply, 197 exclusions, 76 of them inherited fiction, nothing not-assessed.
After: **272 apply, 162 honest exclusions, 17 not assessed, no inherited reasons at all.**

The 18 newly-applicable requirements are mostly the OAuth chapters that v1 could never switch on. The 17
not-assessed are the technology conditions, waiting on the dependency scanner — reported as unanswered rather
than quietly excluded.

## The dependency scanner

The 17 not-assessed requirements are now answered. `sv-scan` reads the app's dependency manifests **and** its
source, and answers the eleven `derived` conditions with evidence attached — which dependency, in which
manifest, or which pattern, in which file.

Reading source as well as manifests is not thoroughness for its own sake. Python's `xml.etree` and Java's JAXB
are XML parsers that nothing declares; a dependency-only scan would answer "no XML parser is used" and switch
off V1.5.1 — an XXE requirement — for an app that parses attacker-supplied XML in its first route. That is the
same class of wrong statement as the inherited v1 reasons, arriving from a different direction, so the example
app now carries exactly that shape: `requirements.txt` names Flask, gunicorn, Authlib and PyJWT, and the XML
comes from the standard library.

### When "not found" is allowed to become "not there"

Only when everything that could have carried it was actually read. Three things stop the scanner concluding:

* **Files it cannot read.** A Swift or Scala file means `sv` has seen part of the app, and "I did not find it"
  is not "it is not there".
* **An ecosystem that pins nothing.** `^4.18.0` is a range, so the declared tree is not the installed one and an
  absent name proves nothing. v1's `ecosystems.ts` already made this point.
* **Having read nothing at all.** An empty folder, or one where everything was skipped, must not come back as
  "none of these technologies are used" — that reads exactly like a thorough scan that found none. A scan that
  did not run is not a clean result.

Matching is case-insensitive substring, which over-matches rather than under-matches. An over-match makes a
condition *true*, which only ever adds requirements — the same safe direction the manifest claims run in.

Each of those three guards was broken on purpose to see what caught it. Each had exactly one witness at first,
which under this project's rule means the coverage was accidental, so each now has a second that fails for a
different reason: a Go standard-library XML parser beside the Python one, a general property that nothing is
ever answered `false` while files go unread, an unpinned npm app beside the unpinned Python one, and a
skipped-directories folder beside the empty one.

### The example app, end to end

    Read 1 source files in python; package manifests: Python.

    274 apply, 177 do not, 0 not assessed, 153 above this level (604 loaded).

    Read from the code, so nobody had to be believed:
      xml              `xml.etree` in app.py
      format-strings   the app contains python

    Does not apply: 177 in total — 162 because the manifest says so, 15 read from the code.

Two bugs surfaced while wiring it up, both worth recording. `resolve` only ever iterated the manifest's claims,
so the scanner's answers — which are not claims — reached nothing downstream: it found the XML parser and the
requirement stayed not-assessed with the evidence sitting right there. And the scanner was willing to conclude
from reading zero files, which is the rule above being broken by its own author.

## The corroborators

The other half of the claims design. `data/claim-corroborators.json` describes how sixteen of the manifest's
claims look in real code, and `sv` checks each one. On the example app:

    The manifest and the code disagree about 1 thing. The code wins:
      securevibe.toml says payments is not used, but `stripe` is declared in requirements.txt

    Read from the code, so nobody had to be believed:
      auth             `authlib` declared in requirements.txt
      oauth            `authlib` declared in requirements.txt
      jwt              `pyjwt` declared in requirements.txt
      payments         `stripe` declared in requirements.txt

### The asymmetry the scanner did not need

For a technology like XML, absence is informative: parsing XML always leaves a trace, a library or a standard-
library import. For a claim like `auth` it is not. Sign-in can be built from a hash function and a database
table, leaving no library behind, and answering "this app has no sign-in" because no auth package appears would
switch off **fifty-three** ASVS requirements on the strength of a missing dependency.

So every corroborator declares `absenceIsEvidence`, and only two set it: `ci-cd` and `iac`. Those are files in
the repository, and a file that is not there is not there. Everywhere else, finding something proves it is
used and finding nothing proves nothing — recorded as the claim being *unverified*, not contradicted.

### Three things this turned up

**A silent field-name mismatch that defaulted to the dangerous value.** `Signature` had no `rename_all`, so
`absenceIsEvidence` in the data file never bound to `absence_is_evidence` in Rust. Every corroborator fell back
to the serde default — `true` — and the only symptom would have been requirements quietly switching off. The
guard test caught it on its first run. `Signature` now uses `deny_unknown_fields`, so a typo in the data file
stops the run instead of changing the answer.

**`.github` is a dot-directory.** The source walk skipped every directory beginning with a dot, which is
exactly where a CI pipeline lives. Left alone it would have answered "no CI/CD" for every repository that has
one — a wrong statement in a report, produced by an optimisation.

**Two conditions gate nothing.** `payments` and `scheduler` are asked about in the manifest and have
plain-language reasons written for them, but no rule in the OWASP data keys on either: ASVS 5.0 has no
payment-specific requirements. Announcing that the manifest is wrong about payments without saying that it
changes no requirement would be its own small overstatement, so `sv` says both — and points at the answer that
does matter, which is that an app taking money should probably be declaring `payment-card` or `financial` in
its data categories, and that *does* raise the target level.

## The reports

Everything else here prints to a terminal, where a line scrolls past and is gone. A report is kept, sent
to somebody, and read by a person who was not there when it ran — which is why it is the most dangerous
thing in the workspace to get wrong. A terminal line saying *not assessed* that nobody reads costs
nothing; the same omission in a document somebody files as evidence of a security review is how an app
ships believing it was checked.

`sv report` writes `report.html` (one file, no external requests), `compliance.md`, `security.md`,
`findings.sarif` and `report.json`. Three rules, each with a test that fails when it is broken:

- **There is no pass.** An applicable requirement is *needs attention*, *checked*, or *not verified*.
  `Checked` means one automated check looked at it and was satisfied — deliberately not called a pass,
  because one config check being happy is not an ASVS requirement met, and the report says so in the
  words around the number. A finding always outranks a satisfied check on the same requirement.
- **What was not examined comes first.** In both the security report and the compliance report, before
  anything that was found. A list of findings read on its own reads as the whole truth about the app,
  and it is only the truth about the part that was looked at.
- **A finding about a requirement the app is not being assessed against gets its own section** rather
  than being dropped. It means either the requirement was excluded when it should not have been, or a
  check is citing a requirement that has nothing to do with it, and both are worth a look.

## Eleven languages, and why the twelfth silences everything

The rules that read code have grammars for Python, JavaScript, TypeScript, Go, Ruby, PHP, Java, C#,
Kotlin, Rust and C. Each one is worth more than one more entry suggests, because of how the fail-closed
rule works: **no rule may speak while a language present in the app goes unparsed.** One Ruby file used
to silence every rule for the whole app — correct behaviour on an app `sv` could not read, and a lot of
silence. Every language added is one fewer kind of app that gets nothing.

### A page of markup is not a hole in the coverage

`html` covers `.html`, `.vue` and `.svelte`, and almost every web application has at least one. Counting
every page as unread therefore silenced every rule for nearly every real app — a great deal of silence
bought by a file that in most cases hides nothing at all. So the script is taken out of the page and
read as what it is. `<script>` elements go to the JavaScript grammar — or TypeScript, when the page
says `lang="ts"` — and so do `on…=` handler attributes, whose values are statements that parse on
their own once their HTML entities are put back. A `<script src="app.js">` with nothing between its
tags holds no code at all: the file it names is parsed like any other.

A finding in a page names the line **in the page**. The fragment's offset is added back before the
finding is written, because a reader sent to line 3 of something they cannot see is worse off than one
given nothing.

One function decides both what a page holds and what comes out of it. When "does this page hold code"
and "what code does this page hold" are answered by two pieces of code they drift, and the direction
they drift in is a page declared read whose code nobody extracted. So `html_fragments` returns the
fragments *and* whatever it could not take — an unclosed `<script`, a `javascript:` URL — and while
anything was left behind the page is still unread and every rule stays silent about the whole app. A
page that cannot be opened at all counts as left behind too.

The terminal's wording followed the behaviour twice: it said *there is no grammar for html* when every
page was unread, then *a page with a script written into it* when only those were, and now says what is
actually true — that something in the page could not be taken out of it.

Not every rule covers every language, and that is deliberate rather than unfinished. Rust has no `eval`
and its `Command` takes an argument list, so it has the SQL rule and nothing else; C has shell and SQL
and neither of the others. A rule with no query for a language says nothing about it and claims no
coverage of it, which is what keeps the clean-coverage claim honest.

The queries were written against dumped parse trees rather than against what the grammars plausibly
produce, which is two minutes' work and settled three things guessing would have got wrong. Ruby uses
one `call` node whether or not there is a receiver, so one pattern covers both. PHP splits them into
`function_call_expression` and `member_call_expression` and wraps each argument in an `argument` node.
Java matches Go's shape exactly.

Three things these languages needed that the others did not:

- **Ruby's backticks are a `subshell` node with no method name.** The name filter drops any match that
  cannot offer a name, which is what keeps a rule from firing on every call in a file — so rather than
  teach that filter to let unnamed matches through, the backtick form is its own rule. `ls` is as fixed
  as any string and `ls #{dir}` is not, and the literal check tells them apart once `subshell` is on the
  list of things that can be literal.
- **PHP interpolates a bare `$name` inside a double-quoted string**, with no wrapper node to recognise.
  A check that only knows `${…}` and `#{…}` reads `"select … $name"` as a written-out constant, which
  is the exact case the SQL rule exists for.

- **Kotlin's grammar gives an interpolated string no node at all.** `"select $n"` is three plain
  `string_content` children with the bare `$` standing alone as one of them, and that last part is the
  whole discriminator — measured, because the obvious alternatives are both wrong. Counting children
  reports `"cost \$5"`, where an escaped dollar leaves two of them either side of an `escape_sequence`.
  Without this, the most natural way to write a Kotlin query reads as a written-out constant.

Ruby's `load` is too common a method name to report on its own, so the receiver has to be one of the
classes that really deserialises. Breaking that check is what showed the test for it was passing for the
wrong reason: `config.load(path)` was being excluded by the query's own shape, because a lower-case
receiver is an `identifier` and the query asks for a `constant`. The receiver pattern could have been
deleted with every test still green. `Settings.load(path)` is the case that actually exercises it.

## The language's own tool

Four tree-sitter rules across four languages is a start, not a security review. Every ecosystem already
has a tool that knows its own traps, and the useful thing `sv` can do is run it and read the result
rather than re-implement a hundred rules badly in Rust. `data/adapters.json` describes bandit, gosec,
brakeman and semgrep; adding a fifth is a data change. `sv report --tools` runs the ones that suit the
app, opt-in for the same reason as `--run` and one more: one of them fetches its rules over the network
the first time it runs, and that is stated in the file rather than discovered from a firewall log.

Three decisions, each a way of not lying:

- **A tool that is not installed reports *not run*, with how to install it.** Never a clean pass. This
  is the whole reason the adapters are a data file with a gap attached rather than a shell script: a
  script that skips a missing binary produces a report identical to one where the tool ran and found
  nothing, and the second is the one everybody assumes.
- **SARIF and nothing else.** One output parser that is trusted is worth more than five that are nearly
  right. A tool that cannot emit SARIF is not listed yet rather than parsed by guesswork — which is why
  bandit's install line names two packages, since its SARIF formatter is a separate one.
- **Rule ids map to requirements one at a time.** Crediting everything a tool knows about to every run
  of it would make one clean bandit run look like an assessment of injection, secrets, weak hashing and
  debug mode at once. A finding whose rule id is not in the map carries no requirement, which is a fair
  thing to be and is shown as such.

Running it is what taught it the distinction it was missing. Semgrep is installed on the machine this
was written on and cannot start under the sandbox, and the first version reported it as *not installed*
and told the owner to install a tool they already had. `presence` now tells **missing** from **here and
will not start**, and prints what the tool said instead of an install line that would not help. The same
run showed adapter findings carrying absolute paths while `sv`'s own are relative: a report is something
an owner may send on, and the layout of their home directory is not part of what they meant to share.

Against a small Flask app with bandit and semgrep installed, `bandit.B608` lands on the same line as
`sv`'s own SQL rule — two independent tools agreeing, which is worth more than either alone — while
`bandit.B104` and a semgrep rule are reported carrying no requirement, because nothing has mapped them.

### A report from a run

`sv report --run` starts the app behind the same fence `sv run` uses and folds what it answered into the
report. Opt-in, not automatic: everything else `sv report` does reads files, and this starts somebody's
code. Both commands go through one `probe_the_running_app`, because two call sites each deciding when an
app is runnable would drift, and the one that drifts quietly is the report.

What changes when it runs is not only that findings appear. The standing gap — *the app was never
started* — is replaced by the probes' own list of what asking it could not reach: authorisation, session
handling, CSRF, anything that needs data sent into a form. An app that ran is not an app fully examined,
and the gap list has to say which of the two happened. The app's declared tests are recorded the same
way: failed means nothing can be concluded from them, passed means no credit is taken, because deciding
which requirements a passing test is evidence about is its own piece of work.

Running it found a fault in the report itself. The probes verified three requirements that are above the
fixture's target level, so every one of those positive claims fell outside the applicable table and
disappeared — the count read *0 checked* on a run where the probes had just checked three things, and a
reader would have concluded they never ran. Findings already had a section for this case; satisfied
checks did not. A vanishing positive claim is safer than a vanishing finding and still tells the reader
something untrue.

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

## Claims nothing can check

Every capability in `securevibe.toml` is a claim, and `data/claim-corroborators.json` says how each one
is checked against the code. Twenty-six claims have a corroborator. One does not, and that is written
down rather than left to look like a search that found nothing.

`shared-hostname` asks whether another application answers on the same address. That is a fact about
where the app is deployed: the same repository is one site on its own hostname in one deployment and one
of five behind a shared proxy in another, and the reverse-proxy configuration that would settle it is
almost never in the app's own repository. A signature that went looking would report "nothing found" on
every app, forever, which reads as a search rather than as a question nobody here can answer. So the
signature carries `noCorroborator` and a reason, `sv` reports it as *no check for this is possible*, and
a test refuses any such signature that also names things to look for.

The corroborators are checked three ways, because a corroborator that never matches anything fails
silently: every language and ecosystem key must be one the scanner actually dispatches on (a misspelled
key is simply skipped, leaving a dead rule that looks like an honest "not found"); every corroborator
must have a witness; and each witness is a file written the way somebody would really write it, not a
copy of the pattern out of the data file.

Writing those witnesses found a fault older than this work. Files with no extension — `Dockerfile`,
`Jenkinsfile`, `CODEOWNERS`, `Procfile` — were skipped by the walk *before* their path was recorded, so
no signature naming one could ever match. For `iac`, which is allowed to rule itself out by absence, that
turned "I did not look" into `Some(false)`: an app whose only infrastructure configuration was a
Dockerfile sitting beside its source was reported as having none at all.

## The container runner

`sv run ./app` starts the app behind a network fence and checks it answers. The fence design was
**measured rather than reasoned about**, and the measurement overturned the obvious translation of v1's.

v1 fences a child process with `sandbox-exec` or a network namespace and probes it over `127.0.0.1`. The
obvious container equivalent — publish a port to loopback, probe from the host — does not work:

| | `--internal` network | default bridge |
|---|---|---|
| sidecar on the same network reaches the app | yes | yes |
| app can reach `1.1.1.1:53` | **blocked** | succeeded |
| host reaches a published port | **no** | yes |

An `--internal` network is exactly the fence wanted, and is unreachable from the host whether or not a port is
published. Moving to a bridge to make host probing work removes the fence entirely. So the probes run from a
**sidecar container on the same internal network**, and nothing is published to this computer at all.

Two earlier attempts at that measurement proved nothing, which is the more useful half of the story. The first
used `alpine:3`, whose busybox has no `httpd` applet: every container exited immediately and dutifully reported
"outbound blocked" while not running. The second used `example.com`'s old address, decommissioned in 2024, which
made the *default bridge* look fenced too. The table above comes from a run with a live target and a host
baseline confirming this machine can reach the outside at all — without that line, "blocked" means nothing.

### What the probes ask, and what they cannot

Four requests, made from the sidecar over a plain socket rather than through an HTTP client. `wget` was
tried first and rejected for two reasons found by trying it: it returns no body at all for a 404 or a 500,
which is exactly the response the error-page probe has to read, and it cannot send a method other than GET
or POST, which rules out the TRACE question. `nc` returns the raw response whatever the status and whatever
the verb.

| question | what a wrong answer means |
|---|---|
| the health path, plain | missing `Content-Security-Policy`, `X-Content-Type-Options`, framing rule or `Referrer-Policy`; a cookie without `HttpOnly` or `SameSite` |
| the health path with an `Origin` that does not exist | the app echoing it back, or `*` — worse if credentials are allowed with it |
| a path that is not there | a stack trace naming the framework, its version and the file layout |
| `TRACE`, carrying a header this probe invented | that header coming back in the body |

**The probes sign in as nobody.** `sv` does not know how to log in to an app it did not write. So
authorisation, session handling, CSRF and anything that needs data sent into a form are **not assessed**,
and `unassessed_requirements()` names each one with the reason. The CLI prints that list *before* any
finding. A suite that quietly covers only the front door, and reports nothing, reads exactly like one that
found nothing wrong.

The request is built by `request_bytes`, which **refuses to send anything** whose method, path, header name
or header value carries a newline, rather than stripping it. The path is the app's own `health_path`, out
of its manifest, so it is not text `sv` wrote; a stripped path is a different request from the one asked
for, and a probe with no answer is already reported as unanswered. The finished request is base64-encoded
before it reaches the sidecar's shell, so nothing in a header value can end the command it travels in — a
scanner that can be made to run a shell command by the app it is scanning would be a poor advertisement.

### Verified against a real container

`tests/fixtures/probe-app` is a busybox CGI script that does two careless things on purpose: it sets
`session=abc` with neither `HttpOnly` nor `SameSite`, and it echoes back whatever `Origin` it is given,
with credentials. The second is what makes the end-to-end test a test of the *transport*: the fixture
only sends that header if the request really carried one, and it sends back the value it was given. On
24 September 2026 the run reported the cookie, the reflected origin and the missing headers, with the
fence verified as `--internal`.

Breaking the transport three ways confirms the test is what catches it, each at a different assertion:
`probe()` answering nothing, the header loop removed from `request_bytes`, and the response body
discarded in `parse_response` — all three go red.

Running the suite on more than one thread also found a real defect the single-threaded run had hidden:
the network and container names were the process id alone, so a second run in the same process asked
the daemon for a network that already existed and failed. A process that checks two apps, or rebuilds
one, hit it the same way. The names now carry a per-run counter, and a test runs the same app twice in
one process so that is checked deliberately rather than by how the tests happen to be invoked.

Two checks are **not** exercised end to end, and the test asserts they stay silent rather than guess:
busybox's own error page carries no stack trace, and busybox does not echo a `TRACE`. The `E404:`
directive that would have supplied a traceback is read from the config file and then ignored by this
build — asked directly in a throw-away container rather than reasoned about, which took two minutes and
settled it. Both checks are exercised against recorded answers in `sv-check`.

### Not trusting the flag

The runner asks the daemon whether the network really is internal before starting any untrusted code, and
refuses the run if the answer is anything but `true`. Passing `--internal` and verifying `--internal` are
different claims, and only the second survives a future edit that drops the flag.

Removing the flag was tried: the runner refuses to run at all and two tests fail. The failure mode is "refuses
to start" rather than "runs unfenced and reports a clean result", which is the fail-secure principle v1 lists
and the only acceptable direction for this particular mistake.

### Everything that cannot run is not assessed

No backend, no run command in the manifest, a backend that refuses, an app that never answers — every one
reports **not assessed**, never `pass` and never `fail`. A test enforces that each reason says so in those
words, because an app that will not start under `sv` has not been shown to be insecure. That test failed on its
first run against a message reading "could not be attempted", and the message was changed rather than the test.

The empty strings `sv init` prints (`image = ""`) are treated as unanswered, not as commands, so an AI tool that
leaves the placeholders produces "not assessed" rather than a container failing for reasons nobody can read.

## The conditions that decide nothing

Wiring up the corroborators produced a contradiction banner that announced the manifest was wrong about
`payments` — and then had nothing to report, because no applicability rule keys on `payments`. Checking properly
found **seven** such conditions, not two:

| condition | why it decides nothing |
|---|---|
| `payments`, `scheduler`, `public-api`, `internet` | asked in the manifest; no rule in ASVS 5.0, AISVS 1.0 or Appendix C keys on them |
| `level2` | redundant — the target level is applied by bucketing requirements, not by a rule |
| `no-auth` | derived from `auth`, and nothing currently uses it |
| `self-assessment` | v1's notion of checking itself, which has no meaning in `sv` |

The tempting fix is to write overlay rules so these gate something. That would be inventing ASVS scoping, which
is the same over-reach as the inherited reasons. They stay inert, and `sv` says so:

    Answered in securevibe.toml but gating nothing: public-api, payments, scheduler, internet.
    No requirement in ASVS 5.0, AISVS 1.0 or Appendix C turns on these, so answering them
    differently changes no result.

A test pins that exact set, so a future OWASP data update that gives one of them a rule — or quietly takes a
rule away from something else — has to be noticed by somebody.

### Where being wrong about payments does cost something

Not in the requirements, but one step along: an app taking money holds financial data, and the data categories
set the target level. v1's profile already says the equivalent about sign-in — `credentials` is described there
as "always present when sign-in is on". So `consistency::check` connects a claim that gates nothing to the
answer that gates a great deal:

    Worth checking in securevibe.toml:
      This app takes payments, but `financial` is not in its data categories. …
      This app has sign-in, but `credentials` is not in its data categories. …
      This app accepts file uploads, but `files` is not in its data categories. …

These are questions, not corrections: `sv` does not edit the manifest or quietly raise the level on the owner's
behalf. And each states its real consequence — an app already at level 2 is told that adding the category
changes no requirement, because saying otherwise would be the same small overstatement in a new place.

## `sv check`: the first findings

`sv check ./app` looks for credentials left in the code. It is the first part of `sv` that produces findings
rather than scope, which makes it the first part where being wrong costs an owner something directly.

Two kinds of rule, split on purpose. The **pattern** rules live in `data/secret-rules.json` — ported from
v1's `scanners/secrets/rules.ts`, with their ASVS, AISVS and SbD ids intact — because a well-known credential
format is data, and adding Azure or Twilio should be a data-file entry rather than a Rust change. The
**judgement** rules are Rust, because deciding whether a high-entropy string is a credential or a content
hash is not something a regex can do.

### What stops it being noise

A scanner people ignore is worse than no scanner, so three things are load-bearing:

* **A placeholder is not a secret.** `your-api-key-here`, `changeme`, `${SESSION_SECRET}`, `<your token>` are
  what a template looks like. An owner whose first run shouts at `.env.example` learns on day one that the
  findings are noise. There is a test that runs a whole realistic example file and requires silence.
* **`.env` is meant to hold real credentials**, so the judgement rules do not run there. The pattern rules
  still do, because a vendor key is exactly what matters if that file turns out to be committed.
* **One secret is one finding.** A vendor key assigned to a well-named variable matches both the vendor rule
  and the generic assignment rule; the vendor rule wins, because it can say what the credential is and how to
  revoke it. This showed up on the first real run, reporting the same Stripe key twice.

### Two things it refuses to do

**A secret never travels in a finding.** `Secret` cannot be built with the value visible — it redacts on
construction and there is no accessor that gives the original back, so a report, a log or a SARIF file
cannot carry the credential onward. Removing the redaction fails five tests.

**Nothing unread is counted as clean.** Files that are binary, too large, or unreadable are listed with the
reason, and `sv check` prints that list *before* the findings, because a short list of findings under a long
list of skipped files is a different result from a short list of findings. Where nothing is found at all it
says so in as many words: these rules know a list of formats and one heuristic, and a credential in a shape
nobody listed would not be found.

### What it looked like on a planted key

    Read 5 files looking for credentials, against 8 known formats plus the assignment rule.

    1 file was not read, so nothing is claimed about it:
      src/logo.png — not a text file

    2 things to look at:

      [critical] Stripe key found in a file
         src/config.py:5
         found: sk_l… (32 more characters)
         evidence about: V13.3.1, AC-05, AC-06

### Configuration checks, and the one that matters most

v1 has nineteen configuration checks and most are about its own template: whether `package.json` was
modified, whether the session policy matches the profile, how many proxy hops to trust. None of that means
anything for an app somebody else wrote. What survives being language-agnostic is small, and one of it is
worth more than everything in the secrets scanner:

**A credential in a file is a problem. A credential in version control is a different problem.** History
keeps it after the file is fixed, and every clone, fork and backup already has a copy. `sv check` can find
a key in `.env`; only git can say whether `.env` was ever committed — so it asks, and the finding's fix
leads with *change the credential*, because that is the part that actually protects anybody.

Three checks so far: a secrets file in version control (critical), nothing in `.gitignore` stopping one
getting there (high), and no way to report a security problem (low).

### A check reports one of three things

Passed, failed, or **not assessed** — never two, and never the third folded into the first. A folder that
is not a git repository is the ordinary case for an app somebody handed over, not an error, and answering
"no committed secrets" there would be a claim about history nobody read. `sv check` prints what could not
be checked *before* what was found, for the same reason the secrets scanner prints skipped files first.

Both ways the question can go unanswered have their own test — a missing `.git`, and a `.git` that git
refuses to read — because they are different code paths and the first one alone left the second untested.

### The lockfile check, and the wrong statement it was one call away from

`sv-scan::ecosystems::unpinned` already worked out which ecosystems have no lockfile, so reporting it
looked like wiring. It was not. Maven has no lockfile to be missing — versions live in `pom.xml` — so
`unpinned` returned "Java (Maven)" for every Maven project, and a check that asked "is there a lockfile?"
would have told every Java owner their app pins nothing.

That is not a coverage gap, which is honest and visible. It is a wrong statement in a report, and an owner
acting on it would go looking for a lockfile Maven does not have. The same shape as telling a Flask app it
was missing `package-lock.json`, which is the incident ADR-012 was written for.

So `DetectedEcosystem` now carries `pins_with_lockfile`, `unpinned` only returns ecosystems that pin with
one, and Maven comes back **not assessed** with a reason: versions live in the manifest and `sv` does not
read ranges out of it yet. Removing that distinction fails two tests — one that Maven produces no finding,
and one that it does not silently pass either, because not reporting something must not mean approving it.

## The bill of materials

`sv sbom ./app` writes CycloneDX 1.5 JSON to standard output and everything else to standard error, so
`sv sbom ./app > sbom.cdx.json` gives a clean file and still tells the person what it is worth.

An SBOM is worth exactly the completeness of its list. The whole reason to hand one to somebody is that
they can ask "is the compromised version of that library in here?" and trust the answer, so a partial one
is more dangerous than none. Two things follow, and both are recorded on the document rather than only in
the terminal — a caveat that stays behind in a terminal is not a caveat.

**A range is not a version.** A lockfile says what is installed; a manifest says what was asked for, and
`^4.18.0` is a different thing on a different day and a different machine. Components read from a manifest
are marked `declared`, the count appears in `metadata.properties`, and `flask>=2.0` produces no component
at all — listing it as though the range were a version is the failure this module is arranged around.

**An ecosystem that could not be read is named.** `poetry.lock` is a format `sv` cannot parse yet, so it
appears in the document as an unread ecosystem rather than being silently dropped. An SBOM that quietly
omits a whole ecosystem reads exactly like one that had nothing to omit.

Lockfile readers so far: `package-lock.json` (v1 and v2/v3 shapes), `Cargo.lock`, `composer.lock`,
`Gemfile.lock`, `go.sum` and exact `==` pins in requirements files. `Gemfile.lock` indentation matters —
specs are indented four spaces and their own dependencies six, and reading both would invent packages the
app does not ship.

Where the list is not complete, `sv check` says so as a medium finding, because the gap is the point: asked
whether a compromised library is in this app, nobody could answer from an incomplete document.

## Matching the list against advisories

`sv audit ./app --advisories ./osv` compares what the app ships with a local OSV database.

### `sv` does not fetch anything

A deliberate decision rather than an unfinished one, for three reasons. **Checking code is not a reason to
phone home**: the list of packages an app depends on is business-confidential, and sending it to a service
to be checked is a disclosure the owner did not ask for — v1 fences generated code to loopback on the same
argument. **A fetch is a dependency on somebody else's uptime**, and a check that silently degrades when a
service is slow is a check that reports a clean result on a bad day. And **`sv` runs where there may be no
network at all** — an air-gapped review, a CI runner with egress rules, a laptop on a train.

So getting the data is the owner's step, done deliberately and visible in their shell history.

### No data is not a clean result

With no database, `audit` reports **not assessed** and says what to do about it. It never prints "no known
vulnerabilities", because that sentence is equally true of an empty directory, a stale one and a healthy
app, and only one of those is good news. The same holds per-ecosystem: a database of npm advisories says
nothing whatever about the Python packages beside them, so those are named as unchecked rather than
counted as clean.

### Three things the comparison has to get right

* **The fixed version is not affected.** An off-by-one here reports every upgraded app as vulnerable,
  which is the fastest way to teach somebody to ignore the check. Ignoring the `fixed` event fails three
  tests.
* **A pre-release comes before its release.** `4.17.20-beta` does not contain the fix that landed in
  `4.17.20`. Treating them as equal reports a genuinely vulnerable install as clean — a false negative,
  and the worst mistake this file can make. My first version did exactly that, by dropping the
  pre-release when parsing; the unit test caught it and an end-to-end test now catches it too.
* **Same name, different ecosystem, different package.** `lodash` on PyPI is not `lodash` on npm, and
  matching on the name alone invents vulnerabilities.

A version that cannot be compared with any range — a Go commit pseudo-version against a `GIT` range, a
build tag — is listed as uncomparable rather than quietly passed.

### pnpm, and a dependency not taken

`pnpm-lock.yaml` is the last common lockfile, and it is YAML. The obvious move is a YAML crate; the
established serde one has been archived since 2024, and putting an unmaintained parser into a tool whose
subject is supply-chain hygiene is a poor trade for one file format.

The only YAML actually needed is the set of keys directly under `packages:`, so that is what is read and
nothing else is guessed at. Both key shapes are handled — `express@4.18.2` and `/express/4.18.2` — and
scoped names keep their scope, because the version is what follows the *last* separator. A peer variant
like `vite@5.0.0(terser@5.0.0)` is one package and the peer is not a second one, and `snapshots:` repeats
every key from `packages:`, so reading both blocks would double the list.

A file this reader does not understand produces no packages, and the caller turns that into "read, and no
packages could be taken from it". That guard is what makes hand-parsing acceptable: an empty list is
otherwise indistinguishable from an app with no dependencies, which is the one wrong answer available.

**It also closed a hole that had nothing to do with pnpm.** Any reader returning an empty list left the
ecosystem present and the document silent about it — `package-lock.json` holding `{"lockfileVersion":3}`
and nothing else produced a bill of materials with no components and no caveat. That is now reported, and
breaking it fails three tests.

Worth recording how it got to one guard: the first version had two, one inside the pnpm reader and one in
the caller. Deleting the inner one failed no test at all, because the outer one already covered it — a
guard that survives being deleted. It went, and the remaining one is asserted by the message it produces
rather than by the fact that something was reported.

### Severity from the advisory, not from a guess

`sv audit` used to decide seriousness by looking for the word CRITICAL and for a substring of a v3.1
vector, and calling everything else medium. That is not a severity, it is a placeholder wearing one's
clothes — and a placeholder reading "medium" is believed by anyone sorting a list by how bad things are.

The vector is now parsed and the base score computed to the specification, so a finding says what the
advisory says:

    [medium] lodash 4.17.15 has a known vulnerability: GHSA-p6mc-m468-83gg (CVE-2020-8203)
       Prototype pollution in lodash. The advisory rates this 5.9 out of 10, which is medium.

Two deliberate limits. **v3.0 and v3.1 only**, because they share the base formula and v2 and v4 do not —
scoring a v4 vector with the v3 formula produces a confident number that is wrong. **Base metrics only**,
because temporal and environmental metrics describe somebody's particular deployment, which is not
something `sv` knows; a vector carrying them is scored on its base and the extras ignored rather than
refused.

Where no vector can be read, the finding says the seriousness shown is a placeholder rather than the
advisory's own rating. A genuinely low-rated advisory and an unrated one used to look identical; they are
different facts.

#### A guard with no test, and why it keeps its place

The specification defines its own rounding in integer arithmetic, because `(x * 10).ceil() / 10` can
disagree with a published score when a value lands exactly on a tenth. Replacing it with the naive
version failed no test — so the question was whether it earns its place.

Every one of the 2,592 base-metric combinations was checked, and **none distinguishes the two**. That is
why no test can catch the substitution, and the equivalence is now recorded in a test of its own so the
next reader finds the answer rather than the puzzle. The specification's version stays: it is what the
specification says, and temporal scoring — if this ever grows it — produces intermediate values the
equivalence does not cover.

## Rules that read the code

Everything else in `sv-check` works on text. That is right for credentials, where the thing being looked
for *is* a string, and wrong for "is this SQL built by pasting a variable into it" — a regex either
misses the case split over two lines or fires on the word `execute` inside a comment. Both are in the
tests, because both are what a text rule gets wrong.

tree-sitter was taken as a dependency where a YAML crate was not, on the argument that decides these:
there is no honest hand-rolled alternative to a parser, it is actively maintained, and four grammars
build in about four seconds. Python, JavaScript, TypeScript and Go today; Ruby, PHP and Java are named as
unread rather than silently producing nothing.

Four rules so far: code built and executed at run time, a shell command assembled from a value, a
database query joined together from pieces, and data from outside deserialised with a reader that builds
objects. Each is a tree-sitter query per language in `data/ast-rules.json`, so teaching one about Ruby is
a data entry.

### What a query cannot decide

Whether the argument is a literal. `eval("1 + 1")` cannot be made to run anything its author did not
write, and reporting it beside `eval(request.args["code"])` at the same seriousness is how a rule teaches
people to skip its findings. That judgement is Rust, where it is tested — the same split as the secrets
scanner, patterns as data and meaning as code.

It is subtler than it looks. A template string is a literal only when nothing is interpolated, and a
Python f-string is still a plain `string` node in its grammar — so `f"… WHERE id = {user_id}"` looked
like a constant, and the SQL rule reported nothing for the case it exists for. The check now asks whether
anything is substituted in, at any depth, whatever the grammar calls it. Breaking that fails four tests.

### A predicate that parses and does nothing

Every rule was first written with tree-sitter's own `(#match? @fn "^eval$")` predicates. **The Rust
binding parses them and does not apply them**, so every rule matched every call in the file — the
deserialization rule fired on `os.system`, the shell rule on `eval`. Nothing about the queries looked
wrong, and the only reason it surfaced is that the tests assert what must *not* be reported as well as
what must.

Name matching moved into Rust, per language, because the dangerous names differ — `eval`, `exec` and
`compile` in Python against `eval` and `Function` in JavaScript, which one shared pattern would get
wrong. And a query containing `#match?` is now **refused at load**, with a test that feeds one in and
expects the refusal, because a guard against a mistake nobody is currently making has no witness
otherwise.
