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

## Signing in (25 September 2026)

The probes signed in as nobody, so authorization and sessions were always *not assessed*. v1 knew how
to sign in because it wrote the app; `sv` is told, in `[stack.run.users]`, by the same manifest that
already says how to start the app, and makes its own accounts with passwords made for the run.

The rule every check follows is the one from this project's `CLAUDE.md` about tests whose setup can fail
quietly. B being refused A's note proves nothing if A was refused it too; a session surviving sign-out
proves nothing if the sign-out was refused. So each check shows what it relies on first. That rule was
tested against the real example app and caught the suite itself: the example's `/logout` has no page to
take an anti-forgery token from, the sign-out went without one, the app correctly refused it, and the
first run reported "signing out does not end the session". A sign-out that did not happen is now not
assessed, and the token is looked for on the user's other pages, as a sign-out button's would be.

### Level 1, asked of the running app

The coverage count showed 49 of the 70 Level 1 requirements with no check at all, and Authentication
with none. Eight of them can be asked of a running app with what `[stack.run.users]` already says, and
now are, which takes Level 1 from 21 to 29.

Two need no account: a Content-Type on responses with a body, with a charset on text (V4.1.1), and
`/.git/HEAD` and `/.git/config` not served (V13.4.1). The Content-Type check is credited only when both
the page and the error answer had a body; an app whose error is a redirect has shown one answer, and
one answer does not stand for its responses. The `.git` check needs git's own contents in the answer,
so a single-page app answering every path with its page is not mistaken for one serving its history.

The password rules are asked through `signup` and answered by signing in, because how an app words a
refusal is its own business and a sign-in is not. A control goes first: an ordinary strong password,
32 characters of every kind. If that account cannot sign in, nothing is asked. Each password after it
differs from the control in one thing, so a refusal is about that thing: 7 characters (V6.2.1), lowercase
letters alone (V6.2.5), and a password from the 3000 most common (V6.2.4) beside a random one of the same
length and kinds of character, because an app that wants a capital refuses the common one for that and
not for being common. That case is not assessed, rather than credited. `signup` works beside `seed`, so
an app can have its admin made by `seed` and still have its passwords asked.

Three can only ever find something. Four default accounts that do not sign in are four, not none
(V6.3.2). A password refused in the address shows one address refuses it (V14.2.1). And a session id
can be shown too short to hold 128 bits, or the same at two sign-ins, but its value never shows it came
from a secure generator (V7.2.3): the length measure is an upper bound, and a run of one letter passes
it. A clean answer to any of the three is credited with nothing.

Run against `examples/notes-with-users`, which gained a sign-up page that refuses short and common
passwords and nothing else: 14 checks confirmed where there were 10, nothing found, in 11 seconds
rather than 4, most of the difference being the app's own password hashing. Three copies with faults
switched on found every one: a short password, a common one, `admin`/`admin`, a password in the address
and an 8-character session id in the first; a rule wanting a capital and a digit in the second, with
V6.2.4 not assessed beside it as intended; a served `/.git/HEAD` and text without a charset in the
third.

### Tests to write

The coverage count said 290 ASVS requirements have no check in `sv`, and that the one route to evidence
for every requirement is the app's own passing test naming it. Nothing turned that into something to act
on: a requirement nobody had written a test for read exactly like one whose test did not run.

The report now has a section, "Tests to write": every applicable requirement with no evidence of any
kind and no test in the app naming it, lowest level first, ASVS before AISVS. The test files are read
whether or not the tests ran, so a requirement named in a test that did not run here is listed apart,
as named and not credited, rather than as a test to write. `sv mcp` gives the AI coding tool the same
list, the first 30 lines of it, because the tool is the one that writes the tests; `sv init` tells it to
work down the list, fixing what the app does not yet meet before writing the test that shows it.

What a test of the application cannot show is left out and counted: a requirement classed as
documentation or a deployment setting, design review, the AISVS appendix on the development process,
and any whose own words ask for documentation. Leaving something off a to-do list credits nothing, so
this can err only towards a shorter list. On `examples/tested-notes`: 71 tests to write, 18 at level 1,
and 84 left out with the reason.

## Handover

`sv check ./my-app` is the primitive: any tool, any editor, CI. An MCP server wrapping the same core comes
second, so an AI coding tool can run the checks mid-conversation and work the findings without the user leaving
the chat. The CLI is what makes it tool-agnostic; MCP is what makes the loop tight.


### As built (25 September 2026)

`sv mcp` is a module of the CLI rather than a crate of its own, because what it serves is the CLI's
report: `assemble_report` was pulled out of `sv report` so both call one function, and a model is told
exactly what a person reads — not a second summary that drifts. It speaks JSON-RPC over stdio with no SDK;
the surface it needs is four methods. It reads only below the folder it was started for, resolving `..`
and symbolic links before checking, because a model can be talked into asking for `~/.ssh` by text it
read somewhere. It does not offer `--run` or `--tools`: both run code, and a model deciding to run code in
a loop is exactly the decision that should stay with a person. The tool result lists what was not
examined before any finding, for the reason every report here does.
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

## Thirteen languages, and why the fourteenth silences everything

The rules that read code have grammars for Python, JavaScript, TypeScript, Go, Ruby, PHP, Java, C#,
Kotlin, Rust, C, Dart and Swift. Each one is worth more than one more entry suggests, because of how the fail-closed
rule works: **no rule may speak while a language present in the app goes unparsed.** One Ruby file used
to silence every rule for the whole app — correct behaviour on an app `sv` could not read, and a lot of
silence. Every language added is one fewer kind of app that gets nothing.

### A page of markup is not a hole in the coverage

`html` covers `.html`, `.vue` and `.svelte`, and almost every web application has at least one. Counting
every page as unread therefore silenced every rule for nearly every real app — a great deal of silence
bought by a file that in most cases hides nothing at all. So the script is taken out of the page and
read as what it is. `<script>` elements go to the JavaScript grammar — or TypeScript, when the page
says `lang="ts"` — and so do `on…=` handler attributes and `javascript:` URLs, whose values are
statements that parse on their own once their HTML entities and percent escapes are put back. A
`<script src="app.js">` with nothing between its tags holds no code at all: the file it names is
parsed like any other.

A `javascript:` URL is read only from a quoted attribute, where its end is not in doubt. An unquoted
value ends at whitespace by one reading and at the tag by another, and guessing between them is how a
fragment ends up half a statement — so those are named rather than read. So is a scheme written around
a control character: a browser runs `java<tab>script:`, this does not read it, and every occurrence of
the scheme is counted against what was taken so one written that way cannot slip past as ordinary text.

A finding in a page names the line **in the page**. The fragment's offset is added back before the
finding is written, because a reader sent to line 3 of something they cannot see is worse off than one
given nothing.

**Anything taken out has to parse.** Tree-sitter always returns a tree, so a fragment of something
that is not JavaScript comes back as a wreck that matches no rule and reports nothing — which reads
exactly like a fragment that was clean. A page whose fragments do not parse is left unread. That catches
less than it looks like it does, and the reason is worth knowing: the JavaScript grammar includes JSX,
so a Vue or React template parses cleanly and reaches the rules as markup. Handlebars, ERB and Jinja do
not. Both halves of that were measured, not assumed.

One function decides both what a page holds and what comes out of it. When "does this page hold code"
and "what code does this page hold" are answered by two pieces of code they drift, and the direction
they drift in is a page declared read whose code nobody extracted. So `html_fragments` returns the
fragments *and* whatever it could not take — an unclosed `<script`, a `javascript:` URL — and while
anything was left behind the page is still unread and every rule stays silent about the whole app. A
page that cannot be opened at all counts as left behind too.

The terminal's wording followed the behaviour twice: it said *there is no grammar for html* when every
page was unread, then *a page with a script written into it* when only those were, and now says what is
actually true — that something in the page could not be taken out of it.

### A language that was read is not a language every rule looked in

A rule with no query for a language says nothing about it. That used to be the whole of it, and it left
a hole: in an app of Python and Rust, the shell-command rule read the Python, found nothing, and claimed
V1.2.5 for the app, with the Rust beside it never looked at by that rule. The parser having read a file
is not the same as each rule having looked in it.

So every rule now accounts for every language `sv` reads, one of two ways: a query, or an entry in
`nothingToFind` saying why the language has nothing for that rule to find. Go has no `eval`; Dart's
decoders give back maps and lists; backticks in Swift quote a name. Each entry carries its reason, and a
language cannot have both. A rule that met a language with neither claims nothing for the app, and the
report says which rule and which language (`AstScan::untaught`), rather than letting the line go
missing. The claim itself still names only the languages the rule has a query for, so an entry in
`nothingToFind` can let a claim through but never widens one.

Adding the rule turned up the gaps it was built to show, and most were filled in the same change:
Kotlin and C# `eval`, JavaScript's `unserialize`, PHP's backticks, Go's `exec.Command("sh", "-c", …)`,
file paths in Kotlin, Rust and C, weak hashes in Rust and C, weak ciphers in C, and redirects in Kotlin
and Rust. The last three followed: shell commands in Rust, weak ciphers in Rust, and redirects in C.
Every rule is now taught every language `sv` reads, and a test pins it, so a grammar added without its
queries shows up there before it shows up as a gap in someone's report. The tests of the mechanism
itself use a small rule file written for them, since the real rules no longer produce the case.

What those three look for, and what they miss:

- **Rust's shell command is a method chain.** `Command::new("sh").arg("-c").arg(cmd)` is three calls,
  each the receiver of the next, so the query follows the chain back two links to the `new` whose
  argument is a shell. `.args(["-c", cmd])` is the same thing written as an array, which is literal when
  every element is. A `Command` built in one statement and given its arguments in another is not
  followed, and neither is a shell named by a variable. `Command::new(exe)` with a value is reported
  whatever the arguments.
- **Rust's weak ciphers are types.** RustCrypto names them (`TdesEde3::new_from_slice`,
  `ecb::Encryptor::<Aes128>::new`) and the `openssl` crate has a function per cipher
  (`Cipher::des_ede3_cbc()`, `Cipher::aes_128_ecb()`). Both are a call on a path, and the path says
  which. A cipher type imported under another name is not seen.
- **C's redirect is a header printed by hand.** A CGI program writes `Location: …` to standard output,
  so the query is `printf`, `fprintf`, `sprintf` or `dprintf` whose format string begins with
  `Location:` and has a value after it. A header built with `strcat` first, or written with `puts`, is
  not seen.

### Dart and Swift

Both used to be read by nothing, which silenced every code rule for any app with a Flutter front end or
an iOS client, back end included. Now each of the nine rules has a query for both or a reason there is
nothing to find. What they needed that the others did not:

- **A shell command is a list.** Neither language has a `system` in common use; Dart writes
  `Process.run('sh', ['-c', cmd])` and Swift `task.arguments = ["-c", cmd]`. A list literal is literal
  when every element in it is, so `['-c', 'ls -la']` is left alone. Dart's `<String>[…]` puts a type in
  the list, which is not an element and is skipped. The Swift query takes the list when its first element
  is `"-c"`, so `["log", name]`, an argument rather than a command, is not reported.
- **Swift's arguments are labeled, and the label matters.** GRDB's `db.execute(literal: "… \(n)")`
  binds what it interpolates, while `db.execute(sql: q)` runs `q` as written. So the Swift queries capture
  the whole argument, label included; the literal check looks at the value inside it, and a pattern can
  read the label: `literal:` is safe, and a file-path call is reported only with a path label
  (`atPath:`, `contentsOfFile:`), so `String(describing: n)` is not.
- **Swift interpolation is `\(x)`**, an `interpolated_expression` node, including inside a raw string
  written `#"…\#(x)"#`. Dart's `$x` and `${x}` are `template_substitution`, which JavaScript already had.
- **Concatenation is an `additive_expression`** in both, and `'a' + 'b'` is as fixed as its parts.

The code rules reading Dart and Swift does not mean the technology scan does. That scan reads no
`pubspec.yaml` or `Package.swift` and has no patterns for either language, so a GraphQL server in Dart
would go unseen and be called absent. Their files still count as not looked in there
(`NO_TECHNOLOGY_READER`), and no technology is called absent on their account.

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

### Shell scripts

AI coding tools put a deploy or setup script in most repositories, and until 25 September 2026 `sv`
did not count `.sh` at all: not read, and not listed as unread either. Now `.sh` and `.bash` are read with
the Bash grammar, as the language `shell`, and every rule is taught it or says why there is nothing to
find. A shell script is not an application, so most of what the rules look for looks different in one:

- **Code and commands.** `eval "$x"` is the code-execution rule's and `sh -c "… $x"` is the
  shell-command rule's. `eval "$(ssh-agent -s)"` is the idiom every setup guide prints, running the
  output of a fixed program, and is named as safe. Single quotes expand nothing, so `sh -c '…'` is a
  literal whatever it holds, and a double-quoted string is literal unless something is expanded in it.
- **A download piped into a shell** is a rule of its own, `ast.download-piped-to-shell`, citing V15.2.4
  (third-party components included from the expected repository). `curl … | sh`, `wget -qO- … | sudo
  bash`, and `bash <(curl …)` run whatever the address serves, unchecked. `curl … | sudo tee` writes a
  file and is not reported, and neither is the download-check-run form the rule's fix describes.
  `sh -c "$(curl …)"` is found by the shell-command rule instead. Every other language has no pipe
  syntax, and says so; a literal `curl … | sh` written inside a Python string and handed to a shell is
  found by neither rule, because the shell-command rule only reports commands built from a value.
- **SQL, hashes, and ciphers** are the command-line tools: `psql -c`, `mysql -e`, `sqlite3 app.db`,
  `md5sum`, `openssl dgst -sha1`, `openssl enc -des3`.
- **Paths and redirects only for CGI.** In a deploy script `cat "$FILE"` is the whole point, and a
  path-from-a-value rule would report every line. What V5.3.2 and V3.7.2 are about in shell is a CGI
  script, so those two look only at the request variables the web server sets (`QUERY_STRING`,
  `PATH_INFO`, `REQUEST_URI`, `HTTP_*`), written into a path or a `Location:` header. A request value
  copied into another variable first is not followed.

Two things stay out on purpose. Unquoted variables are the commonest shell bug, but they are word
splitting rather than an ASVS requirement, and ShellCheck already finds them; it cannot write SARIF, so
it cannot be an adapter under the rule that adapters speak SARIF only. And the technology scan does not
treat shell as a language it failed to look in, as it does Dart and Swift: before the grammar a `.sh`
file was invisible to it, and listing shell would take every "this app does not use X" answer away from
any app with a deploy script. The price is that a technology written only in shell, a CGI app in Bash
using XML, say, is called absent.

A shell file whose parse holds an error silences every rule's claim for the app, the same as any other
language. The Bash grammar reads Bash; a `.sh` file written in zsh's own syntax may not parse, and the
report then names it.

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
`tools/semgrep_rule_map.py` from a checkout of `semgrep/semgrep-rules`, and the judgement went into
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
  `--config-file /dev/null` does not stop Brakeman reading the file.

Where a tool can be made to look anyway, it is: bandit runs with `--ignore-nosec` and `--ini /dev/null`,
gosec with `-track-suppressions`. What any tool reports as suppressed is shown as a finding, and says it
was marked to be ignored and where, since a finding somebody chose to hide is still a finding until
somebody has looked at why. That is the owner's decision to make with the finding in front of them, not
one `sv` makes for them by agreeing to look away. What is left, a clean run whose report still counts
skipped lines or an app with a Brakeman settings file (`switched_off_by` in `adapters.json`), is not
credited, and the report says why in the gaps.

The same measurement turned up a neighbour that is not fixed here: semgrep, by default, skips files
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

### Three more wrong citations, in the place the guard could not see

The citation guard reads `adapters.json` and `ast-rules.json`. Citations hard-coded in Rust were
guarded by nothing, and there were three of them, all pointing at **V1.3.5** — *sanitizing
user-supplied scriptable or expression template language content, such as Markdown, CSS or XSL
stylesheets*:

| check | cited | should be |
| --- | --- | --- |
| the bill of materials is incomplete | V1.3.5 | V15.1.2, an inventory catalogue of third-party libraries |
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
neighbouring requirements that share vocabulary — `V1.2.4` cited where `V1.2.7` belongs would pass, both
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

### A report from a run

`sv report --run` starts the app behind the same fence `sv run` uses and folds what it answered into the
report. Opt-in, not automatic: everything else `sv report` does reads files, and this starts somebody's
code. Both commands go through one `probe_the_running_app`, because two call sites each deciding when an
app is runnable would drift, and the one that drifts quietly is the report.

What changes when it runs is not only that findings appear. The standing gap — *the app was never
started* — is replaced by the probes' own list of what asking it could not reach: authorisation, session
handling, CSRF, anything that needs data sent into a form. An app that ran is not an app fully examined,
and the gap list has to say which of the two happened. The app's declared tests are folded in the same
way, under the rule below.

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
  belt-and-braces and is labelled as such in the code: an empty database covers no ecosystem, so the
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

### One sidecar per run, not one per request

The sidecar used to be a new container for every request: `docker run --rm` into the fence, one
request, gone. That is simple and each request is clean, and it cost about half a second a request.
The anonymous probes are four requests, so nobody noticed. The signed-in checks are twenty-odd, made
one after another because each depends on the cookies the last one returned, and a run of
`examples/notes-with-users` took 11 to 13 seconds on the machine that measured it, 22 on a busy one, and
by an earlier estimate about a minute on a slow one. Logging every Docker call showed where the time
went: 26 throwaway containers were 13 of those seconds, and nothing else was more than a quarter of one.

Now the sidecar is started once, just before the health check, and every request is an `exec` into it:
0.11 seconds against 0.48 measured side by side. It is removed as soon as the last request is made,
before the tests run, and by the teardown whatever happens. It has nothing to write and nothing to be
allowed, so it is given neither: a read-only file system, no capabilities, no way to gain privileges.
It runs `sleep` with `--rm` and a 15-minute limit, so a run that dies without its teardown leaves
nothing behind for longer than that. If it cannot be started, each request starts its own container
as before: slower, the same answers.

The same run, three times each way: 11 to 13 seconds before, 4.3 after, the same ten checks confirmed,
and a text-identical report. A copy of the example with five flaws switched on had all five found in 4.2
seconds, and no container or network was left behind by any of it.

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

## The checklist that was named and never loaded

`sv --help` said it checked against OWASP Secure by Design from the first commit. `Frameworks::load`
read ASVS, AISVS and Appendix C. The checklist contributed nothing at all, and the README carried the
admission in a footnote — which is worse than silence, because it shows somebody knew.

It is a third schema, `checklistDomains` → `controls`, with a `statement` and no level, and loading it
needed two decisions that are choices rather than readings.

**The ids are namespaced `SBD-`.** The checklist numbers its own controls `AC-01` … `AC-07`. AISVS
Appendix C already owns `AC.1.1` … `AC.13.4`. Those are different strings and would never collide in a
map — they collide in a reader's head, which is the failure that matters. This codebase has already
shipped five checkers citing `AC-05` for a family written `AC.5`, and a citation that resolves to the
*wrong framework* is worse than one that resolves to nothing, because nothing about it looks wrong. So
the checklist's controls are `SBD-AC-01` here and the prefix is printed everywhere they appear. The
guard is `no_two_requirement_ids_differ_only_by_how_they_are_punctuated`: it flattens every id anything
can be addressed by to its segments, drops separators and leading zeros, and fails if two distinct ids
come out the same. `AC-05` and `AC.5` both flatten to `AC|5`.

That guard was written comparing requirement ids alone, and in that form it did not work. `AC.5` is a
*family* — a chapter — and not a requirement at all, so the set it compared did not contain the very id
the original mistake cited, while the test passed and looked like it covered it. Removing the `SBD-`
namespace is what exposed it: four tests went red and this one did not. Applicability rules scope to
chapters and sections as well as requirements, so the comparison now covers every addressable id, and
asserts that `AC.5` is in the set before comparing anything.

**Levels are derived, because the checklist has none.** It has `critical` and `severityIfNo`. Critical
or high severity is level 1, medium is level 2, low is level 3. That is this tool's mapping and not
OWASP's, so it lives in one named function rather than three comparisons spread around.

Fifteen of the thirty-six controls are about the space between services — trust zones, service
discovery, contracts between services, sagas, circuit breakers, a bus kept highly available. On a single
service they are not passed, they are *meaningless*, and nothing the manifest already asked came close
to deciding it. So `multiple-services` is a new claim. Unanswered leaves those controls not-assessed,
which is the honest default and the one the engine already had. Two more are gated on `internet`, which
until now was a condition that decided nothing at all — the test pinning that list is what noticed.

**Corrected on 25 September 2026: "one service" was too narrow a question for five of them.** A
single app still needs a circuit breaker in front of the outside APIs it calls (RR-02), handlers that
are safe to run twice when a payment provider retries its webhooks (DM-03), and durable messaging with
defined semantics when it runs a job queue (AS-06, RR-03). "Starting up when a dependency is missing"
(AS-07) applies to anything with a database, so it lost its gate altogether and fourteen controls are
now gated on `multiple-services`. And `tls = off` had been enough on its own to exclude "all
communications use TLS" (AC-01), which excluded it for exactly the app it is most about: one on the
internet without HTTPS. Each now carries a second rule at the same scope — `external-apis`, `payments`,
`scheduler`, `internet` — and rules at one scope are OR-ed, so any one of them keeps the control. The
reasons were rewritten to name both answers, because an exclusion that says only "this runs as one
service" tells its reader half of why. It also took `payments` and `scheduler` off the list of
questions that decide nothing.

**Levels, grounded in ASVS (25 September 2026).** The derived levels above were `sv`'s own, and the
report called the controls they excluded "above the ASVS level this app targets", putting ASVS's name on
a number ASVS never gave. `data/sbd-asvs-crosswalk.json` now ties each control to the ASVS requirements
that ask the same thing, and a control's level is the lower of its derived one and its counterparts'.
Lower only, so the crosswalk cannot hide a control; and a control with no counterpart — the architecture
controls and the incident response plan — is shown at every level, because keeping it out would rest on
the derived number alone. The checklist's statements are too terse for the citation guard to compare
directly (`TLS` is shorter than its shortest word), so each pair carries a few words naming what the two
ask in common, and the guard requires them to share vocabulary with both texts, which is a stricter test
than either side alone.

### Applicable, unverified, and unverifiable are three different things

Loading the checklist could easily have made the reports worse. Its controls are applicable and every
single one is unverified — which is also true of a great many ASVS requirements, and the difference
between the two matters enormously. An ASVS requirement that nothing checked could in principle be
reached by some future check. A Secure by Design control cannot be reached by any check, ever: it asks
whether trust zones are enforced, whether an incident response plan is rehearsed, whether data has named
owners. Counted together, a reader sees one number and concludes the scanner tried and came up short.

`VerificationClass::ManualOnly` already existed and nothing read it. Now every `SBD-` id is manual-only
by construction rather than by a list somebody has to remember to extend, and `sv report` carries a gap
reading *31 requirements that are design review, not scanning*. That count is the checklist's fifteen
plus the sixteen requirements on the existing `manualOnly` list — ASVS and AISVS both — that apply to
this app, out of twenty-six listed overall. Those sixteen had been marked manual-only for as long as the
list has existed and no report had ever said so.

On `examples/tested-notes`: fifteen controls applicable, seven not-assessed because nobody answered
`multiple-services`, and fourteen above the app's target level.

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

### Saying what a clean result looked for

A clean result used to say only what was read: "1 shell file". Beside the path rule, that reads as "the
shell scripts were checked for path traversal", when in shell the rule looks only at commands such as
`cat` or `rm` given a web request variable, which is right for a CGI script and says nothing about a path
built from any other variable. Found by the other session in review, 25 September 2026, and true of every
rule in some language.

So each rule says in plain words what it looks for (`looksFor`), and, per language, where it looks for
something narrower (`looksForIn`), and a clean result names both beside the files:

    a file opened, written, or deleted at a path built from a value rather than written out, in
    2 python files; only commands such as cat, rm, or cp given a path from a web request variable
    (QUERY_STRING, PATH_INFO, and similar); a path from any other variable is not looked at, in
    1 shell file

Every rule that reads shell has its shell wording, because commands and variables are a different shape
from calls and arguments, and a test holds that; a phrase for a language the rule has no query for is
refused at load. The phrases were written from the queries and their patterns, not from what the rule
is meant to catch.

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
