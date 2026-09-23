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

**Docker is not installed on this machine.** `sv-run` is built behind a trait with a container backend, and until
a backend is available every dynamic requirement reports `not assessed` — not `pass`, and not `fail`. The reports
say which applied, as v1's do.

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
