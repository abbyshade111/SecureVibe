# What the first run found

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
between a report and a misleading one. This is v1's ADR-012 exactly — a wrong statement in a report, which an owner
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

The replacements live in `data/applicability-v2.json`, which replaces the rule at a scope rather than
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
owner is their own deliberate statement and is honored; silence is not converted into one.

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
