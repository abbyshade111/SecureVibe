# Methodology

What SecureVibe actually does, assembled from the code rather than from a description of it. Every number here
is checkable against the repository at the commit this was written from.

## The question

> **On the project's age.** The repository's history begins on 18 September 2026 with a commit restoring the
> project after an iCloud eviction destroyed what came before. Ten of the twelve ADRs are dated 16 September, so
> development began at least two days earlier than any commit shows. Where this appendix says "three days" it
> means the surviving record, not the project.

Whether giving a non-programmer a secure foundation — a fixed, hardened template plus automated checking against
OWASP Secure by Design, ASVS 5.0 and AISVS 1.0 — produces a safer way to build software than writing it with an
AI assistant alone.

The claim under test is not "AI writes secure code". It is that the *foundation* carries the security, the AI
fills in what the person described, and the *checking* is what stops either of them being believed without
evidence.

## What a build does

Seventeen stages, in order: `design-freeze`, `scaffold`, `generate`, `install`, `typecheck`, `lint`,
`unit-tests`, `sast`, `secrets`, `deps`, `config`, `dast`, `external`, `ai-review`, `fix`, `compliance`,
`reports`.

Three of those decide what exists (freeze the answers, lay out the template, write the described features).
The rest check what resulted. A run of an app SecureVibe did not build skips everything that would execute it —
`install`, `typecheck`, `unit-tests` and `dast` — and says so in the report rather than leaving them blank.

## The frameworks

| | requirements in the data |
|---|---|
| OWASP ASVS 5.0 | 345 |
| OWASP AISVS 1.0 | 235 |
| OWASP Secure by Design | a checklist of controls, not numbered requirements |

Not all apply to a given app: applicability is decided from the wizard answers (a local-only app is not asked
about TLS termination; an app with no payments is not asked about card data). The reports state the applicable
count rather than the total, which is why the arms below have different denominators.

## The evidence model

This is the mechanism that carries the argument, and it is worth stating precisely because it is what makes the
scores mean anything.

Every requirement's status is decided by the *kind* of evidence supporting it, not by anyone's opinion:

| evidence | tier | example |
|---|---|---|
| a passing test | **strong** | the app's own suite proves a member cannot open an admin page |
| a runtime probe | **strong** | the running app was asked for a page without signing in, and refused |
| a template control | medium | a security header is set by a file the app never changed |
| a scanner result | medium | no dangerous pattern found in the code |
| a configuration check | medium | secrets are not committed |
| **an AI review** | **weak** | Claude read the code and thinks the requirement is met |
| a generated document | weak | the design document says so |
| a human attestation | weak | somebody said so, with a note |

A requirement supported **only** by AI review is recorded as `ai-assessed` and **never** counted as passing. The
verified-pass percentage is computed from strong and medium evidence alone. This is the rule that makes the
comparison below legible: an app can be read by an AI and still verify nothing.

Statuses: `pass`, `ai-assessed`, `documented`, `attested`, `partial`, `fail`, `not-verified`, `not-applicable`,
`out-of-level`.

## What checks the checker

- Server suite: 113 files, 1,075 tests.
- Template suite: 28 security test files; every test name must begin with a requirement id, and a separate check
  compares each test's name and body against that requirement's wording.
- Evaluation harness: five golden applications rebuilt without AI and compared against recorded baselines. A
  template or pipeline change is not finished until they pass.

## What the harness is for, and what it caught

Phrased by the session that built it, which watched the first run:

> The evaluation harness builds four fixed applications from saved answers without any AI, checks each one
> exactly as an owner's app is checked, and compares the outcome with a saved baseline: whether the build
> finished, whether each step passed, how many problems are open and how serious, what share of ASVS and AISVS
> requirements automated checks verified, and how many of the app's own tests passed. Cost and time are recorded
> but never fail a run, so a baseline is free and repeatable. Its first run, on 18 September 2026, found five
> faults in the template that every generated application inherits and that no unit test had caught, because
> each one only appears when a particular set of answers is built: feature switches written in one spelling and
> read in another, so API keys, assistant actions and retention jobs never turned on at runtime; a file removed
> with one switch while the assistant still imported it, so those apps did not compile; applications set to
> serve HTTPS themselves shipped without a certificate and could not start; generated tests that sent text
> where an upload identifier belonged; and the built-in security tests running against each app's deployment
> settings instead of the loopback address, so a proxy setting made unrelated tests fail. Before the fixes, one
> golden app passed 10 of 169 tests and carried 150 high-severity findings; after them, all four build with no
> open critical, high or medium findings and 60–68% of applicable ASVS requirements verified. Every one of those
> faults would have reached a real owner's application first.

This matters to the paper's question because those five faults are invisible to unit testing by construction:
each appears only in a particular *combination* of wizard answers, and the template is a set of switches. A
foundation that is only tested as a library is not tested as the thing people receive.

## The comparison, 20 September 2026

Designed to separate two variables that the obvious version of the experiment confounds.

| arm | app | language | path |
|---|---|---|---|
| A | SecureFit | TypeScript | native — built by SecureVibe, re-checked in place |
| B | SecureFit | TypeScript | uploaded — same code, exported and handed back as a folder |
| C | fitness-tracker | Python | uploaded |

**A vs B isolates the upload path**, language held constant: the code is byte-identical, exported from the
native project. **B vs C isolates the language**, path held constant.

All four runs (C was run twice, with and without AI) used one SecureVibe process, started at 17:14 and not
restarted between them, so no code change can account for a difference between arms.

## What the regression suite can and cannot tell you

Worth stating because it bears on how much weight any "all five golden apps came back clean" sentence in this
paper can carry. The baselines record counts: requirement statuses, findings by severity, tests passed, stage
outcomes. They do not record the wording of anything.

So when a change alters what a report *says* rather than what it *counts* — which several of the changes on
20 September did — five identical apps is consistent with three different worlds: the change working, the change
doing nothing, and the change not being present at all. The harness answers the question the baselines ask,
which is not always the question being asked of it. Where that gap mattered here, a unit test covering the
negative direction is what actually holds the result, and the eval's role was limited to showing nothing else
moved.

## Limits worth stating

- One app per language. The Python arm is a single Flask application; nothing here generalises to Python as such.
- Arm A was run without AI review, because for a native app SecureVibe offers an AI review only as part of a full
  rebuild. Its AI figures come from a separate full build on 19 September and are marked as such.
- The owner answered the wizard for all three. For the Python app, which she did not write, several answers were
  "not sure", which SecureVibe treats as no evidence either way.
- SecureVibe was under active development throughout the three days, including on the day of the comparison. The
  arms are comparable with each other and not with runs from earlier days.
