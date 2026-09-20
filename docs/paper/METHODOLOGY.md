# Methodology

What SecureVibe actually does, assembled from the code rather than from a description of it. Every number here
is checkable against the repository at the commit this was written from.

## The question

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

## Limits worth stating

- One app per language. The Python arm is a single Flask application; nothing here generalises to Python as such.
- Arm A was run without AI review, because for a native app SecureVibe offers an AI review only as part of a full
  rebuild. Its AI figures come from a separate full build on 19 September and are marked as such.
- The owner answered the wizard for all three. For the Python app, which she did not write, several answers were
  "not sure", which SecureVibe treats as no evidence either way.
- SecureVibe was under active development throughout the three days, including on the day of the comparison. The
  arms are comparable with each other and not with runs from earlier days.
