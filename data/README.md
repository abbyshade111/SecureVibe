# What is in `data/`, and what reads it

Everything `sv` knows that is not code lives here: the OWASP standards, the questions it asks, and its rules. Most
files are read each time `sv` runs, so editing one changes `sv`'s behavior without rebuilding it. The exceptions are
marked below. A test (`crates/sv-cli/tests/data_readme.rs`) fails when a file here is not listed in this page, so
the list stays complete.

`sv` finds this folder through the folder it was built in (`crates/<crate>/../../data`). `SV_DATA_DIR` points it
at another copy of the OWASP part: `frameworks/` and `knowledge/`. The Docker image keeps the same layout for that
reason.

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
| `sbd-asvs-crosswalk.json` | `sv-cli` | Which ASVS requirements each Secure by Design control corresponds to. |
| `knowledge/threats.json` | `sv-cli`, `sv-report` | The threat model's rules. |
| `atlas-references.json` | `sv-report`, **compiled in** | MITRE ATLAS references for the threat model. Written by `tools/atlas_references.py`; rebuild `sv` after changing it. |

## What `sv` asks the owner and the AI coding tool

| File | Read by | What it is |
|---|---|---|
| `security-notes.json` | `sv-check`, `sv-cli` | The questions answered in writing, in the security notes file. |
| `design-questions.json` | `sv-check`, `sv-cli` | The design questions answered in `securevibe.toml`. |
| `human-checks.json` | `sv-check`, `sv-cli` | How to check by hand what no automated check can settle. |
| `coding-rules.json` | `sv-check`, `sv-cli` | Rules the AI coding tool follows while it writes the app. |

## How `sv` reads an app

| File | Read by | What it is |
|---|---|---|
| `tech-signatures.json` | `sv-cli` | Signs in the code that a technology is used. |
| `claim-corroborators.json` | `sv-cli` | Signs in the code that back up, or contradict, what `securevibe.toml` says. |
| `ast-rules.json` | `sv-check`, `sv-cli` | `sv`'s own rules for reading code, in each language. |
| `secret-rules.json` | `sv-check`, `sv-cli` | The formats of keys and passwords the secrets scan looks for. |
| `adapters.json` | `sv-check`, `sv-cli` | The outside scanners `sv` can run (semgrep, bandit, and others), and which requirements their rules speak to. |
| `semgrep-packs.json` | tests and `tools/coverage.py` | Which rules each semgrep pack really loads, as measured by `tools/semgrep_packs.py`. |

## Passwords

| File | Read by | What it is |
|---|---|---|
| `knowledge/common-passwords.txt` | nothing at run time | The most common passwords, 96,517 of them, one per line. `sv`'s sign-up check uses one entry from it, written into the code; `tools/pwned_passwords.py` samples it. |
| `breached-password-evidence.json` | `sv-check`, **compiled in** | Evidence that the one password `sv` tries at sign-up is in known breaches. Written by `tools/pwned_passwords.py`; rebuild `sv` after changing it. |
| `common-passwords-breach-sample.json` | nothing at run time | How much of the common-password list is breach data, from a sample. Written by `tools/pwned_passwords.py`. |

## v1's files, which nothing on `main` reads

SecureVibe v1 read these, and `sv` never has. Since 26 September 2026 v1 lives on the `v1` branch with its own copy
of `data/`, so editing these changes nothing, for either program. They are kept rather than deleted; deleting
them is the owner's decision.

| File | What v1 used it for |
|---|---|
| `knowledge/examples.json` | Sample apps a person could build to try v1 |
| `knowledge/glossary.json` | Plain-language definitions |
| `knowledge/injection-patterns.json` | Prompt-injection screening rules for the apps v1 built |
| `knowledge/patterns.json` | Secure-by-design patterns chosen from the owner's answers |
| `knowledge/remediation.json` | Fix advice for each of its scanners' findings |
| `knowledge/requirements-plain.json` | Each ASVS requirement in plain language |
| `knowledge/sbd-rules.json` | How each Secure by Design control was answered from the owner's answers |
| `knowledge/wizard-copy.json` | The wizard's wording |
