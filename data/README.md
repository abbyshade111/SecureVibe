# What is in `data/`, and what reads it

Everything `sv` knows that is not code lives here: the OWASP standards, the questions it asks, and its rules. Most
files are read each time `sv` runs, so editing one changes `sv`'s behavior without rebuilding it. The exceptions are
marked below. A test (`crates/sv-cli/tests/data_readme.rs`) fails when a file here is not listed in this page, so
the list stays complete.

`sv` reads every file here through one place (`crates/sv-frameworks/src/data.rs`, ADR-036), which looks in
`SV_DATA_DIR` (a whole copy of this folder), then beside the program (`data`, or `../share/securevibe/data`), then
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
| `prompts.json` | `sv-check`, `sv-cli`, `tools/coverage.py`; `docs/PROMPTS.md` is written from it by hand | Prompts for the AI coding tool, each with the check that shows whether it worked and the result of trying it. |
| `design-prompts.json` | `sv-check`, `sv-cli`, `tools/coverage.py`; `docs/prompts/design-time.md` is written from it by hand | Design-time prompts from the Secure by Design checklist, in `prompts.json`'s shape, with the checklist controls each helps a person answer. |
| `design-decisions.json` | `sv-check`, `sv-cli` | The sections of `design-decisions.md` that count toward a Secure by Design control, read as the security notes are, each with the heading its design-time prompt writes and what a written section does not show. |
| `feature-briefs.json` | `sv-cli` | The features `sv brief` and `securevibe_before` write a brief for: the conditions and requirements each brings, its design-time prompts, and the `securevibe.toml` settings `sv run` needs to test it. |

## How `sv` reads an app

| File | Read by | What it is |
|---|---|---|
| `tech-signatures.json` | `sv-cli` | Signs in the code that a technology is used. |
| `claim-corroborators.json` | `sv-cli` | Signs in the code that back up, or contradict, what `securevibe.toml` says. |
| `ast-rules.json` | `sv-check`, `sv-cli` | `sv`'s own rules for reading code, in each language. |
| `secret-rules.json` | `sv-check`, `sv-cli` | The formats of keys and passwords the secrets scan looks for. |
| `adapters.json` | `sv-check`, `sv-cli` | The outside scanners `sv` can run (semgrep, bandit, and others), and which requirements their rules speak to. |
| `semgrep-packs.json` | tests and `tools/coverage.py` | Which rules each semgrep pack really loads, as measured by `tools/semgrep_packs.py`. |
| `codeql-suites.json` | tests | Which queries each CodeQL suite the adapters run really selects, as measured by `tools/codeql_suites.py`. |

## Passwords

| File | Read by | What it is |
|---|---|---|
| `knowledge/common-passwords.txt` | nothing at run time | The most common passwords, 96,517 of them, one per line. `sv`'s sign-up check uses one entry from it, written into the code; `tools/pwned_passwords.py` samples it. |
| `breached-password-evidence.json` | `sv-check`, **compiled in** | Evidence that the one password `sv` tries at sign-up is in known breaches. Written by `tools/pwned_passwords.py`; rebuild `sv` after changing it. |
| `common-passwords-breach-sample.json` | nothing at run time | How much of the common-password list is breach data, from a sample. Written by `tools/pwned_passwords.py`. |

## v1's files

Eight more files in `data/knowledge/` were v1's and never read by `sv`: the wizard's wording, its sample apps, its
glossary, and the like. They were removed from `main` on 27 September 2026 at the owner's decision. v1 keeps its own
copy on the `v1` branch and at the tags `v1-paper` and `v1-final` (see `docs/adr/ADR-016.md`).
