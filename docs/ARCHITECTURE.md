# SecureVibe (`sv`): the ten-minute map

What `sv` is made of, how a run goes through it, and where each rule is held. Written 8 October 2026 for a session
or a person opening the repository cold. `docs/design/` is the dated record of every decision as it was made, one file per
entry (nearly 300, some 13,000 lines in all); `docs/adr/` holds the 44 decisions that matter most, each with the files it governs; this page is the map that
neither of them is. When this page and the code disagree, the code is right and this page is out of date: say so in
the pull request that finds it.

## What it does, in one paragraph

A person builds an app in their own AI coding tool, in any language. The tool writes `securevibe.toml`, a manifest of
what the app claims about itself, from the spec `sv init` prints. `sv` reads the code and the manifest, works out
which requirements of OWASP ASVS 5.0, AISVS 1.0, and the Secure by Design checklist apply, checks what it can (the
files, and, when asked, the app running behind a network fence), and writes reports that say what was verified, at
what strength, and what was not looked at. The same engine answers an AI coding tool over MCP, so the tool can check
as it builds. `sv` never says an app is secure; it says what it checked and what it did not.

## The crates, in the order a run passes through them

| Crate | Lines | What it is |
|---|---|---|
| `sv-frameworks` | 1,200 | The standards as data (`data/frameworks/*.json`), and which requirements apply to an app with these conditions (`data/applicability-v2.json`). Also `data::file`, the one way any run-time read finds `data/` (ADR-036). |
| `sv-manifest` | 4,100 | `securevibe.toml`: what the app claims. Nothing in it is a fact; `resolve` corroborates each claim against the code, and corroboration only ever adds requirements, never removes them. |
| `sv-scan` | 4,100 | One walk of the app's folder (`files::Listing`), its languages and frameworks by signature, what the manifest sets apart as not the app (ADR-031), and the names of a report folder so the walk leaves it out. |
| `sv-check` | 97,700 | Every check: keys and passwords (`secrets`), configuration (`config`), rules that read code with tree-sitter (`ast`, `data/ast-rules.json`), the bill of materials (`sbom`) and advisories, outside tools through adapters, and the checks of a running app (`signed_in`, `probes`, `oidc`, `ai`, `mcp_server`, `fetch`, `live`) written against a trait `Http`, so each runs against a fake app in its unit tests. Also what a person's word is worth: `design`, `hand`, `notes`, `confirm`, `review`, and the seals (`seal`). Produces `Finding` and `Verified`, never a verdict. |
| `sv-run` | 6,900 | Starts the app behind the fence: a Docker network with no gateway, a sidecar that sends every request from inside it, the helpers a run needs (a mail server, a test identity provider, a test model, a headless browser), every container read-only with every capability dropped (ADR-019, `prepared`), the install step for the app's packages (ADR-052), and the run's script (`run_after_cleanup`). Implements `Http` for the checks. Depends on `sv-check` today, the reverse of this layering (BACKLOG, 8 October, item 4). |
| `sv-report` | 8,100 | From findings and credits to a status per requirement (`status_of`), the counts, the gaps, and the five renderings: `report.html`, `compliance.md`, `security.md`, `findings.sarif`, `report.json`. The one place a conclusion is drawn. |
| `sv-cli` | 21,300 | The `sv` binary: the commands, the stages of a run (`static_scan`, `assemble_report_saying`, `report_folder`), the report folder's lock and seal, and the MCP server (`mcp/`). |

The rule of the layering: a crate below decides nothing a crate above would want to overrule. `sv-check` says what
it saw; `sv-report` says what that is called; `sv-cli` says it to a person or a tool.

## A run of `sv report`, stage by stage

1. **The manifest** is read once; its hash goes into the report, so a `securevibe.toml` that changes during the run is
   reported (`report_lock::manifest_changed`).
2. **The report folder is claimed** before anything slow happens: a lock file, the marker that keeps the next walk from
   reading the report as the app, and a refusal of any folder that holds somebody else's files (ADR-041,
   `report_folder::write_report_folder`, the same sequence the MCP server's `securevibe_write_report` runs).
3. **The static stage** (`static_scan::StaticScan::read`): one walk of the folder, the languages and packages, the
   keys and passwords, the configuration, the code. `sv check` runs exactly this and stops; `sv report` goes on. Both
   settle their findings the same way (`static_scan::settle`), so they exit alike on the same folder (ADR-023, Later,
   8 October 2026).
4. **Which requirements apply**: the manifest's claims resolved against what the scan saw (`sv_manifest::resolve`),
   then the frameworks' applicability rules (`sv_frameworks`). A claim the code contradicts is reported as such.
5. **What else was asked for**, each opt-in and each saying in the report when it did not run: a local advisory
   database (`--advisories`), the language's own security tools (`--tools`, ADR-032: never a program inside the app),
   and the running app (`--run`): the fence, the helpers, the anonymous questions, the signed-in suites as two users
   and an admin, sign-in through a test provider, the AI feature through a test model, the app's own tests inside its
   container (ADR-050), and whether the app was still up at the end (ADR-021).
6. **A person's word**: the design answers in `securevibe.toml`, the checks made by hand, the security notes and the
   decisions file, and the confirmations and reviews `sv review` sealed (ADR-022, ADR-026). Each becomes a `Verified`
   that says which tier it rests on (`sv_check::Tier`).
7. **Settled**: one weakness reported twice on a line merged, test code and bundled libraries marked, the decisions
   held to the running app, a person's reviews applied, one finding per line (ADR-023).
8. **The report built** (`sv_report::build`): per requirement, a finding beats every credit, and otherwise the
   strongest tier there decides (`status_of`). Gaps say what was not examined; `examined` says the same for a program.
9. **Written and sealed**: the five files, each under a new name and renamed into place, never through a link; the
   folder sealed with this computer's report key so the MCP server can tell `sv`'s report from one anything else wrote
   (ADR-034). The lock goes; the folder stays.

## The nine statuses, strongest evidence first

What a requirement that applies is called in a report (`crates/sv-report/src/lib.rs`, `Status`), decided by
`status_of` from its findings and the tiers of its credits: a finding beats every credit, and otherwise the strongest
tier there decides.

| Status | Means |
|---|---|
| needs attention | A check found something and named this requirement. |
| checked | A check of `sv`'s own ran and was satisfied. One automated check, never a pass. |
| checked in part | Every check behind it tried only part of what it asks (ADR-053). |
| tested by the app's own tests | The app's tests name the requirement, in code, and passed (ADR-050). The tool wrote both the test and the command. |
| documented by the owner | The owner answered its question in the security notes, recorded through `sv review`. A decision, not a reading of the code. |
| checked by hand by the owner | The owner watched the app behave and recorded what they saw. |
| attested by the owner | The owner answered `yes` to a design question. Asserting a property is not the property. |
| stated by the AI coding tool | The tool answered, or nobody recorded that the owner did: the author grading its own work. |
| not verified | Nothing produced evidence either way. The honest default, and the common one. |

Nothing below *checked* ever becomes *checked*, settles a threat, or leaves the list of tests to write.

## The five kinds of rule, and where a new one goes

Every rule cites the requirements it speaks to where it is written, and nowhere else; a citation is a claim.

| Kind | Where | A new one |
|---|---|---|
| Keys and passwords | `data/secret-rules.json`, read by `crates/sv-check/src/secrets.rs` | A new entry: the pattern, the first four characters shown, the length, never the key. |
| Rules that read code | `data/ast-rules.json`, a tree-sitter query per language, read by `crates/sv-check/src/ast.rs` | A new entry with a witness per language it is taught; a language it is not taught is a gap, never a clean result (ADR-054). |
| Configuration | Rust, `crates/sv-check/src/config.rs`, each check a function that reads what it needs from the listing | A new function, cited in `RUST_CHECKS` in `tools/coverage.py`. |
| Outside tools | `data/adapters.json`: how each tool is run, in a container of its own, and how its findings map to requirements, read by `crates/sv-check/src/adapters.rs` | A new entry; never a program inside the app (ADR-032). |
| The running app | Rust, `crates/sv-check/src/signed_in/` and `crates/sv-check/src/probes.rs`, written against `Http` so each runs against a fake app in its tests | A new check in the suite that fits, with the fake-app test that shows it fail; cited in `RUST_CHECKS`. |

Four gates hold the citations to the code (`tools/coverage.py`): a requirement id written into Rust that is in
neither `RUST_CHECKS` nor `MENTIONS` stops the script; `docs/COVERAGE.md` and `docs/REQUIREMENTS.md` must be what the
script would write (`crates/sv-check/tests/coverage_doc.rs`); CI's test run logs every credit given (`SV_CREDIT_LOG`),
and a check that credits a requirement listed as finding-only, or never credits one it is listed for, fails
(`--credits`); and every prompt in `data/prompts.json` and `data/design-prompts.json` names requirements that one of
its rules cites, and nothing else.

## The exit codes

`sv check`, `sv report`, and `sv audit` (`crates/sv-cli/src/exit.rs`): 0, finished; 1, something needs a person (a
known vulnerability for `sv audit`; a finding at or above the bar with `--fail-on attention`); 2, not assessed (a
check could not run, or no file of the app was read; more with `--fail-on not-assessed`); 3, `sv` itself failed. By
default findings alone do not fail a run (ADR-029): an AI coding tool that reads a failure rewrites the code until
it stops, so the bar is the person's to set.

## The MCP server (`crates/sv-cli/src/mcp/`)

JSON-RPC over stdio, hand-written, one request at a time, each on a thread with a time limit. The tools are the
commands (`securevibe_check`, `securevibe_write_report`, `securevibe_plan`, `securevibe_spec`, `securevibe_questions`,
`securevibe_record_answer`, and the rest in `catalog.rs`), built on the same `assemble_report_saying` as `sv report`,
so what the tool is told is what the report says. Three rules hold everywhere in it: every path stays below the folder
the server was started for (`confine.rs`); the app's own text is fenced as data before it reaches the tool, since the
app can write anything (`sv_report::fence`); and a report is offered as a resource only when its seal shows `sv` wrote
it (`resources.rs`, ADR-034). The server never starts the app and never runs outside tools; it says so and names the
terminal command the person can run.

## The rules that hold everywhere

- **Evidence is honest.** Not assessed is never a pass and never a failure; a check that could not run says so.
  Credit is given only over what was read, in a person's words (`Verified::scope`), and a check that names more
  requirements when it passes than when it fails is wrong by construction (`verified.rs`).
- **Whose word, at which rank.** A check of `sv`'s own, then the app's tests, then the owner's written answer, a check
  by hand, the owner's yes, the tool's yes; nothing a model says makes a requirement *checked* (ADR-022, ADR-050).
- **The fence.** The app runs on a Docker network with no gateway, read-only, every capability dropped; every request
  to it is sent from inside; `sv` opens no network connection of its own but `sv probe` and the install step (ADR-019,
  ADR-027, ADR-052). Verified by asking Docker, not by trusting the flag.
- **What `sv` writes into somebody's folder** is the report folder, `security-notes.md`, and its section of
  `AGENTS.md`, and nothing else (ADR-017); never through a link.
- **Every decision has a record** in the same pull request, and the "Decision records" check holds it (`docs/adr/README.md`).

## Where to look

| To change | Start at |
|---|---|
| Which requirements apply to an app | `data/applicability-v2.json`, `crates/sv-frameworks/src/applicability.rs` |
| A rule that reads code | `data/ast-rules.json`, then `python3 tools/coverage.py` (a test holds `docs/COVERAGE.md` current) |
| A check of the running app | `crates/sv-check/src/signed_in/`, against the fake app in its tests; the run's script in `crates/sv-run/src/docker.rs` |
| What a report says | `crates/sv-report/src/` (`lib.rs` decides, `html.rs`, `markdown.rs`, `sarif.rs`, `json.rs` render) |
| What the AI coding tool is told | `crates/sv-cli/src/mcp/catalog.rs` (tools and prompts), `check_text.rs` |
| What a person can set aside or confirm | `crates/sv-check/src/review.rs`, `confirm.rs`, `seal.rs`; `sv review` in `crates/sv-cli/src/review.rs` |
| A data file | `data/README.md` says what each is and what reads it; `sv_frameworks::data::file` finds it |
| What is still to do | `docs/backlog/`, one file per item with its status on its third line; `docs/BACKLOG.md` holds the rules and the roadmap. Claim an item with `python3 tools/backlog.py claim` before starting it |

`cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo test --workspace` are what CI runs;
a test that starts the app needs a container backend and says which branch it took without one.
