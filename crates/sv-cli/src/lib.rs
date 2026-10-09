//! The library behind `sv`: the report's assembly and what it needs, called by the command line and the MCP
//! server alike (BACKLOG, "From the architecture assessment of 8 October 2026", item 12).

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_check::advisories;
use sv_check::ast;
use sv_check::probes;
use sv_check::sbom;
use sv_check::secrets::{SecretRules, scan_dir};
use sv_frameworks::Condition;
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, bucket};
use sv_manifest::Manifest;
use sv_run::RunPlan;
use sv_scan::{Evidence, Signatures};

// Everything `sv` prints goes through `sv_report::visible`, so no control character from the app, in a
// file name, a finding, or what its tests printed, reaches the terminal (the deep review's improvement 5).
// These shadow the standard macros in every module of this crate below them; an `eprint!` added later wants
// one too. The MCP server writes its protocol to its own writer, not through these.
macro_rules! eprintln {
    () => { ::std::eprintln!() };
    ($($arg:tt)*) => { ::std::eprintln!("{}", ::sv_report::visible(&::std::format!($($arg)*))) };
}

pub mod assemble;
pub mod bundle;
pub mod exit;
pub mod report_lock;
pub mod static_scan;
pub use assemble::{REPORT_STAGES, assemble_report_saying};

/// Everything a report reads from `data/`, loaded once per process.
///
/// A command loads it once and is done; the MCP server loads it when it starts and hands the same
/// one to every call, so the code rules' queries — compiled the first time a language is met, and
/// kept in the `AstRules` — are compiled once for the life of the server rather than once per call.
/// Loading itself is cheap (about 30 ms, most of it the regexes); the second every command used to
/// spend before reading a file was the queries, and they are now compiled only for the languages
/// the app holds (review item 6, 27 September 2026).
pub struct Loaded {
    pub frameworks: Frameworks,
    pub config_rules: ApplicabilityConfig,
    pub signatures: Signatures,
    pub threat_rules: sv_report::threats::ThreatRules,
    pub secret_rules: SecretRules,
    pub ast_rules: ast::AstRules,
    /// The outside tools `sv` can run, or why `adapters.json` could not be read. Read here once
    /// for a report rather than three times (the review of 8 October 2026, item 7), and kept as a
    /// result rather than failing the load: only `--tools` needs the tools, so a broken file stops
    /// that run and is said in the report of every other (item 6), where it used to list no tools
    /// at all and say nothing.
    pub adapters: std::result::Result<sv_check::adapters::Adapters, String>,
}

impl Loaded {
    pub fn load() -> Result<Loaded> {
        let data = data_dir()?;
        Ok(Loaded {
            frameworks: load_frameworks(&data)?,
            config_rules: ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay_path())?,
            signatures: Signatures::load_all(&[&signatures_path(), &corroborators_path()])?,
            // Shared with v1, beside the applicability rules, so a threat is corrected in one place.
            threat_rules: sv_report::threats::ThreatRules::load(
                &data.join("knowledge").join("threats.json"),
            )?
            .with_atlas()?,
            secret_rules: SecretRules::load(&secret_rules_path())?,
            ast_rules: ast::AstRules::load(&ast_rules_path())?,
            adapters: sv_check::adapters::Adapters::load(&adapters_path())
                .map_err(|e| format!("{e:#}")),
        })
    }
}

/// Per-language security tools `sv` can run.
pub fn adapters_path() -> PathBuf {
    sv_frameworks::data::file("adapters.json")
}

/// The outside tools in `adapters`, by the names a person knows them by and once each, joined into
/// a sentence: "Bandit, gosec, Brakeman, Semgrep, and CodeQL". Two adapters of one tool for two
/// languages, "CodeQL (Python)" and "CodeQL (JavaScript and TypeScript)", are one name. Until
/// 8 October 2026 the report wrote its own list, which a tool added to the file never reached:
/// Semgrep, which reads every language, was missing from it (the review of that day, item 7).
pub fn tool_names(adapters: &sv_check::adapters::Adapters) -> String {
    let mut names: Vec<&str> = Vec::new();
    for adapter in adapters.all() {
        let name = adapter
            .name
            .split_once(" (")
            .map_or(adapter.name.as_str(), |(name, _)| name);
        if !names.contains(&name) {
            names.push(name);
        }
    }
    match names.as_slice() {
        [] => "no outside tools".to_owned(),
        [one] => (*one).to_owned(),
        [two @ .., last] if two.len() == 1 => format!("{} and {last}", two[0]),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Evidence in the words a person would use.
pub fn describe(evidence: &Evidence) -> String {
    match evidence {
        Evidence::Dependency { name, manifest } => format!("`{name}` is declared in {manifest}"),
        Evidence::Source { pattern, file } => format!("`{pattern}` appears in {file}"),
        Evidence::Language { language } => format!("the app contains {language}"),
        Evidence::File { path } => format!("{path} is in the repository"),
        Evidence::NothingFound { files_read } => {
            format!("nothing like it in the {files_read} files read")
        }
        Evidence::NotFoundButNotDecisive { .. } => {
            "nothing found, which settles nothing".to_owned()
        }
        Evidence::Incomplete { reason } => reason.clone(),
        Evidence::NoCheckExists { .. } => "no check for this is possible".to_owned(),
    }
}

pub fn design_questions_path() -> PathBuf {
    sv_frameworks::data::file("design-questions.json")
}

pub fn notes_path() -> PathBuf {
    sv_frameworks::data::file("security-notes.json")
}

/// The sections of design-decisions.md that count toward a checklist control (`sv_check::decisions`).
pub fn decisions_path() -> PathBuf {
    sv_frameworks::data::file("design-decisions.json")
}

pub fn coding_rules_path() -> PathBuf {
    sv_frameworks::data::file("coding-rules.json")
}

/// Starts the app behind the fence, so the checks that need it running have something to check.
/// Starts the app behind the fence and asks it the probe questions, or says why it could not.
///
/// Shared by `sv run` and `sv report --run` on purpose. Two call sites each deciding when an app is
/// runnable would drift, and the one that drifts quietly is the report — where "not assessed" and
/// "nothing found" look the same to a reader who was not there.
pub fn probe_the_running_app(
    manifest: &Manifest,
    app_dir: &Path,
    slow: bool,
) -> std::result::Result<(sv_run::RunOutcome, sv_run::RunPlan), String> {
    let mut plan = RunPlan::from_manifest(manifest, app_dir)
        .map_err(|e| cannot_run_said(&e.explain(), e.kind()))?;
    plan.slow = slow;
    let backend = sv_run::detect().map_err(|e| cannot_run_said(&e.explain(), e.kind()))?;
    // Said before the wait, not only after it: the wait is a minute (family-hub, 3 October 2026).
    if let Some(warning) = sv_run::loopback_warning(&plan.start) {
        eprintln!("{warning}");
    }
    // A start command that switches something off for the run (family-hub, 3 October 2026, item 3):
    // said here, before the run, and again in the report's note about the run.
    if let Some(warning) = sv_run::weakening_warning(&plan.start) {
        eprintln!("{warning}");
    }
    let requests = anonymous_requests(&plan);
    let outcome = backend.run(&plan, &requests);
    // Stopped with Ctrl-C: the run has removed its containers and network on the way out. What it
    // got to before then is not a report of the app, so nothing is written.
    if sv_run::interrupted() {
        eprintln!(
            "Stopped with Ctrl-C. The app's containers and network were removed; nothing was written."
        );
        report_lock::let_go_of_all();
        exit::exit_with(exit::INTERRUPTED);
    }
    Ok((
        outcome.map_err(|e| cannot_run_said(&e.explain(), e.reason.kind()))?,
        plan,
    ))
}

/// Why the app could not be run, with every credential in it cut down as a finding shows one. The
/// reason quotes the app's own output, which `sv` did not write: its crash line, its last line, the
/// end of a failed install, what the container backend said. A database error that prints its
/// address prints the password in it, and the reason goes into the report and to the terminal
/// (backlog 0226, part 1, item 1). Every way a run can fail passes here, so none is missed.
fn cannot_run_said(said: &str, kind: &str) -> String {
    said_without_credentials(
        said,
        kind,
        SecretRules::load(&secret_rules_path()).ok().as_ref(),
    )
}

/// `cannot_run_said`, with the rules given: `said` is the failure as `sv-run` explains it, and `kind`
/// what kind of failure it was (`CannotRun::kind`). Without the rules nothing can be cut, so the
/// app's own words are left out rather than shown whole, and the reason says only the kind.
fn said_without_credentials(said: &str, kind: &str, rules: Option<&SecretRules>) -> String {
    match rules {
        Some(rules) => sv_check::secrets::redact_text(rules, said).0,
        None => format!(
            "The app could not be run ({kind}). What it printed is left out here, because sv's own \
             rules for finding credentials in it could not be read, so it could not be shown safely: \
             start the app yourself to see what it printed, and reinstall sv. Everything that needs \
             the app running is reported as not assessed."
        ),
    }
}

#[cfg(test)]
mod cannot_run_said_tests;

/// Every request the anonymous probes make: the fixed suite, and the GraphQL and WebSocket
/// questions when stackvet.toml says where those are. One function, because `sv run` also counts
/// how many of these went unanswered, and a count taken from a different list is a wrong count.
pub fn anonymous_requests(plan: &RunPlan) -> Vec<probes::ProbeRequest> {
    let mut requests = probes::requests(&plan.health_path);
    requests.extend(probes::api_requests(
        plan.graphql.as_deref(),
        plan.websocket.as_deref(),
    ));
    let (admin_pages, private_files) = more_questions(plan);
    requests.extend(sv_check::running::requests(&admin_pages, &private_files));
    requests.extend(probes::error_requests(
        &plan.health_path,
        &body_routes(plan.users.as_ref()),
    ));
    requests
}

/// What the running app showed: the anonymous probes, and the signed-in ones when they ran.
///
/// One function for `sv run` and `sv report`, so the two cannot disagree about what was found.
pub fn running_app_evidence(
    outcome: &sv_run::RunOutcome,
    plan: &RunPlan,
) -> (
    Vec<sv_check::Finding>,
    Vec<sv_check::Verified>,
    Vec<(String, String)>,
) {
    let mut findings = probes::evaluate(&outcome.probe_responses);
    let mut verified = probes::verified(&outcome.probe_responses);
    let mut not_assessed = Vec::new();
    let (api_findings, api_verified, api_not_assessed) =
        probes::evaluate_api(&outcome.probe_responses, plan.public_api);
    findings.extend(api_findings);
    verified.extend(api_verified);
    not_assessed.extend(api_not_assessed);
    let (admin_pages, private_files) = more_questions(plan);
    let more = sv_check::running::evaluate(
        &outcome.probe_responses,
        &admin_pages,
        &private_files,
        &outcome.liveness,
    );
    findings.extend(more.findings);
    verified.extend(more.verified);
    not_assessed.extend(more.not_assessed);
    for asked in [
        &outcome.signed_in,
        &outcome.oidc,
        &outcome.ai,
        &outcome.mcp_server,
        &outcome.fetch,
    ]
    .into_iter()
    .flatten()
    {
        findings.extend(asked.findings.iter().cloned());
        verified.extend(asked.verified.iter().cloned());
        not_assessed.extend(asked.not_assessed.iter().cloned());
    }
    (findings, verified, not_assessed)
}

/// What the report and `sv run` say about the anonymous questions the app's rate limiter answered
/// in the app's place. Those answers were left out, so nothing was judged from them; this says so,
/// rather than letting them read as questions the app never answered.
/// The gap when the container the questions are sent from was gone before they were done
/// (ADR-025, Later, 8 October 2026): everything asked after that got no answer because nothing
/// was there to ask, and a reader would otherwise take the silence for the app's.
pub fn sidecar_lost_gap(lost: Option<&str>) -> Option<sv_report::Gap> {
    let lost = lost?;
    Some(sv_report::Gap {
        what: "every question asked after the way to the app ended".to_owned(),
        why: format!(
            "{lost}. From then on every request got no answer, because nothing was there to send \
             it, not because the app was silent: nothing asked after it is judged either way. Run \
             again; if it happens again, the run is taking longer than the container it asks \
             through is allowed to live, which is a fault in sv to report."
        ),
    })
}

pub fn rate_limited_gap(limited: &[String]) -> Option<sv_report::Gap> {
    if limited.is_empty() {
        return None;
    }
    Some(sv_report::Gap {
        what: format!(
            "what the app answers to {} of the questions asked as somebody not signed in",
            limited.len()
        ),
        why: format!(
            "the app's rate limiter answered them in its place, still, after `sv` waited as long \
             as it asked: {}. A rate limiter's page is not the app's, so nothing was judged from \
             it, neither a finding nor a pass. Raise the limit for the test run and run it again.",
            limited.join(", ")
        ),
    })
}

/// What a report is built from, and what the person asked for.
pub struct ReportOptions {
    /// Start the app behind the fence and ask it questions. Opt-in: this runs somebody's code.
    pub run_the_app: bool,
    /// And wait out the session timeouts the owner states. Opt-in: it takes as long as they are.
    pub slow: bool,
    /// Run the language's own security tool. Opt-in: these are other people's programs.
    pub run_tools: bool,
    /// Said in the report when the app was not started, in the words of whoever built it.
    pub why_not_run: String,
    /// Said in the report when the tools were not run.
    pub why_no_tools: String,
    /// A local advisory database to compare the bill of materials with. `sv` never fetches one.
    pub advisories: Option<PathBuf>,
    /// Said in the report when there was no database to compare with.
    pub why_no_advisories: String,
}

impl ReportOptions {
    /// Nothing started, no tool run, and no database read, for a caller that never does any of
    /// them: `caller` is how the report names it ("`sv plan`"). Until 8 October 2026 each caller
    /// wrote its own three sentences and three `false`s; the MCP server's sentences, which say what
    /// the person can do instead, are written over these with the struct-update syntax.
    pub fn reading_only(caller: &str) -> Self {
        Self {
            run_the_app: false,
            slow: false,
            run_tools: false,
            why_not_run: format!("{caller} does not start the app."),
            why_no_tools: format!("{caller} does not run other people's tools."),
            advisories: None,
            why_no_advisories: format!(
                "{caller} does not compare packages with known vulnerabilities."
            ),
        }
    }

    /// What a command with the `--run`, `--slow`, `--tools`, and `--advisories` flags was asked
    /// for, and, for each it was not, how it is asked: `caller` is the command ("`sv report`").
    pub fn asked_of(
        caller: &str,
        run_the_app: bool,
        slow: bool,
        run_tools: bool,
        advisories: Option<PathBuf>,
    ) -> Self {
        Self {
            run_the_app,
            slow,
            run_tools,
            why_not_run: format!("{caller} does not start the app unless you pass --run."),
            why_no_tools: format!(
                "{caller} does not run other people's tools unless you pass --tools."
            ),
            advisories,
            why_no_advisories: format!(
                "{caller} compares against known vulnerabilities only when you pass --advisories \
                 DIR."
            ),
        }
    }
}

/// Everything `sv report` knows about an app, built once for every caller.
///
/// `sv report` and the MCP server both call this, so what an AI coding tool is told about an app
/// is exactly what the written report says — not a second, drifting summary of it.
/// What the report cannot say about this app's dependencies, taken from the bill of materials.
///
/// This used to be built from `scan_report.unpinned`, which knows one thing: whether an ecosystem
/// that pins with a lockfile is missing one. That produced a single sentence for every ecosystem —
/// "pins no versions, so the list of dependencies is what was asked for rather than what is there"
/// — and one sentence covering every ecosystem is wrong about some of them:
///
/// - **npm with no lockfile.** No version in a `package.json` is read at all, so that ecosystem's
///   list is not approximate, it is *empty*. A reader was told the list was what they asked for
///   when the list held nothing. `sv sbom` said this correctly all along, and put a
///   `securevibe:unread:npm` component in the CycloneDX document so a downstream reader saw it too.
/// - **pip with a pinned `requirements.txt`.** `flask==3.0.0` pins a version, and the sentence said
///   the file pinned none. The versions really are what was asked for rather than what resolved,
///   which is worth saying — but that is a different statement from the one being made.
///
/// So the report asks the bill of materials, which already draws both distinctions and had no
/// reader. Nothing is reworded: the ecosystems that produced nothing and the ones that produced
/// manifest-declared versions are two different gaps, and they are reported as two.
pub fn dependency_gaps(sbom: &sbom::Sbom) -> Vec<sv_report::Gap> {
    let mut gaps = Vec::new();

    // Ecosystems that produced no components at all. The bill of materials already words each
    // reason for its own case — no lockfile, a lockfile format `sv` cannot read, a lockfile that
    // parsed and yielded nothing — so the reason is passed through rather than flattened.
    // When the same ecosystem did list packages (a lockfile read in one folder, a `setup.py` not
    // read in another; a `Pipfile.lock` with one package installed from a repository), the list is
    // not empty, and calling it empty would be as wrong as calling an empty one approximate.
    for (ecosystem, why) in &sbom.unread {
        let some_listed = sbom.components.iter().any(|c| &c.ecosystem == ecosystem);
        gaps.push(if some_listed {
            sv_report::Gap {
                what: format!("part of what {ecosystem} installs"),
                why: format!(
                    "{why}. The list of this app's {ecosystem} dependencies leaves these out, so \
                     nothing here can say whether a package with a known vulnerability is among them"
                ),
            }
        } else {
            sv_report::Gap {
                what: format!("everything {ecosystem} installs"),
                why: format!(
                    "{why}. This is not an approximate list of this app's {ecosystem} \
                     dependencies, it is an empty one: nothing here can say whether a package \
                     with a known vulnerability is among them"
                ),
            }
        });
    }

    // Ecosystems whose versions came from a manifest rather than a lockfile. The list is real, and
    // it is what was asked for rather than what an install would resolve to.
    let mut declared: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for component in &sbom.components {
        if component.source == sbom::VersionSource::Declared {
            *declared.entry(component.ecosystem.as_str()).or_default() += 1;
        }
    }
    // A project with two lockfiles of its kind: the list is a full reading of one of them, and
    // nothing here says the app is installed from that one.
    // A manifest that asks for other versions than its lockfile has: the list is the lockfile's,
    // and nothing here says the app is installed from it.
    for disagreement in &sbom.disagreements {
        if disagreement.differs() {
            gaps.push(sv_report::Gap {
                what: format!(
                    "whether {} is installed from `{}` or `{}`",
                    disagreement.project, disagreement.lockfile, disagreement.manifest
                ),
                why: format!(
                    "{}. Bring the two back into step (install from the manifest and write the \
                     lockfile again), and the next report describes both",
                    disagreement.explain()
                ),
            });
        }
        if disagreement.comparison.not_all_compared() {
            gaps.push(sv_report::Gap {
                what: format!(
                    "whether `{}` and `{}` agree about every package",
                    disagreement.manifest, disagreement.lockfile
                ),
                why: disagreement.explain_not_compared(),
            });
        }
    }
    for passed in &sbom.passed_over {
        gaps.push(sv_report::Gap {
            what: format!("which lockfile {} is installed from", passed.project),
            why: format!(
                "{}. Remove the lockfile that is not in use, and the next report reads the one that is",
                passed.explain()
            ),
        });
    }

    for (ecosystem, count) in declared {
        gaps.push(sv_report::Gap {
            what: format!("which {ecosystem} versions are really installed"),
            why: format!(
                "the {count} {ecosystem} package{} listed here {} read from a manifest rather than \
                 a lockfile, so {} what was asked for rather than what an install resolved to",
                if count == 1 { "" } else { "s" },
                if count == 1 { "was" } else { "were" },
                if count == 1 { "it is" } else { "they are" }
            ),
        });
    }

    gaps
}

/// What the report says about `[repository] not-the-app`: the folders it set apart, any it named that
/// are not there, and any entry refused. Said in the report because the list changes what counts as
/// evidence, and a list nobody sees could hide the app's own code from the check.
pub fn not_the_app_gaps(manifest: &Manifest, scan: &sv_scan::ScanReport) -> Vec<sv_report::Gap> {
    let (folders, mut refused) = manifest.not_the_app();
    let mut gaps = Vec::new();
    if let Some(why) = &scan.not_the_app_refused {
        let named: Vec<String> = folders.iter().map(|f| format!("`{f}`")).collect();
        refused.push(format!("{}: {why}", named.join(", ")));
    } else if !folders.is_empty() {
        let found: Vec<String> = scan.set_apart.iter().map(|f| format!("`{f}`")).collect();
        let missing: Vec<String> = folders
            .iter()
            .filter(|f| {
                !scan
                    .set_apart
                    .iter()
                    .any(|p| sv_scan::under_any(p, &[(*f).clone()]))
            })
            .map(|f| format!("`{f}`"))
            .collect();
        let mut why = format!(
            "stackvet.toml says these folders are not the app (`[repository] not-the-app`): {}. \
             Their code is still checked, and its findings count, listed with test and sample \
             code. What is in them cannot change which requirements apply: a library an example \
             uses is not one the app uses. If the app's own code is in one of them, take it off \
             the list.",
            if found.is_empty() {
                "none of them is in this app".to_owned()
            } else {
                let (apart, total) = scan.code_set_apart;
                format!(
                    "{}, holding {apart} of the app's {total} code file{}",
                    found.join(", "),
                    if total == 1 { "" } else { "s" }
                )
            }
        );
        if !found.is_empty() && !missing.is_empty() {
            why.push_str(&format!(" Named but not found: {}.", missing.join(", ")));
        }
        gaps.push(sv_report::Gap {
            what: "what the folders named as not the app use".to_owned(),
            why,
        });
    }
    // What only the folders set apart show (gap analysis, item 19): not read as a "no", so each is a
    // question, unless stackvet.toml answers it.
    let claims = manifest.claims();
    for (condition, shown_by) in &scan.found_only_apart {
        let claimed = claims
            .iter()
            .find(|(c, _)| c == condition)
            .and_then(|(_, v)| *v);
        let answer = match claimed {
            Some(true) => "stackvet.toml says it does, so its requirements apply".to_owned(),
            Some(false) => "stackvet.toml says it does not, and that answer stands; if the app \
                            itself does, change the answer"
                .to_owned(),
            None => "nothing else answers it, so its requirements wait on that question rather \
                     than being set aside"
                .to_owned(),
        };
        gaps.push(sv_report::Gap {
            what: format!("whether the app itself has `{}`", condition.name()),
            why: format!(
                "The only sign of it is {shown_by}, in a folder stackvet.toml says is not the app \
                 (`[repository] not-the-app`), so it is not counted as a \"no\": {answer}."
            ),
        });
    }
    if !refused.is_empty() {
        gaps.push(sv_report::Gap {
            what: "entries in `[repository] not-the-app` that were refused".to_owned(),
            why: format!(
                "{}. Everything they would have named is read as the app.",
                refused.join("; ")
            ),
        });
    }
    gaps
}

/// The same, as gaps in the written report.
/// One `examined` entry per outside tool `sv` knows: the ones that ran, in full or in part, the
/// ones that could not, and the ones for a language this app does not have.
pub fn adapters_examined(
    adapters: &sv_check::adapters::Adapters,
    languages: &[String],
    run: &sv_check::adapters::AdapterRun,
) -> Vec<sv_report::Examined> {
    adapters
        .all()
        .iter()
        .map(|adapter| {
            let rules = format!("{}.", adapter.id);
            let reason = |list: &[(String, String)]| {
                list.iter()
                    .find(|(id, _)| id == &adapter.id)
                    .map(|(_, why)| why.clone())
            };
            let looked = if let Some(why) = reason(&run.partly) {
                Some(sv_report::Examined::partly(rules.clone(), why))
            } else if run.ran.contains(&adapter.id) {
                Some(sv_report::Examined::ran(rules.clone()))
            } else {
                None
            };
            if let Some(looked) = looked {
                match reason(&run.stood_in) {
                    Some(why) => looked.stood_in_by(why),
                    None => looked,
                }
            } else if let Some(why) = reason(&run.not_run) {
                sv_report::Examined::not_run(rules, why)
            } else if !languages.iter().any(|l| adapter.reads(l)) {
                sv_report::Examined::nothing_to_examine(
                    rules,
                    format!("this app has no code in {}", adapter.language),
                )
            } else {
                sv_report::Examined::not_run(rules, "it was not run")
            }
        })
        .collect()
}

/// The decisions held to the running app (`sv_check::decisions::not_held_to`), then what a person
/// set aside (`review`). In that order, so a review of a decision's own finding is applied like any
/// other (the review of 6 October, item 7); and a decision whose running-app finding a person set
/// aside keeps no finding of its own, since a false alarm is not held against a decision either.
pub fn decisions_then_reviews(
    mut findings: Vec<sv_check::Finding>,
    decided: &[sv_check::decisions::Decided],
    review: impl FnOnce(Vec<sv_check::Finding>) -> sv_check::review::Outcome,
) -> sv_check::review::Outcome {
    let not_held = sv_check::decisions::not_held_to(decided, &findings);
    findings.extend(not_held);
    let mut reviewed = review(findings);
    let still_found: std::collections::BTreeSet<String> = reviewed
        .findings
        .iter()
        .map(|f| f.rule_id.clone())
        .collect();
    reviewed.findings.retain(|f| {
        f.rule_id != sv_check::decisions::NOT_HELD_TO
            || decided
                .iter()
                .any(|d| d.line == f.location.line && still_found.contains(d.switch.rule_id))
    });
    // What is left on one line of the code is one finding, the worst first, holding the others
    // (ADR-023, Later, 6 October 2026). After the reviews, which are each about one problem.
    reviewed.findings = sv_check::finding::one_per_line(std::mem::take(&mut reviewed.findings));
    reviewed
}

/// What tells a `[[finding-review]]` entry whose finding is gone from one whose finding was not
/// looked for this time, or that names a rule this version does not have (deep review R3). Read
/// from `examined`, so it says what the report says, and, for the checks that read the app's files,
/// from whether they read the entry's file.
pub struct ReviewLookup<'a> {
    pub app_dir: &'a Path,
    pub examined: &'a [sv_report::Examined],
    pub listing: &'a sv_scan::files::Listing,
    pub code: &'a sv_check::ast::AstScan,
    pub secrets: &'a sv_check::secrets::SecretScan,
    pub ast_rules: &'a sv_check::ast::AstRules,
    pub secret_rules: &'a sv_check::secrets::SecretRules,
}

pub fn untaught_gaps(untaught: &[sv_check::ast::Untaught]) -> Vec<sv_report::Gap> {
    untaught
        .iter()
        .map(|u| sv_report::Gap {
            what: format!(
                "{} ({}), in {}",
                u.title.trim_end_matches('.'),
                u.rule_id,
                u.languages.join(", ")
            ),
            why: format!(
                "this rule has not been taught what to look for in {}, so it claims nothing for this \
                 app; what it found elsewhere stands",
                u.languages.join(" or ")
            ),
        })
        .collect()
}

/// Up to five files, in backquotes, and how many more there are.
pub fn shown_files(files: &[String]) -> String {
    let mut shown: Vec<String> = files.iter().take(5).map(|f| format!("`{f}`")).collect();
    if files.len() > 5 {
        shown.push(format!("and {} more", files.len() - 5));
    }
    shown.join(", ")
}

/// Where the data lives: the OWASP frameworks and knowledge files, and sv's own files beside them, all in the
/// repository's `data/` folder.
pub fn data_dir() -> Result<PathBuf> {
    sv_frameworks::data::dir().map_err(anyhow::Error::msg)
}

/// The v2 overlay, which replaces the applicability rules whose reasons describe v1's own template.
pub fn overlay_path() -> PathBuf {
    sv_frameworks::data::file("applicability-v2.json")
}

/// The OWASP data with the checklist's levels grounded in ASVS. Every command loads it this way, so
/// no two of them can disagree about which controls apply at a level.
pub fn load_frameworks(data: &std::path::Path) -> Result<Frameworks> {
    let mut frameworks =
        Frameworks::load(&data.join("frameworks")).context("loading the OWASP frameworks")?;
    frameworks
        .apply_crosswalk(&crosswalk_path())
        .context("grounding the Secure by Design levels in ASVS")?;
    Ok(frameworks)
}

/// What each `derived` condition looks like in real code.
pub fn signatures_path() -> PathBuf {
    sv_frameworks::data::file("tech-signatures.json")
}

/// Rules that read the code itself.
pub fn ast_rules_path() -> PathBuf {
    sv_frameworks::data::file("ast-rules.json")
}

/// Well-known credential formats.
pub fn secret_rules_path() -> PathBuf {
    sv_frameworks::data::file("secret-rules.json")
}

/// How each manifest claim is checked against the code.
pub fn corroborators_path() -> PathBuf {
    sv_frameworks::data::file("claim-corroborators.json")
}

/// The routes stackvet.toml names that read a body, as `(method, path)`: where a body that does
/// not parse is sent, signed out, to see the app's error answers (ADR-056).
pub fn body_routes(users: Option<&sv_manifest::UsersSection>) -> Vec<(String, String)> {
    let Some(users) = users else {
        return Vec::new();
    };
    users
        .signup
        .iter()
        .chain(users.login.iter())
        .chain(users.owned.iter().map(|o| &o.create))
        .map(|t| (t.method.clone(), t.path.clone()))
        .collect()
}

/// The admin pages stackvet.toml names, and the files in the app's folder that should never be
/// served, for the questions in `sv_check::running`. Worked out the same way for the requests and
/// for reading the answers, so the two agree on what was asked.
pub fn more_questions(plan: &RunPlan) -> (Vec<String>, Vec<sv_check::running::PrivateFile>) {
    let admin_pages = plan
        .users
        .as_ref()
        .map(|users| users.admin.clone())
        .unwrap_or_default();
    let listing = sv_scan::files::Listing::of(&plan.app_dir);
    (admin_pages, sv_check::running::private_files(&listing))
}

/// The Secure by Design checklist's controls against the ASVS requirements that ask the same thing.
pub fn crosswalk_path() -> PathBuf {
    sv_frameworks::data::file("sbd-asvs-crosswalk.json")
}

impl ReviewLookup<'_> {
    fn looked(&self, rule: &str, file: &str) -> sv_check::review::Looked {
        use sv_check::review::Looked;
        if !self.known(rule) {
            return Looked::Unknown;
        }
        let Some(deciding) = sv_report::Examined::deciding(self.examined, rule) else {
            return Looked::NotThisTime(
                "nothing in this run looks for findings of its kind".to_owned(),
            );
        };
        let why = deciding
            .why
            .clone()
            .unwrap_or_else(|| "no reason was recorded".to_owned());
        match deciding.state {
            sv_report::ExaminedState::NotRun | sv_report::ExaminedState::NothingToExamine => {
                Looked::NotThisTime(why)
            }
            // The checks that read the app's files can say whether they read this one, which is
            // what matters for a finding in it, whatever else they did not read.
            _ if ["ast.", "secrets.", "config."]
                .iter()
                .any(|p| rule.starts_with(p)) =>
            {
                match self.file_not_read(rule, file) {
                    Some(why) => Looked::NotThisTime(why),
                    None => Looked::Ran,
                }
            }
            sv_report::ExaminedState::Partly => {
                Looked::NotThisTime(format!("it covered only part of the app: {why}"))
            }
            sv_report::ExaminedState::Ran => Looked::Ran,
        }
    }

    /// Whether this version of `sv` has the rule. Exactly, for the rules read from `data/`; for the
    /// checks written in Rust and the outside tools, whose rule names are not listed anywhere `sv`
    /// can read, by the family alone.
    fn known(&self, rule: &str) -> bool {
        if rule.starts_with("ast.") {
            return self.ast_rules.rules().any(|r| r.id == rule);
        }
        if rule.starts_with("secrets.") {
            return rule == sv_check::secrets::ASSIGNMENT_RULE
                || self.secret_rules.ids().contains(&rule);
        }
        sv_check::finding::is_svs_own(rule)
            || sv_report::Examined::deciding(self.examined, rule).is_some()
    }

    /// Why the check that reports `rule` did not read `file` this time, if it did not. A file that
    /// is not there at all was not skipped: the finding in it is gone with it.
    fn file_not_read(&self, rule: &str, file: &str) -> Option<String> {
        if self
            .listing
            .links
            .iter()
            .any(|l| file == l || file.starts_with(&format!("{l}/")))
        {
            return Some(format!(
                "`{file}` is behind a symbolic link, which was not followed"
            ));
        }
        let inside = Path::new(file)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)));
        if !inside || !self.app_dir.join(file).exists() {
            return None;
        }
        let Some(entry) = self.listing.files.iter().find(|e| e.relative == file) else {
            return Some(format!("`{file}` is not among the files this run read"));
        };
        if rule.starts_with("secrets.") {
            return self
                .secrets
                .coverage
                .skipped
                .iter()
                .find(|(f, _)| f == file)
                .map(|(_, why)| format!("`{file}` was not read: {why}"));
        }
        if !rule.starts_with("ast.") {
            return None;
        }
        if let Some((_, why)) = self.code.unread_files.iter().find(|(f, _)| f == file) {
            return Some(format!("`{file}` was not opened: {why}"));
        }
        if self.code.unparsed_files.iter().any(|f| f == file) {
            return Some(format!(
                "`{file}` did not parse cleanly, so part of it was not read"
            ));
        }
        let Some(language) = entry.language else {
            return Some(format!(
                "the rules that read code read no files like `{file}`"
            ));
        };
        if self.code.unread_languages.contains(language) {
            return Some(format!("there is no parser for {language} here"));
        }
        if self
            .code
            .untaught
            .iter()
            .any(|u| u.rule_id == rule && u.languages.iter().any(|l| l == language))
        {
            return Some(format!("the rule has not been taught {language}"));
        }
        if let Some(broken) = self
            .code
            .broken_queries
            .iter()
            .find(|b| b.rule_id == rule && b.language == language)
        {
            return Some(format!(
                "its query for {language} would not compile: {}",
                broken.why
            ));
        }
        None
    }
}

pub mod brief;

pub mod connect;

pub mod explain;

pub mod parts;

pub mod plan;

pub mod preflight;

/// The plan for an app from its brief, built from the report's own parts (ADR-030).
pub fn plan_for(app_dir: &Path, report: &sv_report::Report) -> Result<plan::Plan> {
    let (manifest, _) = Manifest::load_in(app_dir)?;
    Ok(plan::from_report(report, &manifest, &design_prompts()?))
}

/// The options a plan's report is built with: nothing started and no tool run, since a plan reads
/// the brief and needs no code.
pub fn plan_options() -> ReportOptions {
    ReportOptions::reading_only("`sv plan`")
}

/// The features a brief can be written for (`sv brief`, `stackvet_before`).
pub fn feature_briefs_path() -> PathBuf {
    sv_frameworks::data::file("feature-briefs.json")
}

/// The brief for one feature of an app, from the report's own parts, as the plan is.
pub fn brief_for(
    report: &sv_report::Report,
    feature: &str,
    loaded: &Loaded,
) -> Result<brief::Brief> {
    let features = brief::Features::load(&feature_briefs_path())?;
    let feature = features.get(feature)?;
    let brought = brief::brought(feature, &loaded.frameworks, &loaded.config_rules);
    let rules = sv_check::coding_rules::CodingRules::load(&coding_rules_path())?;
    Ok(brief::from_report(
        report,
        feature,
        &brought,
        &loaded.frameworks,
        &design_prompts()?,
        &coding_prompts()?,
        &rules,
    ))
}

/// One feature's brief for an app with no `stackvet.toml` yet: what the feature brings, whole,
/// with what only the file can decide said to be waiting for it.
pub fn brief_without_manifest(feature: &str, loaded: &Loaded) -> Result<brief::Brief> {
    let features = brief::Features::load(&feature_briefs_path())?;
    let feature = features.get(feature)?;
    let brought = brief::brought(feature, &loaded.frameworks, &loaded.config_rules);
    let rules = sv_check::coding_rules::CodingRules::load(&coding_rules_path())?;
    Ok(brief::without_manifest(
        feature,
        &brought,
        &loaded.frameworks,
        &design_prompts()?,
        &coding_prompts()?,
        &rules,
    ))
}

/// The design-time prompts, read on their own: the second of the library's files.
pub fn design_prompts() -> Result<sv_check::prompts::Prompts> {
    let paths = prompts_paths();
    sv_check::prompts::Prompts::load_all(&[&paths[1]])
}

/// The coding prompts, read on their own: the first of the library's files.
pub fn coding_prompts() -> Result<sv_check::prompts::Prompts> {
    let paths = prompts_paths();
    sv_check::prompts::Prompts::load_all(&[&paths[0]])
}

/// The prompt library's files: the prompts for the coding, then the design-time ones.
pub fn prompts_paths() -> [PathBuf; 2] {
    [
        sv_frameworks::data::file("prompts.json"),
        sv_frameworks::data::file("design-prompts.json"),
    ]
}

pub mod report_files;

pub mod report_folder;

pub mod build_loop;

pub mod report_seal;

/// The coding prompts shown to work, in full, for the two places every builder reads before any code:
/// the end of the specification (`sv init`, `stackvet_spec`) and of the MCP server's opening
/// instructions. In the delivery test (docs/prompts/library-trial/delivery.md) a prompt pasted where
/// the builder starts did better than the same prompt fetched mid-build, every time. Read from
/// `data/prompts.json`, so the list cannot drift from the library; empty if it cannot be read.
pub fn prompts_at_start() -> String {
    let Ok(library) = coding_prompts() else {
        return String::new();
    };
    let shown: Vec<_> = library
        .prompts
        .iter()
        .filter(|p| p.status == sv_check::prompts::Status::Shown)
        .collect();
    if shown.is_empty() {
        return String::new();
    }
    let mut out = String::from(
        "\n## Prompts shown to work\n\nEach of these was given to an AI coding tool building an app, \
         and `sv` found that the problem it is for went away (docs/PROMPTS.md). Follow them while you \
         build, as you follow the rest of these instructions:\n",
    );
    for p in shown {
        out.push_str(&format!(
            "\n### {} (`{}`)\n\n{}\n\n{}\n",
            p.title,
            p.id,
            p.status_sentence(),
            p.prompt
        ));
    }
    out
}

/// The coding prompts shown to work that no feature's brief gives, because none of their
/// requirements is one a feature brings (security headers, keys kept out of the code): the ones
/// for the whole app, which `stackvet_guidance` gives with its rules. Each shown prompt so reaches
/// a builder once, from the brief for its feature or from the guidance read before any code.
pub fn whole_app_prompts(loaded: &Loaded) -> Result<Vec<sv_check::prompts::Prompt>> {
    let features = brief::Features::load(&feature_briefs_path())?;
    let mut brought = std::collections::BTreeSet::new();
    for f in &features.features {
        brought.extend(brief::brought(f, &loaded.frameworks, &loaded.config_rules).all);
    }
    Ok(coding_prompts()?
        .prompts
        .into_iter()
        .filter(|p| p.status == sv_check::prompts::Status::Shown)
        .filter(|p| !p.requirements.iter().any(|r| brought.contains(r)))
        .collect())
}

/// Reads the coding rules and leaves out those whose every cited requirement does not apply to the
/// app. Prints nothing, because the MCP server's stdout is the protocol.
pub fn coding_rules_for(app_dir: &Path) -> Result<RulesForApp> {
    let rules = sv_check::coding_rules::CodingRules::load(&coding_rules_path())?;
    let excluded: Option<std::collections::BTreeSet<String>> =
        if let Some(located) = sv_manifest::locate(app_dir)? {
            let manifest = Manifest::load(&located.path)?;
            let data = data_dir()?;
            let frameworks = load_frameworks(&data)?;
            let config = ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay_path())?;
            let signatures = Signatures::load_all(&[&signatures_path(), &corroborators_path()])?;
            let scan_report = scan_for(
                &manifest,
                &sv_scan::files::Listing::of(app_dir),
                &signatures,
            )?;
            let (ctx, _) = sv_manifest::resolve(&manifest, &scan_report.as_corroborator());
            let buckets = bucket(&frameworks, &config, &ctx, manifest.target_level());
            Some(buckets.not_applicable.into_iter().map(|n| n.id).collect())
        } else {
            None
        };
    let is_excluded = |id: &str| excluded.as_ref().is_some_and(|set| set.contains(id));
    let given: Vec<String> = rules
        .for_app(
            excluded
                .as_ref()
                .map(|_| &is_excluded as &dyn Fn(&str) -> bool),
        )
        .into_iter()
        .map(|r| r.id.clone())
        .collect();
    let withheld = rules.rules.len() - given.len();
    Ok(RulesForApp {
        filtered: excluded.is_some(),
        rules,
        given,
        withheld,
    })
}

/// The library's prompts for one requirement, or all of them, as Markdown, and the ones chosen.
///
/// An id that is not a requirement is refused, so a mistyped one is never answered "no prompt for
/// it" as if the library had been searched for it.
pub fn prompts_for(
    frameworks: &Frameworks,
    requirement: Option<&str>,
) -> Result<(sv_check::prompts::Prompts, Vec<String>, String)> {
    if let Some(id) = requirement {
        anyhow::ensure!(
            frameworks.get(id).is_some(),
            "{id} is not a requirement or a Secure by Design control in any loaded framework"
        );
    }
    let paths = prompts_paths();
    let prompts = sv_check::prompts::Prompts::load_all(&[&paths[0], &paths[1]])?;
    let chosen = prompts.select(requirement);
    let ids = chosen.iter().map(|p| p.id.clone()).collect();
    let text = match (requirement, chosen.is_empty()) {
        (Some(id), true) => {
            format!("No prompt in the library targets {id} yet. `sv prompts` lists all of them.\n")
        }
        _ => prompts.markdown(&chosen),
    };
    Ok((prompts, ids, text))
}

/// The prompts for the requirements an app's last report shows with no evidence (the owner's
/// decision of 3 October 2026, "`sv` can offer the right prompt for a requirement that still has no
/// evidence"). Read from the report, so it says what the report said when it was written: a new
/// report is the only way to see what changed since.
///
pub fn prompts_for_report(report: &Path) -> Result<ReportPrompts> {
    let text = std::fs::read_to_string(report).map_err(|e| {
        anyhow::anyhow!(
            "there is no report to read at {} ({e}). Make one first: `sv report`, or \
             `stackvet_write_report` from the AI coding tool.",
            report.display()
        )
    })?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not a report `sv` can read", report.display()))?;
    let gaps = sv_check::prompts::gaps_in_report(&json)
        .with_context(|| format!("reading {}", report.display()))?;
    let paths = prompts_paths();
    let prompts = sv_check::prompts::Prompts::load_all(&[&paths[0], &paths[1]])?;
    let offered = prompts.for_gaps(&gaps);
    let markdown = prompts.gaps_markdown(&offered, &gaps, &format!("`{}`", report.display()));
    let offered = offered
        .iter()
        .map(|(p, ids)| (p.id.clone(), ids.clone()))
        .collect();
    Ok(ReportPrompts {
        prompts,
        offered,
        gaps,
        text: markdown,
    })
}

/// What `prompts_for_report` found: the library, the ids offered with the requirements each is
/// for, the requirements the report shows unproven with their status, and the offer as text.
pub struct ReportPrompts {
    pub prompts: sv_check::prompts::Prompts,
    pub offered: Vec<(String, Vec<String>)>,
    pub gaps: std::collections::BTreeMap<String, String>,
    pub text: String,
}

/// Writes or refreshes security-notes.md, keeping everything in it that `sv` did not write: the
/// answers under their questions, and any other text in a section of its own. Shared by `sv notes`
/// and the MCP server, and prints nothing, because the MCP server's stdout is the protocol.
pub fn write_notes_file(app_dir: &Path) -> Result<NotesWritten> {
    write_notes(app_dir, None)
}

/// Writes the notes file with the AI coding tool's answer under one question, marked as the tool's.
///
/// Refused when the question does not apply to the app, when the section holds anything but
/// the tool's own marked answer (`Answers::tool_may_write`: the tool's answer never replaces what
/// may be the owner's), and when the answer would not read back as exactly the
/// tool's (`sv_check::notes::tool_answer`). Written under a new name and renamed into place, and
/// never through a link.
pub fn record_tool_answer(app_dir: &Path, id: &str, answer: &str) -> Result<NotesWritten> {
    write_notes(app_dir, Some((id, answer)))
}

/// Makes the zip from a report already built. `zip_abs` has been resolved and is outside the app; the caller
/// checked. Shared by `sv bundle` and the MCP tool, so what an AI tool is told is what the command says.
pub fn write_bundle(
    app_abs: &Path,
    zip_abs: &Path,
    report: &sv_report::Report,
    command: &str,
) -> Result<BundleOutcome> {
    let name = app_abs
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "app".to_owned());
    let folder = bundle::safe_name(&name);
    // What goes in, decided from what the credential scan found and could not read.
    let rules = SecretRules::load(&secret_rules_path())?;
    let scan = scan_dir(&rules, app_abs);
    let plan = bundle::plan(app_abs, &scan);
    let categories = Manifest::load_in(app_abs)
        .map(|(m, _)| m.data.listed().to_vec())
        .unwrap_or_default();

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for rel in &plan.include {
        let bytes = std::fs::read(app_abs.join(rel)).with_context(|| format!("reading {rel}"))?;
        entries.push((format!("{folder}/app/{rel}"), bytes));
    }
    // The report on its way into the zip is written to a folder of this run's own in the system's
    // temporary folder, readable by this user alone and named so nobody can guess it, and removed
    // with everything in it when `private` is dropped, however this returns (ADR-017, Later, 8
    // October 2026). It used to be a folder named by the process id and the time, which anyone
    // on the computer could name first and read.
    let private = sv_check::adapters::PrivateFolder::new_in(&std::env::temp_dir())
        .context("making a private folder for the report on its way into the zip")?;
    let scratch = private.path().to_path_buf();
    let written = write_report_files(report, &scratch);
    let sbom_json =
        serde_json::to_string_pretty(&sbom::to_cyclonedx(&sbom::build(app_abs)))? + "\n";
    let report_files: Result<Vec<(String, Vec<u8>)>> = written.and_then(|names| {
        names
            .iter()
            .map(|n| {
                Ok((
                    format!("{folder}/report/{n}"),
                    std::fs::read(scratch.join(n))?,
                ))
            })
            .collect()
    });
    drop(private);
    let report_files = report_files?;
    refuse_a_credential_in_the_report(&rules, &report_files)?;
    entries.extend(report_files);
    entries.push((
        format!("{folder}/report/sbom.cdx.json"),
        sbom_json.into_bytes(),
    ));

    let made_at = bundle::utc_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let listing = bundle::listing(
        &bundle::Made {
            sv_version: env!("CARGO_PKG_VERSION"),
            commit: env!("SV_GIT_COMMIT"),
            made_at: &made_at,
            command,
            app_name: &name,
            categories: &categories,
        },
        &entries,
        &plan,
    );
    let readme = bundle::readme(&name, &made_at, plan.include.len(), &plan, &categories);
    entries.push((
        format!("{folder}/BUNDLE.json"),
        (serde_json::to_string_pretty(&listing)? + "\n").into_bytes(),
    ));
    entries.push((format!("{folder}/README.txt"), readme.into_bytes()));

    let bytes = bundle::zip(&entries)?;
    if let Some(parent) = zip_abs.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    // Not through a link: a bundle name in the folder beside the app that is a link to another file had
    // that file overwritten (deep review S4).
    refuse_link(zip_abs, FILE_LINK)?;
    // A bundle replaces only one `sv` made: a file of the owner's at that name, given with --out by
    // mistake or there before, is not written over (the deep review's improvement 7).
    if std::fs::symlink_metadata(zip_abs).is_ok() && !bundle::made_by_sv(zip_abs) {
        bail!(
            "{} is already there, and is not a bundle sv made, so it is not written over. Give \
             another name with --out, or move that file first.",
            zip_abs.display()
        );
    }
    let (Some(parent), Some(file_name)) = (zip_abs.parent(), zip_abs.file_name()) else {
        bail!("{} is not a file name", zip_abs.display());
    };
    let Some(file_name) = file_name.to_str() else {
        bail!("{} is not a file name sv can write", zip_abs.display());
    };
    write_without_following(parent, file_name, &bytes)?;
    Ok(BundleOutcome {
        zip: zip_abs.to_path_buf(),
        kilobytes: bytes.len() / 1024,
        files: entries.len(),
        included: plan.include.len(),
        left_out: plan.left_out,
        categories,
    })
}

/// Every name `sv` writes in a report folder: the marker, the lock, and the five reports. A test
/// holds this to what `write_report_files` writes. Kept in `sv-scan`, whose walk leaves a report
/// folder out only while it holds nothing but these (deep review H6).
pub const REPORT_FOLDER_NAMES: &[&str] = sv_scan::ecosystems::REPORT_FOLDER_NAMES;

/// Writes the reports.
///
/// Everything here runs offline and without a container. The probes need a running app, so unless
/// `sv run` has been used they are recorded as a gap rather than as nothing to report — a section
/// missing from a report reads as a section with nothing in it.
/// Writes the five renderings of a report into `out_dir`, and says which were written.
///
/// The report folder usually sits inside the app, and an app can hold links, so nothing here follows
/// one: a folder or a file that is a link is refused, and each file is written under a new name and
/// renamed into place, since a rename replaces a link rather than writing through it. `std::fs::write`
/// follows a link, and did: a `report.json` that was a link to a file outside the app had that file
/// replaced by the report (BACKLOG, "Hardening the MCP server", item 1).
pub fn write_report_files(report: &sv_report::Report, out_dir: &Path) -> Result<Vec<&'static str>> {
    Ok(write_report(report, out_dir)?.names())
}

/// Refuses a path that is a link, whatever it points to, saying so in the owner's terms and saying
/// what to do instead.
pub fn refuse_link(path: &Path, what_to_do: &str) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path)
        && meta.file_type().is_symlink()
    {
        return Err(Remedy::error(
            format!(
                "{} is a link to somewhere else, so sv does not read or write through it.",
                path.display()
            ),
            what_to_do,
        ));
    }
    Ok(())
}

/// What went wrong, and what `sv` itself says to do about it, kept apart. The MCP server fences what
/// went wrong as the app's text, since it quotes the app as often as not, and writes the next step
/// outside the fence as `sv`'s own words, which an AI coding tool reading a fenced instruction as
/// information did not act on (`docs/GAP-ANALYSIS.md`, 5.3). At a terminal the two read as one, as
/// before. `next` is `sv`'s words only: nothing of the app's goes in it.
#[derive(Debug)]
pub struct Remedy {
    pub problem: String,
    pub next: String,
}

impl Remedy {
    /// The error that carries `problem` and `next`.
    pub fn error(problem: impl Into<String>, next: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Remedy {
            problem: problem.into(),
            next: next.into(),
        })
    }
}

impl std::fmt::Display for Remedy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.problem, self.next)
    }
}

impl std::error::Error for Remedy {}

pub fn assemble_report(
    app_dir: &Path,
    options: &ReportOptions,
    loaded: &Loaded,
) -> Result<sv_report::Report> {
    assemble_report_saying(app_dir, options, loaded, &|_, _| {})
}

/// The coding rules for an app, and how many were left out as not applying to it.
pub struct RulesForApp {
    pub rules: sv_check::coding_rules::CodingRules,
    /// The ids of the rules given, in the file's order.
    pub given: Vec<String>,
    pub withheld: usize,
    /// Whether stackvet.toml was there to filter by. Without it every rule is given.
    pub filtered: bool,
}

impl RulesForApp {
    pub fn markdown(&self, topic: Option<&str>) -> String {
        let given: Vec<&sv_check::coding_rules::Rule> = self
            .rules
            .rules
            .iter()
            .filter(|r| self.given.contains(&r.id) && topic.is_none_or(|t| r.topic == t))
            .collect();
        self.rules
            .markdown(&given, if topic.is_none() { self.withheld } else { 0 })
    }

    /// Every rule given, as `sv rules` writes them into `AGENTS.md`.
    pub fn agents_markdown(&self) -> String {
        let given: Vec<&sv_check::coding_rules::Rule> = self
            .rules
            .rules
            .iter()
            .filter(|r| self.given.contains(&r.id))
            .collect();
        self.rules.agents_markdown(&given, self.withheld)
    }
}

/// What writing the notes file came to.
pub struct NotesWritten {
    pub path: PathBuf,
    /// Sections for requirements that apply.
    pub asked: usize,
    /// Of those, how many were already answered.
    pub already: usize,
    /// Whether the file has text that is not under a question, kept in a section of its own.
    pub kept: bool,
}

pub fn write_notes(app_dir: &Path, record: Option<(&str, &str)>) -> Result<NotesWritten> {
    let manifest = Manifest::load_in(app_dir)?.0;
    let data = data_dir()?;
    let frameworks = load_frameworks(&data)?;
    let config = ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay_path())?;
    let signatures = Signatures::load_all(&[&signatures_path(), &corroborators_path()])?;
    let scan_report = scan_for(
        &manifest,
        &sv_scan::files::Listing::of(app_dir),
        &signatures,
    )?;
    let (ctx, _) = sv_manifest::resolve(&manifest, &scan_report.as_corroborator());
    let buckets = bucket(&frameworks, &config, &ctx, manifest.target_level());
    let catalog = sv_check::notes::Catalog::load(&notes_path())?;

    let app_name = if manifest.app.name.is_empty() {
        "This app"
    } else {
        &manifest.app.name
    };
    let facts = notes_facts(&manifest, &scan_report, app_name);
    let applicable: std::collections::BTreeSet<String> =
        buckets.applicable.iter().cloned().collect();
    let out_path = app_dir.join(&catalog.file);
    // Before reading: a notes file that is a link would have what it points at read in as answers and
    // then written over, from `sv notes` as from the MCP tools (deep review S3).
    refuse_link(&out_path, FILE_LINK)?;
    // A file that is there but cannot be read as text is refused, never treated as absent: written
    // over with a fresh template, every answer in it would be gone (deep review R7).
    let existing = match std::fs::read(&out_path) {
        Ok(bytes) => Some(String::from_utf8(bytes).map_err(|_| {
            anyhow::anyhow!(
                "{} is not plain text (UTF-8), so `sv` cannot keep what is in it and has written \
                 nothing. Save it as UTF-8 text in your editor and run this again.",
                out_path.display()
            )
        })?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "{} could not be read, so `sv` has written nothing over it",
                    out_path.display()
                )
            });
        }
    };
    let already = existing
        .as_deref()
        .map(|text| {
            sv_check::notes::read_answers(&catalog, text)
                .answered()
                .len()
        })
        .unwrap_or(0);

    let describe = |id: &str| {
        frameworks
            .requirements
            .get(id)
            .map(|r| r.description.clone())
    };
    let Some((id, answer)) = record else {
        let text = sv_check::notes::write_template(
            &catalog,
            &applicable,
            &facts,
            existing.as_deref(),
            &describe,
        )
        .map_err(|why| anyhow::anyhow!(why))?;
        write_without_following(app_dir, &catalog.file, text.as_bytes())?;
        let asked = catalog
            .sections
            .iter()
            .filter(|s| applicable.contains(&s.id))
            .count();
        return Ok(NotesWritten {
            path: out_path,
            asked,
            already,
            kept: text.contains(sv_check::notes::KEPT_HEADING),
        });
    };
    anyhow::ensure!(
        catalog.section(id).is_some() && applicable.contains(id),
        "{id} is not one of the questions in {} for this app; stackvet_questions lists the ones \
         that are",
        catalog.file
    );
    let mut answers = existing
        .as_deref()
        .map(|text| sv_check::notes::read_answers(&catalog, text))
        .unwrap_or_default();
    // Only an empty question or the tool's own answer: anything else may be the owner's words
    // (deep review R8). Refused before anything is written, so the file is left as it was.
    answers
        .tool_may_write(id, &catalog.file)
        .map_err(|why| anyhow::anyhow!(why))?;
    let body = sv_check::notes::tool_answer(answer).map_err(|why| anyhow::anyhow!(why))?;
    answers.set(id, body);
    let text =
        sv_check::notes::write_template_with(&catalog, &applicable, &facts, &answers, &describe)
            .map_err(|why| anyhow::anyhow!(why))?;
    write_without_following(app_dir, &catalog.file, text.as_bytes())?;

    let asked = catalog
        .sections
        .iter()
        .filter(|s| applicable.contains(&s.id))
        .count();
    Ok(NotesWritten {
        path: out_path,
        asked,
        already,
        kept: text.contains(sv_check::notes::KEPT_HEADING),
    })
}

/// What `sv bundle` and the MCP tool made.
pub struct BundleOutcome {
    pub zip: PathBuf,
    pub kilobytes: usize,
    pub files: usize,
    pub included: usize,
    pub left_out: Vec<(String, String)>,
    pub categories: Vec<String>,
}

impl BundleOutcome {
    /// What is said to the person, on the screen and in the AI tool alike.
    pub fn summary(&self) -> String {
        self.summary_with(&sv_report::fence::Fence::none())
    }

    /// The same, with the app's own text (the zip's path, the files left out, what stackvet.toml
    /// says the app holds) put through `fence`, for the AI coding tool (deep review R9).
    pub fn summary_with(&self, fence: &sv_report::fence::Fence) -> String {
        let mut text = format!(
            "Wrote {} ({} files, {} KB).\n  {} of the app's files, the report, and a SHA-256 for every file in BUNDLE.json.\n",
            fence.wrap(&self.zip.display().to_string()),
            self.files,
            self.kilobytes,
            self.included
        );
        if self.left_out.is_empty() {
            text.push_str("Nothing was left out.\n");
        } else {
            text.push_str(&format!(
                "\nLeft out on purpose, so the zip carries no secret ({}):\n",
                self.left_out.len()
            ));
            for (path, reason) in &self.left_out {
                text.push_str(&format!(
                    "  {}: {}\n",
                    fence.wrap(path),
                    sv_report::one_line(reason)
                ));
            }
        }
        if !self.categories.is_empty() {
            text.push_str(&format!(
                "\nstackvet.toml says this app holds: {}. Those are not left out: sv cannot tell which files hold them.\n",
                fence.wrap(&self.categories.join(", "))
            ));
        }
        text.push_str(
            "\nsv cannot tell which files hold data about your app's people. It leaves out the database files it \
             recognizes by name, and nothing else: look through the zip before you hand it on.",
        );
        text
    }
}

/// Refuses to make the bundle when the report going into it holds something the credential scan
/// reads as a credential, naming the file, line and rule, never the value.
///
/// The backstop to redacting what outside tools say (deep review S8), and a guard for what the report
/// quotes of the app itself (its name in `stackvet.toml`, for one): Bandit's B105 message quoted a
/// password four times inside `report/` of a bundle that had left the file holding it out, so that the
/// zip carried no secret. `sv`'s own findings carry a credential only redacted, and a tool's words
/// are redacted as they are read (`adapters::redact_tool_text`); this is what holds if some other
/// text ever reaches a report unredacted. Refusing, not redacting the files here: a report changed on
/// its way into the zip would no longer be the one `sv` wrote, and the owner is told where to look.
pub fn refuse_a_credential_in_the_report(
    rules: &SecretRules,
    report_files: &[(String, Vec<u8>)],
) -> Result<()> {
    let mut found: Vec<String> = Vec::new();
    for (name, bytes) in report_files {
        let text = String::from_utf8_lossy(bytes);
        for f in sv_check::secrets::scan_text(rules, name, &text) {
            found.push(format!(
                "{} line {} ({})",
                sv_report::one_line(name),
                f.location.line,
                f.rule_id
            ));
        }
    }
    if found.is_empty() {
        return Ok(());
    }
    bail!(
        "the report holds {} thing{} the credential scan reads as a secret, so no bundle was made: \
         a bundle must never carry one. Where: {}. A report quotes some of what the app's own files \
         say, such as its name in stackvet.toml: take the credential out of the place it was \
         quoted from and run this again. If it came from nowhere in the app, it is a fault in sv: \
         please report it.",
        found.len(),
        if found.len() == 1 { "" } else { "s" },
        found.join("; ")
    )
}

/// Makes `out_dir` ready for a report and takes it for this run, before the run starts: the checks
/// `write_report_files` makes on the folder, made early so a refusal comes before the wait rather
/// than after it, and the lock (`report_lock`). The marker is written once the folder is held, so the
/// run's own reading of the app leaves the folder out.
///
/// A run that ends without writing its report leaves the folder as it found it: the marker goes if
/// this wrote it, and the folder if this made it (`made_by_caller`, for a caller that made it just
/// before) and nothing else is in it. Ctrl-C during `sv report --run` wrote no report and left the
/// folder behind, which `interrupt.rs` caught.
pub fn claim_report_folder(
    out_dir: &Path,
    command: &str,
    elsewhere: &str,
    made_by_caller: bool,
) -> Result<report_lock::Held> {
    refuse_link(out_dir, REPORT_LINK)?;
    let made = made_by_caller || std::fs::symlink_metadata(out_dir).is_err();
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    for name in REPORT_FOLDER_NAMES {
        refuse_link(&out_dir.join(name), REPORT_LINK)?;
    }
    let refused = refuse_someone_elses_folder(out_dir, REPORT_FOLDER_NAMES);
    let taken = refused.and_then(|()| report_lock::take(out_dir, command, elsewhere));
    let held = match taken {
        Ok(held) => held,
        Err(e) => {
            if made {
                let _ = std::fs::remove_dir(out_dir);
            }
            return Err(e);
        }
    };
    // The marker under either of its names (ADR-062): one already there is kept until the report
    // is written; a folder without one gets the new name.
    let marker = sv_scan::ecosystems::report_marker_in(out_dir)
        .unwrap_or_else(|| out_dir.join(sv_scan::ecosystems::REPORT_MARKER));
    held.undo_unless_written(
        (!marker.is_file()).then(|| marker.clone()),
        made.then(|| out_dir.to_path_buf()),
    );
    // Part-written files a stopped run left. Held, so no other run of this `sv` is writing them now.
    if let Ok(entries) = std::fs::read_dir(out_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if is_staging(&entry.file_name().to_string_lossy(), REPORT_FOLDER_NAMES) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    // A marker already there is kept until the report is written: it may carry the seal that lets
    // the report go beside a file of the owner's (`refuse_someone_elses_folder`), and the report's
    // own writing and sealing replace it.
    if !marker.is_file() {
        write_without_following(
            out_dir,
            sv_scan::ecosystems::REPORT_MARKER,
            REPORT_MARKER_TEXT.as_bytes(),
        )
        .context("writing the report folder's marker")?;
    }
    Ok(held)
}

/// The report files written, each with the text written to it, which is what a seal is made from.
pub struct Written {
    pub contents: Vec<(&'static str, String)>,
}

impl Written {
    pub fn names(&self) -> Vec<&'static str> {
        self.contents.iter().map(|(name, _)| *name).collect()
    }
}

/// `write_report_files`, keeping what was written.
pub fn write_report(report: &sv_report::Report, out_dir: &Path) -> Result<Written> {
    // Before the folder is created: creating it would follow a link to a folder that does not exist yet.
    refuse_link(out_dir, REPORT_LINK)?;
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    // Marks the folder as `sv`'s own output, so the next check of the app does not read the report
    // as the app's code, whatever the folder is called (`sv_scan::ecosystems::REPORT_MARKER`).
    let marker = (
        sv_scan::ecosystems::REPORT_MARKER,
        REPORT_MARKER_TEXT.to_owned(),
    );
    let written: Vec<(&'static str, String)> = report_files::REPORT_FILES
        .iter()
        .map(|file| (file.name, (file.render)(report)))
        .collect();
    // Every name is looked at before any is written, so a refusal leaves the folder as it was.
    for (name, _) in std::iter::once(&marker).chain(&written) {
        refuse_link(&out_dir.join(name), REPORT_LINK)?;
    }
    refuse_someone_elses_folder(out_dir, REPORT_FOLDER_NAMES)?;
    for (name, contents) in std::iter::once(&marker).chain(&written) {
        write_without_following(out_dir, name, contents.as_bytes())
            .with_context(|| format!("writing {name}"))?;
    }
    Ok(Written { contents: written })
}

/// What to do about a link where `sv` writes one of its own files into the app.
pub const FILE_LINK: &str = "Remove the link, and run it again.";

/// Writes `name` in `dir` without following a link at that name: the bytes go to a file that did not
/// exist before (`create_new` refuses a link as it refuses anything already there), which is then
/// renamed over `name`. A link put at `name` after `refuse_link` looked is replaced, never written
/// through.
pub fn write_without_following(dir: &Path, name: &str, contents: &[u8]) -> Result<()> {
    let target = dir.join(name);
    let staging = dir.join(format!(".{name}.sv-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staging)
        .with_context(|| format!("{} could not be created", staging.display()))?;
    let written = std::io::Write::write_all(&mut file, contents).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = written.and_then(|()| std::fs::rename(&staging, &target)) {
        let _ = std::fs::remove_file(&staging);
        return Err(e).with_context(|| format!("{} could not be written", target.display()));
    }
    Ok(())
}

/// The scan every command reads the app with: the folders the manifest says are not the app are
/// left out of what counts as evidence about it. One place, so no command reads them as the app.
pub fn scan_for(
    manifest: &Manifest,
    listing: &sv_scan::files::Listing,
    signatures: &Signatures,
) -> Result<sv_scan::ScanReport> {
    sv_scan::scan_listing_app(listing, signatures, &manifest.not_the_app().0)
}

/// What `sv` found that belongs in the notes, so the owner starts from their app, not a blank page.
pub fn notes_facts(
    manifest: &Manifest,
    scan_report: &sv_scan::ScanReport,
    app_name: &str,
) -> sv_check::notes::Facts {
    // Each outside service is named by the thing that showed it, never by the condition alone: "the
    // `stripe` package in package.json" is something the owner can go and look at, and "payments"
    // is something they have to take on trust.
    let mut outside_services: Vec<String> = Vec::new();
    for answer in &scan_report.answers {
        if answer.value != Some(true) {
            continue;
        }
        if !matches!(
            answer.condition,
            Condition::ExternalApis | Condition::Payments | Condition::Email | Condition::Ai
        ) {
            continue;
        }
        if let sv_scan::Evidence::Dependency { name, manifest } = &answer.evidence {
            let line = format!("the `{name}` package in {manifest}");
            if !outside_services.contains(&line) {
                outside_services.push(line);
            }
        }
    }
    // The manifest's own list of hosts, which the code cannot show and the owner already wrote.
    for host in manifest
        .capabilities
        .external_apis
        .iter()
        .flatten()
        .filter(|h| !h.is_empty())
    {
        let line = format!("{host}, from stackvet.toml");
        if !outside_services.contains(&line) {
            outside_services.push(line);
        }
    }

    sv_check::notes::Facts {
        app_name: app_name.to_owned(),
        data_categories: manifest.data.listed().to_vec(),
        outside_services,
        ecosystems: scan_report
            .ecosystems
            .iter()
            .map(|e| format!("{} ({})", e.name, e.manifest))
            .collect(),
        uploads: manifest.capabilities.uploads,
        sign_in: manifest.capabilities.auth,
    }
}

pub const REPORT_MARKER_TEXT: &str =
    "This folder holds a report written by sv. sv leaves it out when it checks the app.\n";

/// Seals the report just written in `out_dir` (`report_seal`), so `sv`'s MCP server can show it is
/// `sv`'s before offering it as one. Whether it was sealed, and what the person should be told: that
/// the report key was made, or why the report could not be sealed. The report stands either way.
fn seal_report_folder(out_dir: &Path, written: &Written) -> (bool, Vec<String>) {
    let bytes: Vec<(&str, &[u8])> = written
        .contents
        .iter()
        .map(|(name, text)| (*name, text.as_bytes()))
        .collect();
    match report_seal::seal(out_dir, REPORT_MARKER_TEXT, &bytes) {
        Ok(sealed) => (
            true,
            sealed
                .made_key
                .map(|key| {
                    format!(
                        "Made {}, the key sv seals its reports with on this computer, so its MCP \
                         server can tell a report it wrote from one anything else put in the app. \
                         It is kept outside every app's folder, and never printed.",
                        key.display()
                    )
                })
                .into_iter()
                .collect(),
        ),
        Err(why) => (
            false,
            vec![format!(
                "The report could not be sealed ({why}), so sv's MCP server will not offer it to an \
                 AI coding tool as a report sv wrote. The report itself is complete."
            )],
        ),
    }
}

/// Refuses to write a report into a folder that holds anything but `sv`'s own files, unless `sv` marked
/// it as its own and this computer can show, by its seal, that `sv` wrote the report there; and,
/// marked or not, one holding a file whose name differs from one of `sv`'s only in capitals.
///
/// A report written with `out` "." landed in the app itself, and on a disk that does not tell capitals
/// apart (macOS and Windows, by default) its `security.md` replaced the app's own `SECURITY.md` (deep
/// review S5). A folder holding only names `sv` writes, as a report from before the marker had, is
/// taken as `sv`'s; the marker itself is checked by its exact name, so the app's files are never
/// mistaken for it.
pub fn refuse_someone_elses_folder(out_dir: &Path, ours: &[&str]) -> Result<()> {
    let Ok(entries) = std::fs::read_dir(out_dir) else {
        return Ok(());
    };
    let names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    let like_ours: Vec<&String> = names
        .iter()
        .filter(|name| {
            !ours.contains(&name.as_str()) && ours.iter().any(|o| o.eq_ignore_ascii_case(name))
        })
        .collect();
    anyhow::ensure!(
        like_ours.is_empty(),
        "{} holds {}, which a report file would replace on a disk that does not tell capitals apart, \
         so sv does not write its report there. Give a folder of its own with --out.",
        out_dir.display(),
        like_ours
            .iter()
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let marked = names.iter().any(|name| {
        name == sv_scan::ecosystems::REPORT_MARKER
            || name == sv_frameworks::names::OLD_REPORT_MARKER
    });
    let others: Vec<&String> = names
        .iter()
        .filter(|name| !ours.contains(&name.as_str()) && !is_staging(name, ours))
        .collect();
    if others.is_empty() {
        return Ok(());
    }
    // Beside files `sv` did not write, only in a folder whose last report this computer can show it
    // sealed: the marker alone can be planted in any of the app's folders (the review of 8 October,
    // item 4), and a seal cannot be made without the report key.
    let named = format!(
        "{}{}",
        others
            .iter()
            .take(3)
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", "),
        if others.len() > 3 { ", and more" } else { "" }
    );
    if !marked {
        anyhow::bail!(
            "{} already holds files sv did not write ({named}), so sv does not write its report \
             there. Give an empty folder, or a new one, with --out.",
            out_dir.display()
        );
    }
    if let Err(why) = report_seal::sealed_here(out_dir) {
        anyhow::bail!(
            "{} carries sv's marker and also holds files sv did not write ({named}), and sv cannot \
             show it wrote the report there: {why}. A marker can be copied into any folder, so sv \
             does not write its report there. Give an empty folder, or a new one, with --out.",
            out_dir.display()
        );
    }
    Ok(())
}

/// Whether `name` is one of `ours` part-written by `write_without_following` (`.report.json.sv-4321`):
/// what a run stopped while writing leaves, and what a run writing at that moment has. Seen when two
/// runs started together: the second found the first's marker half-written, in a folder not yet
/// marked, and called the folder someone else's.
pub fn is_staging(name: &str, ours: &[&str]) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.rsplit_once(".sv-"))
        .is_some_and(|(base, pid)| {
            ours.contains(&base) && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
        })
}

/// What to do about a link where a report file or folder goes.
pub const REPORT_LINK: &str = "Remove the link, or give a folder of your own with --out.";

pub mod mcp;
