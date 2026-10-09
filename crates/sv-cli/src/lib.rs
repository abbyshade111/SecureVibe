//! The library behind `sv`: the report's assembly and what it needs, called by the command line and the MCP
//! server alike (BACKLOG, "From the architecture assessment of 8 October 2026", item 12).

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use sv_check::advisories;
use sv_check::ast;
use sv_check::probes;
use sv_check::sbom;
use sv_check::secrets::SecretRules;
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
    let mut plan = RunPlan::from_manifest(manifest, app_dir).map_err(|e| e.explain())?;
    plan.slow = slow;
    let backend = sv_run::detect().map_err(|e| e.explain())?;
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
    Ok((outcome.map_err(|e| e.explain())?, plan))
}

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
