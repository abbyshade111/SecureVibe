//! `sv` — run the SecureVibe checks against code written anywhere, in any language.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_check::advisories;
use sv_check::ast;
use sv_check::config::check_dir;
use sv_check::probes;
use sv_check::sbom;
use sv_check::secrets::{SecretRules, scan_dir};
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, bucket, requirements_gated_on};
use sv_frameworks::{Condition, Source};
use sv_manifest::{ClaimState, Manifest, consistency, spec};
use sv_run::RunPlan;
use sv_scan::{Evidence, Signatures, scan};

mod mcp;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("init") => {
            println!("{}", spec::STARTER_MANIFEST);
            println!("{}", spec::INSTRUCTIONS);
            Ok(())
        }
        Some("scope") => cmd_scope(args.get(1).map(PathBuf::from)),
        Some("notes") => cmd_notes(args.get(1).map(PathBuf::from)),
        Some("probe") => cmd_probe(&args[1..]),
        Some("run") => cmd_run(&args[1..]),
        Some("check") => cmd_check(args.get(1).map(PathBuf::from)),
        Some("sbom") => cmd_sbom(args.get(1).map(PathBuf::from)),
        Some("audit") => cmd_audit(&args[1..]),
        Some("report") => cmd_report(&args[1..]),
        Some("mcp") => mcp::cmd_mcp(&args[1..]),
        Some("--help") | Some("-h") | None => {
            print_help();
            Ok(())
        }
        Some(other) => {
            print_help();
            bail!("unknown command: {other}");
        }
    }
}

fn print_help() {
    println!(
        "sv — check an app against OWASP ASVS 5.0, AISVS 1.0 and Secure by Design.\n\n\
         USAGE:\n  \
         sv init            print the securevibe.toml spec to hand to your AI coding tool\n  \
         sv scope [PATH]    show which requirements apply to the app, and why\n  \
         sv notes [PATH]    write security-notes.md: the questions only you can answer\n  \
         sv probe URL [--hsts-preload FILE]\n                     ask your own live site the few things only it can answer\n  \
         sv run [PATH] [--slow]\n                     start the app behind the network fence and check it answers;\n                     --slow also waits out the session timeouts you state\n  \
         sv check [PATH]    credentials left in the code, and how it is set up\n  \
         sv sbom [PATH]     write the list of what the app ships, as CycloneDX JSON\n  \
         sv audit [PATH] --advisories DIR\n                     \
             match what the app ships against a local OSV database\n  \
         sv report [PATH] [--out DIR] [--run] [--tools] [--advisories DIR]\n                     \
             write the reports: what applies, what was found, what nobody has answered\n  \
         sv mcp [--root DIR]\n                     \
             serve the checks to an AI coding tool over MCP, for the apps under DIR\n"
    );
}

/// Where the OWASP data lives. Shared with v1 rather than copied, so an ASVS correction fixes both.
fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("SV_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    // From the workspace, the repository's own `data` folder is one level up.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = here.join("../../../data");
    if candidate.join("frameworks").is_dir() {
        return Ok(candidate);
    }
    bail!("cannot find the OWASP data folder; set SV_DATA_DIR")
}

/// The v2 overlay, which replaces the applicability rules whose reasons describe v1's own template.
fn overlay_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/applicability-v2.json")
}

/// The Secure by Design checklist's controls against the ASVS requirements that ask the same thing.
fn crosswalk_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/sbd-asvs-crosswalk.json")
}

/// The OWASP data with the checklist's levels grounded in ASVS. Every command loads it this way, so
/// no two of them can disagree about which controls apply at a level.
fn load_frameworks(data: &std::path::Path) -> Result<Frameworks> {
    let mut frameworks =
        Frameworks::load(&data.join("frameworks")).context("loading the OWASP frameworks")?;
    frameworks
        .apply_crosswalk(&crosswalk_path())
        .context("grounding the Secure by Design levels in ASVS")?;
    Ok(frameworks)
}

/// What each `derived` condition looks like in real code.
fn signatures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/tech-signatures.json")
}

/// Rules that read the code itself.
fn ast_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json")
}

/// Per-language security tools `sv` can run.
fn adapters_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

/// Well-known credential formats.
fn secret_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json")
}

/// How each manifest claim is checked against the code.
fn corroborators_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/claim-corroborators.json")
}

/// Breaks a paragraph into lines that fit a terminal.
///
/// These reasons are written as prose, for a reader who is not a programmer, and a single
/// five-hundred-character line is prose nobody reads.
fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.chars().count() + 1 + word.chars().count() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// Evidence in the words a person would use.
fn describe(evidence: &Evidence) -> String {
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

fn cmd_scope(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let manifest = Manifest::load(&manifest_path)?;

    let data = data_dir()?;
    let frameworks = load_frameworks(&data)?;
    let overlay = overlay_path();
    let config = ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay)?;

    // The scanner answers the `derived` conditions from the code, and checks each of the
    // manifest's claims against it. Corroboration only ever moves toward more requirements
    // applying: a claim of "no" cannot survive the code saying otherwise.
    let signatures = Signatures::load_all(&[&signatures_path(), &corroborators_path()])?;
    let report = scan(&app_dir, &signatures)?;
    let (ctx, resolved) = sv_manifest::resolve(&manifest, &report.as_corroborator());
    let buckets = bucket(&frameworks, &config, &ctx, manifest.target_level());

    println!(
        "{} — ASVS level {}",
        if manifest.app.name.is_empty() {
            "(unnamed app)"
        } else {
            &manifest.app.name
        },
        manifest.target_level()
    );
    if !report.ecosystems.is_empty() {
        let names: Vec<&str> = report.ecosystems.iter().map(|e| e.name.as_str()).collect();
        println!(
            "\nRead {} source file{} in {}; package manifests: {}.",
            report.files_read,
            if report.files_read == 1 { "" } else { "s" },
            report
                .languages
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            names.join(", ")
        );
    }
    for eco in &report.unpinned {
        println!(
            "  {} pins no versions ({} has no lockfile), so what is actually installed cannot be known.",
            eco.label(),
            eco.manifest
        );
    }
    if !report.unread_extensions.is_empty() {
        let exts: Vec<&str> = report
            .unread_extensions
            .iter()
            .map(String::as_str)
            .collect();
        println!(
            "  The technology scan did not look in these file types, so it cannot say a technology is absent: {}.",
            exts.join(", ")
        );
    }

    println!(
        "\n{} apply, {} do not, {} not assessed, {} above this level ({} loaded).",
        buckets.applicable.len(),
        buckets.not_applicable.len(),
        buckets.not_assessed.len(),
        buckets.out_of_level.len(),
        frameworks.len()
    );

    let contradicted: Vec<&sv_manifest::ResolvedClaim> = resolved
        .iter()
        .filter(|r| r.state == ClaimState::Contradicted)
        .collect();
    if !contradicted.is_empty() {
        println!(
            "\nThe manifest and the code disagree about {} thing{}. The code wins:",
            contradicted.len(),
            if contradicted.len() == 1 { "" } else { "s" }
        );
        for c in &contradicted {
            let how = report
                .answers
                .iter()
                .find(|a| a.condition == c.condition)
                .map(|a| describe(&a.evidence))
                .unwrap_or_default();
            println!(
                "  securevibe.toml says {} is {}, but {how}",
                c.condition.name(),
                match c.claimed {
                    Some(false) => "not used",
                    _ => "unset",
                }
            );
            let gated =
                requirements_gated_on(&frameworks, &config, c.condition, manifest.target_level());
            if gated == 0 {
                println!(
                    "       On its own this changes no requirement: nothing in the OWASP data \
                     turns on {}.",
                    c.condition.name()
                );
            } else {
                println!("       {gated} requirements turn on this.");
            }
        }
    }

    let unverifiable = resolved
        .iter()
        .filter(|r| r.state == ClaimState::Unverifiable && r.claimed == Some(true))
        .count();
    if unverifiable > 0 {
        println!(
            "\n{unverifiable} of the manifest's claims are asserted and not verified: `sv` looked \
             and found nothing,\nwhich for these is not the same as finding they are absent."
        );
    }

    // Claims nothing could check, said out loud. Silence here would read as a clean scan.
    let uncheckable: Vec<(&str, &str)> = report
        .answers
        .iter()
        .filter_map(|a| match &a.evidence {
            Evidence::NoCheckExists { reason } => Some((a.condition.name(), reason.as_str())),
            _ => None,
        })
        .collect();
    if !uncheckable.is_empty() {
        println!(
            "\n{} of the manifest's claims cannot be checked from the code at all, by anything, \
             ever:",
            uncheckable.len()
        );
        for (name, why) in &uncheckable {
            println!("  {name} —");
            for line in wrap(why, 94) {
                println!("      {line}");
            }
        }
    }

    let mut blocked: std::collections::BTreeMap<Condition, usize> = Default::default();
    for na in &buckets.not_assessed {
        for c in &na.blocked_on {
            *blocked.entry(*c).or_default() += 1;
        }
    }

    if !buckets.not_assessed.is_empty() {
        println!(
            "\n{} are NOT ASSESSED: something has to answer a question about this app before\n\
             anyone can say whether they apply. They are not passes and not exclusions.",
            buckets.not_assessed.len()
        );
        for (condition, n) in &blocked {
            let who = match condition.source() {
                Source::Claim => "securevibe.toml does not say",
                Source::Derived => "no scanner reads this from the code yet",
            };
            println!("  {n:>3}  {:<22} {who}", condition.name());
        }
    }

    // An exclusion resting on somebody's word is weaker than one resting on their dependencies,
    // and a report that prints them identically overstates the first.
    let claimed = buckets
        .not_applicable
        .iter()
        .filter(|na| na.source == Source::Claim)
        .count();
    // A claim can be wrong, change no requirement directly, and still matter — because of what it
    // implies about the data categories, which set the target level.
    let inconsistencies = consistency::check(&manifest, &resolved);
    if !inconsistencies.is_empty() {
        println!("\nWorth checking in securevibe.toml:");
        for i in &inconsistencies {
            println!("  {}", i.explain());
        }
    }

    // Questions the manifest asks that currently decide nothing. Better said plainly than left for
    // someone to discover after answering them carefully.
    let inert: Vec<&str> = Condition::ALL
        .iter()
        .filter(|c| c.source() == Source::Claim)
        // `level2` is computed from the audience and the data categories rather than answered,
        // and `self-assessment` is v1's notion of checking itself. Neither is a question anyone
        // fills in, so listing them as answered would be untrue.
        .filter(|c| {
            !matches!(
                c,
                Condition::Always
                    | Condition::Never
                    | Condition::SelfAssessment
                    | Condition::Level2
            )
        })
        .filter(|c| {
            resolved
                .iter()
                .any(|r| r.condition == **c && r.claimed.is_some())
        })
        .filter(|c| requirements_gated_on(&frameworks, &config, **c, manifest.target_level()) == 0)
        .map(|c| c.name())
        .collect();
    if !inert.is_empty() {
        println!(
            "\nAnswered in securevibe.toml but gating nothing: {}.\n\
             No requirement in ASVS 5.0, AISVS 1.0 or Appendix C turns on these, so answering them\n\
             differently changes no result. They are kept because they describe the app and because\n\
             a future revision of the standards may use them.",
            inert.join(", ")
        );
    }

    let found: Vec<&sv_scan::Answer> = report
        .answers
        .iter()
        .filter(|a| a.value == Some(true))
        .collect();
    if !found.is_empty() {
        println!("\nRead from the code, so nobody had to be believed:");
        for a in &found {
            let how = match &a.evidence {
                Evidence::Dependency { name, manifest } => {
                    format!("`{name}` declared in {manifest}")
                }
                Evidence::Source { pattern, file } => format!("`{pattern}` in {file}"),
                Evidence::Language { language } => format!("the app contains {language}"),
                _ => String::new(),
            };
            println!("  {:<16} {how}", a.condition.name());
        }
    }
    println!(
        "\nDoes not apply: {} in total — {} because the manifest says so, {} read from the code.",
        buckets.not_applicable.len(),
        claimed,
        buckets.not_applicable.len() - claimed
    );
    for na in buckets.not_applicable.iter().take(8) {
        println!("  {} — {}", na.id, na.reason);
    }
    if buckets.not_applicable.len() > 8 {
        println!("  … and {} more", buckets.not_applicable.len() - 8);
    }
    Ok(())
}

fn design_questions_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/design-questions.json")
}

/// Asks the owner's own live site the handful of questions only it can answer.
///
/// The address is an argument and never comes from a file: see `sv_check::production`, where the
/// limits on what this may do are set out and tested.
fn cmd_probe(args: &[String]) -> Result<()> {
    let mut url = None;
    // A copy of Chromium's HSTS preload list the owner downloaded. `sv` never fetches it: looking a
    // name up in somebody else's service tells that service which site is being checked.
    let mut preload_file: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--hsts-preload" => {
                preload_file = Some(PathBuf::from(
                    rest.next()
                        .context("--hsts-preload needs the list's file")?,
                ));
            }
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => url = Some(other),
        }
    }
    let preload = match &preload_file {
        Some(path) => Some(
            std::fs::read_to_string(path)
                .with_context(|| format!("reading the HSTS preload list at {}", path.display()))?,
        ),
        None => None,
    };
    let Some(url) = url else {
        bail!(
            "give the address your app is served from, for example:\n  \
             sv probe https://your-app.example.com\n\n\
             This makes a handful of read-only requests to that address and nothing else. It sends \
             no cookies and no credentials, never signs in, and cannot change anything."
        );
    };
    let target = sv_check::production::read_target(url).map_err(|why| anyhow::anyhow!("{why}"))?;
    if !sv_check::production::Curl::available() {
        bail!(
            "`curl` is not on this computer, and this check uses it for the connection so that the \
             certificate is judged by your system's own trust store. Install curl and run this again."
        );
    }

    println!(
        "Asking {} the few things only a live site can answer.",
        target.host
    );
    println!(
        "Read-only: it fetches headers from that address over HTTPS and over plain HTTP, sends no \
         cookies and no credentials, and follows no redirect to any other host.\n"
    );

    let mut http = sv_check::production::Curl::new();
    let mut out = sv_check::production::run(&mut http, &target);
    // Whether the site answered at all, decided from its own answers before the two questions
    // below, which ask DNS and a local file rather than the site.
    let reached = !(out.findings.is_empty() && out.verified.is_empty());
    let live = sv_check::live_tls::run(
        &mut sv_check::live_tls::SystemDns,
        &target.host,
        preload.as_deref(),
    );

    println!("It asked for:");
    for url in &out.requested {
        println!("  {url}");
    }
    for asked in &live.asked {
        println!("  {asked}");
    }
    println!();
    out.findings.extend(live.findings);
    out.verified.extend(live.verified);
    out.not_assessed.extend(live.not_assessed);

    if !reached {
        // Nothing was reached, so nothing about the site itself was asked. Saying "nothing came
        // back wrong" here reads as a pass, and a clean-looking answer from a site this never
        // touched is the worst thing this command could print.
        println!("It could not reach that address, so it has nothing to say about it either way.");
        if !out.findings.is_empty() {
            println!("Its DNS and the preload list were still asked about:\n");
        }
    } else if out.findings.is_empty() {
        println!("Nothing it asked about came back wrong.");
    }
    if !out.findings.is_empty() {
        if reached {
            println!(
                "{} thing{} to fix:\n",
                out.findings.len(),
                if out.findings.len() == 1 { "" } else { "s" }
            );
        }
        for f in &out.findings {
            println!("[{}] {}", f.severity.name(), f.title);
            for line in wrap(&f.description, 76) {
                println!("  {line}");
            }
            for line in wrap(&f.fix, 76) {
                println!("  → {line}");
            }
            println!();
        }
    }
    if !out.verified.is_empty() {
        println!("What it checked and found nothing wrong with:");
        for v in &out.verified {
            for line in wrap(&format!("{}: {}", v.check_id, v.scope), 76) {
                println!("  {line}");
            }
        }
        println!();
    }
    if !out.not_assessed.is_empty() {
        println!("What it could not settle:");
        for (ids, why) in &out.not_assessed {
            for line in wrap(&format!("{ids} — {why}"), 76) {
                println!("  {line}");
            }
        }
        println!();
    }
    println!(
        "This says nothing about the code. Run `sv report` in the app folder for that, and read \
         the two together."
    );
    Ok(())
}

fn notes_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/security-notes.json")
}

/// What `sv` found that belongs in the notes, so the owner starts from their app, not a blank page.
fn notes_facts(
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
        let line = format!("{host}, from securevibe.toml");
        if !outside_services.contains(&line) {
            outside_services.push(line);
        }
    }

    sv_check::notes::Facts {
        app_name: app_name.to_owned(),
        data_categories: manifest.data.categories.clone(),
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

/// Writes `security-notes.md`: the questions no tool can answer, for the requirements that apply.
fn cmd_notes(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let manifest = Manifest::load(&manifest_path)?;
    let data = data_dir()?;
    let frameworks = load_frameworks(&data)?;
    let config = ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay_path())?;
    let signatures = Signatures::load_all(&[&signatures_path(), &corroborators_path()])?;
    let scan_report = scan(&app_dir, &signatures)?;
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
    let existing = std::fs::read_to_string(&out_path).ok();
    let already = existing
        .as_deref()
        .map(|text| sv_check::notes::read_answers(text).documented().len())
        .unwrap_or(0);

    let describe = |id: &str| {
        frameworks
            .requirements
            .get(id)
            .map(|r| r.description.clone())
    };
    let text = sv_check::notes::write_template(
        &catalog,
        &applicable,
        &facts,
        existing.as_deref(),
        &describe,
    );
    std::fs::write(&out_path, &text).with_context(|| format!("writing {}", out_path.display()))?;

    let asked = catalog
        .sections
        .iter()
        .filter(|s| applicable.contains(&s.id))
        .count();
    println!("Wrote {}.", out_path.display());
    if asked == 0 {
        println!(
            "None of the requirements that ask for a written decision apply to this app, so there \
             is nothing to answer yet."
        );
        return Ok(());
    }
    println!(
        "\n{asked} question{} nobody but you can answer: what the rules are, who may do what, how \
         long things are kept. {}",
        if asked == 1 { "" } else { "s" },
        if already == 0 {
            "None is answered yet.".to_owned()
        } else {
            format!("{already} already answered.")
        }
    );
    println!(
        "\nAnswering one makes its requirement *documented* in the report. That is not the same as \
         checked: nothing here reads whether your answer is right, or whether the app does what it \
         says."
    );
    Ok(())
}

/// Starts the app behind the fence, so the checks that need it running have something to check.
/// Starts the app behind the fence and asks it the probe questions, or says why it could not.
///
/// Shared by `sv run` and `sv report --run` on purpose. Two call sites each deciding when an app is
/// runnable would drift, and the one that drifts quietly is the report — where "not assessed" and
/// "nothing found" look the same to a reader who was not there.
fn probe_the_running_app(
    manifest: &Manifest,
    app_dir: &Path,
    slow: bool,
) -> std::result::Result<(sv_run::RunOutcome, sv_run::RunPlan), String> {
    let mut plan = RunPlan::from_manifest(manifest, app_dir).map_err(|e| e.explain())?;
    plan.slow = slow;
    let backend = sv_run::detect().map_err(|e| e.explain())?;
    let requests = anonymous_requests(&plan);
    let outcome = backend.run(&plan, &requests).map_err(|e| e.explain())?;
    Ok((outcome, plan))
}

/// Every request the anonymous probes make: the fixed suite, and the GraphQL and WebSocket
/// questions when securevibe.toml says where those are. One function, because `sv run` also counts
/// how many of these went unanswered, and a count taken from a different list is a wrong count.
fn anonymous_requests(plan: &RunPlan) -> Vec<probes::ProbeRequest> {
    let mut requests = probes::requests(&plan.health_path);
    requests.extend(probes::api_requests(
        plan.graphql.as_deref(),
        plan.websocket.as_deref(),
    ));
    requests
}

/// What the running app showed: the anonymous probes, and the signed-in ones when they ran.
///
/// One function for `sv run` and `sv report`, so the two cannot disagree about what was found.
fn running_app_evidence(
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
    if let Some(signed_in) = &outcome.signed_in {
        findings.extend(signed_in.findings.iter().cloned());
        verified.extend(signed_in.verified.iter().cloned());
        not_assessed.extend(signed_in.not_assessed.iter().cloned());
    }
    (findings, verified, not_assessed)
}

fn cmd_run(args: &[String]) -> Result<()> {
    let mut app_dir = PathBuf::from(".");
    // Opt-in: waiting out the session timeouts the owner states can take as long as they are.
    let mut slow = false;
    for arg in args {
        match arg.as_str() {
            "--slow" => slow = true,
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => app_dir = PathBuf::from(other),
        }
    }
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let manifest = Manifest::load(&manifest_path)?;

    println!("Starting {} behind the network fence…", manifest.app.name);
    let requests = RunPlan::from_manifest(&manifest, &app_dir)
        .map(|plan| anonymous_requests(&plan))
        .unwrap_or_default();
    if slow {
        println!(
            "With --slow: this waits out the session timeouts securevibe.toml states, so it can take \
             as long as they are."
        );
    }
    match probe_the_running_app(&manifest, &app_dir, slow) {
        Err(reason) => {
            println!("\nNot assessed.\n\n{reason}");
        }
        Ok((outcome, plan)) => {
            println!("\nThe app started and answered on {}.", plan.health_path);
            println!("\n{}", outcome.fence.explain());
            let (findings, verified, signed_in_not_assessed) =
                running_app_evidence(&outcome, &plan);
            println!(
                "\nAsked it {} question{}, as somebody who has not signed in.",
                outcome.probe_responses.len(),
                if outcome.probe_responses.len() == 1 {
                    ""
                } else {
                    "s"
                }
            );
            if outcome.probe_responses.len() < requests.len() {
                println!(
                    "  {} got no answer at all, so nothing is claimed about them.",
                    requests.len() - outcome.probe_responses.len()
                );
            }

            if let Some(signed_in) = &outcome.signed_in
                && !signed_in.steps.is_empty()
            {
                println!("\nThen, as two test users: {}.", signed_in.steps.join("; "));
            }

            // What the probes cannot reach comes before what they found, for the usual reason.
            println!("\nNot assessed by these probes:");
            for (requirements, why) in probes::unassessed_requirements(outcome.signed_in.is_some())
            {
                println!("  {requirements} — {why}");
            }
            for (requirements, why) in &signed_in_not_assessed {
                println!("  {requirements} — {why}");
            }

            if !verified.is_empty() {
                println!(
                    "\n{} thing{} the running app got right:",
                    verified.len(),
                    if verified.len() == 1 { "" } else { "s" }
                );
                for v in &verified {
                    println!("  {} — checked: {}", v.check_id, v.scope);
                    if !v.requirement_ids.is_empty() {
                        println!("     evidence about: {}", v.requirement_ids.join(", "));
                    }
                }
                println!("  These are the only places anything here watched the app do the right");
                println!("  thing, rather than failing to catch it doing the wrong one.");
            }

            if findings.is_empty() {
                println!("\nNothing wrong in what was asked.");
            } else {
                println!(
                    "\n{} thing{} the running app got wrong:",
                    findings.len(),
                    if findings.len() == 1 { "" } else { "s" }
                );
                for f in &findings {
                    println!("\n  [{}] {}", f.severity.name(), f.title);
                    println!("     {}", f.description);
                    println!("     what to do: {}", f.fix);
                    if !f.requirement_ids.is_empty() {
                        println!("     evidence about: {}", f.requirement_ids.join(", "));
                    }
                }
            }

            match outcome.tests {
                None => println!(
                    "\nsecurevibe.toml declares no test command, so no test evidence was \
                     collected. That is recorded as not assessed, not as a pass."
                ),
                Some(result) if result.exit_code == 0 => {
                    println!("\nThe app's own tests passed.")
                }
                Some(result) => println!(
                    "\nThe app's own tests failed (exit {}):\n{}",
                    result.exit_code,
                    result
                        .output
                        .lines()
                        .take(15)
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            }
        }
    }
    Ok(())
}

/// Looks for credentials left in the code.
fn cmd_check(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    let rules = SecretRules::load(&secret_rules_path())?;
    let scan = scan_dir(&rules, &app_dir);
    let config = check_dir(&app_dir);
    let ast_rules = ast::AstRules::load(&ast_rules_path())?;
    let code = ast::scan_dir(&ast_rules, &app_dir);

    println!(
        "Read {} file{} looking for credentials, against {} known formats plus the assignment rule.\n\
         Parsed {} of them against {} rules that read the code itself.",
        scan.coverage.files_read,
        if scan.coverage.files_read == 1 {
            ""
        } else {
            "s"
        },
        rules.len(),
        code.files_parsed,
        ast_rules.len()
    );

    // What was not read comes before what was found. A short list of findings under a long list of
    // skipped files is a different result from a short list of findings.
    if !scan.coverage.skipped.is_empty() {
        println!(
            "\n{} file{} not read, so nothing is claimed about {}:",
            scan.coverage.skipped.len(),
            if scan.coverage.skipped.len() == 1 {
                " was"
            } else {
                "s were"
            },
            if scan.coverage.skipped.len() == 1 {
                "it"
            } else {
                "them"
            }
        );
        for (file, why) in scan.coverage.skipped.iter().take(10) {
            println!("  {file} — {why}");
        }
        if scan.coverage.skipped.len() > 10 {
            println!("  … and {} more", scan.coverage.skipped.len() - 10);
        }
    }

    // What could not be checked comes before what was: these are the questions still open, and an
    // owner reading only the findings would think they had been answered.
    if !code.unread_languages.is_empty() {
        let mut names: Vec<&str> = code.unread_languages.iter().map(String::as_str).collect();
        names.sort_unstable();
        println!(
            "\nNot assessed — nothing here reads {}, so the rules that read code said nothing about\n\
             those files, and nothing they look for can be ruled out anywhere in this app.",
            names.join(", ")
        );
        if names.contains(&"html") {
            // `html` on this list means a page holding script, not any page at all. Saying so
            // matters, because the two have different remedies: one is a language `sv` cannot read,
            // the other is code that could be moved into a file it can.
            println!("  For html that means something in a page that could not be taken out of");
            println!("  it and read: a script with no end, or a `javascript:` link. A page whose");
            println!("  script is written normally is read like any other file.");
        }
    }

    if !code.unparsed_files.is_empty() {
        println!(
            "\nPartly read — the parser could not make sense of part of {}. Anything found in\n\
             {} still counts, but while part of the app went unread, no rule can say it found\n\
             nothing wrong.",
            if code.unparsed_files.len() == 1 {
                "this file".to_owned()
            } else {
                format!("these {} files", code.unparsed_files.len())
            },
            if code.unparsed_files.len() == 1 {
                "it"
            } else {
                "them"
            }
        );
        for file in code.unparsed_files.iter().take(10) {
            println!("  {file}");
        }
        if code.unparsed_files.len() > 10 {
            println!("  … and {} more", code.unparsed_files.len() - 10);
        }
    }

    for line in untaught_lines(&code.untaught) {
        println!("{line}");
    }

    if !config.not_assessed.is_empty() {
        println!("\nNot assessed — these could not be checked here:");
        for (id, why) in &config.not_assessed {
            println!("  {id}\n     {why}");
        }
    }

    let mut findings = scan.findings;
    findings.extend(config.findings);
    let bill_of_materials = sbom::build(&app_dir);
    findings.extend(sbom::incompleteness_finding(&bill_of_materials));
    findings.extend(code.findings.clone());
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });
    let scan = sv_check::SecretScan {
        findings,
        coverage: scan.coverage,
        verified: scan.verified,
    };

    // Exactly one of these speaks: the finding above when the list is short of something, this
    // when it is not. A document cannot be both an incomplete list and a good inventory.
    let mut passed = config.passed.clone();
    passed.extend(sbom::completeness_verified(&bill_of_materials));
    if !passed.is_empty() {
        println!("\nChecked and fine:");
        for claim in &passed {
            println!("  {} — {}", claim.check_id, claim.scope);
        }
    }

    if scan.findings.is_empty() {
        println!(
            "\nNo credentials found in what was read. That is not the same as none being there: these \n\
             rules know a list of well-known formats and one heuristic, and a credential in a shape \n\
             nobody listed would not be found."
        );
        return Ok(());
    }

    println!(
        "\n{} thing{} to look at:",
        scan.findings.len(),
        if scan.findings.len() == 1 { "" } else { "s" }
    );
    for f in &scan.findings {
        println!(
            "\n  [{}] {}\n     {}:{}",
            f.severity.name(),
            f.title,
            f.location.file,
            f.location.line
        );
        if let Some(secret) = &f.secret {
            println!("     found: {}", secret.as_str());
        }
        if !f.impact.is_empty() {
            println!("     why it matters: {}", f.impact);
        }
        if !f.fix.is_empty() {
            println!("     what to do: {}", f.fix);
        }
        if !f.requirement_ids.is_empty() {
            println!("     evidence about: {}", f.requirement_ids.join(", "));
        }
    }
    Ok(())
}

/// Writes the list of what the app ships.
///
/// The document goes to standard output and everything else to standard error, so
/// `sv sbom ./app > sbom.cdx.json` gives a clean file and still tells the person what it is worth.
fn cmd_sbom(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    let sbom = sbom::build(&app_dir);
    println!(
        "{}",
        serde_json::to_string_pretty(&sbom::to_cyclonedx(&sbom))?
    );

    eprintln!(
        "{} package{} listed.",
        sbom.components.len(),
        if sbom.components.len() == 1 { "" } else { "s" }
    );
    if sbom.is_complete() {
        eprintln!("Every ecosystem in use was read from a lockfile, so this is what is installed.");
        return Ok(());
    }
    eprintln!("\nThis list is NOT complete, and the document says so too:");
    if sbom.declared_count() > 0 {
        eprintln!(
            "  {} package(s) carry the version that was asked for, not the version installed.",
            sbom.declared_count()
        );
    }
    for (_, why) in &sbom.unread {
        eprintln!("  {why}");
    }
    eprintln!(
        "\nAsked whether a compromised version of some library is in this app, nobody could answer\n\
         from this document. Commit a lockfile for every ecosystem in use, and install from it."
    );
    Ok(())
}

/// Matches the bill of materials against a local advisory database.
///
/// `sv` opens no network connection, here or anywhere. Fetching the database is the owner's step, done
/// deliberately: the list of packages an app depends on is business-confidential, a fetch is a dependency
/// on somebody else's uptime, and `sv` has to work where there is no network at all.
fn cmd_audit(args: &[String]) -> Result<()> {
    let mut app_dir = PathBuf::from(".");
    let mut advisories_dir: Option<PathBuf> =
        std::env::var("SV_ADVISORY_DIR").ok().map(PathBuf::from);
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--advisories" => {
                advisories_dir = Some(PathBuf::from(
                    rest.next().context("--advisories needs a folder")?,
                ));
            }
            other if other.starts_with("--") => bail!("unknown option: {other}"),
            other => app_dir = PathBuf::from(other),
        }
    }
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }

    let sbom = sbom::build(&app_dir);

    // No database is not a clean result, and must never be printed as one.
    let Some(dir) = advisories_dir else {
        println!(
            "Not assessed: nothing here knows which versions are known to be vulnerable.\n\n\
             `sv` does not fetch anything — the list of packages this app depends on is yours, and a\n\
             check that quietly phones out is one you did not agree to. Download an OSV export for the\n\
             ecosystems below, unpack it, and point at it:\n\n  \
             sv audit {} --advisories ./osv\n\n\
             Ecosystems in this app: {}",
            app_dir.display(),
            if sbom.components.is_empty() {
                "none found".to_owned()
            } else {
                let mut names: Vec<&str> = sbom
                    .components
                    .iter()
                    .map(|c| c.ecosystem.as_str())
                    .collect();
                names.sort_unstable();
                names.dedup();
                names.join(", ")
            }
        );
        return Ok(());
    };

    let database = advisories::load_database(&dir)
        .with_context(|| format!("reading the advisory database at {}", dir.display()))?;
    if database.is_empty() {
        println!(
            "Not assessed: {} holds no advisory records `sv` could read, so nothing was compared.\n\
             An empty database and a healthy app look identical from here, and only one of them is good news.",
            dir.display()
        );
        return Ok(());
    }

    // The time frames are V15.1.1's document, as numbers. Without them every known vulnerability
    // counts against V15.2.1 whatever its age, which is what this said before they existed.
    let manifest_path = app_dir.join("securevibe.toml");
    let time_frames = if manifest_path.is_file() {
        Manifest::load(&manifest_path)?.policy.fix_within_days
    } else {
        None
    };
    let result = advisories::audit_against(
        &sbom,
        &database,
        time_frames.as_ref(),
        advisories::Day::today(),
    );
    println!(
        "Compared {} package{} against {} advisory record{}.",
        result.components_checked,
        if result.components_checked == 1 {
            ""
        } else {
            "s"
        },
        result.advisories_read,
        if result.advisories_read == 1 { "" } else { "s" }
    );

    // Everything the comparison could not cover comes first.
    if !result.uncovered.is_empty() {
        println!(
            "\nNot assessed — the database holds nothing about {}, so its packages were not checked.\n\
             That is not the same as their being clean.",
            result
                .uncovered
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !result.uncomparable.is_empty() {
        println!(
            "\nNot assessed — {} package version(s) could not be compared with any range, so nothing is\n\
             claimed about them:",
            result.uncomparable.len()
        );
        for (name, version) in result.uncomparable.iter().take(8) {
            println!("  {name} {version}");
        }
    }
    if !sbom.is_complete() {
        println!(
            "\nAnd the list itself is incomplete, so this comparison covered less than the whole app.\n\
             `sv sbom` says what is missing."
        );
    }

    if result.findings.is_empty() {
        // Two different sentences, and which one is said depends on whether the comparison really
        // covered the app. "Nothing in what was compared" is true either way and is what a reader
        // skims past; the claim is only made when there is nothing left over to qualify it.
        match result.verified.first() {
            Some(claim) => println!(
                "\nNothing in what was compared matches a record in this database, and there was \
                 nothing it could not compare:\n  {} — {}",
                claim.check_id, claim.scope
            ),
            None => println!(
                "\nNothing in what was compared matches a record in this database. That is not a \
                 clean bill: the lines above say what this comparison could not reach."
            ),
        }
        return Ok(());
    }
    println!(
        "\n{} known vulnerabilit{}:",
        result.findings.len(),
        if result.findings.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );

    // Late first, because that is what V15.2.1 asks about. Then the ones nothing could judge, which
    // count as late: not shown to be late is not shown to be on time. On time last — still known
    // vulnerabilities, each with the day it is due, and still what stops a clean result.
    use advisories::Due;
    let due = |f: &&sv_check::finding::Finding| result.due.get(&f.rule_id);
    let late: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(due(f), Some(Due::Overdue { .. })))
        .collect();
    let unjudged: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(due(f), Some(Due::Unjudged(_)) | None))
        .collect();
    let on_time: Vec<_> = result
        .findings
        .iter()
        .filter(|f| matches!(due(f), Some(Due::Within { .. })))
        .collect();
    let print = |f: &sv_check::finding::Finding| {
        println!("\n  [{}] {}", f.severity.name(), f.title);
        if !f.description.is_empty() {
            println!("     {}", f.description);
        }
        println!("     what to do: {}", f.fix);
    };
    if !late.is_empty() {
        println!("\nPast the time frame you set for fixing them (V15.2.1):");
        late.iter().for_each(|f| print(f));
    }
    if !unjudged.is_empty() {
        println!(
            "\nNot judged against a time frame, so each counts against V15.2.1 as though it were late:"
        );
        unjudged.iter().for_each(|f| print(f));
        if time_frames.is_none() {
            println!(
                "\n  To judge them, write your time frames in securevibe.toml:\n\n    \
                 [policy]\n    fix-within-days = {{ critical = 7, high = 30, medium = 90, low = 180 }}\n\n  \
                 with your own numbers — the ones in your security notes for V15.1.1."
            );
        }
    }
    if !on_time.is_empty() {
        println!(
            "\nInside the time frame you set — still to fix, and still why this is not a clean result:"
        );
        on_time.iter().for_each(|f| print(f));
    }
    Ok(())
}

/// Writes the reports.
///
/// Everything here runs offline and without a container. The probes need a running app, so unless
/// `sv run` has been used they are recorded as a gap rather than as nothing to report — a section
/// missing from a report reads as a section with nothing in it.
/// Writes the five renderings of a report into `out_dir`, and says which were written.
fn write_report_files(report: &sv_report::Report, out_dir: &Path) -> Result<Vec<&'static str>> {
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let written = [
        ("report.html", sv_report::html::page(report)),
        ("compliance.md", sv_report::markdown::compliance(report)),
        ("security.md", sv_report::markdown::security(report)),
        ("findings.sarif", sv_report::sarif::render(report)),
        ("report.json", serde_json::to_string_pretty(report)? + "\n"),
    ];
    for (name, contents) in &written {
        std::fs::write(out_dir.join(name), contents).with_context(|| format!("writing {name}"))?;
    }
    Ok(written.iter().map(|(name, _)| *name).collect())
}

/// What a report is built from, and what the person asked for.
struct ReportOptions {
    /// Start the app behind the fence and ask it questions. Opt-in: this runs somebody's code.
    run_the_app: bool,
    /// And wait out the session timeouts the owner states. Opt-in: it takes as long as they are.
    slow: bool,
    /// Run the language's own security tool. Opt-in: these are other people's programs.
    run_tools: bool,
    /// Said in the report when the app was not started, in the words of whoever built it.
    why_not_run: &'static str,
    /// Said in the report when the tools were not run.
    why_no_tools: &'static str,
    /// A local advisory database to compare the bill of materials with. `sv` never fetches one.
    advisories: Option<PathBuf>,
    /// Said in the report when there was no database to compare with.
    why_no_advisories: &'static str,
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
fn dependency_gaps(sbom: &sbom::Sbom) -> Vec<sv_report::Gap> {
    let mut gaps = Vec::new();

    // Ecosystems that produced no components at all. The bill of materials already words each
    // reason for its own case — no lockfile, a lockfile format `sv` cannot read, a lockfile that
    // parsed and yielded nothing — so the reason is passed through rather than flattened.
    for (ecosystem, why) in &sbom.unread {
        gaps.push(sv_report::Gap {
            what: format!("everything {ecosystem} installs"),
            why: format!(
                "{why}. This is not an approximate list of this app's {ecosystem} dependencies, \
                 it is an empty one: nothing here can say whether a package with a known \
                 vulnerability is among them"
            ),
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

fn assemble_report(app_dir: &Path, options: &ReportOptions) -> Result<sv_report::Report> {
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let manifest = Manifest::load(&manifest_path)?;

    let data = data_dir()?;
    let frameworks = load_frameworks(&data)?;
    let config_rules = ApplicabilityConfig::load_v2(&data.join("knowledge"), &overlay_path())?;
    let signatures = Signatures::load_all(&[&signatures_path(), &corroborators_path()])?;
    let scan_report = scan(app_dir, &signatures)?;
    let (ctx, resolved) = sv_manifest::resolve(&manifest, &scan_report.as_corroborator());
    let buckets = bucket(&frameworks, &config_rules, &ctx, manifest.target_level());
    // Shared with v1, beside the applicability rules, so a threat is corrected in one place.
    let threat_rules =
        sv_report::threats::ThreatRules::load(&data.join("knowledge").join("threats.json"))?;

    let secret_rules = SecretRules::load(&secret_rules_path())?;
    let secrets = scan_dir(&secret_rules, app_dir);
    let config = check_dir(app_dir);
    let ast_rules = ast::AstRules::load(&ast_rules_path())?;
    let code = ast::scan_dir(&ast_rules, app_dir);
    // The report used to reason about dependencies from the scan alone, which knows only whether a
    // lockfile is missing. The bill of materials knows what actually came out of each ecosystem,
    // and that is the difference between "this list is approximate" and "this list is empty".
    // Building it reads manifests and lockfiles; it opens no network connection.
    let bill_of_materials = sbom::build(app_dir);
    let mut findings_from_advisories = Vec::new();

    // Known vulnerabilities, when the owner has pointed at a local advisory database, held to the
    // time frames in securevibe.toml exactly as `sv audit` holds them. Without a database this says
    // so: a report silent about known vulnerabilities reads as a report that found none.
    let mut advisory_verified = Vec::new();
    let mut advisory_gaps = Vec::new();
    match &options.advisories {
        None => advisory_gaps.push(sv_report::Gap {
            what: "known vulnerabilities in the packages this app ships".to_owned(),
            why: format!(
                "{} `sv` does not fetch anything, because the list of packages an app depends on \
                 is yours: download an OSV export for this app's ecosystems, unpack it, and pass \
                 its folder with --advisories.",
                options.why_no_advisories
            ),
        }),
        Some(dir) => {
            let database = advisories::load_database(dir)
                .with_context(|| format!("reading the advisory database at {}", dir.display()))?;
            if database.is_empty() {
                advisory_gaps.push(sv_report::Gap {
                    what: "known vulnerabilities in the packages this app ships".to_owned(),
                    why: format!(
                        "{} holds no advisory records `sv` could read, so nothing was compared. \
                         An empty database and a healthy app look the same from here.",
                        dir.display()
                    ),
                });
            } else {
                let result = advisories::audit_against(
                    &bill_of_materials,
                    &database,
                    manifest.policy.fix_within_days.as_ref(),
                    advisories::Day::today(),
                );
                findings_from_advisories = result.findings;
                advisory_verified = result.verified;
                if !result.uncovered.is_empty() {
                    advisory_gaps.push(sv_report::Gap {
                        what: format!(
                            "known vulnerabilities in this app's {} packages",
                            result
                                .uncovered
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        why: "the advisory database holds nothing about them, so they were not \
                              compared. That is not the same as their being clean."
                            .to_owned(),
                    });
                }
                if !result.uncomparable.is_empty() {
                    let n = result.uncomparable.len();
                    let shown: Vec<String> = result
                        .uncomparable
                        .iter()
                        .take(5)
                        .map(|(name, version)| format!("{name} {version}"))
                        .collect();
                    advisory_gaps.push(sv_report::Gap {
                        what: format!(
                            "whether {n} package version{} {} a known vulnerability ({}{})",
                            if n == 1 { "" } else { "s" },
                            if n == 1 { "has" } else { "have" },
                            shown.join(", "),
                            if n > 5 { ", …" } else { "" }
                        ),
                        why: "these versions could not be compared with any affected range, so \
                              nothing is claimed about them either way"
                            .to_owned(),
                    });
                }
            }
        }
    }

    let mut probe_verified = Vec::new();
    let mut tool_verified = Vec::new();
    let mut test_verified = Vec::new();
    let mut findings = Vec::new();
    findings.extend(findings_from_advisories);
    findings.extend(secrets.findings.iter().cloned());
    findings.extend(config.findings.iter().cloned());
    findings.extend(code.findings.iter().cloned());

    // The language's own tool, where there is one and it is here. A tool that is not installed is
    // recorded as not run, with how to install it — never as having found nothing.
    let mut tool_gaps = Vec::new();
    if options.run_tools {
        let adapters = sv_check::adapters::Adapters::load(&adapters_path())?;
        let languages: Vec<String> = scan_report.languages.iter().cloned().collect();
        let outcome = sv_check::adapters::run_all(
            &adapters,
            app_dir,
            &languages,
            &sv_check::adapters::scratch_dir(),
        );
        findings.extend(outcome.findings);
        tool_verified = outcome.verified;
        for (id, why) in outcome.not_run {
            tool_gaps.push(sv_report::Gap {
                what: format!("what `{id}` would have found"),
                why,
            });
        }
    } else {
        tool_gaps.push(sv_report::Gap {
            what: "the security tool this language already has".to_owned(),
            why: format!(
                "{} bandit, gosec, brakeman, and CodeQL each know their languages far better than \
                 the handful of rules built in here.",
                options.why_no_tools
            ),
        });
    }

    // Every limit `sv` knows about, said out loud. This list existing is the difference between a
    // report about an app and a report about the part of an app somebody happened to look at.
    let mut gaps = Vec::new();
    let mut run_note = None;
    let mut run_steps: Vec<String> = Vec::new();

    if options.run_the_app {
        match probe_the_running_app(&manifest, app_dir, options.slow) {
            Ok((outcome, plan)) => {
                let (running_findings, running_verified, signed_in_not_assessed) =
                    running_app_evidence(&outcome, &plan);
                findings.extend(running_findings);
                probe_verified = running_verified;
                // The summary, and the steps kept apart from it. Joining them made one
                // 381-word paragraph at the top of the report — the first thing the reader met,
                // and unreadable. The renderers lay the steps out as a list.
                let signed_in_steps: Vec<String> = outcome
                    .signed_in
                    .as_ref()
                    .map(|s| s.steps.clone())
                    .unwrap_or_default();
                run_steps = signed_in_steps.clone();
                run_note = Some(format!(
                    "This app was started with {} and asked {} question{} while it ran, as \
                     somebody who had not signed in. It answered on {}.{} {}",
                    plan.image,
                    outcome.probe_responses.len(),
                    if outcome.probe_responses.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    plan.health_path,
                    if signed_in_steps.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " It was then asked {} more question{} as two signed-in test users.",
                            signed_in_steps.len(),
                            if signed_in_steps.len() == 1 { "" } else { "s" }
                        )
                    },
                    outcome.fence.explain()
                ));
                for (requirements, why) in signed_in_not_assessed {
                    gaps.push(sv_report::Gap {
                        what: format!(
                            "{requirements}, by asking the running app as a signed-in user"
                        ),
                        why,
                    });
                }
                // What asking it could not reach. These replace the "it was never started" gap
                // rather than removing it: the app running answers some questions and not others,
                // and the ones it cannot answer are the ones behind a login.
                for (requirements, why) in
                    probes::unassessed_requirements(outcome.signed_in.is_some())
                {
                    gaps.push(sv_report::Gap {
                        what: format!("{requirements}, by asking the running app"),
                        why: why.to_owned(),
                    });
                }
                match &outcome.tests {
                    Some(result) => {
                        // Only tests that name a requirement count, and only when something says
                        // they passed. Matching a test to a requirement by what it is called would
                        // credit one on the strength of a name somebody chose for other reasons.
                        let known: std::collections::BTreeSet<&str> =
                            frameworks.requirements.keys().map(String::as_str).collect();
                        let named = sv_check::suite::tests_naming_requirements(app_dir, &known);
                        let describe = |id: &str| {
                            frameworks
                                .requirements
                                .get(id)
                                .map(|r| r.description.clone())
                        };

                        // A suite that passed outright needs no report. One that did not is worth
                        // whatever its runner's own report says still passed — and nothing more,
                        // which is why an unreadable report falls back to crediting nothing rather
                        // than to crediting what it managed to understand.
                        let passed_cases = if result.exit_code == 0 {
                            None
                        } else {
                            match result.report.as_deref().map(sv_check::junit::parse) {
                                Some(Ok(cases)) => Some(sv_check::junit::passed_names(&cases)),
                                Some(Err(unreadable)) => {
                                    gaps.push(sv_report::Gap {
                                        what: "which of the app's own tests passed".to_owned(),
                                        why: format!(
                                            "the suite failed (exit {}) and its report could not \
                                             be read: {}. Nothing is credited from it.",
                                            result.exit_code, unreadable.why
                                        ),
                                    });
                                    None
                                }
                                None => None,
                            }
                        };
                        let suite_outcome = if result.exit_code == 0 {
                            sv_check::suite::SuiteOutcome::Passed
                        } else {
                            sv_check::suite::SuiteOutcome::Failed {
                                passed: passed_cases.as_ref(),
                            }
                        };
                        let (credited, mismatches) =
                            sv_check::suite::credit(&named, suite_outcome, &describe);

                        if result.exit_code != 0 {
                            gaps.push(sv_report::Gap {
                                what: "anything the failing tests would have shown".to_owned(),
                                why: match (&passed_cases, credited.len()) {
                                    (Some(_), 0) => format!(
                                        "the suite failed (exit {}) and no test its runner \
                                         reported as passing names a requirement",
                                        result.exit_code
                                    ),
                                    (Some(_), n) => format!(
                                        "the suite failed (exit {}); {n} requirement {} from \
                                         tests its runner reported as passing, and the rest of \
                                         the suite says nothing either way",
                                        result.exit_code,
                                        if n == 1 { "claim comes" } else { "claims come" }
                                    ),
                                    (None, _) => format!(
                                        "they failed (exit {}) and nothing says which of them did, \
                                         so nothing can be concluded from them either way. {}",
                                        result.exit_code,
                                        result.report_note.as_deref().unwrap_or(
                                            "Declare test-report in securevibe.toml to have the \
                                             tests that did pass still count."
                                        )
                                    ),
                                },
                            });
                        } else if credited.is_empty() {
                            gaps.push(sv_report::Gap {
                                what: "what the app's own tests cover".to_owned(),
                                why: "the suite passed, and no test names the requirement it is \
                                      for, so nothing here can say which requirements they are \
                                      evidence about. `sv init` explains how to name them."
                                    .to_owned(),
                            });
                        }
                        findings.extend(mismatches);
                        test_verified = credited;
                    }
                    None => gaps.push(sv_report::Gap {
                        what: "the app's own tests".to_owned(),
                        why: "securevibe.toml declares no test command".to_owned(),
                    }),
                }
            }
            Err(reason) => gaps.push(sv_report::Gap {
                what: "the running app".to_owned(),
                why: format!("--run was given and the app could not be run. {reason}"),
            }),
        }
    } else {
        gaps.push(sv_report::Gap {
            what: "the running app".to_owned(),
            why: format!(
                "{} Without it, nothing here has asked the app anything — what it sends to a \
                 browser, what it says when something goes wrong, which sites it accepts.",
                options.why_not_run
            ),
        });
    }
    gaps.extend(tool_gaps);
    for (id, why) in &config.not_assessed {
        gaps.push(sv_report::Gap {
            what: format!("the check `{id}`"),
            why: why.clone(),
        });
    }
    if !secrets.coverage.skipped.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} file{} not read while looking for credentials",
                secrets.coverage.skipped.len(),
                if secrets.coverage.skipped.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: "a credential in a file nothing read is a credential nothing found".to_owned(),
        });
    }
    if !code.unread_languages.is_empty() {
        let mut names: Vec<&str> = code.unread_languages.iter().map(String::as_str).collect();
        names.sort_unstable();
        gaps.push(sv_report::Gap {
            what: format!("code written in {}", names.join(", ")),
            why: "`sv` has no parser for these, so the rules that read code did not run on them"
                .to_owned(),
        });
    }
    if !code.unparsed_files.is_empty() {
        let n = code.unparsed_files.len();
        let mut shown: Vec<&str> = code
            .unparsed_files
            .iter()
            .map(String::as_str)
            .take(5)
            .collect();
        if n > 5 {
            shown.push("…");
        }
        gaps.push(sv_report::Gap {
            what: format!(
                "part of {n} file{} that did not parse cleanly ({})",
                if n == 1 { "" } else { "s" },
                shown.join(", ")
            ),
            why: "whatever sat where the parser gave up was not read, so no rule that reads code \
                  can say it found nothing wrong anywhere in this app; what it did find stands"
                .to_owned(),
        });
    }
    gaps.extend(untaught_gaps(&code.untaught));
    if !scan_report.unread_extensions.is_empty() {
        let mut exts: Vec<&str> = scan_report
            .unread_extensions
            .iter()
            .map(String::as_str)
            .collect();
        exts.sort_unstable();
        gaps.push(sv_report::Gap {
            what: format!("files ending {}", exts.join(", ")),
            why:
                "the technology scan did not look in these, so no technology can be called absent \
                  on their account"
                    .to_owned(),
        });
    }
    // The Secure by Design checklist is design review, not scanning. Its controls are applicable
    // and every one is unverified — which is true of a great many ASVS requirements too, and the
    // difference matters: those could in principle be reached by some check, and these cannot be
    // reached by any, ever. Counting them together lets a reader think the scanner tried.
    let manual_only = buckets.manual_only(&config_rules);
    let design_review = manual_only.len();
    if design_review > 0 {
        gaps.push(sv_report::Gap {
            what: format!(
                "{design_review} requirement{} that are design review, not scanning",
                if design_review == 1 { "" } else { "s" }
            ),
            why: "these ask how the system was designed and how it is run \u{2014} whether trust \
                  zones are enforced, whether an incident response plan is rehearsed, whether data \
                  has named owners. No check here reaches them and none ever will, so they are \
                  counted as applicable and unverified, and a person has to answer them."
                .to_owned(),
        });
    }
    gaps.extend(dependency_gaps(&bill_of_materials));
    gaps.extend(advisory_gaps);

    // Everything that ran, looked at what it needed to, and found nothing wrong. Each of these
    // fails closed on its own coverage, so the list is short on an app `sv` could not read fully —
    // which is the honest shape for it to have.
    let mut verified = config.passed.clone();
    verified.extend(secrets.verified.iter().cloned());
    verified.extend(code.verified.iter().cloned());
    verified.extend(probe_verified.iter().cloned());
    verified.extend(tool_verified.iter().cloned());
    verified.extend(advisory_verified);
    verified.extend(test_verified.iter().cloned());

    // Which requirements the app's tests name, read from the files whether or not the tests ran, so
    // the report can tell a requirement nobody has written a test for from one whose test did not
    // run here.
    let named_in_tests: std::collections::BTreeSet<String> = {
        let known: std::collections::BTreeSet<&str> =
            frameworks.requirements.keys().map(String::as_str).collect();
        sv_check::suite::tests_naming_requirements(app_dir, &known)
            .into_iter()
            .flat_map(|t| t.requirement_ids)
            .collect()
    };

    // What an application's own tests cannot show, so it is not listed as a test to write: a
    // requirement classed as documentation or deployment, the AISVS appendix on the development
    // process, and any whose own words ask for documentation.
    let not_for_tests: std::collections::BTreeSet<String> = buckets
        .applicable
        .iter()
        .filter(|id| {
            matches!(
                config_rules.verification_class_for(id),
                sv_frameworks::applicability::VerificationClass::DocGenerated
                    | sv_frameworks::applicability::VerificationClass::DeploymentTime
            ) || id.starts_with("AC.")
                || frameworks.requirements.get(id.as_str()).is_some_and(|r| {
                    let text = r.description.to_lowercase();
                    text.contains("documentation") || text.contains("documented")
                })
        })
        .cloned()
        .collect();

    // The owner's answers, from the notes file beside the app. Absent when they have not run
    // `sv notes`, which is the common case and not a gap: the report then says the file exists to
    // be written.
    let notes_catalog = sv_check::notes::Catalog::load(&notes_path())?;
    let documented = match std::fs::read_to_string(app_dir.join(&notes_catalog.file)) {
        Ok(text) => sv_check::notes::evidence(
            &notes_catalog,
            &sv_check::notes::read_answers(&text),
            &notes_catalog.file,
        ),
        Err(_) => {
            let asked = notes_catalog
                .sections
                .iter()
                .filter(|s| buckets.applicable.contains(&s.id))
                .count();
            if asked > 0 {
                gaps.push(sv_report::Gap {
                    what: format!(
                        "{asked} requirement{} that ask for a written decision",
                        if asked == 1 { "" } else { "s" }
                    ),
                    why: format!(
                        "No tool can answer these: they ask what your rules are, who may do what, \
                         and how long things are kept. Run `sv notes` to write {}, answer the \
                         questions in it, and they become documented.",
                        notes_catalog.file
                    ),
                });
            }
            Vec::new()
        }
    };

    // The design questions, answered in securevibe.toml. `yes` is the owner's word and the weakest
    // tier here; `no`, and a `where` naming a file the app does not have, are findings.
    let design_questions = sv_check::design::Questions::load(&design_questions_path())?;
    let human_checks = sv_check::human::HumanChecks::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/human-checks.json"),
    )?;
    let design_answers: std::collections::BTreeMap<String, sv_check::design::Answer> = manifest
        .design
        .iter()
        .map(|(id, a)| {
            (
                id.clone(),
                sv_check::design::Answer {
                    answer: a.answer.clone(),
                    location: a.r#where.clone(),
                },
            )
        })
        .collect();
    let design = sv_check::design::evaluate(
        &design_questions,
        &design_answers,
        &|id| buckets.applicable.iter().any(|a| a == id),
        &|path| app_dir.join(path).exists(),
    );
    findings.extend(design.findings.iter().cloned());
    if !design.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "your answer to {} design question{}",
                design.unreadable.len(),
                if design.unreadable.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "securevibe.toml answers {} with a word that is not yes, no, or not-sure, so \
                 nothing could be made of it: {}.",
                if design.unreadable.len() == 1 {
                    "this"
                } else {
                    "these"
                },
                design.unreadable.join(", ")
            ),
        });
    }
    if !design.unanswered.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} question{} about how this app is built",
                design.unanswered.len(),
                if design.unanswered.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "No tool can settle these — whether input is validated on the server, whether the \
                 app's own services authenticate to each other. Answer them in the [design] \
                 section of securevibe.toml: {}.",
                design.unanswered.join(", ")
            ),
        });
    }

    Ok(sv_report::build(sv_report::Inputs {
        app_name: if manifest.app.name.is_empty() {
            "This app"
        } else {
            &manifest.app.name
        },
        target_level: manifest.target_level(),
        generated: None,
        run_note,
        run_steps,
        frameworks: &frameworks,
        buckets: &buckets,
        claims: &resolved,
        findings,
        verified: &verified,
        gaps,
        manual_only,
        named_in_tests,
        not_for_tests,
        documented: &documented,
        attested: &design.attested,
        human: Some((&notes_catalog, &design_questions, &human_checks)),
        threats: Some((&threat_rules, &ctx)),
    }))
}

fn cmd_report(args: &[String]) -> Result<()> {
    let mut app_dir = PathBuf::from(".");
    let mut out_dir: Option<PathBuf> = None;
    // Opt-in. Everything else `sv report` does reads files; this starts somebody's code. It runs
    // behind the same fence `sv run` uses — no network beyond loopback, nothing published to this
    // computer — and it is still their decision to make rather than a default.
    let mut run_the_app = false;
    // With --run: wait out the session timeouts too.
    let mut slow = false;
    // Opt-in for the same reason as --run, and one more: these are other people's programs, and one
    // of them fetches its rules over the network the first time it runs.
    let mut run_tools = false;
    // A folder the owner downloaded on purpose. `sv` never fetches advisories itself.
    let mut advisories_dir: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                out_dir = Some(PathBuf::from(
                    rest.next().context("--out needs a directory")?,
                ));
            }
            "--run" => run_the_app = true,
            "--slow" => slow = true,
            "--tools" => run_tools = true,
            "--advisories" => {
                advisories_dir = Some(PathBuf::from(
                    rest.next().context("--advisories needs a folder")?,
                ));
            }
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => app_dir = PathBuf::from(other),
        }
    }
    let out_dir = out_dir.unwrap_or_else(|| app_dir.join("securevibe-report"));

    let report = assemble_report(
        &app_dir,
        &ReportOptions {
            run_the_app,
            slow,
            run_tools,
            why_not_run: "`sv report` does not start the app unless you pass --run.",
            why_no_tools: "`sv report` does not run other people's tools unless you pass --tools.",
            advisories: advisories_dir,
            why_no_advisories: "`sv report` compares against known vulnerabilities only when you \
                                pass --advisories DIR.",
        },
    )?;

    let written = write_report_files(&report, &out_dir)?;

    let c = &report.counts;
    println!("Wrote {} files to {}:", written.len(), out_dir.display());
    for name in &written {
        println!("  {name}");
    }
    println!(
        "\n{} requirements apply. {} need{} attention, {} {} checked by an automated check, \
         {} {} not verified by anything.",
        c.applicable,
        c.needs_attention,
        if c.needs_attention == 1 { "s" } else { "" },
        c.checked,
        if c.checked == 1 { "was" } else { "were" },
        c.not_verified,
        if c.not_verified == 1 { "was" } else { "were" }
    );
    if c.attested > 0 {
        println!(
            "A further {} you answered yes to in the [design] section of securevibe.toml. That is \
             your word about how the app is built, which is the weakest thing this report says: \
             each one is still listed as a test to write.",
            c.attested
        );
    }
    if c.documented > 0 {
        println!(
            "A further {} you answered yourself in security-notes.md. That is documented, not \
             checked: nothing here reads whether the answer is right, or whether the app does what \
             it says.",
            c.documented
        );
    }
    if !report.out_of_scope.is_empty() {
        println!(
            "{} finding{} name a requirement this app is not being assessed against; the reports \
             list them.",
            report.out_of_scope.len(),
            if report.out_of_scope.len() == 1 {
                ""
            } else {
                "s"
            }
        );
    }
    if c.not_assessed > 0 {
        println!(
            "{} more could not be placed at all: nobody has answered the question that decides \
             whether they apply.",
            c.not_assessed
        );
    }
    if !report.tests_to_write.is_empty() {
        let level_one = report
            .tests_to_write
            .iter()
            .filter(|t| t.level == 1)
            .count();
        println!(
            "{} have no evidence and no test naming them ({level_one} at level 1): compliance.md \
             lists them under \"Tests to write\".",
            report.tests_to_write.len()
        );
    }
    if !report.threats.is_empty() {
        println!(
            "{} compliance.md lists them under \"Threats\".",
            sv_report::threats::count_line(&report.threats)
        );
    }
    println!(
        "\nOpen report.html to read it. Nothing in there says a requirement passed, because \
         nothing here can establish that."
    );
    Ok(())
}

/// The terminal's account of rules that met a language they were not taught.
fn untaught_lines(untaught: &[sv_check::ast::Untaught]) -> Vec<String> {
    if untaught.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![
        "\nNot looked for — these rules read other languages in this app, but have not been\n\
         taught the ones named, so they claim nothing for it:"
            .to_owned(),
    ];
    for u in untaught {
        lines.push(format!(
            "  {} ({}) — not in {}",
            u.title,
            u.rule_id,
            u.languages.join(", ")
        ));
    }
    lines
}

/// The same, as gaps in the written report.
fn untaught_gaps(untaught: &[sv_check::ast::Untaught]) -> Vec<sv_report::Gap> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn untaught() -> Vec<sv_check::ast::Untaught> {
        vec![sv_check::ast::Untaught {
            rule_id: "ast.shell-command".to_owned(),
            title: "A shell command is built from a value".to_owned(),
            languages: vec!["rust".to_owned(), "zig".to_owned()],
        }]
    }

    #[test]
    fn the_terminal_names_each_untaught_rule_and_its_languages() {
        let lines = untaught_lines(&untaught());
        assert!(lines[0].contains("Not looked for"), "{lines:?}");
        assert_eq!(
            lines[1],
            "  A shell command is built from a value (ast.shell-command) — not in rust, zig"
        );
        assert!(untaught_lines(&[]).is_empty(), "no heading over nothing");
    }

    #[test]
    fn the_report_carries_each_untaught_rule_as_a_gap() {
        let gaps = untaught_gaps(&untaught());
        assert_eq!(gaps.len(), 1);
        assert_eq!(
            gaps[0].what,
            "A shell command is built from a value (ast.shell-command), in rust, zig"
        );
        assert!(
            gaps[0]
                .why
                .contains("has not been taught what to look for in rust or zig"),
            "{}",
            gaps[0].why
        );
    }

    fn data() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data")
    }

    #[test]
    fn every_command_sees_the_checklist_levels_grounded_in_asvs() {
        // `scope`, `check` and `report` all load the frameworks through this one function. Without
        // the crosswalk step a checklist control keeps the level `sv` invented for it, and a report
        // files it as above the target on that alone.
        let frameworks = load_frameworks(&data()).expect("the frameworks load");
        let as02 = frameworks
            .get("SBD-AS-02")
            .expect("the checklist is loaded");
        assert_eq!(
            as02.level, 1,
            "nothing in ASVS asks for unified service discovery"
        );
        assert_eq!(
            frameworks
                .get("SBD-DM-01")
                .and_then(|r| r.level_basis.as_deref()),
            Some("level 2, as V14.1.1")
        );
    }

    #[test]
    fn a_level_one_app_is_asked_the_controls_asvs_has_no_level_for() {
        // The same step seen from where it matters: bucketing. At level 1 a control nothing in ASVS
        // matches is applicable, not set aside on a level `sv` made up.
        let frameworks = load_frameworks(&data()).unwrap();
        let config =
            ApplicabilityConfig::load_v2(&data().join("knowledge"), &overlay_path()).unwrap();
        let buckets = sv_frameworks::applicability::bucket(
            &frameworks,
            &config,
            &sv_frameworks::applicability::ConditionContext::default(),
            1,
        );
        assert!(
            !buckets.out_of_level.iter().any(|id| id == "SBD-MT-02"),
            "SBD-MT-02 (metrics and dashboards) was set aside at level 1"
        );
    }
}

#[cfg(test)]
mod dependency_gap_tests {
    use super::*;

    fn component(ecosystem: &str, name: &str, source: sbom::VersionSource) -> sbom::Component {
        sbom::Component {
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            ecosystem: ecosystem.to_owned(),
            source,
        }
    }

    #[test]
    fn a_fully_locked_bill_of_materials_produces_no_gap() {
        // The second witness for the over-reporting guard, at the level the end-to-end test cannot
        // reach: given a document whose every version came from a lockfile, there is nothing to
        // report, and a gap row for nothing reads as a hole where there is none.
        let sbom = sbom::Sbom {
            components: vec![
                component("npm", "react", sbom::VersionSource::Locked),
                component("npm", "express", sbom::VersionSource::Locked),
                component("Python", "flask", sbom::VersionSource::Locked),
            ],
            unread: Vec::new(),
        };
        assert!(dependency_gaps(&sbom).is_empty());
    }

    #[test]
    fn an_unread_ecosystem_is_reported_as_empty_and_a_declared_one_is_not() {
        // The distinction the whole item is about, held at one place rather than across two apps:
        // these are two different gaps and must not collapse into one sentence again.
        let sbom = sbom::Sbom {
            components: vec![component("Python", "flask", sbom::VersionSource::Declared)],
            unread: vec![(
                "npm".to_owned(),
                "npm is in use but nothing readable says which versions are installed, so none of \
                 its packages are listed"
                    .to_owned(),
            )],
        };
        let gaps = dependency_gaps(&sbom);
        assert_eq!(gaps.len(), 2, "{gaps:?}");

        let npm = gaps.iter().find(|g| g.what.contains("npm")).expect("npm");
        assert!(npm.why.contains("empty one"), "{}", npm.why);

        let python = gaps
            .iter()
            .find(|g| g.what.contains("Python"))
            .expect("Python");
        assert!(python.why.contains("what was asked for"), "{}", python.why);
        assert!(
            !python.why.contains("empty one"),
            "a list that was read is not empty: {}",
            python.why
        );
    }

    #[test]
    fn one_ecosystem_being_unreadable_says_nothing_about_another_that_was_read() {
        // An app with both. The npm half is absent and the Python half is real, and the report has
        // to say each of those about the right one — which is exactly what a single sentence for
        // every ecosystem could not do.
        let sbom = sbom::Sbom {
            components: vec![
                component("Python", "flask", sbom::VersionSource::Declared),
                component("Rust", "serde", sbom::VersionSource::Locked),
            ],
            unread: vec![("npm".to_owned(), "nothing readable".to_owned())],
        };
        let gaps = dependency_gaps(&sbom);
        let named: Vec<&str> = gaps.iter().map(|g| g.what.as_str()).collect();
        assert_eq!(gaps.len(), 2, "{named:?}");
        assert!(
            !named.iter().any(|w| w.contains("Rust")),
            "the locked Rust packages are not a gap: {named:?}"
        );
    }
}
