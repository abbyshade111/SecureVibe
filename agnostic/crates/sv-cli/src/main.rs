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
        Some("run") => cmd_run(args.get(1).map(PathBuf::from)),
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
         sv run [PATH]      start the app behind the network fence and check it answers\n  \
         sv check [PATH]    credentials left in the code, and how it is set up\n  \
         sv sbom [PATH]     write the list of what the app ships, as CycloneDX JSON\n  \
         sv audit [PATH] --advisories DIR\n                     \
             match what the app ships against a local OSV database\n  \
         sv report [PATH] [--out DIR] [--run] [--tools]\n                     \
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

/// Starts the app behind the fence, so the checks that need it running have something to check.
/// Starts the app behind the fence and asks it the probe questions, or says why it could not.
///
/// Shared by `sv run` and `sv report --run` on purpose. Two call sites each deciding when an app is
/// runnable would drift, and the one that drifts quietly is the report — where "not assessed" and
/// "nothing found" look the same to a reader who was not there.
fn probe_the_running_app(
    manifest: &Manifest,
    app_dir: &Path,
) -> std::result::Result<(sv_run::RunOutcome, sv_run::RunPlan), String> {
    let plan = RunPlan::from_manifest(manifest, app_dir).map_err(|e| e.explain())?;
    let backend = sv_run::detect().map_err(|e| e.explain())?;
    let requests = probes::requests(&plan.health_path);
    let outcome = backend.run(&plan, &requests).map_err(|e| e.explain())?;
    Ok((outcome, plan))
}

/// What the running app showed: the anonymous probes, and the signed-in ones when they ran.
///
/// One function for `sv run` and `sv report`, so the two cannot disagree about what was found.
fn running_app_evidence(
    outcome: &sv_run::RunOutcome,
) -> (
    Vec<sv_check::Finding>,
    Vec<sv_check::Verified>,
    Vec<(String, String)>,
) {
    let mut findings = probes::evaluate(&outcome.probe_responses);
    let mut verified = probes::verified(&outcome.probe_responses);
    let mut not_assessed = Vec::new();
    if let Some(signed_in) = &outcome.signed_in {
        findings.extend(signed_in.findings.iter().cloned());
        verified.extend(signed_in.verified.iter().cloned());
        not_assessed.extend(signed_in.not_assessed.iter().cloned());
    }
    (findings, verified, not_assessed)
}

fn cmd_run(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let manifest = Manifest::load(&manifest_path)?;

    println!("Starting {} behind the network fence…", manifest.app.name);
    let requests = probes::requests(
        &RunPlan::from_manifest(&manifest, &app_dir)
            .map(|p| p.health_path)
            .unwrap_or_default(),
    );
    match probe_the_running_app(&manifest, &app_dir) {
        Err(reason) => {
            println!("\nNot assessed.\n\n{reason}");
        }
        Ok((outcome, plan)) => {
            println!("\nThe app started and answered on {}.", plan.health_path);
            println!("\n{}", outcome.fence.explain());
            let (findings, verified, signed_in_not_assessed) = running_app_evidence(&outcome);
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
                    println!("  {} — checked over {}", v.check_id, v.scope);
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

    if !code.untaught.is_empty() {
        println!(
            "\nNot looked for — these rules read other languages in this app, but have not been\n\
             taught the ones named, so they claim nothing for it:"
        );
        for u in &code.untaught {
            println!(
                "  {} ({}) — not in {}",
                u.title,
                u.rule_id,
                u.languages.join(", ")
            );
        }
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

    let result = advisories::audit(&sbom, &database);
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
    for f in &result.findings {
        println!("\n  [{}] {}", f.severity.name(), f.title);
        if !f.description.is_empty() {
            println!("     {}", f.description);
        }
        println!("     what to do: {}", f.fix);
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
    /// Run the language's own security tool. Opt-in: these are other people's programs.
    run_tools: bool,
    /// Said in the report when the app was not started, in the words of whoever built it.
    why_not_run: &'static str,
    /// Said in the report when the tools were not run.
    why_no_tools: &'static str,
}

/// Everything `sv report` knows about an app, built once for every caller.
///
/// `sv report` and the MCP server both call this, so what an AI coding tool is told about an app
/// is exactly what the written report says — not a second, drifting summary of it.
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

    let secret_rules = SecretRules::load(&secret_rules_path())?;
    let secrets = scan_dir(&secret_rules, app_dir);
    let config = check_dir(app_dir);
    let ast_rules = ast::AstRules::load(&ast_rules_path())?;
    let code = ast::scan_dir(&ast_rules, app_dir);

    let mut probe_verified = Vec::new();
    let mut tool_verified = Vec::new();
    let mut test_verified = Vec::new();
    let mut findings = Vec::new();
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
                "{} bandit, gosec and brakeman each know their own language far better than the \
                 handful of rules built in here.",
                options.why_no_tools
            ),
        });
    }

    // Every limit `sv` knows about, said out loud. This list existing is the difference between a
    // report about an app and a report about the part of an app somebody happened to look at.
    let mut gaps = Vec::new();
    let mut run_note = None;

    if options.run_the_app {
        match probe_the_running_app(&manifest, app_dir) {
            Ok((outcome, plan)) => {
                let (running_findings, running_verified, signed_in_not_assessed) =
                    running_app_evidence(&outcome);
                findings.extend(running_findings);
                probe_verified = running_verified;
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
                    match &outcome.signed_in {
                        Some(s) if !s.steps.is_empty() => {
                            format!(" Then, as two test users: {}.", s.steps.join("; "))
                        }
                        _ => String::new(),
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
    for u in &code.untaught {
        gaps.push(sv_report::Gap {
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
        });
    }
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
    for eco in &scan_report.unpinned {
        gaps.push(sv_report::Gap {
            what: format!("what {} actually installs", eco.label()),
            why: format!(
                "{} pins no versions, so the list of dependencies is what was asked for rather \
                 than what is there",
                eco.manifest
            ),
        });
    }

    // Everything that ran, looked at what it needed to, and found nothing wrong. Each of these
    // fails closed on its own coverage, so the list is short on an app `sv` could not read fully —
    // which is the honest shape for it to have.
    let mut verified = config.passed.clone();
    verified.extend(secrets.verified.iter().cloned());
    verified.extend(code.verified.iter().cloned());
    verified.extend(probe_verified.iter().cloned());
    verified.extend(tool_verified.iter().cloned());
    verified.extend(test_verified.iter().cloned());

    Ok(sv_report::build(sv_report::Inputs {
        app_name: if manifest.app.name.is_empty() {
            "This app"
        } else {
            &manifest.app.name
        },
        target_level: manifest.target_level(),
        generated: None,
        run_note,
        frameworks: &frameworks,
        buckets: &buckets,
        claims: &resolved,
        findings,
        verified: &verified,
        gaps,
        manual_only,
    }))
}

fn cmd_report(args: &[String]) -> Result<()> {
    let mut app_dir = PathBuf::from(".");
    let mut out_dir: Option<PathBuf> = None;
    // Opt-in. Everything else `sv report` does reads files; this starts somebody's code. It runs
    // behind the same fence `sv run` uses — no network beyond loopback, nothing published to this
    // computer — and it is still their decision to make rather than a default.
    let mut run_the_app = false;
    // Opt-in for the same reason as --run, and one more: these are other people's programs, and one
    // of them fetches its rules over the network the first time it runs.
    let mut run_tools = false;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                out_dir = Some(PathBuf::from(
                    rest.next().context("--out needs a directory")?,
                ));
            }
            "--run" => run_the_app = true,
            "--tools" => run_tools = true,
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => app_dir = PathBuf::from(other),
        }
    }
    let out_dir = out_dir.unwrap_or_else(|| app_dir.join("securevibe-report"));

    let report = assemble_report(
        &app_dir,
        &ReportOptions {
            run_the_app,
            run_tools,
            why_not_run: "`sv report` does not start the app unless you pass --run.",
            why_no_tools: "`sv report` does not run other people's tools unless you pass --tools.",
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
    println!(
        "\nOpen report.html to read it. Nothing in there says a requirement passed, because \
         nothing here can establish that."
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
