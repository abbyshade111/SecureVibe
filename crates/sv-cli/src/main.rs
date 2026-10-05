//! `sv` — run the SecureVibe checks against code written anywhere, in any language.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_check::advisories;
use sv_check::ast;
use sv_check::config::check_dir_in;
use sv_check::probes;
use sv_check::sbom;
use sv_check::secrets::{SecretRules, scan_dir};
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, bucket, requirements_gated_on};
use sv_frameworks::{Condition, Source};
use sv_manifest::{ClaimState, Manifest, consistency, spec};
use sv_run::RunPlan;
use sv_scan::{Evidence, Signatures};

mod bundle;
mod exit;
mod mcp;
mod plan;
mod report_lock;
mod report_seal;
mod review;

/// Runs the command, and ends with its status: 3 for any error `sv` could not get past, whichever
/// command met it, so a pipeline can tell "`sv` did not run" from anything a run found (DESIGN, "Exit
/// codes for CI"). The error is printed as it always was, `Error:` and its causes.
fn main() {
    match run() {
        Ok(exit::CLEAN) => {}
        Ok(code) => exit::exit_with(code),
        Err(error) => {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            eprintln!("Error: {error:?}");
            exit::exit_with(exit::FAILED)
        }
    }
}

/// The command named on the command line, and the status it ends with when it finished.
fn run() -> Result<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(first) = args.first().map(String::as_str) else {
        print_help();
        return Ok(exit::CLEAN);
    };
    match first {
        "--help" | "-h" | "help" => {
            print_help();
            return Ok(exit::CLEAN);
        }
        "--version" | "-V" | "version" => {
            println!("{}", version_line());
            return Ok(exit::CLEAN);
        }
        _ => {}
    }
    let Some(command) = COMMANDS.iter().find(|c| c.name == first) else {
        print_help();
        bail!("unknown command: {first}");
    };
    let rest = &args[1..];
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        print!("USAGE:\n{}", command.help);
        return Ok(exit::CLEAN);
    }
    check_args(command, rest)?;
    let finished = |done: Result<()>| done.map(|()| exit::CLEAN);
    match command.name {
        "init" => {
            println!("{}", spec::STARTER_MANIFEST);
            println!("{}", spec::INSTRUCTIONS);
            Ok(exit::CLEAN)
        }
        "scope" => finished(cmd_scope(rest.first().map(PathBuf::from))),
        "plan" => finished(cmd_plan(rest.first().map(PathBuf::from))),
        "notes" => finished(cmd_notes(rest.first().map(PathBuf::from))),
        "questions" => finished(cmd_questions(rest.first().map(PathBuf::from))),
        "rules" => finished(cmd_rules(rest)),
        "prompts" => finished(cmd_prompts(rest)),
        "probe" => finished(cmd_probe(rest)),
        "run" => finished(cmd_run(rest)),
        "check" => cmd_check(rest),
        "sbom" => finished(cmd_sbom(rest.first().map(PathBuf::from))),
        "audit" => cmd_audit(rest),
        "report" => cmd_report(rest),
        "review" => finished(review::cmd_review(rest.first().map(PathBuf::from))),
        "bundle" => finished(cmd_bundle(rest)),
        "mcp" => finished(mcp::cmd_mcp(rest)),
        other => unreachable!("{other} is in COMMANDS and has no arm"),
    }
}

/// One command: its name, the options it takes, and its lines of the help.
struct Command {
    name: &'static str,
    /// What the one word that is not an option names, such as `PATH`, or `None` when it takes none.
    word: Option<&'static str>,
    /// Options that stand alone.
    flags: &'static [&'static str],
    /// Options followed by a value, the word after them.
    valued: &'static [&'static str],
    /// The command's lines of `sv --help`, as they are printed there.
    help: &'static str,
}

/// Every command `sv` knows, in the order `sv --help` lists them.
const COMMANDS: &[Command] = &[
    Command {
        name: "init",
        word: None,
        flags: &[],
        valued: &[],
        help: "  sv init            print the securevibe.toml spec to hand to your AI coding tool\n",
    },
    Command {
        name: "scope",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv scope [PATH]    show which requirements apply to the app, and why\n",
    },
    Command {
        name: "plan",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv plan [PATH]     before any code: what applies, what to decide, the tests to write,\n                     and what the app must give `sv run`; credits nothing\n",
    },
    Command {
        name: "notes",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv notes [PATH]    write security-notes.md: the questions only you can answer\n",
    },
    Command {
        name: "questions",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv questions [PATH]\n                     the questions only a person can answer, for your AI coding\n                     tool to ask you: paste them into its chat\n",
    },
    Command {
        name: "rules",
        word: Some("PATH"),
        flags: &["--print"],
        valued: &[],
        help: "  sv rules [PATH] [--print]\n                     write the security rules your AI coding tool follows while it\n                     codes into AGENTS.md (--print shows them instead)\n",
    },
    Command {
        name: "prompts",
        word: None,
        flags: &[],
        valued: &["--requirement"],
        help: "  sv prompts [--requirement ID]\n                     prompts to give your AI coding tool, each saying whether it has\n                     been shown to work; --requirement gives only those for one requirement\n                     or Secure by Design control, such as V1.2.4 or SBD-AC-03\n",
    },
    Command {
        name: "probe",
        word: Some("URL"),
        flags: &[],
        valued: &["--hsts-preload"],
        help: "  sv probe URL [--hsts-preload FILE]\n                     ask your own live site the few things only it can answer\n",
    },
    Command {
        name: "run",
        word: Some("PATH"),
        flags: &["--slow"],
        valued: &[],
        help: "  sv run [PATH] [--slow]\n                     start the app behind the network fence and check it answers;\n                     --slow also waits out the session timeouts you state,\n                     and ten minutes before using an emailed sign-in code\n",
    },
    Command {
        name: "check",
        word: Some("PATH"),
        flags: &[],
        valued: &["--fail-on"],
        help: "  sv check [PATH] [--fail-on WHAT]\n                     credentials left in the code, and how it is set up\n                     --fail-on also fails for attention[:SEVERITY] (a finding at SEVERITY\n                     or worse: critical, high, medium, low (the default), or info),\n                     not-assessed (also a symbolic link not followed), or any (both),\n                     several separated by commas\n                     exit status: 0 finished; 1 needs attention (only with --fail-on);\n                     2 not assessed: a check could not run, or no file of the app was read;\n                     3 sv itself failed (no such folder, an option it does not know)\n",
    },
    Command {
        name: "sbom",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv sbom [PATH]     write the list of what the app ships, as CycloneDX JSON\n",
    },
    Command {
        name: "audit",
        word: Some("PATH"),
        flags: &[],
        valued: &["--advisories"],
        help: "  sv audit [PATH] --advisories DIR\n                     match what the app ships against a local OSV database\n                     exit status: 0 everything compared and nothing matched; 1 a known\n                     vulnerability; 2 the comparison did not cover the whole app (no\n                     database, an ecosystem it lacks, a list of packages not complete);\n                     3 sv itself failed (an unreadable database or manifest, no such folder)\n",
    },
    Command {
        name: "report",
        word: Some("PATH"),
        flags: &["--run", "--slow", "--tools"],
        valued: &["--out", "--advisories", "--fail-on"],
        help: "  sv report [PATH] [--out DIR] [--run] [--tools] [--advisories DIR] [--fail-on WHAT]\n                     write the reports: what applies, what was found, what nobody has answered\n                     --fail-on also fails for attention[:SEVERITY] (a finding at SEVERITY\n                     or worse: critical, high, medium, low (the default), or info),\n                     not-assessed (also a symbolic link not followed, a tool --tools could\n                     not run, or an --advisories comparison that did not cover the app),\n                     or any (both), several separated by commas\n                     exit status: 0 finished; 1 needs attention (only with --fail-on);\n                     2 not assessed: a check could not run, no file of the app was read,\n                     or --run was given and the app could not be started;\n                     3 sv itself failed (no securevibe.toml, a bad manifest, no such folder)\n",
    },
    Command {
        name: "review",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv review [PATH]   record, in your own terminal, the findings you set aside and the\n                     answers you confirm; only what you record here counts\n",
    },
    Command {
        name: "bundle",
        word: Some("PATH"),
        flags: &["--run", "--slow", "--tools"],
        valued: &["--out", "--advisories"],
        help: "  sv bundle [PATH] [--out FILE.zip] [--run] [--tools] [--advisories DIR]\n                     the app, its report and a SHA-256 for every file in one zip, with\n                     anything that could hold a secret left out and listed\n",
    },
    Command {
        name: "mcp",
        word: None,
        flags: &[],
        valued: &["--root", "--time-limit"],
        help: "  sv mcp [--root DIR] [--time-limit SECONDS]\n                     serve the checks to an AI coding tool over MCP, for the apps under DIR;\n                     a check that takes longer than SECONDS (50) is reported as not finished\n",
    },
];

/// Refuses what a command cannot take before it runs, so an option is never read as a folder: an unknown
/// option, an option missing its value, and a second word where the command takes one or none.
fn check_args(command: &Command, args: &[String]) -> Result<()> {
    let refuse = |problem: String| -> Result<()> {
        bail!("{problem}\n\nUSAGE:\n{}", command.help.trim_end())
    };
    let name = command.name;
    let mut words = 0;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if command.valued.contains(&arg.as_str()) {
            match rest.next() {
                None => return refuse(format!("`{arg}` needs a value after it")),
                // `sv report --out --run` once wrote the report to a folder named `--run` and did
                // not run the app (the deep review's improvement 7).
                Some(value) if value.starts_with("--") => {
                    return refuse(format!(
                        "`{arg}` needs a value after it, and was given the option {value}. A \
                         folder or file whose name starts with `-` can be given as ./{value}"
                    ));
                }
                Some(_) => {}
            }
        } else if command.flags.contains(&arg.as_str()) {
        } else if arg.starts_with('-') && arg.len() > 1 {
            let known: Vec<&str> = command
                .flags
                .iter()
                .chain(command.valued)
                .copied()
                .collect();
            let takes = if known.is_empty() {
                "it takes no options but --help".to_owned()
            } else {
                format!("it takes {}, and --help", known.join(", "))
            };
            return refuse(format!(
                "unknown option for `sv {name}`: {arg} ({takes}). A folder whose name starts with `-` \
                 can be given as ./{arg}"
            ));
        } else {
            words += 1;
            match command.word {
                None => {
                    return refuse(format!(
                        "`sv {name}` takes only options, and was given {arg}"
                    ));
                }
                Some(word) if words > 1 => {
                    return refuse(format!(
                        "`sv {name}` takes one {word}, and was given a second: {arg}"
                    ));
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

/// `sv --version`: the version, and the commit the build was made from, as a bundle records it.
fn version_line() -> String {
    format!(
        "sv {} (commit {})",
        env!("CARGO_PKG_VERSION"),
        env!("SV_GIT_COMMIT")
    )
}

fn print_help() {
    let mut text = String::from(
        "sv — check an app against OWASP ASVS 5.0, AISVS 1.0 and Secure by Design.\n\nUSAGE:\n",
    );
    for command in COMMANDS {
        text.push_str(command.help);
    }
    text.push_str("  sv --version       the version, and the commit it was built from\n");
    text.push_str(
        "\nEXIT STATUS:\n  0 finished; 1 needs attention (sv audit, or --fail-on); 2 not assessed (a check\n  could not run); 3 sv itself failed. `sv COMMAND --help` says what each means for it.\n",
    );
    println!("{text}");
}

/// Where the data lives: the OWASP frameworks and knowledge files, and sv's own files beside them, all in the
/// repository's `data/` folder.
fn data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("SV_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    // From the workspace, the repository's `data` folder is two levels up from a crate.
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = here.join("../../data");
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

/// Everything a report reads from `data/`, loaded once per process.
///
/// A command loads it once and is done; the MCP server loads it when it starts and hands the same
/// one to every call, so the code rules' queries — compiled the first time a language is met, and
/// kept in the `AstRules` — are compiled once for the life of the server rather than once per call.
/// Loading itself is cheap (about 30 ms, most of it the regexes); the second every command used to
/// spend before reading a file was the queries, and they are now compiled only for the languages
/// the app holds (review item 6, 27 September 2026).
pub(crate) struct Loaded {
    pub frameworks: Frameworks,
    pub config_rules: ApplicabilityConfig,
    pub signatures: Signatures,
    pub threat_rules: sv_report::threats::ThreatRules,
    pub secret_rules: SecretRules,
    pub ast_rules: ast::AstRules,
}

impl Loaded {
    pub(crate) fn load() -> Result<Loaded> {
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
        })
    }
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

/// The design-time prompts, read on their own: the second of the library's files.
pub(crate) fn design_prompts() -> Result<sv_check::prompts::Prompts> {
    let paths = prompts_paths();
    sv_check::prompts::Prompts::load_all(&[&paths[1]])
}

/// The plan for an app from its brief, built from the report's own parts (ADR-030).
pub(crate) fn plan_for(app_dir: &Path, report: &sv_report::Report) -> Result<plan::Plan> {
    let manifest = Manifest::load(&app_dir.join("securevibe.toml"))?;
    Ok(plan::from_report(report, &manifest, &design_prompts()?))
}

/// The options a plan's report is built with: nothing started and no tool run, since a plan reads
/// the brief and needs no code.
pub(crate) fn plan_options() -> ReportOptions {
    ReportOptions {
        run_the_app: false,
        slow: false,
        run_tools: false,
        why_not_run: "`sv plan` does not start the app.".to_owned(),
        why_no_tools: "`sv plan` does not run other people's tools.".to_owned(),
        advisories: None,
        why_no_advisories: "`sv plan` does not compare packages with known vulnerabilities."
            .to_owned(),
    }
}

/// Prints the plan. A plan is not a check, so it ends clean whatever the app holds.
fn cmd_plan(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let report = assemble_report(&app_dir, &plan_options(), &Loaded::load()?)?;
    print!("{}", plan::markdown(&plan_for(&app_dir, &report)?));
    Ok(())
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
    let report = scan_for(
        &manifest,
        &sv_scan::files::Listing::of(&app_dir),
        &signatures,
    )?;
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
    if let Some(why) = manifest.level_from_unanswered_data() {
        println!("{why}");
    }
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
            "  {} does not pin every version it installs (see {}), so what is actually installed cannot be known.",
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

    // Looked up once, here, and every address checked before anything is sent: a name that leads
    // to this computer or its network is refused, and curl is held to the addresses checked.
    let addresses =
        sv_check::production::addresses(&target, &mut sv_check::production::SystemResolver)
            .map_err(|why| anyhow::anyhow!("{why}"))?;
    let mut http = sv_check::production::Curl::held_to(&target, &addresses);
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

/// Writes `security-notes.md`: the questions no tool can answer, for the requirements that apply.
fn cmd_notes(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let NotesWritten {
        path: out_path,
        asked,
        already,
        kept,
    } = write_notes_file(&app_dir)?;
    println!("Wrote {}.", out_path.display());
    if kept {
        println!(
            "\nSome of the text in it is not under any question. It is kept as you wrote it, near \
             the top, under \"{}\"; the report does not read it as an answer.",
            sv_check::notes::KEPT_HEADING.trim_start_matches("## ")
        );
    }
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
        "\nAnswering one makes its requirement *documented* in the report, when the answer starts \
         with `Written by: owner`. That is not the same as checked: nothing here reads whether your \
         answer is right, or whether the app does what it says. One your AI coding tool wrote, or \
         one that does not say who wrote it, counts for less, as *stated by the AI coding tool*."
    );
    Ok(())
}

pub(crate) fn coding_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/coding-rules.json")
}

/// The coding rules for an app, and how many were left out as not applying to it.
pub(crate) struct RulesForApp {
    pub rules: sv_check::coding_rules::CodingRules,
    /// The ids of the rules given, in the file's order.
    pub given: Vec<String>,
    pub withheld: usize,
    /// Whether securevibe.toml was there to filter by. Without it every rule is given.
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
}

/// Reads the coding rules and leaves out those whose every cited requirement does not apply to the
/// app. Prints nothing, because the MCP server's stdout is the protocol.
pub(crate) fn coding_rules_for(app_dir: &Path) -> Result<RulesForApp> {
    let rules = sv_check::coding_rules::CodingRules::load(&coding_rules_path())?;
    let manifest_path = app_dir.join("securevibe.toml");
    let excluded: Option<std::collections::BTreeSet<String>> = if manifest_path.exists() {
        let manifest = Manifest::load(&manifest_path)?;
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

/// The prompt library's files: the prompts for the coding, then the design-time ones.
pub(crate) fn prompts_paths() -> [PathBuf; 2] {
    let data = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data");
    [data.join("prompts.json"), data.join("design-prompts.json")]
}

/// The library's prompts for one requirement, or all of them, as Markdown, and the ones chosen.
///
/// An id that is not a requirement is refused, so a mistyped one is never answered "no prompt for
/// it" as if the library had been searched for it.
pub(crate) fn prompts_for(
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

/// Prints the prompts for the AI coding tool, for one requirement or all of them.
fn cmd_prompts(args: &[String]) -> Result<()> {
    let requirement = args
        .iter()
        .position(|a| a == "--requirement")
        .and_then(|i| args.get(i + 1))
        .map(String::as_str);
    let frameworks = load_frameworks(&data_dir()?)?;
    let (_, _, text) = prompts_for(&frameworks, requirement)?;
    print!("{text}");
    Ok(())
}

/// Writes the coding rules into the app's `AGENTS.md`, between `sv`'s markers, or prints them.
fn cmd_rules(args: &[String]) -> Result<()> {
    let mut app_dir = PathBuf::from(".");
    let mut print = false;
    for arg in args {
        match arg.as_str() {
            "--print" => print = true,
            other if other.starts_with("--") => bail!("unknown option: {other}"),
            other => app_dir = sv_check::adapters::clean_folder(Path::new(other)),
        }
    }
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    let found = coding_rules_for(&app_dir)?;
    let section = found.markdown(None);
    if print {
        print!("{section}");
        return Ok(());
    }
    let path = app_dir.join("AGENTS.md");
    // Before reading, too: an AGENTS.md that is a link would have the file it points at read in and
    // then written over (deep review S3).
    refuse_link(&path, FILE_LINK)?;
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let text = found
        .rules
        .into_agents_file(existing.as_deref(), &section)
        .with_context(|| format!("{} was left as it was", path.display()))?;
    write_without_following(&app_dir, "AGENTS.md", text.as_bytes())?;
    println!(
        "Wrote {} security rule{} for your AI coding tool into {}{}.",
        found.given.len(),
        if found.given.len() == 1 { "" } else { "s" },
        path.display(),
        match &existing {
            Some(text) if text.contains(sv_check::coding_rules::BEGIN) => {
                ", replacing only the section `sv` wrote there"
            }
            Some(_) => ", after what was already in it, which is unchanged",
            None => "",
        }
    );
    if !found.filtered {
        println!(
            "There is no securevibe.toml yet, so every rule is included. Run `sv rules` again once \
             it is written, and the rules that do not apply to this app are left out."
        );
    } else if found.withheld > 0 {
        println!(
            "{} left out, because what {} about does not apply to this app.",
            if found.withheld == 1 {
                "1 rule is".to_owned()
            } else {
                format!("{} rules are", found.withheld)
            },
            if found.withheld == 1 {
                "it is"
            } else {
                "they are"
            }
        );
    }
    println!(
        "\nThey are instructions for the tool, not a check: following them is not evidence that the \
         app meets anything. They are adapted from OWASP AISVS 1.0 Appendix C, under CC BY-SA 4.0; \
         the file says so, with a link."
    );
    Ok(())
}

/// The questions only a person can answer, written for the AI coding tool to ask them. For a tool
/// that cannot use `sv mcp`: the owner pastes this into its chat.
fn cmd_questions(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    if !app_dir.join("securevibe.toml").exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    let report = assemble_report(
        &app_dir,
        &ReportOptions {
            run_the_app: false,
            slow: false,
            run_tools: false,
            why_not_run: "".to_owned(),
            why_no_tools: "".to_owned(),
            advisories: None,
            why_no_advisories: "".to_owned(),
        },
        &Loaded::load()?,
    )?;
    println!(
        "Paste everything below into your AI coding tool's chat. It will ask you these one at a \
         time.\n"
    );
    print!("{}", sv_report::interview::text(&report));
    Ok(())
}

/// What writing the notes file came to.
pub(crate) struct NotesWritten {
    pub path: PathBuf,
    /// Sections for requirements that apply.
    pub asked: usize,
    /// Of those, how many were already answered.
    pub already: usize,
    /// Whether the file has text that is not under a question, kept in a section of its own.
    pub kept: bool,
}

/// Writes or refreshes security-notes.md, keeping everything in it that `sv` did not write: the
/// answers under their questions, and any other text in a section of its own. Shared by `sv notes`
/// and the MCP server, and prints nothing, because the MCP server's stdout is the protocol.
pub(crate) fn write_notes_file(app_dir: &Path) -> Result<NotesWritten> {
    write_notes(app_dir, None)
}

/// Writes the notes file with the AI coding tool's answer under one question, marked as the tool's.
///
/// Refused when the question does not apply to the app, when the section holds anything but
/// the tool's own marked answer (`Answers::tool_may_write`: the tool's answer never replaces what
/// may be the owner's), and when the answer would not read back as exactly the
/// tool's (`sv_check::notes::tool_answer`). Written under a new name and renamed into place, and
/// never through a link.
pub(crate) fn record_tool_answer(app_dir: &Path, id: &str, answer: &str) -> Result<NotesWritten> {
    write_notes(app_dir, Some((id, answer)))
}

fn write_notes(app_dir: &Path, record: Option<(&str, &str)>) -> Result<NotesWritten> {
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
        "{id} is not one of the questions in {} for this app; securevibe_questions lists the ones \
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
        std::process::exit(130);
    }
    Ok((outcome.map_err(|e| e.explain())?, plan))
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
    let (admin_pages, private_files) = more_questions(plan);
    requests.extend(sv_check::running::requests(&admin_pages, &private_files));
    requests
}

/// The admin pages securevibe.toml names, and the files in the app's folder that should never be
/// served, for the questions in `sv_check::running`. Worked out the same way for the requests and
/// for reading the answers, so the two agree on what was asked.
fn more_questions(plan: &RunPlan) -> (Vec<String>, Vec<sv_check::running::PrivateFile>) {
    let admin_pages = plan
        .users
        .as_ref()
        .map(|users| users.admin.clone())
        .unwrap_or_default();
    let listing = sv_scan::files::Listing::of(&plan.app_dir);
    (admin_pages, sv_check::running::private_files(&listing))
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
fn rate_limited_gap(limited: &[String]) -> Option<sv_report::Gap> {
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

fn cmd_run(args: &[String]) -> Result<()> {
    let mut app_dir = PathBuf::from(".");
    // Opt-in: waiting out the session timeouts the owner states can take as long as they are.
    let mut slow = false;
    for arg in args {
        match arg.as_str() {
            "--slow" => slow = true,
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => app_dir = sv_check::adapters::clean_folder(Path::new(other)),
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
            "With --slow: this waits out the session timeouts securevibe.toml states, and ten \
             minutes before using an emailed sign-in code, so it can take as long as they are."
        );
    }
    match probe_the_running_app(&manifest, &app_dir, slow) {
        Err(reason) => {
            println!("\nNot assessed.\n\n{reason}");
        }
        Ok((outcome, plan)) => {
            if let Some(removed) = sv_run::cleanup::removed_sentence(&outcome.left_over_removed) {
                println!("\n{removed}");
            }
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
            let unanswered = requests
                .len()
                .saturating_sub(outcome.probe_responses.len() + outcome.probes_rate_limited.len());
            if unanswered > 0 {
                println!("  {unanswered} got no answer at all, so nothing is claimed about them.");
            }
            if let Some(gap) = rate_limited_gap(&outcome.probes_rate_limited) {
                println!("  {} — {}", gap.what, gap.why);
            }

            if let Some(signed_in) = &outcome.signed_in
                && !signed_in.steps.is_empty()
            {
                println!("\nThen, as two test users: {}.", signed_in.steps.join("; "));
            }
            if let Some(oidc) = &outcome.oidc
                && !oidc.steps.is_empty()
            {
                println!(
                    "\nThen, through a test provider standing in for the one it signs in with: {}.",
                    oidc.steps.join("; ")
                );
            }
            if let Some(ai) = &outcome.ai
                && !ai.steps.is_empty()
            {
                println!(
                    "\nThen, its AI feature, with a test model standing in for the real one: {}.",
                    ai.steps.join("; ")
                );
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
                Some(result) if result.stopped_after.is_some() => println!(
                    "\nThe app's own tests had not finished after {}, the most a test run may \
                     take, and were stopped. A suite cut short credits nothing.",
                    sv_run::minutes(result.stopped_after.unwrap_or(sv_run::TEST_LIMIT))
                ),
                Some(result) if result.exit_code == 0 => {
                    println!("\nThe app's own tests passed.")
                }
                Some(result) => {
                    // The end of the output, where runners say which tests failed, and with any
                    // credential a runner printed cut short, as in the report.
                    let rules = SecretRules::load(&secret_rules_path())?;
                    if let Some(t) =
                        sv_check::suite::failing_output(result.exit_code, &result.output, &rules)
                    {
                        println!("\n{}", sv_report::test_output_intro(&t));
                        if !t.text.is_empty() {
                            println!("{}", t.text);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Looks for credentials left in the code.
/// `sv check`, ending with its exit status (`exit`): 2 when a check could not run, 1 with
/// `--fail-on attention` and a finding at its severity, and 0 otherwise.
fn cmd_check(args: &[String]) -> Result<i32> {
    let (fail_on, rest) = exit::FailOn::take(args)?;
    let app_dir = rest
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    // One walk of the folder, shared by every check below (DESIGN, "One walk of the app").
    let listing = sv_scan::files::Listing::of(&app_dir);
    let rules = SecretRules::load(&secret_rules_path())?;
    let scan = sv_check::secrets::scan_listing(&rules, &listing);
    let bill_of_materials = sbom::build_in(&listing);
    let config = check_dir_in(&listing, &bill_of_materials);
    let ast_rules = ast::AstRules::load(&ast_rules_path())?;
    let code = ast::scan_listing(&ast_rules, &listing);
    let gaps = exit::Gaps::of_files(&listing, &scan, &code);

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
    // Named too, so nobody goes looking for them: these hold no text for a credential to be in.
    if !scan.coverage.no_written_text.is_empty() {
        let n = scan.coverage.no_written_text.len();
        println!(
            "\n{n} file{} not read, being {} that hold{} no text a person writes:",
            if n == 1 { " was" } else { "s were" },
            if n == 1 { "one" } else { "ones" },
            if n == 1 { "s" } else { "" }
        );
        for (file, what) in scan.coverage.no_written_text.iter().take(10) {
            println!("  {file} — {what}");
        }
        if n > 10 {
            println!("  … and {} more", n - 10);
        }
    }

    if !listing.links.is_empty() {
        println!(
            "\n{} symbolic link{} not followed, so whatever {} point{} at was not read:",
            listing.links.len(),
            if listing.links.len() == 1 {
                " was"
            } else {
                "s were"
            },
            if listing.links.len() == 1 {
                "it"
            } else {
                "they"
            },
            if listing.links.len() == 1 { "s" } else { "" }
        );
        for link in listing.links.iter().take(10) {
            println!("  {link}");
        }
        if listing.links.len() > 10 {
            println!("  … and {} more", listing.links.len() - 10);
        }
    }
    if !listing.special.is_empty() {
        println!(
            "\n{} {} not an ordinary file (a named pipe, a socket, or a device), so nothing read {}:",
            listing.special.len(),
            if listing.special.len() == 1 {
                "entry is"
            } else {
                "entries are"
            },
            if listing.special.len() == 1 {
                "it"
            } else {
                "them"
            }
        );
        for name in listing.special.iter().take(10) {
            println!("  {name}");
        }
        if listing.special.len() > 10 {
            println!("  … and {} more", listing.special.len() - 10);
        }
    }
    if !listing.skipped.is_empty() {
        println!(
            "\nLeft out as installed or built code, so nothing read {}:",
            if listing.skipped.len() == 1 {
                "it"
            } else {
                "them"
            }
        );
        for (dir, why) in listing.skipped.iter().take(10) {
            println!("  {dir}/ ({why})");
        }
        if listing.skipped.len() > 10 {
            println!("  … and {} more", listing.skipped.len() - 10);
        }
    }
    if !listing.refused_markers.is_empty() {
        println!(
            "\nMarked as a report of `sv`'s but holding other files, so read as the app's own code:"
        );
        for dir in listing.refused_markers.iter().take(10) {
            println!("  {dir}/");
        }
    }

    if !code.unread_files.is_empty() {
        println!(
            "\nNot read — {} in a language the rules read {} not opened, so no rule that reads that\n\
             language can say it found nothing wrong:",
            if code.unread_files.len() == 1 {
                "a file".to_owned()
            } else {
                format!("{} files", code.unread_files.len())
            },
            if code.unread_files.len() == 1 {
                "was"
            } else {
                "were"
            }
        );
        for (file, why) in code.unread_files.iter().take(10) {
            println!("  {file} — {why}");
        }
        if code.unread_files.len() > 10 {
            println!("  … and {} more", code.unread_files.len() - 10);
        }
    }
    if !code.broken_queries.is_empty() {
        println!(
            "\n{} code rule{} could not run, because its query would not compile (a fault in sv's \
             rule file, not in your app), so no rule claims a clean result:",
            code.broken_queries.len(),
            if code.broken_queries.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        for b in &code.broken_queries {
            println!("  {} for {} — {}", b.rule_id, b.language, b.why);
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
             {} still counts. A rule whose call is named anywhere in {} cannot say it found\n\
             nothing wrong; a rule whose call is not named there could not have found it there,\n\
             and still can.",
            if code.unparsed_files.len() == 1 {
                "this file".to_owned()
            } else {
                format!("these {} files", code.unparsed_files.len())
            },
            if code.unparsed_files.len() == 1 {
                "it"
            } else {
                "them"
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

    let (status, reasons) = gaps.status(fail_on, scan.findings.iter().map(|f| f.severity));
    if scan.findings.is_empty() {
        println!(
            "\nNo credentials found in what was read. That is not the same as none being there: these \n\
             rules know a list of well-known formats and one heuristic, and a credential in a shape \n\
             nobody listed would not be found."
        );
        exit::explain(status, &reasons)
            .iter()
            .for_each(|l| println!("{l}"));
        return Ok(status);
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
        for note in sv_report::finding_notes(f) {
            println!("     {note}");
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
    exit::explain(status, &reasons)
        .iter()
        .for_each(|l| println!("{l}"));
    Ok(status)
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
    // Said before the verdict on completeness, which it does not change: the list is a full
    // reading of one lockfile, and this says which one.
    for passed in &sbom.passed_over {
        eprintln!(
            "{}: {}. Remove the lockfile that is not in use.",
            passed.project,
            passed.explain()
        );
    }
    for disagreement in &sbom.disagreements {
        if disagreement.differs() {
            eprintln!("{}: {}.", disagreement.project, disagreement.explain());
        }
        if !disagreement.comparison.not_compared.is_empty() {
            eprintln!(
                "{}: {}.",
                disagreement.project,
                disagreement.explain_not_compared()
            );
        }
    }
    let disagreeing = sbom.disagreements.iter().any(sbom::Disagreement::differs);
    if sbom.is_complete() {
        if disagreeing {
            eprintln!(
                "Every ecosystem in use was read from a lockfile. It is what is installed only if \
                 the app is installed from the lockfile, not the manifest that disagrees with it."
            );
        } else if sbom.passed_over.is_empty() {
            eprintln!(
                "Every ecosystem in use was read from a lockfile, so this is what is installed."
            );
        } else {
            eprintln!(
                "Every ecosystem in use was read from a lockfile. It is what is installed only if \
                 the app is installed from the lockfile named as read above."
            );
        }
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
/// `sv` opens no network connection here, and none of its own anywhere but `sv probe`, which the owner
/// points at an address by name. Fetching the database is the owner's step, done
/// deliberately: the list of packages an app depends on is business-confidential, a fetch is a dependency
/// on somebody else's uptime, and `sv` has to work where there is no network at all.
/// Ends with its exit status: 0, 1 or 2 as `exit` says for audit; an error is 3, from `main`.
fn cmd_audit(args: &[String]) -> Result<i32> {
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
            other => app_dir = sv_check::adapters::clean_folder(Path::new(other)),
        }
    }
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }

    // What securevibe.toml says is not the app (examples, test fixtures) is compared too, listed apart,
    // and still counted, as every finding in those folders is (DESIGN, "Folders the manifest says are
    // not the app"): securevibe.toml is written by the AI coding tool, and a line in it that stopped a
    // vulnerability counting would hide one by naming the folder it is in.
    let manifest_path = app_dir.join("securevibe.toml");
    let manifest = if manifest_path.is_file() {
        Some(Manifest::load(&manifest_path)?)
    } else {
        None
    };
    let folders = manifest
        .as_ref()
        .map(|m| m.not_the_app().0)
        .unwrap_or_default();
    let listing = sv_scan::files::Listing::of(&app_dir);
    // A list that would set apart all the app's code is not used, as in every other command (ADR-031).
    let (folders, refused, _) = sv_scan::not_the_app_in(&listing, &folders);
    if let Some(why) = refused {
        println!("securevibe.toml's `[repository] not-the-app` is not used: {why}.\n");
    }
    let (ours, theirs) = listing.split(&folders);
    let sbom = sbom::build_in(&ours);
    let elsewhere = sbom::build_in(&theirs);

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
        return Ok(exit::NOT_ASSESSED);
    };

    let advisories::Database {
        records: database,
        unread,
    } = advisories::read_database(&dir)
        .with_context(|| format!("reading the advisory database at {}", dir.display()))?;
    if database.is_empty() {
        println!(
            "Not assessed: {} holds no advisory records `sv` could read, so nothing was compared.\n\
             An empty database and a healthy app look identical from here, and only one of them is good news.",
            dir.display()
        );
        return Ok(exit::NOT_ASSESSED);
    }

    // The time frames are V15.1.1's document, as numbers. Without them every known vulnerability
    // counts against V15.2.1 whatever its age, which is what this said before they existed.
    let time_frames = manifest
        .as_ref()
        .and_then(|m| m.policy.fix_within_days.clone());
    let mut result = advisories::audit_against(
        &sbom,
        &database,
        time_frames.as_ref(),
        advisories::Day::today(),
    );
    // A file of the database that could not be read is a record nothing compared: the comparison did not
    // cover the database, so it makes no claim that nothing was missed (the deep review's improvement 4).
    if !unread.is_empty() {
        result.verified.clear();
    }
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
    if !unread.is_empty() {
        println!(
            "\nNot assessed — {} file{} in the advisory database could not be read, so the records in \
             {} were not compared:",
            unread.len(),
            if unread.len() == 1 { "" } else { "s" },
            if unread.len() == 1 { "it" } else { "them" }
        );
        for (name, why) in unread.iter().take(8) {
            println!(
                "  {}: {}",
                sv_report::one_line(name),
                sv_report::one_line(why)
            );
        }
        if unread.len() > 8 {
            println!("  and {} more", unread.len() - 8);
        }
    }
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
        // What was not read, said here as well: an owner told only that something is missing
        // has to run a second command to learn which file, and why.
        for (ecosystem, why) in &sbom.unread {
            println!("\nNot assessed — {ecosystem}: {why}.");
        }
    }
    for passed in &sbom.passed_over {
        println!(
            "\nNot assessed — {}: {}. Remove the lockfile that is not in use.",
            passed.project,
            passed.explain()
        );
    }
    for disagreement in sbom.disagreements.iter().filter(|d| d.differs()) {
        println!(
            "\nNot assessed — {}: {}.",
            disagreement.project,
            disagreement.explain()
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
        let theirs = not_the_app_audit(&elsewhere, &database, &folders, time_frames.as_ref());
        let whole = !result.verified.is_empty() && sbom.is_complete();
        return Ok(exit::worse(
            if whole {
                exit::CLEAN
            } else {
                exit::NOT_ASSESSED
            },
            theirs,
        ));
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
    not_the_app_audit(&elsewhere, &database, &folders, time_frames.as_ref());
    Ok(exit::ATTENTION)
}

/// What `sv audit` found in folders securevibe.toml says are not the app, listed after the app's own,
/// one line per vulnerability, and counted all the same. Returns the status it adds.
fn not_the_app_audit(
    elsewhere: &sbom::Sbom,
    database: &[advisories::Advisory],
    folders: &[String],
    time_frames: Option<&sv_manifest::FixWithinDays>,
) -> i32 {
    if folders.is_empty() || (elsewhere.components.is_empty() && elsewhere.is_complete()) {
        return 0;
    }
    let result =
        advisories::audit_against(elsewhere, database, time_frames, advisories::Day::today());
    let named = folders.join(", ");
    println!(
        "\nIn folders securevibe.toml says are not the app ({named}), listed apart and counted all the \
         same: naming a folder there changes where its findings are listed, never whether they count."
    );
    let mut status = 0;
    if !result.uncovered.is_empty() {
        println!(
            "  Not compared for {}, which this database holds nothing about.",
            result
                .uncovered
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        );
        status = exit::NOT_ASSESSED;
    }
    if !result.uncomparable.is_empty() {
        println!(
            "  {} package version(s) could not be compared with any range.",
            result.uncomparable.len()
        );
        status = exit::NOT_ASSESSED;
    }
    if !elsewhere.is_complete() {
        println!("  The list of packages there is incomplete; `sv sbom` says what is missing.");
        status = exit::NOT_ASSESSED;
    }
    if result.findings.is_empty() {
        // Only when nothing above qualifies it: "none matches" beside "not compared" reads as clean.
        if status != 0 {
            return status;
        }
        println!(
            "  {} package{} compared, and none matches a record in this database.",
            result.components_checked,
            if result.components_checked == 1 {
                ""
            } else {
                "s"
            }
        );
        return status;
    }
    println!(
        "  {} known vulnerabilit{}:",
        result.findings.len(),
        if result.findings.len() == 1 {
            "y"
        } else {
            "ies"
        }
    );
    for f in &result.findings {
        println!("  [{}] {}", f.severity.name(), f.title);
    }
    exit::ATTENTION
}

/// `sv bundle`: the app, its report and the record of what was checked, in one zip (see `bundle.rs`).
fn cmd_bundle(args: &[String]) -> Result<()> {
    let ReportArgs {
        app_dir,
        out,
        run_the_app,
        slow,
        run_tools,
        advisories_dir,
    } = parse_report_args(args, "a file name ending in .zip")?;
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    let app_abs = std::fs::canonicalize(&app_dir)
        .with_context(|| format!("opening {}", app_dir.display()))?;
    let name = app_abs
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "app".to_owned());
    let folder = bundle::safe_name(&name);
    // Outside the app folder, beside it: a bundle written inside would be read back as the app.
    let zip_path = match out {
        Some(path) => path,
        None => app_abs
            .parent()
            .unwrap_or(&app_abs)
            .join(format!("{folder}-securevibe-bundle.zip")),
    };
    // Resolved through whatever links lie on the way (on a Mac `/var` is a link to `/private/var`), so the same
    // folder written two ways is still recognized as the app's own.
    let zip_abs = bundle::resolve_for_writing(&if zip_path.is_absolute() {
        zip_path.clone()
    } else {
        std::env::current_dir()?.join(&zip_path)
    });
    if zip_abs.starts_with(&app_abs) {
        bail!(
            "{} is inside the app folder. Choose a place outside it, so the bundle is not read back as part of the app.",
            zip_path.display()
        );
    }

    let report = assemble_report(
        &app_abs,
        &ReportOptions {
            run_the_app,
            slow,
            run_tools,
            why_not_run: "`sv bundle` does not start the app unless you pass --run.".to_owned(),
            why_no_tools: "`sv bundle` does not run other people's tools unless you pass --tools."
                .to_owned(),
            advisories: advisories_dir,
            why_no_advisories: "`sv bundle` compares against known vulnerabilities only when you \
                                pass --advisories DIR."
                .to_owned(),
        },
        &Loaded::load()?,
    )?;
    let command = format!("sv bundle {}", args.join(" "));
    let outcome = write_bundle(&app_abs, &zip_abs, &report, command.trim())?;
    println!("{}", outcome.summary());
    Ok(())
}

/// What `sv bundle` and the MCP tool made.
struct BundleOutcome {
    zip: PathBuf,
    kilobytes: usize,
    files: usize,
    included: usize,
    left_out: Vec<(String, String)>,
    categories: Vec<String>,
}

impl BundleOutcome {
    /// What is said to the person, on the screen and in the AI tool alike.
    fn summary(&self) -> String {
        self.summary_with(&sv_report::fence::Fence::none())
    }

    /// The same, with the app's own text (the zip's path, the files left out, what securevibe.toml
    /// says the app holds) put through `fence`, for the AI coding tool (deep review R9).
    fn summary_with(&self, fence: &sv_report::fence::Fence) -> String {
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
                "\nsecurevibe.toml says this app holds: {}. Those are not left out: sv cannot tell which files hold them.\n",
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

/// Makes the zip from a report already built. `zip_abs` has been resolved and is outside the app; the caller
/// checked. Shared by `sv bundle` and the MCP tool, so what an AI tool is told is what the command says.
fn write_bundle(
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
    let categories = Manifest::load(&app_abs.join("securevibe.toml"))
        .map(|m| m.data.listed().to_vec())
        .unwrap_or_default();

    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for rel in &plan.include {
        let bytes = std::fs::read(app_abs.join(rel)).with_context(|| format!("reading {rel}"))?;
        entries.push((format!("{folder}/app/{rel}"), bytes));
    }
    let scratch = bundle::scratch_dir();
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
    let _ = std::fs::remove_dir_all(&scratch);
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

/// Refuses to make the bundle when the report going into it holds something the credential scan
/// reads as a credential, naming the file, line and rule, never the value.
///
/// The backstop to redacting what outside tools say (deep review S8), and a guard for what the report
/// quotes of the app itself (its name in `securevibe.toml`, for one): Bandit's B105 message quoted a
/// password four times inside `report/` of a bundle that had left the file holding it out, so that the
/// zip carried no secret. `sv`'s own findings carry a credential only redacted, and a tool's words
/// are redacted as they are read (`adapters::redact_tool_text`); this is what holds if some other
/// text ever reaches a report unredacted. Refusing, not redacting the files here: a report changed on
/// its way into the zip would no longer be the one `sv` wrote, and the owner is told where to look.
fn refuse_a_credential_in_the_report(
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
         say, such as its name in securevibe.toml: take the credential out of the place it was \
         quoted from and run this again. If it came from nowhere in the app, it is a fault in sv: \
         please report it.",
        found.len(),
        if found.len() == 1 { "" } else { "s" },
        found.join("; ")
    )
}

/// Every name `sv` writes in a report folder: the marker, the lock, and the five reports. A test
/// holds this to what `write_report_files` writes. Kept in `sv-scan`, whose walk leaves a report
/// folder out only while it holds nothing but these (deep review H6).
const REPORT_FOLDER_NAMES: &[&str] = sv_scan::ecosystems::REPORT_FOLDER_NAMES;

/// Makes `out_dir` ready for a report and takes it for this run, before the run starts: the checks
/// `write_report_files` makes on the folder, made early so a refusal comes before the wait rather
/// than after it, and the lock (`report_lock`). The marker is written once the folder is held, so the
/// run's own reading of the app leaves the folder out.
///
/// A run that ends without writing its report leaves the folder as it found it: the marker goes if
/// this wrote it, and the folder if this made it (`made_by_caller`, for a caller that made it just
/// before) and nothing else is in it. Ctrl-C during `sv report --run` wrote no report and left the
/// folder behind, which `interrupt.rs` caught.
fn claim_report_folder(
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
    let marker = out_dir.join(sv_scan::ecosystems::REPORT_MARKER);
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
    write_without_following(
        out_dir,
        sv_scan::ecosystems::REPORT_MARKER,
        REPORT_MARKER_TEXT.as_bytes(),
    )
    .context("writing the report folder's marker")?;
    Ok(held)
}

const REPORT_MARKER_TEXT: &str =
    "This folder holds a report written by sv. sv leaves it out when it checks the app.\n";

/// Seals the report just written in `out_dir` (`report_seal`), so `sv`'s MCP server can show it is
/// `sv`'s before offering it as one. Whether it was sealed, and what the person should be told: that
/// the report key was made, or why the report could not be sealed. The report stands either way.
fn seal_report_folder(out_dir: &Path) -> (bool, Vec<String>) {
    match report_seal::seal(out_dir, REPORT_MARKER_TEXT) {
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
fn write_report_files(report: &sv_report::Report, out_dir: &Path) -> Result<Vec<&'static str>> {
    // Before the folder is created: creating it would follow a link to a folder that does not exist yet.
    refuse_link(out_dir, REPORT_LINK)?;
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    // Marks the folder as `sv`'s own output, so the next check of the app does not read the report
    // as the app's code, whatever the folder is called (`sv_scan::ecosystems::REPORT_MARKER`).
    let marker = (
        sv_scan::ecosystems::REPORT_MARKER,
        REPORT_MARKER_TEXT.to_owned(),
    );
    let written = [
        ("report.html", sv_report::html::page(report)),
        ("compliance.md", sv_report::markdown::compliance(report)),
        ("security.md", sv_report::markdown::security(report)),
        ("findings.sarif", sv_report::sarif::render(report)),
        ("report.json", sv_report::json::to_string(report)),
    ];
    // Every name is looked at before any is written, so a refusal leaves the folder as it was.
    for (name, _) in std::iter::once(&marker).chain(&written) {
        refuse_link(&out_dir.join(name), REPORT_LINK)?;
    }
    refuse_someone_elses_folder(out_dir, REPORT_FOLDER_NAMES)?;
    for (name, contents) in std::iter::once(&marker).chain(&written) {
        write_without_following(out_dir, name, contents.as_bytes())
            .with_context(|| format!("writing {name}"))?;
    }
    Ok(written.iter().map(|(name, _)| *name).collect())
}

/// Refuses to write a report into a folder that holds anything but `sv`'s own files, unless `sv` marked
/// it as its own; and, marked or not, one holding a file whose name differs from one of `sv`'s only in
/// capitals.
///
/// A report written with `out` "." landed in the app itself, and on a disk that does not tell capitals
/// apart (macOS and Windows, by default) its `security.md` replaced the app's own `SECURITY.md` (deep
/// review S5). A folder holding only names `sv` writes, as a report from before the marker had, is
/// taken as `sv`'s; the marker itself is checked by its exact name, so the app's files are never
/// mistaken for it.
fn refuse_someone_elses_folder(out_dir: &Path, ours: &[&str]) -> Result<()> {
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
    let marked = names
        .iter()
        .any(|name| name == sv_scan::ecosystems::REPORT_MARKER);
    let others: Vec<&String> = names
        .iter()
        .filter(|name| !ours.contains(&name.as_str()) && !is_staging(name, ours))
        .collect();
    anyhow::ensure!(
        marked || others.is_empty(),
        "{} already holds files sv did not write ({}{}), so sv does not write its report there. Give \
         an empty folder, or a new one, with --out.",
        out_dir.display(),
        others
            .iter()
            .take(3)
            .map(|n| format!("`{n}`"))
            .collect::<Vec<_>>()
            .join(", "),
        if others.len() > 3 { ", and more" } else { "" }
    );
    Ok(())
}

/// Whether `name` is one of `ours` part-written by `write_without_following` (`.report.json.sv-4321`):
/// what a run stopped while writing leaves, and what a run writing at that moment has. Seen when two
/// runs started together: the second found the first's marker half-written, in a folder not yet
/// marked, and called the folder someone else's.
fn is_staging(name: &str, ours: &[&str]) -> bool {
    name.strip_prefix('.')
        .and_then(|rest| rest.rsplit_once(".sv-"))
        .is_some_and(|(base, pid)| {
            ours.contains(&base) && !pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Refuses a path that is a link, whatever it points to, saying so in the owner's terms and saying
/// what to do instead.
fn refuse_link(path: &Path, what_to_do: &str) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        anyhow::ensure!(
            !meta.file_type().is_symlink(),
            "{} is a link to somewhere else, so sv does not read or write through it. {what_to_do}",
            path.display()
        );
    }
    Ok(())
}

/// What to do about a link where a report file or folder goes.
const REPORT_LINK: &str = "Remove the link, or give a folder of your own with --out.";
/// What to do about a link where `sv` writes one of its own files into the app.
const FILE_LINK: &str = "Remove the link, and run it again.";

/// Writes `name` in `dir` without following a link at that name: the bytes go to a file that did not
/// exist before (`create_new` refuses a link as it refuses anything already there), which is then
/// renamed over `name`. A link put at `name` after `refuse_link` looked is replaced, never written
/// through.
fn write_without_following(dir: &Path, name: &str, contents: &[u8]) -> Result<()> {
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

/// What a report is built from, and what the person asked for.
struct ReportOptions {
    /// Start the app behind the fence and ask it questions. Opt-in: this runs somebody's code.
    run_the_app: bool,
    /// And wait out the session timeouts the owner states. Opt-in: it takes as long as they are.
    slow: bool,
    /// Run the language's own security tool. Opt-in: these are other people's programs.
    run_tools: bool,
    /// Said in the report when the app was not started, in the words of whoever built it.
    why_not_run: String,
    /// Said in the report when the tools were not run.
    why_no_tools: String,
    /// A local advisory database to compare the bill of materials with. `sv` never fetches one.
    advisories: Option<PathBuf>,
    /// Said in the report when there was no database to compare with.
    why_no_advisories: String,
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
        if !disagreement.comparison.not_compared.is_empty() {
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

/// The scan every command reads the app with: the folders the manifest says are not the app are
/// left out of what counts as evidence about it. One place, so no command reads them as the app.
fn scan_for(
    manifest: &Manifest,
    listing: &sv_scan::files::Listing,
    signatures: &Signatures,
) -> Result<sv_scan::ScanReport> {
    sv_scan::scan_listing_app(listing, signatures, &manifest.not_the_app().0)
}

/// What the report says about `[repository] not-the-app`: the folders it set apart, any it named that
/// are not there, and any entry refused. Said in the report because the list changes what counts as
/// evidence, and a list nobody sees could hide the app's own code from the check.
fn not_the_app_gaps(manifest: &Manifest, scan: &sv_scan::ScanReport) -> Vec<sv_report::Gap> {
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
            "securevibe.toml says these folders are not the app (`[repository] not-the-app`): {}. \
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

fn assemble_report(
    app_dir: &Path,
    options: &ReportOptions,
    loaded: &Loaded,
) -> Result<sv_report::Report> {
    assemble_report_saying(app_dir, options, loaded, &|_, _| {})
}

/// The stages of a report that `assemble_report_saying` names as it starts each, in order. The MCP
/// server passes them on, so a long check does not look stuck.
pub(crate) const REPORT_STAGES: [&str; 7] = [
    "Reading the app's files",
    "Recognizing its languages and frameworks",
    "Listing the packages it uses",
    "Looking for keys and passwords",
    "Reading its configuration",
    "Reading its code",
    "Putting the report together",
];

/// `assemble_report`, calling `starting` with each stage's number (from 0) and name as it begins.
fn assemble_report_saying(
    app_dir: &Path,
    options: &ReportOptions,
    loaded: &Loaded,
    starting: &dyn Fn(usize, &'static str),
) -> Result<sv_report::Report> {
    let stage = |n: usize| starting(n, REPORT_STAGES[n]);
    let started = std::time::SystemTime::now();
    let manifest_path = app_dir.join("securevibe.toml");
    if !manifest_path.exists() {
        bail!(
            "no securevibe.toml in {}. Run `sv init` and give the spec to your AI coding tool.",
            app_dir.display()
        );
    }
    // Read once, so the hash recorded is of the very bytes parsed.
    let manifest_text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = Manifest::parse(&manifest_text, &manifest_path)?;
    let run_record = report_lock::run_record(started, manifest_text.as_bytes());

    let Loaded {
        frameworks,
        config_rules,
        signatures,
        threat_rules,
        secret_rules,
        ast_rules,
    } = loaded;
    // One walk of the folder, shared by every check in this report (DESIGN, "One walk of the app").
    stage(0);
    let listing = sv_scan::files::Listing::of(app_dir);
    stage(1);
    let scan_report = scan_for(&manifest, &listing, signatures)?;
    let (ctx, resolved) = sv_manifest::resolve(&manifest, &scan_report.as_corroborator());
    let buckets = bucket(frameworks, config_rules, &ctx, manifest.target_level());

    // The report used to reason about dependencies from the scan alone, which knows only whether a
    // lockfile is missing. The bill of materials knows what actually came out of each ecosystem,
    // and that is the difference between "this list is approximate" and "this list is empty".
    // Building it reads manifests and lockfiles; it opens no network connection. Built once, here,
    // and handed to the lockfile check and the findings below.
    stage(2);
    let bill_of_materials = sbom::build_in(&listing);
    stage(3);
    let secrets = sv_check::secrets::scan_listing(secret_rules, &listing);
    stage(4);
    let config = check_dir_in(&listing, &bill_of_materials);
    stage(5);
    let code = ast::scan_listing(ast_rules, &listing);
    stage(6);
    let mut findings_from_advisories = Vec::new();

    // Known vulnerabilities, when the owner has pointed at a local advisory database, held to the
    // time frames in securevibe.toml exactly as `sv audit` holds them. Without a database this says
    // so: a report silent about known vulnerabilities reads as a report that found none.
    let mut advisory_verified = Vec::new();
    let mut advisory_gaps = Vec::new();
    // What was examined, per family of findings, for a program reading report.json: the same
    // limits as the gaps, decided in the same places (DESIGN, "What was examined, for a program").
    let mut examined: Vec<sv_report::Examined> = vec![sv_report::Examined::ran("sbom.")];
    match &options.advisories {
        None => {
            examined.push(sv_report::Examined::not_run(
                "advisory.",
                "no advisory database was given (--advisories)",
            ));
            advisory_gaps.push(sv_report::Gap {
                what: "known vulnerabilities in the packages this app ships".to_owned(),
                why: format!(
                    "{} `sv` does not fetch anything, because the list of packages an app depends \
                     on is yours: download an OSV export for this app's ecosystems, unpack it, and \
                     pass its folder with --advisories.",
                    options.why_no_advisories
                ),
            })
        }
        Some(dir) => {
            let advisories::Database {
                records: database,
                unread,
            } = advisories::read_database(dir)
                .with_context(|| format!("reading the advisory database at {}", dir.display()))?;
            if database.is_empty() {
                examined.push(sv_report::Examined::not_run(
                    "advisory.",
                    "the advisory database holds no records `sv` could read",
                ));
                advisory_gaps.push(sv_report::Gap {
                    what: "known vulnerabilities in the packages this app ships".to_owned(),
                    why: format!(
                        "{} holds no advisory records `sv` could read, so nothing was compared. \
                         An empty database and a healthy app look the same from here.",
                        dir.display()
                    ),
                });
            } else {
                let mut result = advisories::audit_against(
                    &bill_of_materials,
                    &database,
                    manifest.policy.fix_within_days.as_ref(),
                    advisories::Day::today(),
                );
                // Whole only as `sv audit` counts it: every ecosystem covered, every version
                // comparable, and the list of packages itself complete.
                let mut short = Vec::new();
                if !unread.is_empty() {
                    short.push(format!(
                        "{} file{} in the advisory database could not be read ({})",
                        unread.len(),
                        if unread.len() == 1 { "" } else { "s" },
                        unread
                            .iter()
                            .take(3)
                            .map(|(name, _)| format!("`{name}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !result.uncovered.is_empty() {
                    let names: Vec<String> = result.uncovered.iter().cloned().collect();
                    short.push(format!(
                        "the database holds nothing about {}",
                        names.join(", ")
                    ));
                }
                if !result.uncomparable.is_empty() {
                    short.push(format!(
                        "{} package version(s) could not be compared",
                        result.uncomparable.len()
                    ));
                }
                if !bill_of_materials.is_complete() {
                    short.push("the list of packages is incomplete".to_owned());
                }
                // A finding that stops appearing because a different lockfile was read is not a
                // fixed finding, so a second lockfile nothing compared keeps this from `ran`.
                for passed in &bill_of_materials.passed_over {
                    short.push(format!(
                        "{} not read beside `{}`",
                        passed.not_read_list(),
                        passed.read
                    ));
                }
                // Nor is one that stops appearing because the manifest moved on and the lock did not.
                for disagreement in bill_of_materials
                    .disagreements
                    .iter()
                    .filter(|d| d.differs())
                {
                    short.push(format!(
                        "`{}` asks for other versions than `{}` has",
                        disagreement.manifest, disagreement.lockfile
                    ));
                }
                examined.push(if short.is_empty() {
                    sv_report::Examined::ran("advisory.")
                } else {
                    sv_report::Examined::partly("advisory.", short.join("; "))
                });
                // Records in a file nobody read were not compared, so nothing is credited on the
                // comparison, as `sv audit` credits nothing (the deep review's improvement 4).
                if !unread.is_empty() {
                    result.verified.clear();
                    advisory_gaps.push(sv_report::Gap {
                        what: "advisory files that could not be read".to_owned(),
                        why: format!(
                            "{}{}. The records in them were not compared with this app's packages.",
                            unread
                                .iter()
                                .take(10)
                                .map(|(name, why)| format!("`{name}`: {why}"))
                                .collect::<Vec<_>>()
                                .join("; "),
                            if unread.len() > 10 {
                                format!("; and {} more", unread.len() - 10)
                            } else {
                                String::new()
                            }
                        ),
                    });
                }
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
    let mut test_output = None;
    let mut findings = Vec::new();
    findings.extend(findings_from_advisories);
    findings.extend(secrets.findings.iter().cloned());
    findings.extend(config.findings.iter().cloned());
    // The bill of materials speaks for itself here as it does in `sv check`: incomplete is a finding
    // against V15.1.2, complete is evidence for it, and exactly one of the two says anything. The
    // report used to read only its gaps, so a lockfile it could take nothing from was left to the
    // lockfile check, which saw a lockfile and passed it.
    findings.extend(sbom::incompleteness_finding(&bill_of_materials));
    findings.extend(code.findings.iter().cloned());

    // The language's own tool, where there is one and it is here. A tool that is not installed is
    // recorded as not run, with how to install it — never as having found nothing.
    let mut tool_gaps = Vec::new();
    if options.run_tools {
        let adapters = sv_check::adapters::Adapters::load(&adapters_path())?;
        let languages: Vec<String> = scan_report.languages.iter().cloned().collect();
        let not_holding = adapters.not_holding(|condition| ctx.get(condition));
        let outcome = sv_check::adapters::run_all_in(
            &adapters,
            &listing,
            &languages,
            &not_holding,
            &sv_check::adapters::scratch_dir(),
            &loaded.secret_rules,
        );
        examined.extend(adapters_examined(&adapters, &languages, &outcome));
        findings.extend(outcome.findings);
        tool_verified = outcome.verified;
        for (id, why) in outcome.not_run {
            tool_gaps.push(sv_report::Gap {
                what: format!("what `{id}` would have found"),
                why,
            });
        }
    } else {
        if let Ok(adapters) = sv_check::adapters::Adapters::load(&adapters_path()) {
            for adapter in adapters.all() {
                examined.push(sv_report::Examined::not_run(
                    format!("{}.", adapter.id),
                    "outside tools run only with --tools",
                ));
            }
        }
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
    let run_status;

    if options.run_the_app {
        match probe_the_running_app(&manifest, app_dir, options.slow) {
            Ok((outcome, plan)) => {
                run_status = sv_report::RunStatus::Started {
                    image: plan.image.clone(),
                    asked: anonymous_requests(&plan).len(),
                    answered: outcome.probe_responses.len(),
                    signed_in: outcome.signed_in.is_some(),
                    tests: match &outcome.tests {
                        Some(t) if t.stopped_after.is_some() => "stopped",
                        other => {
                            sv_report::RunStatus::tests_state(other.as_ref().map(|t| t.exit_code))
                        }
                    }
                    .to_owned(),
                };
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
                let oidc_steps: Vec<String> = outcome
                    .oidc
                    .as_ref()
                    .map(|s| s.steps.clone())
                    .unwrap_or_default();
                let ai_steps: Vec<String> = outcome
                    .ai
                    .as_ref()
                    .map(|s| s.steps.clone())
                    .unwrap_or_default();
                run_steps = signed_in_steps.clone();
                run_steps.extend(oidc_steps.iter().cloned());
                run_steps.extend(ai_steps.iter().cloned());
                let signed_in_note = if signed_in_steps.is_empty() {
                    String::new()
                } else {
                    format!(
                        " It was then asked {} more question{} as two signed-in test users.",
                        signed_in_steps.len(),
                        if signed_in_steps.len() == 1 { "" } else { "s" }
                    )
                };
                let oidc_note = if oidc_steps.is_empty() {
                    ""
                } else {
                    " Its sign-in through another service was asked about with a test provider of \
                     `sv`'s own, pointed at it for the run."
                };
                let ai_note = if ai_steps.is_empty() {
                    ""
                } else {
                    " Its AI feature was asked with a test model of `sv`'s own in place of the \
                     real one, so nothing was sent to an AI service and nothing was spent."
                };
                run_note = Some(format!(
                    "This app was started with {} and asked {} question{} while it ran, as \
                     somebody who had not signed in. It answered on {}.{signed_in_note}{oidc_note}{ai_note} {}",
                    plan.image,
                    outcome.probe_responses.len(),
                    if outcome.probe_responses.len() == 1 {
                        ""
                    } else {
                        "s"
                    },
                    plan.health_path,
                    outcome.fence.explain()
                ));
                if let (Some(note), Some(removed)) = (
                    run_note.as_mut(),
                    sv_run::cleanup::removed_sentence(&outcome.left_over_removed),
                ) {
                    note.push_str(&format!(" {removed}"));
                }
                if let (Some(note), Some(weaker)) =
                    (run_note.as_mut(), sv_run::weakening_note(&plan.start))
                {
                    note.push_str(&format!(" {weaker}"));
                }
                for (requirements, why) in signed_in_not_assessed {
                    // AISVS ids are the AI feature's, asked through the test model, which may not
                    // have involved signing in at all.
                    let how = if requirements.starts_with('C') {
                        "by asking the running app's AI feature through a test model"
                    } else {
                        "by asking the running app as a signed-in user"
                    };
                    gaps.push(sv_report::Gap {
                        what: format!("{requirements}, {how}"),
                        why,
                    });
                }
                gaps.extend(rate_limited_gap(&outcome.probes_rate_limited));
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
                    Some(result) if result.stopped_after.is_some() => {
                        let after = result.stopped_after.unwrap_or(sv_run::TEST_LIMIT);
                        gaps.push(sv_report::Gap {
                            what: "anything the app's own tests would have shown".to_owned(),
                            why: format!(
                                "they had not finished after {}, the most a test run may take, \
                                 and were stopped. A suite cut short credits nothing, whatever it \
                                 printed before it was stopped.",
                                sv_run::minutes(after)
                            ),
                        });
                        test_output = sv_check::suite::failing_output(
                            result.exit_code,
                            &result.output,
                            secret_rules,
                        )
                        .map(|t| sv_check::suite::FailingOutput {
                            stopped_after: Some(sv_run::minutes(after)),
                            ..t
                        });
                    }
                    Some(result) => {
                        // Only tests that name a requirement count, and only when something says
                        // they passed. Matching a test to a requirement by what it is called would
                        // credit one on the strength of a name somebody chose for other reasons.
                        let known: std::collections::BTreeSet<&str> =
                            frameworks.requirements.keys().map(String::as_str).collect();
                        let named = sv_check::suite::tests_naming_requirements_in(&listing, &known);
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

                        test_output = sv_check::suite::failing_output(
                            result.exit_code,
                            &result.output,
                            secret_rules,
                        );
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
            Err(reason) => {
                run_status = sv_report::RunStatus::CouldNotStart {
                    why: reason.clone(),
                };
                gaps.push(sv_report::Gap {
                    what: "the running app".to_owned(),
                    why: format!("--run was given and the app could not be run. {reason}"),
                })
            }
        }
    } else {
        run_status = sv_report::RunStatus::NotAsked {
            why: options.why_not_run.clone(),
        };
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
    if !listing.links.is_empty() {
        let shown: Vec<&str> = listing.links.iter().take(5).map(String::as_str).collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} symbolic link{} in the app, not followed",
                listing.links.len(),
                if listing.links.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "a link can lead outside the app, or back into it in a loop, so nothing here \
                 followed {}: {}{}. What it points at was not read by any check.",
                if listing.links.len() == 1 {
                    "it"
                } else {
                    "them"
                },
                shown.join(", "),
                if listing.links.len() > 5 {
                    format!(", and {} more", listing.links.len() - 5)
                } else {
                    String::new()
                }
            ),
        });
    }
    if !listing.skipped.is_empty() {
        let shown: Vec<String> = listing
            .skipped
            .iter()
            .take(5)
            .map(|(dir, why)| format!("`{dir}/` ({why})"))
            .collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} folder{} left out as installed or built code",
                listing.skipped.len(),
                if listing.skipped.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "a folder named like an ecosystem's output, beside the file that makes it so, holds \
                 code the app installed or built rather than wrote, and no check read it: {}{}. If \
                 one holds the app's own code, move it or rename the folder.",
                shown.join(", "),
                if listing.skipped.len() > 5 {
                    format!(", and {} more", listing.skipped.len() - 5)
                } else {
                    String::new()
                }
            ),
        });
    }
    if !listing.special.is_empty() {
        let shown: Vec<&str> = listing.special.iter().take(5).map(String::as_str).collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} {} in the app that {} not an ordinary file",
                listing.special.len(),
                if listing.special.len() == 1 {
                    "entry"
                } else {
                    "entries"
                },
                if listing.special.len() == 1 {
                    "is"
                } else {
                    "are"
                }
            ),
            why: format!(
                "a named pipe, a socket, or a device is not opened, since opening a pipe waits for \
                 something to write into it: {}{}. No check read {}.",
                shown.join(", "),
                if listing.special.len() > 5 {
                    format!(", and {} more", listing.special.len() - 5)
                } else {
                    String::new()
                },
                if listing.special.len() == 1 {
                    "it"
                } else {
                    "them"
                }
            ),
        });
    }
    if !code.unread_files.is_empty() {
        let shown: Vec<String> = code
            .unread_files
            .iter()
            .take(5)
            .map(|(file, why)| format!("{file} ({why})"))
            .collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} file{} in a language the rules read, not opened",
                code.unread_files.len(),
                if code.unread_files.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "{}{}. While part of the app went unread, no rule that reads these files' language \
                 can say it found nothing wrong.",
                shown.join("; "),
                if code.unread_files.len() > 5 {
                    format!("; and {} more", code.unread_files.len() - 5)
                } else {
                    String::new()
                }
            ),
        });
    }
    if !code.broken_queries.is_empty() {
        let shown: Vec<String> = code
            .broken_queries
            .iter()
            .map(|b| format!("{} for {} ({})", b.rule_id, b.language, b.why))
            .collect();
        gaps.push(sv_report::Gap {
            what: format!(
                "{} code rule{} that could not run",
                code.broken_queries.len(),
                if code.broken_queries.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ),
            why: format!(
                "{}. The rule's query for that language would not compile, so it read none of \
                 those files; while a rule did not run, no rule that reads code can say it found \
                 nothing wrong. This is a fault in sv's rule file, not in the app.",
                shown.join("; ")
            ),
        });
    }
    gaps.extend(not_the_app_gaps(&manifest, &scan_report));
    for (id, why) in &config.not_assessed {
        gaps.push(sv_report::Gap {
            what: format!("the check `{id}`"),
            why: why.clone(),
        });
    }
    if !secrets.coverage.skipped.is_empty() {
        // Each named, with why, so nobody has to go looking for which file it was.
        const SHOWN: usize = 5;
        let skipped = &secrets.coverage.skipped;
        let mut named: Vec<String> = skipped
            .iter()
            .take(SHOWN)
            .map(|(file, why)| format!("`{file}` ({why})"))
            .collect();
        if skipped.len() > SHOWN {
            named.push(format!(
                "and {} more, listed by `sv check`",
                skipped.len() - SHOWN
            ));
        }
        gaps.push(sv_report::Gap {
            what: format!(
                "{} file{} not read while looking for credentials",
                skipped.len(),
                if skipped.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "{}. A credential in a file nothing read is a credential nothing found.",
                named.join(", ")
            ),
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
            why: "whatever sat where the parser gave up was not read, so a rule whose call is named \
                  anywhere in these files cannot say it found nothing wrong anywhere in this app; a \
                  rule whose call is named nowhere in them could not have found it there. What was \
                  found stands"
                .to_owned(),
        });
    }
    gaps.extend(untaught_gaps(&code.untaught));
    examined.extend(file_checks_examined(&listing, &code, &secrets, &config));
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
    let manual_only = buckets.manual_only(config_rules);
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
    verified.extend(sbom::completeness_verified(&bill_of_materials));
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
    // What this computer can check `sv review`'s seals with (`sv_check::seal`): the owner's own
    // answers, here and below, count as theirs only when `sv review` recorded them.
    let seals = sv_check::seal::Checker::this_computer();
    let notes = match std::fs::read_to_string(app_dir.join(&notes_catalog.file)) {
        Ok(text) => sv_check::notes::evidence(
            &notes_catalog,
            &sv_check::notes::read_answers(&notes_catalog, &text),
            &notes_catalog.file,
            &seals,
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
                         questions in it, and they become documented. Your AI coding tool can \
                         ask you them: `sv questions` prints them for its chat.",
                        notes_catalog.file
                    ),
                });
            }
            sv_check::notes::Evidence::default()
        }
    };
    if !notes.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "who wrote {} section{} of {}",
                notes.unreadable.len(),
                if notes.unreadable.len() == 1 { "" } else { "s" },
                notes_catalog.file
            ),
            why: format!(
                "Each section says who wrote it on one line, `{} {}` or `{} {}`, and {} names \
                 somebody else or says both, so nothing was made of it: {}.",
                sv_check::notes::WRITTEN_BY,
                sv_check::notes::BY_OWNER,
                sv_check::notes::WRITTEN_BY,
                sv_check::notes::BY_AI_TOOL,
                if notes.unreadable.len() == 1 {
                    "this one"
                } else {
                    "these"
                },
                notes.unreadable.join(", ")
            ),
        });
    }
    if !notes.not_read.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "what is under {} heading{} of your own in {}",
                notes.not_read.len(),
                if notes.not_read.len() == 1 { "" } else { "s" },
                notes_catalog.file
            ),
            why: format!(
                "A heading that is not one of the file's questions ends the answer above it, so \
                 what is under it was not read as an answer to anything: {}. Keeping notes of your \
                 own there is fine. If one of them is part of an answer, move it up into that \
                 answer, or use a `####` heading inside the answer instead.",
                notes.not_read.join("; ")
            ),
        });
    }
    let documented = notes.documented;

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
                    by: a.by.clone(),
                    recorded: sv_check::seal::owner_recorded(
                        &seals,
                        a.seal.as_deref(),
                        &sv_check::seal::design_answer_fields(id, a),
                    ),
                },
            )
        })
        .collect();
    let mut design = sv_check::design::evaluate(
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
                "securevibe.toml answers {} with a word that is not yes, no, or not-sure, or \
                 says it was answered `by` somebody other than \"owner\" or \"ai-tool\", so \
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
                 section of securevibe.toml: {}. Your AI coding tool can ask you them: `sv \
                 questions` prints them for its chat.",
                design.unanswered.join(", ")
            ),
        });
    }

    // The checks made by hand, recorded in securevibe.toml. The owner's `done` is their word about
    // what they saw; `problem` is a finding; an old one is out of date and counts for nothing.
    let hand_answers: std::collections::BTreeMap<String, sv_check::hand::Answer> = manifest
        .checked_by_hand
        .iter()
        .map(|(id, a)| {
            (
                id.clone(),
                sv_check::hand::Answer {
                    result: a.result.clone(),
                    on: a.on.clone(),
                    by: a.by.clone(),
                    how: a.how.clone(),
                    recorded: sv_check::seal::owner_recorded(
                        &seals,
                        a.seal.as_deref(),
                        &sv_check::seal::hand_check_fields(id, a),
                    ),
                },
            )
        })
        .collect();
    let mut hand = match sv_check::advisories::Day::today() {
        Some(today) => sv_check::hand::evaluate(
            &human_checks,
            &hand_answers,
            &|id| buckets.applicable.iter().any(|a| a == id),
            today,
        ),
        // A clock before 1970 cannot say whether a check is current, so none is counted.
        None => sv_check::hand::Outcome::default(),
    };
    findings.extend(hand.findings.iter().cloned());
    if !hand.unreadable.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} check{} made by hand",
                hand.unreadable.len(),
                if hand.unreadable.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "securevibe.toml records {} in [checked-by-hand] in a way nothing could be made \
                 of, so it counts for nothing: {}.",
                if hand.unreadable.len() == 1 {
                    "this"
                } else {
                    "these"
                },
                hand.unreadable
                    .iter()
                    .map(|(id, why)| format!("{id} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    if !hand.out_of_date.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} check{} made by hand more than {} days ago",
                hand.out_of_date.len(),
                if hand.out_of_date.len() == 1 { "" } else { "s" },
                sv_check::hand::CURRENT_FOR_DAYS
            ),
            why: format!(
                "Certificates expire and apps change, so an old check counts for nothing. Make \
                 {} again and record the new date: {}.",
                if hand.out_of_date.len() == 1 {
                    "it"
                } else {
                    "them"
                },
                hand.out_of_date
                    .iter()
                    .map(|(id, on)| format!("{id}, checked on {on}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    // A person confirming what the AI tool said moves it up to their tier, shown as confirmed. What
    // does not hold stays the tool's word and is named with its reason. See `sv_check::confirm`.
    let confirmation = |c: &sv_manifest::Confirmed| sv_check::confirm::Confirmation {
        by: c.by.clone(),
        on: c.on.clone(),
        how: c.how.clone(),
        answer: c.answer.clone(),
        location: c.r#where.clone(),
        result: c.result.clone(),
        seal: c.seal.clone(),
    };
    let design_confirmations: std::collections::BTreeMap<
        String,
        (sv_check::confirm::Confirmation, String, Option<String>),
    > = manifest
        .design
        .iter()
        .filter_map(|(id, a)| {
            let c = a.confirmed.as_ref()?;
            Some((
                id.clone(),
                (confirmation(c), a.answer.clone(), a.r#where.clone()),
            ))
        })
        .collect();
    let hand_confirmations: std::collections::BTreeMap<
        String,
        (sv_check::confirm::Confirmation, String),
    > = manifest
        .checked_by_hand
        .iter()
        .filter_map(|(id, a)| {
            let c = a.confirmed.as_ref()?;
            Some((id.clone(), (confirmation(c), a.result.clone())))
        })
        .collect();
    let modified = |path: &str| {
        std::fs::metadata(app_dir.join(path))
            .and_then(|m| m.modified())
            .ok()
            .and_then(sv_check::advisories::Day::of)
    };
    let (confirmed_design, confirmed_hand) = match sv_check::advisories::Day::today() {
        Some(today) => (
            sv_check::confirm::apply(
                &mut design.stated,
                sv_check::confirm::DESIGN_CONFIRMED,
                &|id| {
                    let (c, answer, location) = design_confirmations.get(id)?;
                    Some((
                        c,
                        sv_check::confirm::Current::Design {
                            answer,
                            location: location.as_deref(),
                            modified: location.as_deref().and_then(modified),
                        },
                    ))
                },
                today,
                &seals,
            ),
            sv_check::confirm::apply(
                &mut hand.stated,
                sv_check::confirm::HAND_CONFIRMED,
                &|id| {
                    let (c, result) = hand_confirmations.get(id)?;
                    Some((c, sv_check::confirm::Current::Hand { result }))
                },
                today,
                &seals,
            ),
        ),
        None => Default::default(),
    };
    if let Some(why) = manifest.level_from_unanswered_data() {
        gaps.push(sv_report::Gap {
            what: "What information the app holds about people".to_owned(),
            why: why.to_owned(),
        });
    }
    let not_counted: Vec<&(String, String)> = confirmed_design
        .not_counted
        .iter()
        .chain(confirmed_hand.not_counted.iter())
        .collect();
    if !not_counted.is_empty() {
        gaps.push(sv_report::Gap {
            what: format!(
                "{} confirmation{} of what your AI coding tool said",
                not_counted.len(),
                if not_counted.len() == 1 { "" } else { "s" }
            ),
            why: format!(
                "securevibe.toml records {} in a way that does not count, so the tool's word is \
                 all there is and the question is asked again: {}.",
                if not_counted.len() == 1 {
                    "this confirmation"
                } else {
                    "these confirmations"
                },
                not_counted
                    .iter()
                    .map(|(id, why)| format!("{id} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        });
    }
    let attested: Vec<sv_check::Verified> = design
        .attested
        .iter()
        .chain(confirmed_design.confirmed.iter())
        .cloned()
        .collect();
    let by_hand: Vec<sv_check::Verified> = hand
        .by_owner
        .iter()
        .chain(confirmed_hand.confirmed.iter())
        .cloned()
        .collect();
    let stated: Vec<sv_check::Verified> = design
        .stated
        .iter()
        .chain(hand.stated.iter())
        .chain(notes.stated.iter())
        .cloned()
        .collect();

    // The Appendix C requirements the coding rules given to this app come from, for the report's
    // section on how the app is built with AI. The same rules `sv rules` would write.
    let coding_rules = sv_check::coding_rules::CodingRules::load(&coding_rules_path())?;
    let set_aside: std::collections::BTreeSet<&str> = buckets
        .not_applicable
        .iter()
        .map(|n| n.id.as_str())
        .collect();
    let is_set_aside = |id: &str| set_aside.contains(id);
    let coding_rules_cited: std::collections::BTreeSet<String> = coding_rules
        .for_app(Some(&is_set_aside))
        .into_iter()
        .flat_map(|r| r.cites.keys().cloned())
        .collect();

    // The same weakness on the same line, reported by two tools, is one thing to fix.
    let mut findings = sv_check::finding::merge_same_place(findings);
    // Rust keeps its unit tests beside the code, so the file's name cannot say which is which.
    sv_check::finding::mark_rust_test_code(app_dir, &mut findings);
    // What the manifest says is not the app is listed with test and sample code.
    // As the scan used it: none when the list would have set apart all the app's code (ADR-031).
    sv_check::finding::mark_not_the_app(&scan_report.not_the_app, &mut findings);
    // What a person set aside, matched by the fingerprint the report prints beside each finding.
    sv_check::review::fill_fingerprints(app_dir, &mut findings);
    let reviewed = sv_check::review::apply(
        app_dir,
        &manifest.finding_review,
        findings,
        sv_check::advisories::Day::today().unwrap_or(sv_check::advisories::Day(0)),
        &seals,
    );
    let findings = reviewed.findings;
    examined.push(match &run_status {
        // Started is still only part of what the app could be asked: what sits behind a sign-in
        // it could not reach, and the requirements no question reaches, are in the gaps.
        sv_report::RunStatus::Started { .. } => sv_report::Examined::partly(
            "probe.",
            "the running app was asked what `sv` knows to ask; the gaps say what that could not reach",
        ),
        sv_report::RunStatus::NotAsked { why } | sv_report::RunStatus::CouldNotStart { why } => {
            sv_report::Examined::not_run("probe.", why.clone())
        }
    });
    let mut report = sv_report::build(sv_report::Inputs {
        app_name: if manifest.app.name.is_empty() {
            "This app"
        } else {
            &manifest.app.name
        },
        target_level: manifest.target_level(),
        generated: None,
        made_by: sv_report::MadeBy {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: env!("SV_GIT_COMMIT").to_owned(),
        },
        run_note,
        run_steps,
        test_output,
        run_status: Some(run_status),
        coding_rules_cited,
        frameworks,
        buckets: &buckets,
        claims: &resolved,
        findings,
        set_aside: reviewed.set_aside,
        reviews_not_counted: reviewed.not_counted,
        verified: &verified,
        gaps,
        manual_only,
        named_in_tests,
        not_for_tests,
        documented: &documented,
        attested: &attested,
        stated: &stated,
        by_hand: &by_hand,
        human: Some((&notes_catalog, &design_questions, &human_checks)),
        threats: Some((threat_rules, &ctx)),
    });
    report.examined = examined;
    let file_gaps = exit::Gaps::of_files(&listing, &secrets, &code);
    report.could_not_run = file_gaps.could_not_run;
    report.partly_read = file_gaps.partly;
    report.run_record = Some(run_record);
    // A contradiction says what in the code contradicted the manifest, so whoever wrote the
    // manifest can see what to correct. "The code says otherwise" alone left the AI coding tool that
    // wrote it with nothing to go on; `sv scope` always said, and now the report does too.
    for claim in report
        .claims
        .iter_mut()
        .filter(|c| c.state == "contradicted")
    {
        if let Some(answer) = scan_report
            .answers
            .iter()
            .find(|a| a.condition.name() == claim.name && a.value == Some(true))
        {
            claim.note = format!(
                "{} What the code shows: {}.",
                claim.note,
                describe(&answer.evidence)
            );
        }
    }
    Ok(report)
}

/// What `sv report` and `sv bundle` are asked for.
struct ReportArgs {
    app_dir: PathBuf,
    /// A folder for `sv report`, a file for `sv bundle`.
    out: Option<PathBuf>,
    /// Opt-in. Everything else these commands do reads files; this starts somebody's code. It runs
    /// behind the same fence `sv run` uses — no network beyond loopback, nothing published to this
    /// computer — and it is still their decision to make rather than a default.
    run_the_app: bool,
    /// With --run: wait out the session timeouts too.
    slow: bool,
    /// Opt-in for the same reason as --run, and one more: these are other people's programs, and one
    /// of them fetches its rules over the network the first time it runs.
    run_tools: bool,
    /// A folder the owner downloaded on purpose. `sv` never fetches advisories itself.
    advisories_dir: Option<PathBuf>,
}

fn parse_report_args(args: &[String], out_wants: &str) -> Result<ReportArgs> {
    let mut parsed = ReportArgs {
        app_dir: PathBuf::from("."),
        out: None,
        run_the_app: false,
        slow: false,
        run_tools: false,
        advisories_dir: None,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                parsed.out = Some(PathBuf::from(
                    rest.next()
                        .with_context(|| format!("--out needs {out_wants}"))?,
                ));
            }
            "--run" => parsed.run_the_app = true,
            "--slow" => parsed.slow = true,
            "--tools" => parsed.run_tools = true,
            "--advisories" => {
                parsed.advisories_dir = Some(PathBuf::from(
                    rest.next().context("--advisories needs a folder")?,
                ));
            }
            other if other.starts_with('-') => bail!("unknown option: {other}"),
            other => parsed.app_dir = sv_check::adapters::clean_folder(Path::new(other)),
        }
    }
    Ok(parsed)
}

/// `sv report`, ending with its exit status (`exit`, and DESIGN, "Exit codes for CI").
fn cmd_report(args: &[String]) -> Result<i32> {
    let (fail_on, args) = exit::FailOn::take(args)?;
    let args = &args[..];
    let ReportArgs {
        app_dir,
        out,
        run_the_app,
        slow,
        run_tools,
        advisories_dir,
    } = parse_report_args(args, "a directory")?;
    let advisories_given = advisories_dir.is_some();
    let out_dir = out.unwrap_or_else(|| app_dir.join("securevibe-report"));
    // Taken before the run, and held until its report is written, so a second run at the same time
    // is refused at once rather than replacing this one's report when it finishes (BACKLOG, "What the
    // owner hit building family-hub", item 2).
    let command = std::iter::once("sv report")
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let held = claim_report_folder(
        &out_dir,
        &command,
        "give this run a folder of its own with --out",
        false,
    )?;
    for note in &held.notes {
        eprintln!("{note}\n");
    }

    let mut report = assemble_report(
        &app_dir,
        &ReportOptions {
            run_the_app,
            slow,
            run_tools,
            why_not_run: "`sv report` does not start the app unless you pass --run.".to_owned(),
            why_no_tools: "`sv report` does not run other people's tools unless you pass --tools."
                .to_owned(),
            advisories: advisories_dir,
            why_no_advisories: "`sv report` compares against known vulnerabilities only when you \
                                pass --advisories DIR."
                .to_owned(),
        },
        &Loaded::load()?,
    )?;

    if let Some((note, gap)) = report_lock::manifest_changed(&report, &app_dir) {
        eprintln!("{note}\n");
        report.gaps.push(gap);
    }
    report_lock::refuse_older(
        &report,
        &out_dir,
        "give this run a folder of its own with --out",
    )?;
    let written = write_report_files(&report, &out_dir)?;
    for note in seal_report_folder(&out_dir).1 {
        eprintln!("{note}\n");
    }
    held.written();
    drop(held);

    let c = &report.counts;
    println!("Wrote {} files to {}:", written.len(), out_dir.display());
    for name in &written {
        println!("  {name}");
    }
    // First, because the counts below mean something different depending on it.
    if let Some(status) = &report.run_status {
        println!("\n{}", status.line());
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
    if c.ai_process > 0 {
        println!(
            "A further {} about how the app is built with an AI coding tool (OWASP AISVS Appendix \
             C) are counted apart; the reports list them in a section of their own.",
            c.ai_process
        );
    }
    if c.attested > 0 {
        println!(
            "A further {} you answered yes to in the [design] section of securevibe.toml, or \
             confirmed after your AI coding tool did. That is your word about how the app is built, \
             which is the weakest thing this report says: each one is still listed as a test to \
             write.",
            c.attested
        );
    }
    if c.by_hand > 0 {
        println!(
            "A further {} you checked by hand, or confirmed after your AI coding tool did, and \
             recorded in securevibe.toml with what you saw. That is your word, which nothing here \
             repeated.",
            c.by_hand
        );
    }
    if c.stated > 0 {
        println!(
            "A further {} your AI coding tool answered yes to or checked by hand in \
             securevibe.toml, or wrote in security-notes.md, or that do not say who answered. That \
             is the word of the tool that wrote the code, weaker still than yours: each one is \
             still listed as a test to write.",
            c.stated
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
    let gaps = report_gaps(&report, run_tools, advisories_given);
    let (status, reasons) = gaps.status(fail_on, report.findings.iter().map(|f| f.severity));
    exit::explain(status, &reasons)
        .iter()
        .for_each(|l| println!("{l}"));
    Ok(status)
}

/// What a report could not do, for its exit status. Beyond the files the checks could not read:
/// with `--run`, an app that could not be started, which always counts, because every check of the
/// running app was asked for and none ran; with `--tools`, a tool that did not run or ran only in
/// part, and with `--advisories`, a comparison that did not cover the whole app (`sv audit`'s 2),
/// which count only with `--fail-on not-assessed`, being partial rather than absent.
fn report_gaps(report: &sv_report::Report, run_tools: bool, advisories: bool) -> exit::Gaps {
    let mut gaps = exit::Gaps {
        could_not_run: report.could_not_run.clone(),
        partly: report.partly_read.clone(),
    };
    if let Some(sv_report::RunStatus::CouldNotStart { why }) = &report.run_status {
        gaps.could_not_run.push(format!(
            "--run was given and the app could not be started: {why}"
        ));
    }
    let tools: Vec<String> = if run_tools {
        sv_check::adapters::Adapters::load(&adapters_path())
            .map(|a| a.all().iter().map(|t| format!("{}.", t.id)).collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    for examined in &report.examined {
        let asked =
            (advisories && examined.rules == "advisory.") || tools.contains(&examined.rules);
        let short = matches!(
            examined.state,
            sv_report::ExaminedState::Partly | sv_report::ExaminedState::NotRun
        );
        if asked && short {
            gaps.partly.push(format!(
                "{} {}: {}",
                examined.rules.trim_end_matches('.'),
                if examined.state == sv_report::ExaminedState::NotRun {
                    "did not run"
                } else {
                    "covered only part of the app"
                },
                examined.why.as_deref().unwrap_or("no reason was recorded")
            ));
        }
    }
    gaps
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
/// One `examined` entry per outside tool `sv` knows: the ones that ran, in full or in part, the
/// ones that could not, and the ones for a language this app does not have.
fn adapters_examined(
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

/// The checks that read the app's files, per family. Each one read only part of the app when a
/// symbolic link was not followed; the rules that read code, also when a file was not opened or
/// did not parse, or a language had no parser; a single code rule, when it could not run or had
/// not been taught a language here.
fn file_checks_examined(
    listing: &sv_scan::files::Listing,
    code: &sv_check::ast::AstScan,
    secrets: &sv_check::secrets::SecretScan,
    config: &sv_check::config::ConfigReport,
) -> Vec<sv_report::Examined> {
    let family = |rules: &str, short: Vec<String>| {
        if short.is_empty() {
            sv_report::Examined::ran(rules)
        } else {
            sv_report::Examined::partly(rules, short.join("; "))
        }
    };
    let mut links: Vec<String> = if listing.links.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "{} symbolic link(s) in the app were not followed",
            listing.links.len()
        )]
    };
    if !listing.special.is_empty() {
        links.push(format!(
            "{} entry(s) in the app that are not ordinary files were not opened",
            listing.special.len()
        ));
    }

    let mut code_short = links.clone();
    if !code.unread_files.is_empty() {
        code_short.push(format!(
            "{} file(s) in a language the rules read were not opened",
            code.unread_files.len()
        ));
    }
    if !code.unread_languages.is_empty() {
        let mut names: Vec<&str> = code.unread_languages.iter().map(String::as_str).collect();
        names.sort_unstable();
        code_short.push(format!("no parser for {}", names.join(", ")));
    }
    if !code.unparsed_files.is_empty() {
        code_short.push(format!(
            "{} file(s) did not parse cleanly",
            code.unparsed_files.len()
        ));
    }
    let mut examined = vec![family("ast.", code_short)];
    for broken in &code.broken_queries {
        examined.push(sv_report::Examined::partly(
            broken.rule_id.clone(),
            format!(
                "its query for {} would not compile: {}",
                broken.language, broken.why
            ),
        ));
    }
    for untaught in &code.untaught {
        examined.push(sv_report::Examined::partly(
            untaught.rule_id.clone(),
            format!("it has not been taught {}", untaught.languages.join(", ")),
        ));
    }

    let mut secrets_short = links.clone();
    if !secrets.coverage.skipped.is_empty() {
        secrets_short.push(format!(
            "{} file(s) were not read",
            secrets.coverage.skipped.len()
        ));
    }
    examined.push(family("secrets.", secrets_short));

    examined.push(family("config.", links));
    for (id, why) in &config.not_assessed {
        examined.push(sv_report::Examined::not_run(id.clone(), why.clone()));
    }
    examined
}

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

    #[test]
    fn every_outside_tool_gets_an_entry_saying_whether_it_looked() {
        let adapters = sv_check::adapters::Adapters::load(&adapters_path()).unwrap();
        let run = sv_check::adapters::AdapterRun {
            ran: vec!["bandit".into()],
            partly: vec![("semgrep".into(), "told to skip tests/".into())],
            not_run: vec![
                (
                    "semgrep".into(),
                    "ran and found nothing, but was told not to look".into(),
                ),
                ("codeql-python".into(), "not installed".into()),
            ],
            ..Default::default()
        };
        let examined = adapters_examined(&adapters, &["python".to_owned()], &run);
        let state = |rules: &str| {
            examined
                .iter()
                .find(|e| e.rules == rules)
                .unwrap_or_else(|| panic!("no entry for {rules}"))
                .state
        };
        use sv_report::ExaminedState::*;
        assert_eq!(state("bandit."), Ran);
        assert_eq!(
            state("semgrep."),
            Partly,
            "looking away outranks not having found anything"
        );
        assert_eq!(state("codeql-python."), NotRun);
        assert_eq!(state("gosec."), NothingToExamine);
        assert_eq!(state("brakeman."), NothingToExamine);
        assert_eq!(
            examined.len(),
            adapters.all().len(),
            "one entry per tool `sv` knows"
        );
    }

    #[test]
    fn an_entry_names_the_stand_in_that_did_the_looking() {
        let adapters = sv_check::adapters::Adapters::load(&adapters_path()).unwrap();
        let said = "Opengrep ran in place of Semgrep, which is not installed on this computer.";
        let entry = |run: &sv_check::adapters::AdapterRun| {
            adapters_examined(&adapters, &["python".to_owned()], run)
                .into_iter()
                .find(|e| e.rules == "semgrep.")
                .unwrap()
        };
        let mut run = sv_check::adapters::AdapterRun {
            ran: vec!["semgrep".into(), "bandit".into()],
            stood_in: vec![("semgrep".into(), said.into())],
            ..Default::default()
        };
        let ran = entry(&run);
        assert_eq!(ran.state, sv_report::ExaminedState::Ran);
        assert_eq!(ran.stand_in.as_deref(), Some(said));
        // Said on the one tool it is about, and nowhere else.
        let bandit = adapters_examined(&adapters, &["python".to_owned()], &run)
            .into_iter()
            .find(|e| e.rules == "bandit.")
            .unwrap();
        assert_eq!(bandit.stand_in, None);
        // A run that read only part of the app says which program read that part.
        run.ran.clear();
        run.partly = vec![("semgrep".into(), "told to skip tests/".into())];
        let partly = entry(&run);
        assert_eq!(partly.state, sv_report::ExaminedState::Partly);
        assert_eq!(partly.stand_in.as_deref(), Some(said));
        let json = serde_json::to_value(&partly).unwrap();
        assert_eq!(json["stand_in"], said, "{json}");
    }

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
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data")
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
            passed_over: Vec::new(),
            disagreements: Vec::new(),
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
            passed_over: Vec::new(),
            disagreements: Vec::new(),
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
            passed_over: Vec::new(),
            disagreements: Vec::new(),
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

#[cfg(test)]
mod rate_limited_gap_tests {
    use super::*;

    #[test]
    fn questions_the_limiter_answered_are_named_and_nothing_else_is_said() {
        assert!(rate_limited_gap(&[]).is_none(), "no limiter, no gap");
        let gap = rate_limited_gap(&["home (429)".to_owned(), "git-head (429)".to_owned()])
            .expect("a gap when the limiter answered");
        assert!(gap.what.contains("2 of the questions"), "{}", gap.what);
        assert!(
            gap.why.contains("home (429), git-head (429)")
                && gap.why.contains("neither a finding nor a pass"),
            "{}",
            gap.why
        );
    }
}

#[cfg(all(test, unix))]
mod writing_through_links_tests {
    use super::{write_report_files, write_without_following};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-links-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_link_put_where_a_file_is_written_is_replaced_and_what_it_points_to_is_left_alone() {
        // The race `refuse_link` cannot close by looking first: a link put at the name after it looked.
        let dir = scratch("replace");
        std::fs::write(dir.join("precious.txt"), "keep me\n").unwrap();
        std::fs::create_dir(dir.join("out")).unwrap();
        std::os::unix::fs::symlink(dir.join("precious.txt"), dir.join("out/report.json")).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("out/report.json")).unwrap(),
            "keep me\n"
        );

        write_without_following(&dir.join("out"), "report.json", b"{}\n").unwrap();
        let kept = std::fs::read_to_string(dir.join("precious.txt")).unwrap();
        let meta = std::fs::symlink_metadata(dir.join("out/report.json")).unwrap();
        let written = std::fs::read_to_string(dir.join("out/report.json")).unwrap();
        let left: Vec<_> = std::fs::read_dir(dir.join("out"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(kept, "keep me\n", "the write went through the link");
        assert!(!meta.file_type().is_symlink() && written == "{}\n");
        assert_eq!(left.len(), 1, "a staging file was left behind: {left:?}");
    }

    #[test]
    fn a_report_folder_that_is_a_link_is_refused_and_nothing_is_written() {
        // `sv report` writes to `<app>/securevibe-report` unless told otherwise, and an app can ship
        // that name as a link to a folder of the owner's.
        let dir = scratch("folder");
        std::fs::create_dir(dir.join("theirs")).unwrap();
        std::os::unix::fs::symlink(dir.join("theirs"), dir.join("securevibe-report")).unwrap();
        let app =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
        let report = super::assemble_report(
            &app,
            &super::ReportOptions {
                run_the_app: false,
                slow: false,
                run_tools: false,
                why_not_run: String::new(),
                why_no_tools: String::new(),
                advisories: None,
                why_no_advisories: String::new(),
            },
            &super::Loaded::load().unwrap(),
        )
        .unwrap();
        let result = write_report_files(&report, &dir.join("securevibe-report"));
        let written: Vec<_> = std::fs::read_dir(dir.join("theirs")).unwrap().collect();
        std::fs::remove_dir_all(&dir).ok();
        let err = result.expect_err("a report folder that is a link was written through");
        assert!(format!("{err:#}").contains("is a link"), "{err:#}");
        assert!(
            written.is_empty(),
            "files were written through the link: {written:?}"
        );
    }
}

#[cfg(test)]
mod report_folder_tests {
    use super::{REPORT_FOLDER_NAMES, claim_report_folder, is_staging};

    #[test]
    fn a_part_written_file_of_svs_is_svs_and_is_cleared_once_the_folder_is_held() {
        // What a run killed while writing its marker leaves: the folder not yet marked, and the
        // marker's part-written file. Seen on 4 October 2026, when the next run called the folder
        // someone else's and refused it.
        let dir = std::env::temp_dir().join(format!("sv-staging-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        for name in ["..securevibe-report.sv-98295", ".report.json.sv-7"] {
            std::fs::write(dir.join(name), "part").unwrap();
        }
        let held =
            claim_report_folder(&dir, "sv report", "give --out", false).expect("sv's own folder");
        assert!(dir.join(".securevibe-report").is_file(), "marked");
        assert!(
            !dir.join("..securevibe-report.sv-98295").exists(),
            "cleared"
        );
        assert!(!dir.join(".report.json.sv-7").exists(), "cleared");
        drop(held);
        std::fs::remove_dir_all(&dir).ok();

        // Names only like them are still someone else's.
        for name in [
            ".notes.md.sv-1",
            ".report.json.sv-",
            ".report.json.sv-12a",
            "report.json.sv-1",
        ] {
            assert!(!is_staging(name, REPORT_FOLDER_NAMES), "{name}");
        }
        let theirs = std::env::temp_dir().join(format!("sv-staging-theirs-{}", std::process::id()));
        std::fs::remove_dir_all(&theirs).ok();
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(theirs.join(".notes.md.sv-1"), "theirs").unwrap();
        let refused = claim_report_folder(&theirs, "sv report", "give --out", false)
            .err()
            .expect("not sv's folder")
            .to_string();
        assert!(refused.contains("files sv did not write"), "{refused}");
        assert!(
            !theirs.join(".securevibe-report.lock").exists(),
            "refused before a lock was put in someone else's folder"
        );
        std::fs::remove_dir_all(&theirs).ok();
    }
}

#[cfg(test)]
mod bundle_backstop_tests {
    use super::*;

    #[test]
    fn a_report_holding_a_credential_is_not_zipped_and_the_refusal_does_not_quote_it() {
        let rules = SecretRules::load(&secret_rules_path()).unwrap();
        // Built from pieces, so this file holds none.
        let key = ["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb9Xm2Qc"].join("-");
        let password = ["Qv7r", "Lm2x", "Tz9k"].concat();
        let (redacted, n) = sv_check::secrets::redact_text(
            &rules,
            &format!("Possible hardcoded password: '{password}' and {key}"),
        );
        assert_eq!(n, 2, "{redacted}");
        // What `sv` writes, redacted, goes in.
        let clean = vec![
            ("app/report/security.md".to_owned(), redacted.into_bytes()),
            (
                "app/report/report.json".to_owned(),
                b"{\"title\": \"fine\"}\n".to_vec(),
            ),
        ];
        refuse_a_credential_in_the_report(&rules, &clean).expect("a redacted report is zipped");
        // A value that reached a report whole does not, and the refusal says where, not what.
        for planted in [
            format!("Possible hardcoded password: '{password}'"),
            format!("Authorization: Bearer {key}"),
        ] {
            let mut files = clean.clone();
            files.push((
                "app/report/compliance.md".to_owned(),
                format!("# Report\n\n{planted}\n").into_bytes(),
            ));
            let refused = refuse_a_credential_in_the_report(&rules, &files)
                .expect_err("a report holding a credential is refused")
                .to_string();
            assert!(
                refused.contains("app/report/compliance.md line 3"),
                "{refused}"
            );
            assert!(
                !refused.contains(&password[..5]) && !refused.contains(&key[..8]),
                "the refusal quotes the value: {refused}"
            );
        }
    }
}
