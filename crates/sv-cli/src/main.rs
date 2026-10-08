//! `sv` — run the SecureVibe checks against code written anywhere, in any language.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_check::advisories;
use sv_check::ast;
use sv_check::probes;
use sv_check::sbom;
use sv_check::secrets::{SecretRules, scan_dir};
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, bucket, requirements_gated_on};
use sv_frameworks::{Condition, Source};
use sv_manifest::{ClaimState, Manifest, consistency, spec};
use sv_run::RunPlan;
use sv_scan::{Evidence, Signatures};

// Everything `sv` prints goes through `sv_report::visible`, so no control character from the app, in a
// file name, a finding, or what its tests printed, reaches the terminal (the deep review's improvement 5).
// These shadow the standard macros in every module of this crate below them; an `eprint!` added later wants
// one too. The MCP server writes its protocol to its own writer, not through these.
macro_rules! println {
    () => { ::std::println!() };
    ($($arg:tt)*) => { ::std::println!("{}", ::sv_report::visible(&::std::format!($($arg)*))) };
}
macro_rules! eprintln {
    () => { ::std::eprintln!() };
    ($($arg:tt)*) => { ::std::eprintln!("{}", ::sv_report::visible(&::std::format!($($arg)*))) };
}
macro_rules! print {
    ($($arg:tt)*) => { ::std::print!("{}", ::sv_report::visible(&::std::format!($($arg)*))) };
}

mod assemble;
mod brief;
mod bundle;
mod exit;
mod history;
mod mcp;
mod parts;
mod plan;
mod preflight;
mod report_files;
mod report_folder;
mod report_lock;
mod report_seal;
mod review;
mod static_scan;

pub(crate) use assemble::{REPORT_STAGES, assemble_report_saying};

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
            // Which data this copy reads, so an install whose data is older than the code says so.
            match sv_frameworks::data::dir() {
                Ok(dir) => println!("data: {}", dir.display()),
                Err(why) => println!("data: none found. {why}"),
            }
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
    // Every command reads sv's own data, so a copy that cannot find it says so before doing
    // anything, rather than reading some files from the build folder and going without others
    // (ADR-036).
    if let Err(why) = sv_frameworks::data::dir() {
        bail!("{why}");
    }
    check_args(command, rest)?;
    let finished = |done: Result<()>| done.map(|()| exit::CLEAN);
    match command.name {
        "init" => {
            println!("{}", spec::STARTER_MANIFEST);
            if stdout_is_a_file() {
                // `sv init > securevibe.toml`: the instructions after the starter file are prose,
                // and would make the file one `sv` cannot read (gap analysis 5.3).
                eprintln!(
                    "Wrote only the starter securevibe.toml, because the output went into a file. \
                     The instructions for your AI coding tool were left out: run `sv init` \
                     without `>` to read them, or let your AI coding tool call securevibe_spec."
                );
            } else {
                println!("{}", spec::INSTRUCTIONS);
                print!("{}", prompts_at_start());
            }
            Ok(exit::CLEAN)
        }
        "scope" => finished(cmd_scope(rest.first().map(PathBuf::from))),
        "plan" => finished(cmd_plan(rest.first().map(PathBuf::from))),
        "preflight" => finished(cmd_preflight(rest.first().map(PathBuf::from))),
        "brief" => finished(cmd_brief(rest)),
        "notes" => finished(cmd_notes(rest.first().map(PathBuf::from))),
        "questions" => finished(cmd_questions(rest.first().map(PathBuf::from))),
        "rules" => finished(cmd_rules(rest)),
        "prompts" => finished(cmd_prompts(rest)),
        "probe" => finished(cmd_probe(rest)),
        "run" => cmd_run(rest),
        "check" => cmd_check(rest),
        "sbom" => finished(cmd_sbom(rest.first().map(PathBuf::from))),
        "audit" => cmd_audit(rest),
        "report" => cmd_report(rest),
        "dashboard" => finished(cmd_dashboard(rest)),
        "history" => finished(history::command(rest)),
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
        name: "preflight",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv preflight [PATH]\n                     once there is code: whether it gives `sv run` what securevibe.toml\n                     says, read from the files and never run; credits nothing\n",
    },
    Command {
        name: "brief",
        word: Some("PATH"),
        flags: &[],
        valued: &["--feature"],
        help: "  sv brief [PATH] --feature FEATURE
                     before building one feature (sign-in, uploads, payments, ai, ...):
                     its requirements, what to decide, the rules to code by, the tests to
                     write, and what `sv run` needs; credits nothing. No --feature lists them
",
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
        valued: &["--requirement", "--app", "--report"],
        help: "  sv prompts [--requirement ID | --app DIR | --report FILE]\n                     prompts to give your AI coding tool, each saying whether it has\n                     been shown to work; --requirement gives only those for one requirement\n                     or Secure by Design control, such as V1.2.4 or SBD-AC-03; --app gives\n                     those for what the app's last report (DIR/securevibe-report/report.json,\n                     or --report FILE) shows unproven\n",
    },
    Command {
        name: "probe",
        word: Some("URL"),
        flags: &[],
        valued: &["--hsts-preload", "--api"],
        help: "  sv probe URL [--hsts-preload FILE] [--api PATH]\n                     ask your own live site the few things only it can answer;\n                     --api names an address of the app's API, such as /api/health,\n                     to ask over plain HTTP the way a program asks (one more request)\n",
    },
    Command {
        name: "run",
        word: Some("PATH"),
        flags: &["--slow"],
        valued: &[],
        help: "  sv run [PATH] [--slow]\n                     start the app behind the network fence, check it answers, ask it\n                     questions as a stranger and as the test users, and run its tests;\n                     with `install = true` it first downloads the packages the app names,\n                     in a container that sees only the dependency files;\n                     --slow also waits out the session timeouts you state,\n                     and ten minutes before using an emailed sign-in code\n                     exit status: 0 the app ran; 2 not assessed: it could not be started\n                     or never answered; 3 sv itself failed (no securevibe.toml, a bad manifest)\n",
    },
    Command {
        name: "check",
        word: Some("PATH"),
        flags: &[],
        valued: &["--fail-on"],
        help: "  sv check [PATH] [--fail-on WHAT]\n                     credentials left in the code, what the rules that read the code find,\n                     and how it is set up: a narrower scan than `sv report` (or\n                     securevibe_check), saying nothing about requirements; it reads\n                     securevibe.toml when it is there only to stop on one it cannot read\n                     --fail-on also fails for attention[:SEVERITY] (a finding at SEVERITY\n                     or worse: critical, high, medium, low (the default), or info),\n                     not-assessed (also a symbolic link not followed, or an entry that is not an\n                     ordinary file), or any (both), several separated by commas\n                     exit status: 0 finished; 1 needs attention (only with --fail-on);\n                     2 not assessed: a check could not run, or no file of the app was read;\n                     3 sv itself failed (no such folder, an option it does not know, a\n                     securevibe.toml it cannot read)\n",
    },
    Command {
        name: "sbom",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv sbom [PATH]     print the list of what the app ships, as CycloneDX JSON\n",
    },
    Command {
        name: "audit",
        word: Some("PATH"),
        flags: &[],
        valued: &["--advisories"],
        help: "  sv audit [PATH] [--advisories DIR]\n                     match what the app ships against a local OSV database (DIR, or the\n                     folder SV_ADVISORY_DIR names)\n                     exit status: 0 everything compared and nothing matched; 1 a known\n                     vulnerability; 2 the comparison did not cover the whole app (no\n                     database, an ecosystem it lacks, a list of packages not complete);\n                     3 sv itself failed (an unreadable database or manifest, no such folder)\n",
    },
    Command {
        name: "report",
        word: Some("PATH"),
        flags: &["--run", "--slow", "--tools"],
        valued: &["--out", "--advisories", "--fail-on"],
        help: "  sv report [PATH] [--out DIR] [--run [--slow]] [--tools] [--advisories DIR] [--fail-on WHAT]\n                     write the reports: what applies, what was found, what nobody has answered,\n                     into PATH/securevibe-report unless --out says where; --run starts the app\n                     as `sv run` does, downloading its packages first with `install = true`\n                     --fail-on also fails for attention[:SEVERITY] (a finding at SEVERITY\n                     or worse: critical, high, medium, low (the default), or info),\n                     not-assessed (also a symbolic link not followed, a tool --tools could\n                     not run, or an --advisories comparison that did not cover the app),\n                     or any (both), several separated by commas\n                     exit status: 0 finished; 1 needs attention (only with --fail-on);\n                     2 not assessed: a check could not run, no file of the app was read,\n                     or --run was given and the app could not be started;\n                     3 sv itself failed (no securevibe.toml, a bad manifest, no such folder)\n",
    },
    Command {
        name: "review",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv review [PATH]   record, in your own terminal, the findings you set aside, the answers\n                     you confirm, and your own answers and checks made by hand; only what\n                     you record here counts as yours\n",
    },
    Command {
        name: "bundle",
        word: Some("PATH"),
        flags: &["--run", "--slow", "--tools"],
        valued: &["--out", "--advisories"],
        help: "  sv bundle [PATH] [--out FILE.zip] [--run [--slow]] [--tools] [--advisories DIR]\n                     the app, its report and a SHA-256 for every file in one zip, beside\n                     the app unless --out says where, with anything that could hold a\n                     secret left out and listed\n",
    },
    Command {
        name: "dashboard",
        word: Some("FOLDER..."),
        flags: &[],
        valued: &["--out"],
        help: "  sv dashboard FOLDER... --out FILE.html\n                     one page for several apps, from the report already in each one's\n                     securevibe-report folder: every app in alphabetical order, and each\n                     app's own view; it checks nothing itself, and writes only FILE.html\n",
    },
    Command {
        name: "history",
        word: Some("ACTION..."),
        flags: &["--all"],
        valued: &[],
        help: "  sv history on|off|status|forget FOLDER|forget --all\n                     keep a small record of each sv report run, for sv dashboard to show\n                     how an app changes; off until you turn it on, kept outside every\n                     app's folder, readable only by you, and never your code\n",
    },
    Command {
        name: "mcp",
        word: None,
        flags: &[],
        valued: &["--root", "--time-limit"],
        help: "  sv mcp [--root DIR] [--time-limit SECONDS]\n                     serve the checks to an AI coding tool over MCP, for the apps under DIR\n                     (the current folder when none is given);\n                     a check that takes longer than SECONDS (50) is reported as not finished\n",
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
                Some(word) if words > 1 && !word.ends_with("...") => {
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
    text.push_str(
        "  sv --version       the version, the commit it was built from, and the folder it reads its\n                     data from\n",
    );
    text.push_str(
        "\nEXIT STATUS:\n  For sv check, sv report, sv audit and sv run: 0 finished; 1 needs attention (sv audit, or\n  --fail-on); 2 not assessed (a check could not run); 3 sv itself failed. `sv COMMAND --help`\n  says what each means for it. Every other command ends with 0, or 3 when it failed.\n",
    );
    println!("{text}");
}

/// Where the data lives: the OWASP frameworks and knowledge files, and sv's own files beside them, all in the
/// repository's `data/` folder.
fn data_dir() -> Result<PathBuf> {
    sv_frameworks::data::dir().map_err(anyhow::Error::msg)
}

/// The v2 overlay, which replaces the applicability rules whose reasons describe v1's own template.
fn overlay_path() -> PathBuf {
    sv_frameworks::data::file("applicability-v2.json")
}

/// The Secure by Design checklist's controls against the ASVS requirements that ask the same thing.
fn crosswalk_path() -> PathBuf {
    sv_frameworks::data::file("sbd-asvs-crosswalk.json")
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
    /// The outside tools `sv` can run, or why `adapters.json` could not be read. Read here once
    /// for a report rather than three times (the review of 8 October 2026, item 7), and kept as a
    /// result rather than failing the load: only `--tools` needs the tools, so a broken file stops
    /// that run and is said in the report of every other (item 6), where it used to list no tools
    /// at all and say nothing.
    pub adapters: std::result::Result<sv_check::adapters::Adapters, String>,
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
            adapters: sv_check::adapters::Adapters::load(&adapters_path())
                .map_err(|e| format!("{e:#}")),
        })
    }
}

/// What each `derived` condition looks like in real code.
fn signatures_path() -> PathBuf {
    sv_frameworks::data::file("tech-signatures.json")
}

/// Rules that read the code itself.
fn ast_rules_path() -> PathBuf {
    sv_frameworks::data::file("ast-rules.json")
}

/// Per-language security tools `sv` can run.
fn adapters_path() -> PathBuf {
    sv_frameworks::data::file("adapters.json")
}

/// The outside tools in `adapters`, by the names a person knows them by and once each, joined into
/// a sentence: "Bandit, gosec, Brakeman, Semgrep, and CodeQL". Two adapters of one tool for two
/// languages, "CodeQL (Python)" and "CodeQL (JavaScript and TypeScript)", are one name. Until
/// 8 October 2026 the report wrote its own list, which a tool added to the file never reached:
/// Semgrep, which reads every language, was missing from it (the review of that day, item 7).
fn tool_names(adapters: &sv_check::adapters::Adapters) -> String {
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

/// Well-known credential formats.
fn secret_rules_path() -> PathBuf {
    sv_frameworks::data::file("secret-rules.json")
}

/// How each manifest claim is checked against the code.
fn corroborators_path() -> PathBuf {
    sv_frameworks::data::file("claim-corroborators.json")
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

/// The coding prompts, read on their own: the first of the library's files.
pub(crate) fn coding_prompts() -> Result<sv_check::prompts::Prompts> {
    let paths = prompts_paths();
    sv_check::prompts::Prompts::load_all(&[&paths[0]])
}

/// The coding prompts shown to work, in full, for the two places every builder reads before any code:
/// the end of the specification (`sv init`, `securevibe_spec`) and of the MCP server's opening
/// instructions. In the delivery test (docs/prompts/library-trial/delivery.md) a prompt pasted where
/// the builder starts did better than the same prompt fetched mid-build, every time. Read from
/// `data/prompts.json`, so the list cannot drift from the library; empty if it cannot be read.
pub(crate) fn prompts_at_start() -> String {
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
/// for the whole app, which `securevibe_guidance` gives with its rules. Each shown prompt so reaches
/// a builder once, from the brief for its feature or from the guidance read before any code.
pub(crate) fn whole_app_prompts(loaded: &Loaded) -> Result<Vec<sv_check::prompts::Prompt>> {
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

/// The plan for an app from its brief, built from the report's own parts (ADR-030).
pub(crate) fn plan_for(app_dir: &Path, report: &sv_report::Report) -> Result<plan::Plan> {
    let manifest = Manifest::load(&app_dir.join("securevibe.toml"))?;
    Ok(plan::from_report(report, &manifest, &design_prompts()?))
}

/// The options a plan's report is built with: nothing started and no tool run, since a plan reads
/// the brief and needs no code.
pub(crate) fn plan_options() -> ReportOptions {
    ReportOptions::reading_only("`sv plan`")
}

/// The features a brief can be written for (`sv brief`, `securevibe_before`).
pub(crate) fn feature_briefs_path() -> PathBuf {
    sv_frameworks::data::file("feature-briefs.json")
}

/// The brief for one feature of an app, from the report's own parts, as the plan is.
pub(crate) fn brief_for(
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

/// One feature's brief for an app with no `securevibe.toml` yet: what the feature brings, whole,
/// with what only the file can decide said to be waiting for it.
pub(crate) fn brief_without_manifest(feature: &str, loaded: &Loaded) -> Result<brief::Brief> {
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

/// Prints one feature's brief, or the features there are when none is named. Like the plan, it
/// is not a check, so it ends clean whatever the app holds.
fn cmd_brief(args: &[String]) -> Result<()> {
    let feature = args
        .iter()
        .position(|a| a == "--feature")
        .and_then(|i| args.get(i + 1));
    let path = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && (*i == 0 || args[i - 1] != "--feature"))
        .map(|(_, a)| PathBuf::from(a));
    let Some(feature) = feature else {
        let features = brief::Features::load(&feature_briefs_path())?;
        println!("Name a feature with --feature:");
        for f in &features.features {
            println!("  {:<18} {}", f.id, f.name);
        }
        return Ok(());
    };
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let loaded = Loaded::load()?;
    // The feature is checked before the report is built, so a misspelt name is said at once.
    brief::Features::load(&feature_briefs_path())?.get(feature)?;
    // Before securevibe.toml is written, the brief gives what does not wait for it.
    let brief = if app_dir.join("securevibe.toml").exists() {
        let report = assemble_report(&app_dir, &plan_options(), &loaded)?;
        brief_for(&report, feature, &loaded)?
    } else {
        brief_without_manifest(feature, &loaded)?
    };
    print!(
        "{}",
        brief::markdown_with(&brief, &sv_report::fence::Fence::none())
    );
    Ok(())
}

/// Prints the plan. A plan is not a check, so it ends clean whatever the app holds.
fn cmd_plan(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let report = assemble_report(&app_dir, &plan_options(), &Loaded::load()?)?;
    print!("{}", plan::markdown(&plan_for(&app_dir, &report)?));
    Ok(())
}

fn cmd_preflight(path: Option<PathBuf>) -> Result<()> {
    let app_dir = path.unwrap_or_else(|| PathBuf::from("."));
    let (items, ahead, unread) = preflight::of(&app_dir)?;
    print!("{}", preflight::markdown(&items, &ahead, &unread));
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
    if let Some(why) = manifest.level_from_unknown_data() {
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
    sv_frameworks::data::file("design-questions.json")
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
    // A path of the app's API, asked over plain HTTP as a program asks (V4.1.2). Typed here, like
    // the address, and never read from a file (ADR-027).
    let mut api: Option<&str> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--hsts-preload" => {
                preload_file = Some(PathBuf::from(
                    rest.next()
                        .context("--hsts-preload needs the list's file")?,
                ));
            }
            "--api" => {
                api = Some(
                    rest.next()
                        .context("--api needs a path of the app's API, such as /api/health")?,
                );
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
    let target = match api {
        Some(path) => target
            .with_api(path)
            .map_err(|why| anyhow::anyhow!("{why}"))?,
        None => target,
    };
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
         cookies and no credentials, and follows no redirect to any other host.{}\n",
        if target.api.is_some() {
            " It also asks the API address you named, over plain HTTP, the way a program would."
        } else {
            ""
        }
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
    sv_frameworks::data::file("security-notes.json")
}

/// The sections of design-decisions.md that count toward a checklist control (`sv_check::decisions`).
fn decisions_path() -> PathBuf {
    sv_frameworks::data::file("design-decisions.json")
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
    sv_frameworks::data::file("coding-rules.json")
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
    [
        sv_frameworks::data::file("prompts.json"),
        sv_frameworks::data::file("design-prompts.json"),
    ]
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

/// The prompts for the requirements an app's last report shows with no evidence (the owner's
/// decision of 3 October 2026, "`sv` can offer the right prompt for a requirement that still has no
/// evidence"). Read from the report, so it says what the report said when it was written: a new
/// report is the only way to see what changed since.
///
pub(crate) fn prompts_for_report(report: &Path) -> Result<ReportPrompts> {
    let text = std::fs::read_to_string(report).map_err(|e| {
        anyhow::anyhow!(
            "there is no report to read at {} ({e}). Make one first: `sv report`, or \
             `securevibe_write_report` from the AI coding tool.",
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
pub(crate) struct ReportPrompts {
    pub prompts: sv_check::prompts::Prompts,
    pub offered: Vec<(String, Vec<String>)>,
    pub gaps: std::collections::BTreeMap<String, String>,
    pub text: String,
}

/// Prints the prompts for the AI coding tool: for one requirement, for what an app's last report
/// shows unproven, or all of them.
fn cmd_prompts(args: &[String]) -> Result<()> {
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let requirement = value("--requirement");
    let report = match (value("--report"), value("--app")) {
        (Some(file), _) => Some(PathBuf::from(file)),
        (None, Some(app)) => Some(Path::new(app).join("securevibe-report").join("report.json")),
        (None, None) => None,
    };
    if let Some(report) = report {
        anyhow::ensure!(
            requirement.is_none(),
            "give either --requirement or --app (or --report), not both"
        );
        print!("{}", prompts_for_report(&report)?.text);
        return Ok(());
    }
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
    let section = found.agents_markdown();
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
        &ReportOptions::reading_only("`sv questions`"),
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
        exit::exit_with(exit::INTERRUPTED);
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
    requests.extend(probes::error_requests(
        &plan.health_path,
        &body_routes(plan.users.as_ref()),
    ));
    requests
}

/// The routes securevibe.toml names that read a body, as `(method, path)`: where a body that does
/// not parse is sent, signed out, to see the app's error answers (ADR-056).
fn body_routes(users: Option<&sv_manifest::UsersSection>) -> Vec<(String, String)> {
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
/// The gap when the container the questions are sent from was gone before they were done
/// (ADR-025, Later, 8 October 2026): everything asked after that got no answer because nothing
/// was there to ask, and a reader would otherwise take the silence for the app's.
fn sidecar_lost_gap(lost: Option<&str>) -> Option<sv_report::Gap> {
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

fn cmd_run(args: &[String]) -> Result<i32> {
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
            // Nothing about the running app was checked, which ADR-029 says with a 2, as `sv check` and
            // `sv report` do when a check could not run (the owner's decision, 6 October 2026).
            return Ok(exit::NOT_ASSESSED);
        }
        Ok((outcome, plan)) => {
            if let Some(removed) = sv_run::cleanup::removed_sentence(&outcome.left_over_removed) {
                println!("\n{removed}");
            }
            println!("\nThe app started and answered on {}.", plan.health_path);
            if let Some(installed) = sv_run::install::sentence(&outcome.installed) {
                println!("\n{installed}");
            }
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
            if let Some(gap) = sidecar_lost_gap(outcome.sidecar_lost.as_deref()) {
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
            for (requirements, why) in probes::running_app_gaps(
                outcome.signed_in.is_some(),
                &outcome.probe_responses,
                &sbom::build(&app_dir).components,
            ) {
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
    Ok(exit::CLEAN)
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
    // securevibe.toml is not needed here, and is read when it is there: one the AI coding tool wrote
    // and `sv` cannot read stops the run, as it stops `sv report`. Until 7 October 2026 it was not
    // read at all, so a broken one finished with 0 at a terminal (gap analysis 5.1).
    let manifest_path = app_dir.join("securevibe.toml");
    let manifest = if manifest_path.is_file() {
        Some(Manifest::load(&manifest_path)?)
    } else {
        None
    };
    // The same reading of the app `sv report` makes, and the same findings counted at the end
    // (`static_scan`; ADR-023, Later, 8 October 2026): what the manifest sets apart, what a person
    // set aside through `sv review`, one finding per line.
    let loaded = Loaded::load()?;
    let not_the_app = manifest
        .as_ref()
        .map(|m| m.not_the_app().0)
        .unwrap_or_default();
    let static_scan = static_scan::StaticScan::read(&app_dir, &not_the_app, &loaded, &|_| {})?;
    let static_scan::StaticScan {
        listing,
        secrets,
        config,
        code,
        ..
    } = &static_scan;
    let gaps = static_scan.file_gaps();

    println!(
        "Read {} file{} looking for credentials, against {} known formats plus the assignment rule.\n\
         Parsed {} of them against {} rules that read the code itself.",
        secrets.coverage.files_read,
        if secrets.coverage.files_read == 1 {
            ""
        } else {
            "s"
        },
        loaded.secret_rules.len(),
        code.files_parsed,
        loaded.ast_rules.len()
    );

    // What was not read comes before what was found. A short list of findings under a long list of
    // skipped files is a different result from a short list of findings.
    if !secrets.coverage.skipped.is_empty() {
        println!(
            "\n{} file{} not read, so nothing is claimed about {}:",
            secrets.coverage.skipped.len(),
            if secrets.coverage.skipped.len() == 1 {
                " was"
            } else {
                "s were"
            },
            if secrets.coverage.skipped.len() == 1 {
                "it"
            } else {
                "them"
            }
        );
        for (file, why) in secrets.coverage.skipped.iter().take(10) {
            println!("  {file} — {why}");
        }
        if secrets.coverage.skipped.len() > 10 {
            println!("  … and {} more", secrets.coverage.skipped.len() - 10);
        }
    }
    // Named too, so nobody goes looking for them: these hold no text for a credential to be in.
    if !secrets.coverage.no_written_text.is_empty() {
        let n = secrets.coverage.no_written_text.len();
        println!(
            "\n{n} file{} not read, being {} that hold{} no text a person writes:",
            if n == 1 { " was" } else { "s were" },
            if n == 1 { "one" } else { "ones" },
            if n == 1 { "s" } else { "" }
        );
        for (file, what) in secrets.coverage.no_written_text.iter().take(10) {
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
        if !code.unread_templates.is_empty() {
            // ADR-054: a template that holds code keeps the rules from a clean result, so the owner is
            // told which files did it.
            println!(
                "  Templates with code in them, which `sv` does not read yet: {}.",
                shown_files(&code.unread_templates)
            );
        }
    }
    if !code.sql_files.is_empty() {
        println!(
            "\nNot read by the rules that read code: {} ({} SQL file{}). They hold nothing back: the\n\
             rules against queries built by hand look at how the app's code builds a query.",
            shown_files(&code.sql_files),
            code.sql_files.len(),
            if code.sql_files.len() == 1 { "" } else { "s" }
        );
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

    // What this run looked at, for a review entry that matches nothing to say whether its rule
    // looked: the five scanners, and nothing else runs here.
    let mut examined = vec![sv_report::Examined::ran("sbom.")];
    examined.extend(static_scan.examined());
    let seals = sv_check::seal::Checker::for_app(&app_dir);
    let reviews = manifest
        .as_ref()
        .map(|m| m.finding_review.as_slice())
        .unwrap_or_default();
    let settled = static_scan::settle(
        &app_dir,
        reviews,
        static_scan.findings(),
        &static_scan,
        &examined,
        &loaded,
        &seals,
        &[],
    );
    let mut findings = settled.findings;
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });

    // Exactly one of these speaks: the finding above when the list is short of something, this
    // when it is not. A document cannot be both an incomplete list and a good inventory.
    let passed = static_scan.passed();
    if !passed.is_empty() && gaps.read_nothing() {
        // A check that found nothing in no files is not one that found the app fine.
        println!(
            "\nNothing is listed as checked and fine: no file of the app was read, so the {} check{} \
             that found nothing had nothing to look in.",
            passed.len(),
            if passed.len() == 1 { "" } else { "s" }
        );
    } else if !passed.is_empty() {
        println!("\nChecked and fine:");
        for claim in &passed {
            println!("  {} — {}", claim.check_id, claim.scope);
        }
    }

    // What a person set aside, and what in [[finding-review]] does not count, said as the report
    // says it: nothing is dropped quietly (ADR-023).
    if !settled.set_aside.is_empty() {
        println!("\nIn securevibe.toml, through `sv review`:");
        for s in &settled.set_aside {
            let (what, listed) = if s.verdict == "false-alarm" {
                ("a false alarm", "not listed below")
            } else {
                ("an accepted risk", "still listed and counted below")
            };
            println!(
                "  {} in {}: {what}, by {} on {} ({listed}): {}",
                s.finding.rule_id, s.finding.location.file, s.by, s.on, s.why
            );
        }
    }
    if !settled.not_counted.is_empty() {
        println!("\nNot counted in [[finding-review]], so each finding stands:");
        for why in &settled.not_counted {
            println!("  {why}");
        }
    }

    let (status, reasons) = gaps.status(fail_on, findings.iter().map(|f| f.severity));
    if findings.is_empty() {
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
        findings.len(),
        if findings.len() == 1 { "" } else { "s" }
    );
    for f in &findings {
        // A finding about a file that is missing, such as no SECURITY.md, names the file it
        // would be, not a line of it.
        // A file name and a tool's title are the app's words or a tool's, and a line break in either
        // started a line that read as `sv`'s own (the review of 8 October 2026, item 6): each is
        // written on one line, its breaks shown as `\n`.
        let file = sv_report::one_line(&f.location.file);
        let place = if app_dir.join(&f.location.file).symlink_metadata().is_ok() {
            format!("{file}:{}", f.location.line)
        } else {
            format!("{file} (not there)")
        };
        println!(
            "\n  [{}] {}\n     {place}",
            f.severity.name(),
            sv_report::one_line(&f.title)
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

/// Whether standard output goes straight into a file, as with `sv init > securevibe.toml`, rather
/// than to a terminal or a pipe.
fn stdout_is_a_file() -> bool {
    #[cfg(unix)]
    {
        use std::os::fd::AsFd;
        std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .map(std::fs::File::from)
            .and_then(|f| f.metadata())
            .is_ok_and(|m| m.is_file())
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// `sv dashboard`: one page for several apps, from their reports (`sv_report::dashboard`; ADR-057).
///
/// It writes one file, only where it is told, and never over a file it did not make: not a link,
/// not a folder, not a page without its mark, and not inside one of the apps, where the next check
/// would read it as the app's own.
fn cmd_dashboard(args: &[String]) -> Result<()> {
    let mut folders = Vec::new();
    let mut out = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg == "--out" {
            out = rest.next().map(PathBuf::from);
        } else {
            folders.push(PathBuf::from(arg));
        }
    }
    if folders.is_empty() {
        folders = history::apps();
    }
    if folders.is_empty() {
        bail!(
            "`sv dashboard` needs the app folders to show, for example: sv dashboard ~/code/app-one ~/code/app-two --out ~/sv-dashboard.html (with history on, `sv history on`, it shows every app whose runs were kept)"
        );
    }
    let Some(out) = out else {
        bail!(
            "`sv dashboard` writes only where it is told: add --out FILE.html, for example --out ~/sv-dashboard.html"
        );
    };
    let mut apps = Vec::new();
    for folder in &folders {
        if !folder.is_dir() {
            bail!("{} is not a folder", folder.display());
        }
        let folder = std::fs::canonicalize(folder)
            .with_context(|| format!("finding the folder {}", folder.display()))?;
        let reports = folder.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR);
        let summary = match std::fs::read_to_string(reports.join("report.json")) {
            Ok(text) => sv_report::dashboard::read(&text),
            Err(_) => Err(format!(
                "there is no report.json in its {} folder yet",
                sv_scan::ecosystems::DEFAULT_REPORT_DIR
            )),
        };
        let report_html = reports.join("report.html");
        apps.push(sv_report::dashboard::App {
            report_html: report_html.is_file().then_some(report_html),
            runs: history::runs(&folder),
            folder,
            summary,
        });
    }

    // Where it writes: a file of its own, beside nothing of the apps'.
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent = std::fs::canonicalize(&parent)
        .with_context(|| format!("finding the folder {} to write into", parent.display()))?;
    let name = out
        .file_name()
        .with_context(|| format!("{} names no file", out.display()))?;
    let target = parent.join(name);
    if let Some(app) = apps.iter().find(|a| target.starts_with(&a.folder)) {
        bail!(
            "{} is inside the app folder {}. Choose a place outside it, so the page is not read back as part of the app.",
            target.display(),
            app.folder.display()
        );
    }
    if let Ok(meta) = std::fs::symlink_metadata(&target) {
        if meta.file_type().is_symlink() {
            bail!(
                "{} is a link, and nothing is written through it",
                target.display()
            );
        }
        if meta.is_dir() {
            bail!(
                "{} is a folder; give a file name, such as sv-dashboard.html",
                target.display()
            );
        }
        let existing = std::fs::read(&target).unwrap_or_default();
        if !String::from_utf8_lossy(&existing).contains(sv_report::dashboard::MADE_BY) {
            bail!(
                "{} is already there and was not written by sv dashboard, so it is left as it is. Choose another name.",
                target.display()
            );
        }
    }
    let written = crate::bundle::utc_time(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let page = sv_report::dashboard::page(&apps, &written[..written.len().min(10)]);
    let staging = parent.join(format!(
        ".{}.sv-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&staging, page).with_context(|| format!("writing {}", staging.display()))?;
    std::fs::rename(&staging, &target).with_context(|| format!("writing {}", target.display()))?;

    let missing: Vec<&sv_report::dashboard::App> =
        apps.iter().filter(|a| a.summary.is_err()).collect();
    println!(
        "Wrote {} ({} app{}). Open it in a browser.",
        target.display(),
        apps.len(),
        if apps.len() == 1 { "" } else { "s" }
    );
    for app in missing {
        if let Err(why) = &app.summary {
            println!(
                "  {}: no report to show, because {why}. Run `sv report` on it first.",
                app.folder.display()
            );
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
        if disagreement.comparison.not_all_compared() {
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
        let mut names: Vec<&str> = sbom
            .components
            .iter()
            .map(|c| c.ecosystem.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        println!(
            "Not assessed: nothing here knows which versions are known to be vulnerable.\n\n\
             `sv` does not fetch anything — the list of packages this app depends on is yours, and a\n\
             check that quietly phones out is one you did not agree to. Download the OSV export for\n\
             each ecosystem below, unpack it, and point at it:\n\n  \
             sv audit {} --advisories ./osv\n\n\
             Ecosystems in this app: {}\n\n{}",
            app_dir.display(),
            if names.is_empty() {
                "none found".to_owned()
            } else {
                names.join(", ")
            },
            if names.is_empty() {
                String::new()
            } else {
                advisories::how_to_download(&names, "osv")
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
        &ReportOptions::asked_of("`sv bundle`", run_the_app, slow, run_tools, advisories_dir),
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

const REPORT_MARKER_TEXT: &str =
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
    Ok(write_report(report, out_dir)?.names())
}

/// The report files written, each with the text written to it, which is what a seal is made from.
pub(crate) struct Written {
    contents: Vec<(&'static str, String)>,
}

impl Written {
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.contents.iter().map(|(name, _)| *name).collect()
    }
}

/// `write_report_files`, keeping what was written.
fn write_report(report: &sv_report::Report, out_dir: &Path) -> Result<Written> {
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

/// Refuses to write a report into a folder that holds anything but `sv`'s own files, unless `sv` marked
/// it as its own and this computer can show, by its seal, that `sv` wrote the report there; and,
/// marked or not, one holding a file whose name differs from one of `sv`'s only in capitals.
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
pub(crate) struct Remedy {
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

impl ReportOptions {
    /// Nothing started, no tool run, and no database read, for a caller that never does any of
    /// them: `caller` is how the report names it ("`sv plan`"). Until 8 October 2026 each caller
    /// wrote its own three sentences and three `false`s; the MCP server's sentences, which say what
    /// the person can do instead, are written over these with the struct-update syntax.
    fn reading_only(caller: &str) -> Self {
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
    fn asked_of(
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
    // What only the folders set apart show (gap analysis, item 19): not read as a "no", so each is a
    // question, unless securevibe.toml answers it.
    let claims = manifest.claims();
    for (condition, shown_by) in &scan.found_only_apart {
        let claimed = claims
            .iter()
            .find(|(c, _)| c == condition)
            .and_then(|(_, v)| *v);
        let answer = match claimed {
            Some(true) => "securevibe.toml says it does, so its requirements apply".to_owned(),
            Some(false) => "securevibe.toml says it does not, and that answer stands; if the app \
                            itself does, change the answer"
                .to_owned(),
            None => "nothing else answers it, so its requirements wait on that question rather \
                     than being set aside"
                .to_owned(),
        };
        gaps.push(sv_report::Gap {
            what: format!("whether the app itself has `{}`", condition.name()),
            why: format!(
                "The only sign of it is {shown_by}, in a folder securevibe.toml says is not the app \
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

fn assemble_report(
    app_dir: &Path,
    options: &ReportOptions,
    loaded: &Loaded,
) -> Result<sv_report::Report> {
    assemble_report_saying(app_dir, options, loaded, &|_, _| {})
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
/// The terminal's count of what applies: the total, then a line per status under it, adding up to
/// it. The four that rest on somebody's word are listed only when there are any, and each says
/// whose word it is.
fn summary_counts(c: &sv_report::Counts) -> String {
    use sv_report::Status;
    let mut out = format!("{} requirements apply:", c.applicable);
    for (status, n) in c.by_status() {
        let words = match status {
            Status::NeedsAttention => {
                if n == 1 {
                    "needs attention"
                } else {
                    "need attention"
                }
            }
            Status::Checked => {
                if n == 1 {
                    "was checked by an automated check"
                } else {
                    "were checked by an automated check"
                }
            }
            Status::CheckedInPart => {
                if n == 1 {
                    "was checked in part: an automated check tried some of what it asks"
                } else {
                    "were checked in part: an automated check tried some of what each asks"
                }
            }
            Status::AppTested => {
                if n == 1 {
                    "was tested only by your app's own tests: your AI coding tool's, not sv's"
                } else {
                    "were tested only by your app's own tests: your AI coding tool's, not sv's"
                }
            }
            Status::Documented => "you answered in security-notes.md: your word, not a check",
            Status::ByHand => "you checked by hand: your word, not an automated check",
            Status::Attested => {
                "you answered yes about how the app is built: your word, not a check"
            }
            Status::Stated => "your AI coding tool answered yes: the tool's word, not a check",
            Status::NotVerified => {
                if n == 1 {
                    "was not verified by anything"
                } else {
                    "were not verified by anything"
                }
            }
        };
        let always = matches!(
            status,
            Status::NeedsAttention | Status::Checked | Status::NotVerified
        );
        if n > 0 || always {
            out.push_str(&format!("\n  {n} {words}"));
        }
    }
    out
}

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
    // Loaded before the report and kept after it, so the exit status is decided from the same
    // reading of `adapters.json` the report was made from.
    let loaded = Loaded::load()?;
    let out_dir = out.unwrap_or_else(|| app_dir.join("securevibe-report"));
    // Taken before the run, and held until its report is written, so a second run at the same time
    // is refused at once rather than replacing this one's report when it finishes (BACKLOG, "What the
    // owner hit building family-hub", item 2).
    let command = std::iter::once("sv report")
        .chain(args.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let elsewhere = "give this run a folder of its own with --out";
    let report_folder::ReportFolder {
        report, written, ..
    } = report_folder::write_report_folder(
        &app_dir,
        &out_dir,
        &command,
        elsewhere,
        false,
        || {
            assemble_report(
                &app_dir,
                &ReportOptions::asked_of(
                    "`sv report`",
                    run_the_app,
                    slow,
                    run_tools,
                    advisories_dir,
                ),
                &loaded,
            )
        },
        &mut |note| eprintln!("{note}\n"),
    )?;
    let written = written.names();

    // History, when the person keeps it (ADR-057): after the report is written, never instead of it.
    let kept = sv_report::dashboard::Run::of(&report).map(|run| history::keep(&app_dir, &run));

    let c = &report.counts;
    println!("Wrote {} files to {}:", written.len(), out_dir.display());
    for name in &written {
        println!("  {name}");
    }
    // First, because the counts below mean something different depending on it.
    if let Some(status) = &report.run_status {
        println!("\n{}", status.line());
    }
    // A line per status, so the numbers add up to what applies (deep review R5): it used to give
    // three of the seven in its first sentence and the rest as "a further", as if on top.
    println!("\n{}\n", summary_counts(c));
    if c.ai_process > 0 {
        println!(
            "A further {} about how the app is built with an AI coding tool (OWASP AISVS Appendix \
             C) are counted apart; the reports list them in a section of their own.",
            c.ai_process
        );
    }
    if c.app_tested > 0 {
        println!(
            "The {} tested only by your app's own tests {} tested, not checked: your AI coding tool \
             wrote those tests, and nothing here reads whether each asks what its requirement \
             asks. They settle no threat, and stay on the list before going live.",
            c.app_tested,
            if c.app_tested == 1 { "is" } else { "are" }
        );
    }
    if c.documented > 0 {
        println!(
            "The {} you answered in security-notes.md {} documented, not checked: nothing here \
             reads whether the answer is right, or whether the app does what it says.",
            c.documented,
            if c.documented == 1 { "is" } else { "are" }
        );
    }
    if c.by_hand > 0 {
        println!(
            "The {} you checked by hand, or confirmed after your AI coding tool did, and recorded \
             in securevibe.toml with what you saw {} your word, which nothing here repeated.",
            c.by_hand,
            if c.by_hand == 1 { "is" } else { "are" }
        );
    }
    if c.attested > 0 {
        println!(
            "The {} you answered yes to in the [design] section of securevibe.toml, or confirmed \
             after your AI coding tool did, {} your word about how the app is built, which is the \
             weakest thing this report says: each one is still listed as a test to write.",
            c.attested,
            if c.attested == 1 { "is" } else { "are" }
        );
    }
    if c.stated > 0 {
        println!(
            "The {} your AI coding tool answered yes to or checked by hand in securevibe.toml, or \
             wrote in security-notes.md, or that do not say who answered, {} the word of the tool \
             that wrote the code, weaker still than yours: each one is still listed as a test to \
             write.",
            c.stated,
            if c.stated == 1 { "is" } else { "are" }
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
             lists the level 1 ones under \"Tests worth writing first\", and report.json all of them.",
            report.tests_to_write.len()
        );
    }
    if !report.threats.is_empty() {
        println!(
            "{} compliance.md lists them under \"Threats\".",
            sv_report::threats::count_line(&report.threats)
        );
    }
    let gaps = report_gaps(&report, &loaded.adapters, run_tools, advisories_given);
    let (status, reasons) = gaps.status(fail_on, report.findings.iter().map(|f| f.severity));
    // What was asked for and did not all run is said here whatever the exit status: by default it
    // does not change the status (ADR-029), and a run that ends quietly reads as one where it ran.
    let unsaid: Vec<&String> = gaps
        .partly
        .iter()
        .filter(|g| !reasons.iter().any(|r| r.starts_with(g.as_str())))
        .collect();
    if !unsaid.is_empty() {
        println!("\nAsked for, and not all of it ran (the reports say the same):");
        for gap in unsaid {
            println!("  {gap}");
        }
    }
    println!(
        "\nOpen report.html to read it. Nothing in there says a requirement passed, because \
         nothing here can establish that."
    );
    match kept {
        Some(Ok(Some(_))) => println!(
            "Kept a record of this run in your history (`sv history off` stops it; `sv dashboard` shows it)."
        ),
        Some(Err(e)) => eprintln!("History is on, and this run could not be kept: {e:#}"),
        _ => {}
    }
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
fn report_gaps(
    report: &sv_report::Report,
    adapters: &std::result::Result<sv_check::adapters::Adapters, String>,
    run_tools: bool,
    advisories: bool,
) -> exit::Gaps {
    let mut gaps = exit::Gaps {
        could_not_run: report.could_not_run.clone(),
        partly: report.partly_read.clone(),
    };
    if let Some(sv_report::RunStatus::CouldNotStart { why }) = &report.run_status {
        gaps.could_not_run.push(format!(
            "--run was given and the app could not be started: {why}"
        ));
    }
    // With `--tools` the report was made only if these were read, so they are here.
    let tools: Vec<String> = if run_tools {
        adapters
            .as_ref()
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

/// The decisions held to the running app (`sv_check::decisions::not_held_to`), then what a person
/// set aside (`review`). In that order, so a review of a decision's own finding is applied like any
/// other (the review of 6 October, item 7); and a decision whose running-app finding a person set
/// aside keeps no finding of its own, since a false alarm is not held against a decision either.
fn decisions_then_reviews(
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
struct ReviewLookup<'a> {
    app_dir: &'a Path,
    examined: &'a [sv_report::Examined],
    listing: &'a sv_scan::files::Listing,
    code: &'a sv_check::ast::AstScan,
    secrets: &'a sv_check::secrets::SecretScan,
    ast_rules: &'a sv_check::ast::AstRules,
    secret_rules: &'a sv_check::secrets::SecretRules,
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

/// Up to five files, in backquotes, and how many more there are.
fn shown_files(files: &[String]) -> String {
    let mut shown: Vec<String> = files.iter().take(5).map(|f| format!("`{f}`")).collect();
    if files.len() > 5 {
        shown.push(format!("and {} more", files.len() - 5));
    }
    shown.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_body_goes_to_the_routes_the_manifest_names() {
        // ADR-056: the routes that read a body are where the app's code can be made to fail.
        let example = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/notes-with-users/securevibe.toml");
        let manifest = sv_manifest::Manifest::load(&example).expect("the example loads");
        let users = manifest.stack.run.users.as_ref().expect("it has users");
        let routes = body_routes(Some(users));
        let login = users.login.as_ref().expect("it signs in");
        assert!(
            routes.contains(&(login.method.clone(), login.path.clone())),
            "{routes:?}"
        );
        let create = &users.owned.as_ref().expect("it has an owned record").create;
        assert!(
            routes.contains(&(create.method.clone(), create.path.clone())),
            "{routes:?}"
        );
        let ids: Vec<String> = probes::error_requests("/health", &routes)
            .into_iter()
            .map(|r| r.id)
            .collect();
        assert!(
            ids.contains(&format!("bad-body POST {}", login.path)),
            "{ids:?}"
        );
        assert!(body_routes(None).is_empty());
    }

    #[test]
    fn a_decisions_finding_reaches_the_reviews_and_goes_with_its_running_app_finding() {
        // The review of 6 October, item 7: the decision's own finding was made after the reviews
        // were applied, so no review of it could ever count.
        let section = "# Design decisions\n\n## Safe defaults\n\n- Debug mode: off\n";
        let decided = sv_check::decisions::safe_defaults(section).decided;
        assert_eq!(decided.len(), 1, "the setup: the line is read");
        let probe = sv_check::Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
            rule_id: decided[0].switch.rule_id.to_owned(),
            title: "open".to_owned(),
            severity: sv_check::Severity::High,
            confidence: sv_check::Confidence::High,
            location: sv_check::Location {
                file: "(running app)".to_owned(),
                line: 0,
            },
            secret: None,
            requirement_ids: vec!["V13.4.2".to_owned()],
            cwe: Vec::new(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
        };
        let as_is = |findings: Vec<sv_check::Finding>| sv_check::review::Outcome {
            findings,
            set_aside: Vec::new(),
            not_counted: Vec::new(),
        };
        // The review is shown the decision's finding.
        let mut seen = Vec::new();
        decisions_then_reviews(vec![probe.clone()], &decided, |findings| {
            seen = findings.iter().map(|f| f.rule_id.clone()).collect();
            as_is(findings)
        });
        assert!(
            seen.iter().any(|r| r == sv_check::decisions::NOT_HELD_TO),
            "{seen:?}"
        );
        // Kept while the running app's finding is, and gone with it when a person set that aside.
        let kept = decisions_then_reviews(vec![probe.clone()], &decided, as_is);
        assert_eq!(kept.findings.len(), 2);
        let set_aside = decisions_then_reviews(vec![probe], &decided, |mut findings| {
            findings.retain(|f| f.rule_id == sv_check::decisions::NOT_HELD_TO);
            as_is(findings)
        });
        assert!(set_aside.findings.is_empty(), "{:?}", set_aside.findings);
    }

    #[test]
    fn a_line_is_gathered_after_the_reviews_so_a_verdict_sets_aside_one_problem_only() {
        let at = |rule: &str| {
            let mut f = sv_check::Finding {
                rule_id: rule.to_owned(),
                title: rule.to_owned(),
                severity: sv_check::Severity::High,
                confidence: sv_check::Confidence::Medium,
                location: sv_check::Location {
                    file: "app.py".to_owned(),
                    line: 5,
                },
                secret: None,
                requirement_ids: Vec::new(),
                cwe: Vec::new(),
                description: String::new(),
                impact: String::new(),
                fix: String::new(),
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                earlier_fingerprints: Vec::new(),
                marked_test_code: false,
                bundled_library: None,
                outranked: None,
                also_on_this_line: Vec::new(),
            };
            f.fingerprint = format!("fp-{rule}");
            f
        };
        // A review that sets aside `ast.eval` by its rule, as a counted false alarm does.
        let out =
            decisions_then_reviews(vec![at("ast.sql"), at("ast.eval")], &[], |mut findings| {
                assert_eq!(findings.len(), 2, "the review sees each problem on its own");
                findings.retain(|f| f.rule_id != "ast.eval");
                sv_check::review::Outcome {
                    findings,
                    set_aside: Vec::new(),
                    not_counted: Vec::new(),
                }
            });
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, "ast.sql");
        assert!(
            out.findings[0].also_on_this_line.is_empty(),
            "{:?}",
            out.findings
        );
        // The control: with nothing set aside, the line is one finding holding the other.
        let out = decisions_then_reviews(vec![at("ast.sql"), at("ast.eval")], &[], |findings| {
            sv_check::review::Outcome {
                findings,
                set_aside: Vec::new(),
                not_counted: Vec::new(),
            }
        });
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].also_on_this_line.len(), 1);
    }

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
            lockfiles: Vec::new(),
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
            lockfiles: Vec::new(),
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
            lockfiles: Vec::new(),
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
            &super::ReportOptions::reading_only("a test"),
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

#[cfg(test)]
mod adapters_once_tests;
