//! `sv` — run the StackVet checks against code written anywhere, in any language.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_check::advisories;
use sv_check::probes;
use sv_check::sbom;
use sv_check::secrets::SecretRules;
use sv_frameworks::applicability::{ApplicabilityConfig, bucket, requirements_gated_on};
use sv_frameworks::{Condition, Source};
use sv_manifest::{ClaimState, Manifest, consistency, spec};
use sv_run::RunPlan;
use sv_scan::{Evidence, Signatures};
// The report's assembly and what it needs are the library's; the commands below call it.
use sv_cli::*;

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

mod baseline;
mod crash;
mod history;
mod review;

/// Runs the command, and ends with its status: 3 for any error `sv` could not get past, whichever
/// command met it, so a pipeline can tell "`sv` did not run" from anything a run found (DESIGN, "Exit
/// codes for CI"). The error is printed as it always was, `Error:` and its causes.
///
/// A panic is a fault in `sv`, so it ends the same way: what failed and where, that it is `sv`'s fault
/// and not the app's, that nothing was assessed, and 3, rather than Rust's own line and 101, a code
/// no document names (backlog 226, part 1, item 5). The panic unwinds first, so whatever cleans up
/// on the way out (the run's containers, the report folder's lock) still does.
fn main() {
    crash::install();
    let ran = std::panic::catch_unwind(run);
    match ran {
        Ok(Ok(exit::CLEAN)) => {}
        Ok(Ok(code)) => exit::exit_with(code),
        Ok(Err(error)) => {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            eprintln!("Error: {error:?}");
            exit::exit_with(exit::FAILED)
        }
        Err(_) => {
            use std::io::Write;
            let _ = std::io::stdout().flush();
            eprintln!("{}", crash::said());
            exit::exit_with(exit::FAILED)
        }
    }
}

/// The command named on the command line, and the status it ends with when it finished.
fn run() -> Result<i32> {
    // Only in a debug build, so the crash path can be tested: no released `sv` has it.
    #[cfg(debug_assertions)]
    if std::env::var_os("SV_PANIC_FOR_TEST").is_some() {
        panic!("a panic asked for by SV_PANIC_FOR_TEST");
    }
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
                // `sv init > stackvet.toml`: the instructions after the starter file are prose,
                // and would make the file one `sv` cannot read (gap analysis 5.3).
                eprintln!(
                    "Wrote only the starter stackvet.toml, because the output went into a file. \
                     The instructions for your AI coding tool were left out: run `sv init` \
                     without `>` to read them, or let your AI coding tool call stackvet_spec."
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
        "explain" => finished(cmd_explain(rest)),
        "prompts" => finished(cmd_prompts(rest)),
        "probe" => finished(cmd_probe(rest)),
        "run" => cmd_run(rest),
        "check" => cmd_check(rest),
        "sbom" => finished(cmd_sbom(rest.first().map(PathBuf::from))),
        "audit" => cmd_audit(rest),
        "report" => cmd_report(rest),
        "dashboard" => finished(cmd_dashboard(rest)),
        "compare" => finished(sv_cli::compare::command(rest)),
        "history" => finished(history::command(rest)),
        "review" => finished(review::cmd_review(rest.first().map(PathBuf::from))),
        "bundle" => finished(cmd_bundle(rest)),
        "connect" => {
            print!("{}", sv_cli::connect::command(rest)?);
            if let Some(line) = sv_cli::connect::where_it_goes(rest) {
                eprintln!("{line}");
            }
            Ok(exit::CLEAN)
        }
        "doctor" => finished(cmd_doctor(rest)),
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
        help: "  sv init            print the stackvet.toml spec to hand to your AI coding tool\n",
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
        help: "  sv preflight [PATH]\n                     once there is code: whether it gives `sv run` what stackvet.toml\n                     says, read from the files and never run; credits nothing\n",
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
        name: "explain",
        word: Some("ID"),
        flags: &[],
        valued: &["--app", "--report"],
        help: "  sv explain ID [--app DIR | --report FILE]\n                     one requirement, such as V7.4.1: what it asks, the checks that speak\n                     to it and the kind of run each needs, and what to do; --app adds what\n                     the app's last report said about it, --report what that report said\n",
    },
    Command {
        name: "prompts",
        word: Some("report"),
        flags: &[],
        valued: &["--requirement", "--app", "--report"],
        help: "  sv prompts [report | --requirement ID | --app DIR | --report FILE]\n                     prompts to give your AI coding tool, each saying whether it has\n                     been shown to work; --requirement gives only those for one requirement\n                     or Secure by Design control, such as V1.2.4 or SBD-AC-03; --app gives\n                     those for what the app's last report (DIR/stackvet-report/report.json,\n                     or --report FILE) shows unproven; `report` gives the one that has your\n                     AI coding tool read the report with you, what was not checked first\n",
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
        help: "  sv run [PATH] [--slow]\n                     start the app behind the network fence, check it answers, ask it\n                     questions as a stranger and as the test users, and run its tests;\n                     with `install = true` it first downloads the packages the app names,\n                     in a container that sees only the dependency files;\n                     --slow also waits out the session timeouts you state,\n                     and ten minutes before using an emailed sign-in code\n                     exit status: 0 the app ran; 2 not assessed: it could not be started\n                     or never answered; 3 sv itself failed (no stackvet.toml, a bad manifest)\n",
    },
    Command {
        name: "check",
        word: Some("PATH"),
        flags: &[],
        valued: &["--fail-on", "--baseline"],
        help: "  sv check [PATH] [--fail-on WHAT] [--baseline DIR]\n                     credentials left in the code, what the rules that read the code find,\n                     and how it is set up: a narrower scan than `sv report` (or\n                     stackvet_check), saying nothing about requirements; it reads\n                     stackvet.toml when it is there only to stop on one it cannot read\n                     --fail-on also fails for attention[:SEVERITY] (a finding at SEVERITY\n                     or worse: critical, high, medium, low (the default), or info),\n                     not-assessed (also a symbolic link not followed, or an entry that is not an\n                     ordinary file), or any (both), several separated by commas\n                     --baseline DIR, an older report folder: attention fails only for a\n                     finding that report did not hold; every finding is still listed\n                     exit status: 0 finished; 1 needs attention (only with --fail-on);\n                     2 not assessed: a check could not run, or no file of the app was read;\n                     3 sv itself failed (no such folder, an option it does not know, a\n                     stackvet.toml it cannot read)\n",
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
        flags: &["--run", "--slow", "--tools", "--keep-tool-output"],
        valued: &["--out", "--advisories", "--fail-on", "--baseline"],
        help: "  sv report [PATH] [--out DIR] [--run [--slow]] [--tools [--keep-tool-output]] [--advisories DIR] [--fail-on WHAT] [--baseline DIR]\n                     write the reports: what applies, what was found, what nobody has answered,\n                     into PATH/stackvet-report unless --out says where; --run starts the app\n                     as `sv run` does, downloading its packages first with `install = true`\n\
                     --keep-tool-output, with --tools, keeps each tool's own report,\n\
                     credentials cut out, in seen.json beside the report\n                     --fail-on also fails for attention[:SEVERITY] (a finding at SEVERITY\n                     or worse: critical, high, medium, low (the default), or info),\n                     not-assessed (also a symbolic link not followed, a tool --tools could\n                     not run, or an --advisories comparison that did not cover the app),\n                     or any (both), several separated by commas\n                     --baseline DIR, an older report folder: attention fails only for a\n                     finding that report did not hold; every finding is still listed and\n                     counted, and those it held are marked\n                     exit status: 0 finished; 1 needs attention (only with --fail-on);\n                     2 not assessed: a check could not run, no file of the app was read,\n                     or --run was given and the app could not be started;\n                     3 sv itself failed (no stackvet.toml, a bad manifest, no such folder)\n",
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
        help: "  sv dashboard FOLDER... --out FILE.html\n                     one page for several apps, from the report already in each one's\n                     stackvet-report folder: every app in alphabetical order, and each\n                     app's own view; it checks nothing itself, and writes only FILE.html\n",
    },
    Command {
        name: "compare",
        word: Some("REPORT..."),
        flags: &[],
        valued: &[],
        help: "  sv compare OLDER [NEWER]\n                     what changed between two reports of an app: each requirement whose\n                     status moved, with what it gained or lost, and the findings that\n                     came or went; NEWER is this folder's report when not given; writes\n                     nothing\n",
    },
    Command {
        name: "history",
        word: Some("ACTION..."),
        flags: &["--all"],
        valued: &[],
        help: "  sv history on|off|status|forget FOLDER|forget --all\n                     keep a small record of each sv report run, for sv dashboard to show\n                     how an app changes; off until you turn it on, kept outside every\n                     app's folder, readable only by you, and never your code\n",
    },
    Command {
        name: "connect",
        word: Some("TOOL"),
        flags: &[],
        valued: &["--docker", "--user", "--folder"],
        help: "  sv connect TOOL [--docker PATH] [--user UID:GID] [--folder DIR]\n                     print the settings that connect an AI coding tool (claude, vscode,\n                     or cursor) to `sv` for this folder, the paths already filled in;\n                     --docker PATH (where docker is, from `which docker`) for the\n                     container, --user UID:GID on Linux; writes nothing\n",
    },
    Command {
        name: "doctor",
        word: Some("PATH"),
        flags: &[],
        valued: &[],
        help: "  sv doctor [PATH]   is everything ready? which sv this is, whether the folder is in\n                     git, whether stackvet.toml reads and says how to start the app, and\n                     whether Docker can start it; opens no network connection, writes nothing\n",
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
    sv_cli::doctor::version_line()
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
    // Before stackvet.toml is written, the brief gives what does not wait for it.
    let brief = if sv_manifest::locate(&app_dir)?.is_some() {
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
    let manifest = Manifest::load_in(&app_dir)?.0;

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
    for unread in &report.unread_manifests {
        println!(
            "  {} was not read: {}, so a technology known only by its package may read as not used.",
            unread.manifest, unread.why
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
                "  stackvet.toml says {} is {}, but {how}",
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
                Source::Claim => "stackvet.toml does not say",
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
        println!("\nWorth checking in stackvet.toml:");
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
            "\nAnswered in stackvet.toml but gating nothing: {}.\n\
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

/// Prints the prompts for the AI coding tool: for one requirement, for what an app's last report
/// shows unproven, or all of them.
/// `sv explain ID [--app DIR]`: one requirement explained (`explain.rs`).
fn cmd_explain(args: &[String]) -> Result<()> {
    let mut id = None;
    let mut app = None;
    let mut report = None;
    let mut words = args.iter();
    while let Some(arg) = words.next() {
        match arg.as_str() {
            "--app" => app = words.next().map(PathBuf::from),
            "--report" => report = words.next().map(PathBuf::from),
            other if other.starts_with("--") => bail!("unknown option: {other}"),
            other => id = Some(other.to_owned()),
        }
    }
    let id = id.context("give the requirement's id, such as `sv explain V7.4.1`")?;
    print!(
        "{}",
        sv_cli::explain::command(&id, app.as_deref(), report.as_deref())?
    );
    Ok(())
}

fn cmd_prompts(args: &[String]) -> Result<()> {
    // `sv prompts report`: the one for reading the report with the person (backlog 0217 part 5).
    if args.first().map(String::as_str) == Some("report") {
        anyhow::ensure!(
            args.len() == 1,
            "`sv prompts report` takes nothing more: it prints one prompt, the same for every app"
        );
        print!("{}", sv_cli::report_prompt::with_mark());
        return Ok(());
    }
    // The only word it takes is `report`, first; any other would otherwise be passed over unread.
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if ["--requirement", "--app", "--report"].contains(&arg.as_str()) {
            rest.next();
        } else if !arg.starts_with("--") {
            bail!("`sv prompts` takes one word, `report`, and was given {arg}");
        }
    }
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .map(String::as_str)
    };
    let requirement = value("--requirement");
    let report = match (value("--report"), value("--app")) {
        (Some(file), _) => Some(PathBuf::from(file)),
        (None, Some(app)) => {
            Some(sv_scan::ecosystems::default_report_dir_in(Path::new(app)).join("report.json"))
        }
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
            "There is no stackvet.toml yet, so every rule is included. Run `sv rules` again once \
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
    sv_manifest::locate_or_bail(&app_dir)?;
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
    let manifest = Manifest::load_in(&app_dir)?.0;

    println!("Starting {} behind the network fence…", manifest.app.name);
    let requests = RunPlan::from_manifest(&manifest, &app_dir)
        .map(|plan| anonymous_requests(&plan))
        .unwrap_or_default();
    if slow {
        println!(
            "With --slow: this waits out the session timeouts stackvet.toml states, and ten \
             minutes before using an emailed sign-in code, so it can take as long as they are."
        );
    }
    match probe_the_running_app(&manifest, &app_dir, slow) {
        Err((reason, _)) => {
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
            if let Some(container) = outcome.container.sentences() {
                println!("\n{container}");
            }
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

            for (lead, asked) in outcome.asked() {
                if !asked.steps.is_empty() {
                    println!("\nThen, {lead}: {}.", asked.steps.join("; "));
                }
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
                    "\nstackvet.toml declares no test command, so no test evidence was \
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
    // Read before anything else, so a baseline that cannot be read stops the run at once.
    let (baseline, rest) = baseline::Baseline::take(&rest)?;
    let baseline = baseline
        .as_deref()
        .map(baseline::Baseline::load)
        .transpose()?;
    let app_dir = rest
        .first()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    // stackvet.toml is not needed here, and is read when it is there: one the AI coding tool wrote
    // and `sv` cannot read stops the run, as it stops `sv report`. Until 7 October 2026 it was not
    // read at all, so a broken one finished with 0 at a terminal (gap analysis 5.1).
    let manifest = match sv_manifest::locate(&app_dir)? {
        Some(located) => Some(Manifest::load(&located.path)?),
        None => None,
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
        println!("\nIn stackvet.toml, through `sv review`:");
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

    let (status, reasons) = match &baseline {
        None => gaps.status(fail_on, findings.iter().map(|f| f.severity)),
        Some(b) => {
            b.same_app(
                manifest
                    .as_ref()
                    .map(|m| m.app.name.as_str())
                    .filter(|n| !n.is_empty())
                    .unwrap_or("This app"),
            )?;
            let new = findings.iter().filter(|f| !b.holds(f)).count();
            println!(
                "\nCompared with the baseline in {}: {new} of {} finding(s) new since then. Every \
                 finding is listed below either way.",
                b.folder.display(),
                findings.len()
            );
            gaps.status_of(
                fail_on,
                findings.iter().filter(|f| !b.holds(f)).map(|f| f.severity),
                "new finding(s), not in the baseline,",
            )
        }
    };
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
        if baseline.as_ref().is_some_and(|b| b.holds(f)) {
            println!("     also in the baseline: it was there before");
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

/// Whether standard output goes straight into a file, as with `sv init > stackvet.toml`, rather
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
    // The same question, asked of Windows itself: until 9 October 2026 the answer there was always
    // no, so `sv init > stackvet.toml` wrote the instructions into the file too, and every later
    // command refused it (backlog 0120). Rust's `metadata().is_file()` will not do here, since on
    // Windows it counts anything that is not a folder or a link as a file, a pipe included, so an AI
    // coding tool reading through a pipe lost the instructions. `GetFileType` tells a file on disk
    // from a pipe or a console.
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetFileType(handle: *mut std::ffi::c_void) -> u32;
        }
        const FILE_TYPE_DISK: u32 = 1;
        // SAFETY: a plain system call that only reads the handle standard output already holds.
        unsafe { GetFileType(std::io::stdout().as_raw_handle()) == FILE_TYPE_DISK }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// `sv doctor [PATH]`: is everything ready (`sv_cli::doctor`).
fn cmd_doctor(args: &[String]) -> Result<()> {
    let app_dir = args
        .first()
        .map_or_else(|| PathBuf::from("."), PathBuf::from);
    anyhow::ensure!(app_dir.is_dir(), "{} is not a folder", app_dir.display());
    let version = version_line();
    let backend = || sv_run::detect().map(|_| ());
    let asked = sv_cli::doctor::Asked {
        version: &version,
        data: sv_frameworks::data::dir(),
        in_container: sv_cli::connect::in_a_container(),
        backend: &backend,
    };
    let lines = sv_cli::doctor::answers(&app_dir, &asked);
    print!("{}", sv_cli::doctor::text(&app_dir, &lines));
    Ok(())
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
        let folder = sv_frameworks::paths::canonical(folder)
            .with_context(|| format!("finding the folder {}", folder.display()))?;
        let reports = sv_scan::ecosystems::default_report_dir_in(&folder);
        let summary = match std::fs::read_to_string(reports.join("report.json")) {
            Ok(text) => sv_report::dashboard::read(&text),
            Err(_) => Err(format!(
                "there is no report.json in its {} folder yet",
                sv_scan::ecosystems::DEFAULT_REPORT_DIR
            )),
        };
        let report_html = reports.join("report.html");
        let (runs, unread_runs) = history::runs(&folder);
        apps.push(sv_report::dashboard::App {
            report_html: report_html.is_file().then_some(report_html),
            runs,
            unread_runs,
            folder,
            summary,
        });
    }

    // Where it writes: a file of its own, beside nothing of the apps'.
    let parent = match out.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let parent = sv_frameworks::paths::canonical(&parent)
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

    // What stackvet.toml says is not the app (examples, test fixtures) is compared too, listed apart,
    // and still counted, as every finding in those folders is (DESIGN, "Folders the manifest says are
    // not the app"): stackvet.toml is written by the AI coding tool, and a line in it that stopped a
    // vulnerability counting would hide one by naming the folder it is in.
    let manifest = match sv_manifest::locate(&app_dir)? {
        Some(located) => Some(Manifest::load(&located.path)?),
        None => None,
    };
    let folders = manifest
        .as_ref()
        .map(|m| m.not_the_app().0)
        .unwrap_or_default();
    let listing = sv_scan::files::Listing::of(&app_dir);
    // A list that would set apart all the app's code is not used, as in every other command (ADR-031).
    let (folders, refused, _) = sv_scan::not_the_app_in(&listing, &folders);
    if let Some(why) = refused {
        println!("stackvet.toml's `[repository] not-the-app` is not used: {why}.\n");
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
                "\n  To judge them, write your time frames in stackvet.toml:\n\n    \
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

/// What `sv audit` found in folders stackvet.toml says are not the app, listed after the app's own,
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
        "\nIn folders stackvet.toml says are not the app ({named}), listed apart and counted all the \
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
        ..
    } = parse_report_args(args, "a file name ending in .zip")?;
    if !app_dir.is_dir() {
        bail!("{} is not a folder", app_dir.display());
    }
    let app_abs = sv_frameworks::paths::canonical(&app_dir)
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
            .join(format!("{folder}-{}", sv_frameworks::names::BUNDLE_SUFFIX)),
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
    /// With --tools, keep each tool's own report in `seen.json` (`sv report` only).
    keep_tool_output: bool,
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
        keep_tool_output: false,
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
            "--keep-tool-output" => parsed.keep_tool_output = true,
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

/// `sv report`, and, when history is on, a record of a run that failed or was stopped with Ctrl-C
/// before it wrote its report, so the dashboard does not show the last report as current (ADR-083,
/// part 2). A command line that names no app folder is not a run, and leaves no record.
fn cmd_report(args: &[String]) -> Result<i32> {
    let started = std::time::SystemTime::now();
    let mut app_seen = None;
    let result = report_command(args, started, &mut app_seen);
    if let (Err(_), Some(app)) = (&result, &app_seen) {
        keep_unfinished(
            app,
            started,
            sv_report::dashboard::Outcome::Failed,
            exit::FAILED,
        );
    }
    result
}

/// Keeps the record of a run that did not finish, when history is on; a failure to keep it is said,
/// never in place of what stopped the run.
fn keep_unfinished(
    app: &Path,
    started: std::time::SystemTime,
    outcome: sv_report::dashboard::Outcome,
    code: i32,
) {
    let run = sv_report::dashboard::Run::unfinished(
        &report_lock::run_record(started, b""),
        sv_report::MadeBy {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            commit: env!("SV_GIT_COMMIT").to_owned(),
        }
        .describe(),
        outcome,
        code,
    );
    if let Err(e) = history::keep(app, &run) {
        eprintln!("History is on, and this run's record could not be kept: {e:#}");
    }
}

fn report_command(
    args: &[String],
    started: std::time::SystemTime,
    app_seen: &mut Option<PathBuf>,
) -> Result<i32> {
    let (fail_on, args) = exit::FailOn::take(args)?;
    // Read before the run, and before this run's report is written: the baseline may be the very
    // folder it is written into.
    let (baseline, args) = baseline::Baseline::take(&args)?;
    let baseline = baseline
        .as_deref()
        .map(baseline::Baseline::load)
        .transpose()?;
    let args = &args[..];
    let ReportArgs {
        app_dir,
        out,
        run_the_app,
        slow,
        run_tools,
        keep_tool_output,
        advisories_dir,
    } = parse_report_args(args, "a directory")?;
    if keep_tool_output && !run_tools {
        bail!("--keep-tool-output keeps what the tools wrote, so it needs --tools as well");
    }
    *app_seen = Some(app_dir.clone());
    {
        let app = app_dir.clone();
        exit::on_interrupt(Box::new(move || {
            keep_unfinished(
                &app,
                started,
                sv_report::dashboard::Outcome::Stopped,
                exit::INTERRUPTED,
            )
        }));
    }
    let advisories_given = advisories_dir.is_some();
    // Loaded before the report and kept after it, so the exit status is decided from the same
    // reading of `adapters.json` the report was made from.
    let loaded = Loaded::load()?;
    let out_dir = out.unwrap_or_else(|| sv_scan::ecosystems::default_report_dir_in(&app_dir));
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
            // Each stage as it starts, on stderr, so a long run is seen to be moving and the
            // report on stdout is left alone (backlog 226, part 2, item 15).
            let mut report = assemble_report_saying(
                &app_dir,
                &ReportOptions {
                    keep_tool_output,
                    ..ReportOptions::asked_of(
                        "`sv report`",
                        run_the_app,
                        slow,
                        run_tools,
                        advisories_dir,
                    )
                },
                &loaded,
                &|n, name| eprintln!("{}", sv_cli::assemble::stage_line(n, name)),
            )?;
            if let Some(b) = &baseline {
                b.same_app(&report.app_name)?;
                report.baseline = Some(b.note(&report.findings));
            }
            Ok(report)
        },
        &mut |note| eprintln!("{note}\n"),
    )?;
    let written = written.names();

    let c = &report.counts;
    println!("Wrote {} files to {}:", written.len(), out_dir.display());
    for name in &written {
        println!("  {name}");
    }
    let kept = report.seen.as_ref().map_or(0, |s| s.tool_output.len());
    if keep_tool_output {
        println!(
            "Each outside tool's own report is kept in {} ({kept} of them), with the credentials \
             sv recognized cut out. It quotes the app's code, so share it as you would the code.",
            sv_report::seen::FILE
        );
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
             in stackvet.toml with what you saw {} your word, which nothing here repeated.",
            c.by_hand,
            if c.by_hand == 1 { "is" } else { "are" }
        );
    }
    if c.attested > 0 {
        println!(
            "The {} you answered yes to in the [design] section of stackvet.toml, or confirmed \
             after your AI coding tool did, {} your word about how the app is built, which is the \
             weakest thing this report says: each one is still listed as a test to write.",
            c.attested,
            if c.attested == 1 { "is" } else { "are" }
        );
    }
    if c.stated > 0 {
        println!(
            "The {} your AI coding tool answered yes to or checked by hand in stackvet.toml, or \
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
    let (status, reasons) = match &report.baseline {
        None => gaps.status(fail_on, report.findings.iter().map(|f| f.severity)),
        Some(_) => {
            if let Some(line) = sv_report::baseline_line(&report) {
                println!("{line}");
            }
            gaps.status_of(
                fail_on,
                report
                    .findings
                    .iter()
                    .filter(|f| !report.in_baseline(f))
                    .map(|f| f.severity),
                "new finding(s), not in the baseline,",
            )
        }
    };
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
    // History, when the person keeps it (ADR-057): after the report is written, never instead of it,
    // with what the run ends with (ADR-083, part 2).
    let kept = sv_report::dashboard::Run::of(&report).map(|mut run| {
        run.exit_code = Some(status);
        history::keep(&app_dir, &run)
    });
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_body_goes_to_the_routes_the_manifest_names() {
        // ADR-056: the routes that read a body are where the app's code can be made to fail.
        let example = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/notes-with-users/stackvet.toml");
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
                    sv_check::adapters::NotRunCause::LeftOut,
                ),
                (
                    "codeql-python".into(),
                    "not installed".into(),
                    sv_check::adapters::NotRunCause::NotInstalled,
                ),
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
        // `sv report` writes to `<app>/stackvet-report` unless told otherwise, and an app can ship
        // that name as a link to a folder of the owner's.
        let dir = scratch("folder");
        std::fs::create_dir(dir.join("theirs")).unwrap();
        std::os::unix::fs::symlink(dir.join("theirs"), dir.join("stackvet-report")).unwrap();
        let app =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
        let report = super::assemble_report(
            &app,
            &super::ReportOptions::reading_only("a test"),
            &super::Loaded::load().unwrap(),
        )
        .unwrap();
        let result = write_report_files(&report, &dir.join("stackvet-report"));
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
        for name in ["..stackvet-report.sv-98295", ".report.json.sv-7"] {
            std::fs::write(dir.join(name), "part").unwrap();
        }
        let held =
            claim_report_folder(&dir, "sv report", "give --out", false).expect("sv's own folder");
        assert!(
            dir.join(sv_scan::ecosystems::REPORT_MARKER).is_file(),
            "marked"
        );
        assert!(!dir.join("..stackvet-report.sv-98295").exists(), "cleared");
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
            !theirs.join(".stackvet-report.lock").exists(),
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
