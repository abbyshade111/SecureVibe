//! Running the language's own security tool, and being honest about when it did not run.
//!
//! Four tree-sitter rules across four languages is a start, not a security review. Every ecosystem
//! already has a tool that knows its own traps — bandit, gosec, brakeman — and the useful thing `sv`
//! can do is run it and read the result, rather than re-implement a hundred rules badly in Rust.
//!
//! Three decisions shape this, and each one is a way of not lying:
//!
//! **A tool that is not installed reports *not run*, and says how to install it.** Never a clean
//! pass. This is the entire reason the adapters are a data file with a `Gap` attached rather than a
//! shell script: a script that skips a missing binary produces a report that looks identical to one
//! where the tool ran and found nothing, and the second is the one everybody assumes.
//!
//! **SARIF and nothing else.** Every tool is asked for SARIF 2.1.0. One output parser that is
//! trusted is worth more than five that are nearly right, and a tool that cannot emit SARIF is not
//! listed yet rather than parsed by guesswork.
//!
//! **The tool's rule ids map to requirements one at a time.** Crediting every requirement a tool
//! knows about to every run of it would make one clean bandit run look like an assessment of Python
//! injection, secrets, weak hashing and debug mode at once. A finding whose rule id is not in the
//! map carries no requirement, which is a fair thing to be and is shown as such.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Adapter {
    pub id: String,
    pub name: String,
    /// The language this tool reads, several separated by commas when one tool reads them all the
    /// same way (CodeQL's JavaScript extractor reads TypeScript too), or `*` for one that reads
    /// several and runs a different pack of rules for each.
    pub language: String,
    /// How to ask whether the tool is here at all.
    pub version: Invocation,
    /// A step run before `run`, for a tool that works in two: CodeQL builds a database of the code
    /// and then analyzes it. It writes nothing `sv` reads; if it fails, the tool did not run.
    #[serde(default)]
    pub prepare: Option<Invocation>,
    pub run: Invocation,
    /// What to tell somebody who wants it and does not have it.
    pub install: String,
    #[serde(default)]
    pub note: String,
    /// Run from inside this directory rather than passing it as an argument.
    #[serde(default)]
    pub working_directory: Option<String>,
    /// Whether this tool reaches the network. `sv` itself never does; one that does is named.
    #[serde(default)]
    pub network: bool,
    /// The tool's own rule ids, mapped to what each detects and the requirements it is about.
    #[serde(default)]
    pub rules: BTreeMap<String, MappedRule>,
    /// Files in the app, relative to its folder, that can turn this tool's checks off without its
    /// report saying so, and that it cannot be told to disregard. While one is present a run that
    /// finds nothing is not credited.
    #[serde(default)]
    pub switched_off_by: Vec<String>,
    /// Credit a clean run only with the rules its report says were run. For a tool that runs a
    /// chosen suite rather than every rule it has, the map can know rules the suite left out, and a
    /// clean run is evidence about none of those.
    #[serde(default)]
    pub credit_loaded_only: bool,
    /// Arguments added to `run` only for an app a condition may hold for, put just before its `--`.
    /// Semgrep's AI pack is one: its rules are about code that calls a model, so it is left out of a
    /// run only when the app is known not to use AI. When nobody has said, it runs, because its rules
    /// can only ever find something and on code that calls no model they find nothing.
    #[serde(default)]
    pub conditional_args: Vec<ConditionalArgs>,
    /// Set for every command this adapter starts. Semgrep's is `SEMGREP_ENABLE_VERSION_CHECK=0`,
    /// which stops it asking semgrep.dev whether a newer semgrep is out.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Another program run in this one's place when this one is not installed.
    #[serde(default)]
    pub stand_in: Option<StandIn>,
}

/// A program that reads the same rules and writes the same report as an adapter's own, run when
/// the adapter's own program is not installed: Opengrep for semgrep (DESIGN, "Opengrep in
/// semgrep's place"). Only when it is missing, never when it is here and will not start: that is
/// something for the owner to fix, and working around it quietly would hide it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandIn {
    pub name: String,
    /// Replaces the adapter's command for asking its version and for running it.
    pub command: String,
    /// Arguments the stand-in refuses, left out when it runs. Opengrep stops at `--metrics=off` as
    /// an option it does not know; it has no usage reporting to turn off.
    #[serde(default)]
    pub leave_out: Vec<String>,
}

/// Which program ran when it was a stand-in, and the sentence the report says it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoodIn {
    pub name: String,
    pub why: String,
}

/// Arguments for `run` that apply unless `condition` is known not to hold for the app.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConditionalArgs {
    /// A condition's name as the applicability data writes it: `ai`.
    pub condition: String,
    pub args: Vec<String>,
}

impl Adapter {
    /// `run`'s arguments for an app, leaving out those whose condition is in `not_holding`.
    pub fn run_args(&self, not_holding: &BTreeSet<String>) -> Vec<String> {
        let extra: Vec<String> = self
            .conditional_args
            .iter()
            .filter(|c| !not_holding.contains(&c.condition))
            .flat_map(|c| c.args.iter().cloned())
            .collect();
        let mut args = self.run.args.clone();
        let at = args.iter().position(|a| a == "--").unwrap_or(args.len());
        args.splice(at..at, extra);
        args
    }

    /// This adapter with its stand-in's name and command, and without the arguments it refuses.
    pub fn standing_in(&self) -> Option<Adapter> {
        let other = self.stand_in.as_ref()?;
        let keep = |args: &[String]| -> Vec<String> {
            args.iter()
                .filter(|a| !other.leave_out.contains(a))
                .cloned()
                .collect()
        };
        let mut adapter = self.clone();
        adapter.name = other.name.clone();
        adapter.version.command = other.command.clone();
        adapter.run.command = other.command.clone();
        adapter.run.args = keep(&self.run.args);
        for c in &mut adapter.conditional_args {
            c.args = keep(&c.args);
        }
        adapter.stand_in = None;
        Some(adapter)
    }
}

/// One of a tool's rules: what it detects, and which requirements that is evidence about.
///
/// `what` exists so the citation can be checked. A bare id-to-id mapping gives a guard nothing to
/// compare, and every citation in `adapters.json` was wrong before one existed — `V1.2.1` is output
/// encoding and was cited for SQL injection by seven rules, because nothing ever read the
/// requirement back. `crates/sv-check/tests/citations.rs` now does.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MappedRule {
    /// Plain language, and compared against the requirement's own words by the citation guard.
    pub what: String,
    pub requirements: Vec<String>,
    /// Requirements a finding of this rule is evidence against, and a run that finds nothing is
    /// evidence of nothing about. A pattern can show a control missing without being able to show it
    /// present: no user input reaching a system prompt is not an enforced instruction hierarchy
    /// (AISVS C2.1.6). So these are carried on a finding and never credited by a clean run.
    #[serde(default)]
    pub findings_against: Vec<String>,
    /// The languages the rule is written for, in `sv`'s names, with `*` for any file. Only read for
    /// a tool that covers several languages (`language: "*"`): a clean run of it is evidence only
    /// about rules that were written for a language this app is in.
    #[serde(default)]
    pub languages: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterFile {
    #[serde(rename = "_comment", default)]
    _comment: String,
    adapters: Vec<Adapter>,
}

#[derive(Debug)]
pub struct Adapters {
    adapters: Vec<Adapter>,
}

/// A placeholder in an adapter's arguments that this code knows how to fill.
///
/// `{files}` stands alone and becomes one argument per code file in the app, relative to it, for a
/// tool that decides by itself which files in a folder to skip (see `code_files`). `{scanned}` is
/// where such a tool writes the list of files it read, which is checked against the list it was
/// given.
///
/// `{database}` is a folder for a tool's own working state between `prepare` and `run`, made fresh
/// for each run and removed afterwards.
const PLACEHOLDERS: &[&str] = &["{dir}", "{output}", "{files}", "{scanned}", "{database}"];

/// How much a list of file names may add to a command line. Well inside the smallest limit of the
/// systems this runs on (macOS allows 1 MiB for arguments and environment together).
const MOST_FILE_ARGUMENT_BYTES: usize = 256 * 1024;

impl Adapters {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: AdapterFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        for adapter in &file.adapters {
            // The commands come from this repository rather than from the app, so this is not the
            // last line of defense — but a security tool that can be made to run something else by
            // an edit to a data file would be a poor advertisement, and the check costs nothing.
            for command in [&adapter.version.command, &adapter.run.command]
                .into_iter()
                .chain(adapter.prepare.as_ref().map(|p| &p.command))
                .chain(adapter.stand_in.as_ref().map(|s| &s.command))
            {
                if command.is_empty()
                    || command.contains(['/', '\\', ';', '|', '&', '$', '`', '\n', '\r', ' '])
                {
                    anyhow::bail!(
                        "adapter `{}` names a command that is not a plain program name: {command:?}",
                        adapter.id
                    );
                }
            }
            for arg in adapter
                .run
                .args
                .iter()
                .chain(adapter.prepare.iter().flat_map(|p| &p.args))
            {
                let unknown = arg
                    .match_indices('{')
                    .filter_map(|(i, _)| arg[i..].find('}').map(|j| &arg[i..=i + j]))
                    .find(|p| !PLACEHOLDERS.contains(p));
                if let Some(p) = unknown {
                    anyhow::bail!("adapter `{}` uses an unknown placeholder {p}", adapter.id);
                }
                if arg.contains("{files}") && arg != "{files}" {
                    anyhow::bail!(
                        "adapter `{}` puts {{files}} inside another argument: {arg:?}",
                        adapter.id
                    );
                }
            }
            for (rule_id, rule) in &adapter.rules {
                if let Some(both) = rule
                    .findings_against
                    .iter()
                    .find(|r| rule.requirements.contains(r))
                {
                    anyhow::bail!(
                        "adapter `{}` rule `{rule_id}` names {both} both as credited by a clean run \
                         and as only ever a finding",
                        adapter.id
                    );
                }
            }
            for c in &adapter.conditional_args {
                if sv_frameworks::Condition::from_name(&c.condition).is_none() {
                    anyhow::bail!(
                        "adapter `{}` adds arguments for an unknown condition `{}`",
                        adapter.id,
                        c.condition
                    );
                }
                if c.args.is_empty() || c.args.iter().any(|a| a.contains(['{', '}'])) {
                    anyhow::bail!(
                        "adapter `{}` adds no arguments, or a placeholder, for `{}`",
                        adapter.id,
                        c.condition
                    );
                }
                if !adapter.run.args.iter().any(|a| a == "--") {
                    anyhow::bail!(
                        "adapter `{}` adds arguments for `{}` and has no `--` to put them before",
                        adapter.id,
                        c.condition
                    );
                }
            }
            if let Some(other) = &adapter.stand_in {
                // A stand-in replaces one command; a tool run in two steps has two.
                if adapter.prepare.is_some() {
                    anyhow::bail!(
                        "adapter `{}` has a stand-in and a step before it runs",
                        adapter.id
                    );
                }
                // An argument to leave out that is not there is one the stand-in will be handed
                // after the adapter's arguments are edited, and it will refuse it.
                let all: Vec<&String> = adapter
                    .run
                    .args
                    .iter()
                    .chain(adapter.conditional_args.iter().flat_map(|c| &c.args))
                    .collect();
                if let Some(missing) = other.leave_out.iter().find(|a| !all.contains(a)) {
                    anyhow::bail!(
                        "adapter `{}` leaves {missing:?} out for its stand-in and does not pass it",
                        adapter.id
                    );
                }
            }
            if let Some(name) = adapter
                .env
                .keys()
                .find(|k| k.is_empty() || k.contains(['=', '\0']))
            {
                anyhow::bail!(
                    "adapter `{}` sets an environment variable with no usable name: {name:?}",
                    adapter.id
                );
            }
            // The file names are relative to the app, so the tool has to be started inside it.
            if adapter.run.args.iter().any(|a| a == "{files}")
                && adapter.working_directory.is_none()
            {
                anyhow::bail!(
                    "adapter `{}` is given {{files}} and not run inside the app folder",
                    adapter.id
                );
            }
        }
        Ok(Adapters {
            adapters: file.adapters,
        })
    }

    pub fn all(&self) -> &[Adapter] {
        &self.adapters
    }

    /// The conditions some adapter adds arguments for that are known not to hold for this app, given
    /// how the app answers each (`Some(false)` known not to hold, `None` nobody has settled). Only a
    /// known "no" leaves arguments out: semgrep's AI pack still runs for an app nobody has said
    /// anything about, because its rules can only ever find something.
    pub fn not_holding(
        &self,
        answer: impl Fn(sv_frameworks::Condition) -> Option<bool>,
    ) -> BTreeSet<String> {
        self.adapters
            .iter()
            .flat_map(|a| &a.conditional_args)
            .filter(|c| {
                sv_frameworks::Condition::from_name(&c.condition)
                    .is_some_and(|condition| answer(condition) == Some(false))
            })
            .map(|c| c.condition.clone())
            .collect()
    }

    /// The adapters worth trying for an app containing these languages.
    pub fn for_languages<'a>(&'a self, languages: &[String]) -> Vec<&'a Adapter> {
        self.adapters
            .iter()
            .filter(|a| a.language == "*" || languages.iter().any(|l| a.reads(l)))
            .collect()
    }
}

impl Adapter {
    /// Whether this tool reads a language, by `sv`'s name for it.
    pub fn reads(&self, language: &str) -> bool {
        self.language == "*" || self.language.split(',').any(|l| l.trim() == language)
    }

    /// What the tool reads, in the words a report uses.
    fn subject(&self) -> String {
        if self.language == "*" {
            "code".to_owned()
        } else {
            self.language.replace(',', " and ")
        }
    }
}

/// What happened when an adapter was asked to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// It ran and produced a report. `loaded` is every rule id the report says was run, whether or
    /// not it found anything.
    Ran {
        findings: Vec<Finding>,
        loaded: BTreeSet<String>,
        /// Every way the tool was told to look away from part of the app, in plain words. Empty
        /// is the only state in which finding nothing is evidence of anything.
        looked_away: Vec<String>,
        /// The program that ran, when it was the adapter's stand-in rather than its own.
        stood_in: Option<StoodIn>,
    },
    /// It did not run, and this is why, in words somebody can act on.
    NotRun { why: String },
}

#[derive(Debug, Default)]
pub struct AdapterRun {
    pub findings: Vec<Finding>,
    /// Adapters that were satisfied: they ran over the app and reported nothing.
    pub verified: Vec<Verified>,
    /// Adapter id and why it did not run. Never folded into "found nothing".
    pub not_run: Vec<(String, String)>,
    /// Adapters that ran over everything they read, found something or not.
    pub ran: Vec<String>,
    /// Adapters that ran but were told not to look at part of the app, and what they skipped. One
    /// that also found nothing is in `not_run` as well, as the report has always said it.
    pub partly: Vec<(String, String)>,
    /// Adapters whose stand-in ran in place of their own program, and the sentence saying so.
    pub stood_in: Vec<(String, String)>,
}

/// Whether the tool is here, and whether it works.
///
/// Two different answers with two different remedies, and telling somebody to install a tool they
/// already have is worse than saying nothing. Found by running this: semgrep is installed on the
/// machine that wrote it and cannot start under the sandbox, and the first version of this reported
/// it as missing and told the owner to install it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Presence {
    /// Nothing by that name could be started.
    Missing,
    /// It is here, and asking it for its version did not work.
    Broken {
        detail: String,
    },
    Ready,
}

pub fn presence(adapter: &Adapter) -> Presence {
    let output = Command::new(&adapter.version.command)
        .args(&adapter.version.args)
        .envs(&adapter.env)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    judge_presence(output.ok().map(|out| {
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }))
}

/// What a tool's version command showed: `None` when it could not be started at all, else its exit
/// code and what it wrote to stderr.
///
/// Exit status 127 with nothing said is the shell's "command not found", and is missing, not broken:
/// under amd64 emulation on an ARM Mac, starting a program that does not exist succeeds and the
/// child exits 127, so Semgrep and CodeQL, absent from the image, read as "installed and would not
/// start" until 29 September 2026 (found by the owner's comparison study). A tool that exits 127 and
/// says why (a wrapper whose interpreter is gone) did start, and stays broken with its words.
fn judge_presence(ran: Option<(Option<i32>, String)>) -> Presence {
    let Some((code, stderr)) = ran else {
        return Presence::Missing;
    };
    if code == Some(0) {
        return Presence::Ready;
    }
    let said = stderr.lines().find(|l| !l.trim().is_empty());
    if code == Some(127) && said.is_none() {
        return Presence::Missing;
    }
    let detail = said
        .unwrap_or("it exited with an error and said nothing")
        .trim()
        .chars()
        .take(160)
        .collect();
    Presence::Broken { detail }
}

pub fn is_installed(adapter: &Adapter) -> bool {
    presence(adapter) == Presence::Ready
}

/// Runs one adapter over an app folder.
///
/// Never through a shell. The arguments are passed as a list, so nothing in a path can end the
/// command and start another — and the app folder's path is the one thing here that a stranger
/// might have chosen.
pub fn run_one(adapter: &Adapter, app_dir: &Path, report_path: &Path) -> Outcome {
    run_one_for(adapter, app_dir, report_path, &BTreeSet::new())
}

/// `run_one`, leaving out the conditional arguments whose condition is known not to hold.
pub fn run_one_for(
    adapter: &Adapter,
    app_dir: &Path,
    report_path: &Path,
    not_holding: &BTreeSet<String>,
) -> Outcome {
    run_one_in(
        adapter,
        &sv_scan::files::Listing::of(app_dir),
        report_path,
        not_holding,
    )
}

/// `run_one_for`, with the app's files from a listing already made.
pub fn run_one_in(
    adapter: &Adapter,
    listing: &sv_scan::files::Listing,
    report_path: &Path,
    not_holding: &BTreeSet<String>,
) -> Outcome {
    let app_dir = listing.root.as_path();
    let subject = adapter.subject();
    let own = presence(adapter);
    // Asked only when the adapter's own program is missing, so a stand-in never runs beside it.
    let other = match own {
        Presence::Missing => adapter.standing_in().map(|other| (presence(&other), other)),
        _ => None,
    };
    let (adapter, own, stood_in) = match &other {
        Some((Presence::Ready, other)) => (
            other,
            Presence::Ready,
            Some(StoodIn {
                name: other.name.clone(),
                why: format!(
                    "{} ran in place of {}, which is not installed on this computer.",
                    other.name, adapter.name
                ),
            }),
        ),
        _ => (adapter, own, None),
    };
    let run_args = adapter.run_args(not_holding);
    match own {
        Presence::Ready => {}
        Presence::Missing => {
            let also = match &other {
                Some((Presence::Missing, other)) => format!(
                    " {}, which can run in its place, is not installed either.",
                    other.name
                ),
                Some((Presence::Broken { detail }, other)) => format!(
                    " {}, which can run in its place, is installed and would not start. It said: \
                     {detail}",
                    other.name
                ),
                _ => String::new(),
            };
            return Outcome::NotRun {
                why: format!(
                    "{} is not installed on this computer, so nothing here has checked the \
                     {subject} in this app the way it would have. Install it with `{}` and run \
                     this again.{also}",
                    adapter.name, adapter.install
                ),
            };
        }
        Presence::Broken { detail } => {
            return Outcome::NotRun {
                why: format!(
                    "{} is installed and would not start, so nothing here has checked the \
                     {subject} in this app the way it would have. It said: {detail}",
                    adapter.name
                ),
            };
        }
    }

    let scanned_path = report_path.with_extension("scanned.json");
    let names_files = run_args.iter().any(|a| a == "{files}");
    let lists_scanned = run_args.iter().any(|a| a.contains("{scanned}"));
    // A list left behind by an earlier run would vouch for files this one never read.
    std::fs::remove_file(&scanned_path).ok();
    let files = if names_files {
        code_files_in(listing)
    } else {
        Vec::new()
    };
    if names_files {
        if files.is_empty() {
            return Outcome::NotRun {
                why: format!(
                    "there is no code in this app in a language `sv` reads, so {} was given \
                     nothing to read",
                    adapter.name
                ),
            };
        }
        let bytes: usize = files.iter().map(|f| f.len() + 3).sum();
        if bytes > MOST_FILE_ARGUMENT_BYTES {
            return Outcome::NotRun {
                why: format!(
                    "this app has {} code files, too many to name to {} one by one, and given \
                     the folder instead it leaves some out without saying which",
                    files.len(),
                    adapter.name
                ),
            };
        }
    }

    let database = report_path.with_extension("db");
    // A database left from an earlier run would be analyzed in place of this app's code.
    std::fs::remove_dir_all(&database).ok();
    let fill = |arg: &str| {
        arg.replace("{dir}", &app_dir.to_string_lossy())
            .replace("{output}", &report_path.to_string_lossy())
            .replace("{scanned}", &scanned_path.to_string_lossy())
            .replace("{database}", &database.to_string_lossy())
    };
    if let Some(prepare) = &adapter.prepare {
        let mut command = Command::new(&prepare.command);
        command.args(prepare.args.iter().map(|a| fill(a)));
        command.envs(&adapter.env);
        if adapter.working_directory.is_some() {
            command.current_dir(app_dir);
        }
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::piped());
        let failed = match command.output() {
            Ok(out) if out.status.success() => None,
            Ok(out) => Some(last_line(&String::from_utf8_lossy(&out.stderr))),
            Err(e) => Some(e.to_string()),
        };
        if let Some(detail) = failed {
            std::fs::remove_dir_all(&database).ok();
            return Outcome::NotRun {
                why: format!(
                    "{} could not prepare the {subject} in this app for reading, so it did not \
                     run ({detail})",
                    adapter.name
                ),
            };
        }
    }
    let mut command = Command::new(&adapter.run.command);
    command.envs(&adapter.env);
    for arg in &run_args {
        if arg == "{files}" {
            // `./` as well as the `--` before it in the data: a file called `-x.py` is a file.
            command.args(files.iter().map(|f| format!("./{f}")));
        } else {
            command.arg(fill(arg));
        }
    }
    if adapter.working_directory.is_some() {
        command.current_dir(app_dir);
    }
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::piped());

    let output = command.output();
    std::fs::remove_dir_all(&database).ok();
    let output = match output {
        Ok(output) => output,
        Err(e) => {
            return Outcome::NotRun {
                why: format!("{} could not be started: {e}", adapter.name),
            };
        }
    };

    // A non-zero exit is how most of these tools say "I found something", not "I failed". The report
    // file is the thing that decides: no report means no run, whatever the exit code said.
    let Ok(text) = std::fs::read_to_string(report_path) else {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.lines().next().unwrap_or("no output").trim();
        return Outcome::NotRun {
            why: format!(
                "{} ran and wrote no report, so nothing can be concluded from it either way ({detail})",
                adapter.name
            ),
        };
    };
    let scanned = std::fs::read_to_string(&scanned_path).ok();
    std::fs::remove_file(&scanned_path).ok();
    match parse_sarif_relative_to(adapter, &text, app_dir) {
        Ok(findings) => Outcome::Ran {
            findings,
            loaded: loaded_rules(&text),
            looked_away: {
                let mut reasons = looked_away(adapter, &text, app_dir);
                if lists_scanned {
                    reasons.extend(unread_files(&files, scanned.as_deref()));
                }
                reasons
            },
            stood_in,
        },
        Err(e) => Outcome::NotRun {
            why: format!("{}'s report could not be read: {e}", adapter.name),
        },
    }
}

/// Runs every adapter that suits this app, and records the ones that could not run.
///
/// `not_holding` names the conditions known not to hold for this app (`ai` for an app known not to
/// call a model), whose conditional arguments are left out.
pub fn run_all(
    adapters: &Adapters,
    app_dir: &Path,
    languages: &[String],
    not_holding: &BTreeSet<String>,
    scratch: &Path,
) -> AdapterRun {
    run_all_in(
        adapters,
        &sv_scan::files::Listing::of(app_dir),
        languages,
        not_holding,
        scratch,
    )
}

/// `run_all`, with the app's files from a listing already made.
pub fn run_all_in(
    adapters: &Adapters,
    listing: &sv_scan::files::Listing,
    languages: &[String],
    not_holding: &BTreeSet<String>,
    scratch: &Path,
) -> AdapterRun {
    let mut run = AdapterRun::default();
    for adapter in adapters.for_languages(languages) {
        let report_path = scratch.join(format!("sv-{}.sarif", adapter.id));
        std::fs::remove_file(&report_path).ok();
        match run_one_in(adapter, listing, &report_path, not_holding) {
            Outcome::Ran {
                findings,
                loaded,
                looked_away,
                stood_in,
            } => {
                // The program that ran, in what the report says about it.
                let name = match &stood_in {
                    Some(other) => format!("{} (in place of {})", other.name, adapter.name),
                    None => adapter.name.clone(),
                };
                if let Some(other) = stood_in {
                    run.stood_in.push((adapter.id.clone(), other.why));
                }
                if looked_away.is_empty() {
                    run.ran.push(adapter.id.clone());
                } else {
                    run.partly.push((
                        adapter.id.clone(),
                        format!(
                            "{} was told not to look at part of this app: {}.",
                            name,
                            looked_away.join("; ")
                        ),
                    ));
                }
                if findings.is_empty() && !looked_away.is_empty() {
                    run.not_run.push((
                        adapter.id.clone(),
                        format!(
                            "{} ran and found nothing, but it was told not to look at part of \
                             this app, so finding nothing is not counted as a clean result: {}.",
                            name,
                            looked_away.join("; ")
                        ),
                    ));
                } else if findings.is_empty() {
                    let ids = clean_run_evidence(adapter, &loaded, languages);
                    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
                    if !ids.is_empty() {
                        run.verified.push(Verified::new(
                            &format!("adapter.{}", adapter.id),
                            &ids,
                            format!("{name} over the {} in this app", adapter.subject()),
                        ));
                    }
                }
                run.findings.extend(findings);
            }
            Outcome::NotRun { why } => run.not_run.push((adapter.id.clone(), why)),
        }
        std::fs::remove_file(&report_path).ok();
    }
    run.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    run
}

/// Every way this run was told to look away, in words the owner can act on.
///
/// A line marked `# nosec` makes bandit report nothing about it, and the SARIF it writes then holds
/// an empty list of results beside a count of the lines it skipped. Crediting that as clean is the
/// missing-tool mistake one layer in: a tool that did not look reads exactly like one that looked
/// and found nothing. Where a tool can be made to look anyway, `adapters.json` asks it to, and
/// what it finds under a suppression is reported like anything else; this is for what is left.
pub fn looked_away(adapter: &Adapter, sarif: &str, app_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(document) = serde_json::from_str::<serde_json::Value>(sarif) {
        let (mut lines, mut tests) = (0, 0);
        for run in document["runs"].as_array().into_iter().flatten() {
            let totals = &run["properties"]["metrics"]["_totals"];
            lines += totals["nosec"].as_u64().unwrap_or(0);
            tests += totals["skipped_tests"].as_u64().unwrap_or(0);
        }
        if lines > 0 {
            out.push(format!(
                "{lines} line{} marked `# nosec`, which it skipped entirely",
                if lines == 1 { " is" } else { "s are" }
            ));
        }
        // CodeQL counts the lines of the app's own code it extracted. None at all means it read
        // nothing: a language it was told to read and could not find, or files it skipped.
        let extracted: Vec<u64> = document["runs"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|run| {
                run["properties"]["metricResults"]
                    .as_array()
                    .into_iter()
                    .flatten()
            })
            .filter(|m| {
                m["ruleId"]
                    .as_str()
                    .is_some_and(|id| id.ends_with("/summary/lines-of-user-code"))
            })
            .filter_map(|m| m["value"].as_u64())
            .collect();
        if !extracted.is_empty() && extracted.iter().all(|&n| n == 0) {
            out.push("it found no code of its language in the app to read".to_owned());
        }
        if tests > 0 {
            out.push(format!(
                "{tests} of its checks {} switched off on particular lines with `# nosec` and a \
                 rule id",
                if tests == 1 { "was" } else { "were" }
            ));
        }
    }
    for file in &adapter.switched_off_by {
        if app_dir.join(file).exists() {
            out.push(format!(
                "`{file}` can turn its checks off, and its report does not say which ran"
            ));
        }
    }
    out
}

/// The requirements a run that found nothing is evidence about.
///
/// Only the requirements this adapter's rules map to: a tool finding nothing is evidence about what
/// it looks for, not about its whole language. For a tool that reads one language and runs all its
/// rules on it, that is every mapped rule. For one that covers several, it is narrower, twice over:
/// a rule counts only if the report says it was loaded, because the pack that ran is not every rule
/// the map knows, and only if it is written for a language in this app, because a Go rule for
/// zip slip that ran over a Python app has said nothing about the Python.
pub fn clean_run_evidence(
    adapter: &Adapter,
    loaded: &BTreeSet<String>,
    app_languages: &[String],
) -> Vec<String> {
    let counts = |rule_id: &str, rule: &MappedRule| {
        let ran =
            !(adapter.language == "*" || adapter.credit_loaded_only) || loaded.contains(rule_id);
        let for_this_app = adapter.language != "*"
            || rule
                .languages
                .iter()
                .any(|l| l == "*" || app_languages.iter().any(|a| a == l));
        ran && for_this_app
    };
    let ids: BTreeSet<String> = adapter
        .rules
        .iter()
        .filter(|(id, rule)| counts(id, rule))
        .flat_map(|(_, rule)| rule.requirements.iter().cloned())
        .collect();
    ids.into_iter().collect()
}

/// Every rule id a SARIF report says was run, found or not.
pub fn loaded_rules(text: &str) -> BTreeSet<String> {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(text) else {
        return BTreeSet::new();
    };
    document["runs"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|run| {
            run["tool"]["driver"]["rules"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(|rule| rule["id"].as_str().map(str::to_owned))
        .collect()
}

/// The app's code files, relative to its folder: every file outside `SKIP_DIRS` whose extension is a
/// language `sv` knows. The same folders `sv`'s own reading leaves out, and no others.
///
/// Given a folder, semgrep 1.178.0 also leaves out `tests/` and `test/`, anything `.gitignore`
/// covers, and whatever the app's own `.semgrepignore` names, and says nothing about any of it in
/// its SARIF. Given file names, it reads them all. So a tool that is handed this list reads what
/// `sv` counts as the app, and what the app says about ignoring does not decide it.
pub fn code_files(app_dir: &Path) -> Vec<String> {
    code_files_in(&sv_scan::files::Listing::of(app_dir))
}

/// `code_files`, from a listing already made. The listing never follows a link, which is what this
/// walk refused on its own before there was one walk.
pub fn code_files_in(listing: &sv_scan::files::Listing) -> Vec<String> {
    let mut out: Vec<String> = listing.code_files().map(|e| e.relative.clone()).collect();
    out.sort();
    out
}

/// Which of the files a tool was given it did not read, as a reason not to credit its clean run.
///
/// `scanned` is the tool's own list (semgrep's `--json-output`, `paths.scanned`). No list at all is a
/// reason too: a tool that does not say what it read has not shown it read anything.
pub fn unread_files(given: &[String], scanned: Option<&str>) -> Option<String> {
    let Some(document) = scanned.and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
    else {
        return Some("it did not write the list of files it read".to_owned());
    };
    let Some(list) = document["paths"]["scanned"].as_array() else {
        return Some("the list of files it wrote does not say which it read".to_owned());
    };
    let read: BTreeSet<&str> = list
        .iter()
        .filter_map(|p| p.as_str())
        .map(|p| p.trim_start_matches("./"))
        .collect();
    let unread: Vec<&str> = given
        .iter()
        .map(String::as_str)
        .filter(|f| !read.contains(f))
        .collect();
    if unread.is_empty() {
        return None;
    }
    let shown: Vec<String> = unread.iter().take(5).map(|f| format!("`{f}`")).collect();
    Some(format!(
        "it did not read {} of the {} code files it was given ({}{})",
        unread.len(),
        given.len(),
        shown.join(", "),
        if unread.len() > shown.len() {
            ", and others"
        } else {
            ""
        }
    ))
}

/// Reads a SARIF 2.1.0 document into findings.
pub fn parse_sarif(adapter: &Adapter, text: &str) -> Result<Vec<Finding>> {
    parse_sarif_relative_to(adapter, text, Path::new(""))
}

/// The same, with paths made relative to the app folder.
///
/// Tools report where *they* looked, which is an absolute path when they were given one. `sv`'s own
/// findings are relative, and a report is something an owner may send to somebody else — the layout
/// of their home directory is not part of what they meant to share.
pub fn parse_sarif_relative_to(
    adapter: &Adapter,
    text: &str,
    app_dir: &Path,
) -> Result<Vec<Finding>> {
    let document: serde_json::Value =
        serde_json::from_str(text).context("the report is not JSON")?;
    let runs = document["runs"]
        .as_array()
        .context("the report has no `runs`")?;
    let mut out = Vec::new();
    for run in runs {
        // A tool's rule metadata, for the text a result does not carry itself.
        let mut help: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
        let mut rule_meta: BTreeMap<&str, &serde_json::Value> = BTreeMap::new();
        if let Some(rules) = run["tool"]["driver"]["rules"].as_array() {
            for rule in rules {
                let Some(id) = rule["id"].as_str() else {
                    continue;
                };
                let short = rule["shortDescription"]["text"].as_str().unwrap_or("");
                let full = rule["fullDescription"]["text"]
                    .as_str()
                    .or_else(|| rule["help"]["text"].as_str())
                    .unwrap_or("");
                help.insert(id, (short, full));
                rule_meta.insert(id, rule);
            }
        }
        let Some(results) = run["results"].as_array() else {
            continue;
        };
        for result in results {
            let rule_id = result["ruleId"].as_str().unwrap_or("").to_owned();
            let message = result["message"]["text"].as_str().unwrap_or("").trim();
            let location = &result["locations"][0]["physicalLocation"];
            let file = location["artifactLocation"]["uri"]
                .as_str()
                .unwrap_or("(unknown file)")
                .trim_start_matches("file://")
                .to_owned();
            let line = location["region"]["startLine"].as_u64().unwrap_or(1) as usize;
            let file = relative_to(&file, app_dir);
            let (short, full) = help.get(rule_id.as_str()).copied().unwrap_or(("", ""));
            let requirement_ids = adapter
                .rules
                .get(&rule_id)
                .map(|r| {
                    r.requirements
                        .iter()
                        .chain(&r.findings_against)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            out.push(Finding {
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                marked_test_code: false,
                rule_id: format!("{}.{}", adapter.id, rule_id),
                title: if short.is_empty() {
                    format!("{} reported {rule_id}", adapter.name)
                } else {
                    short.to_owned()
                },
                severity: rule_meta
                    .get(rule_id.as_str())
                    .and_then(|rule| scored_severity(rule))
                    .unwrap_or_else(|| {
                        severity_of(
                            result["level"]
                                .as_str()
                                .or_else(|| {
                                    rule_meta.get(rule_id.as_str()).and_then(|rule| {
                                        rule["defaultConfiguration"]["level"].as_str()
                                    })
                                })
                                .unwrap_or("warning"),
                        )
                    }),
                // Somebody else's rule fired. `sv` did not decide it was right, and saying so is
                // more useful than a confidence this code is in no position to judge.
                confidence: Confidence::Medium,
                location: Location { file, line },
                secret: None,
                requirement_ids,
                cwe: {
                    let own = cwes_of(result);
                    if own.is_empty() {
                        rule_meta
                            .get(rule_id.as_str())
                            .map(|rule| cwes_of(rule))
                            .unwrap_or_default()
                    } else {
                        own
                    }
                },
                description: {
                    let said = if message.is_empty() { full } else { message };
                    match suppressed_by(result) {
                        Some(how) => format!(
                            "{said}\n\nThis one is marked to be ignored ({how}), so {} would \
                             not normally show it. It is shown here because a finding somebody \
                             chose to hide is still a finding until somebody has looked at why.",
                            adapter.name
                        ),
                        None => said.to_owned(),
                    }
                },
                impact: format!(
                    "Reported by {}, which reads {} the way its own community has learned to.",
                    adapter.name,
                    adapter.subject()
                ),
                fix: if full.is_empty() {
                    format!("See {}'s documentation for rule {rule_id}.", adapter.name)
                } else {
                    full.to_owned()
                },
            });
        }
    }
    Ok(out)
}

/// How a result was suppressed, when the tool says it was.
///
/// SARIF records a suppression on the result rather than dropping it: semgrep does this for
/// `// nosemgrep`, gosec for `#nosec` when asked to track them, and Brakeman for a warning listed in
/// `config/brakeman.ignore`, which it names as the location.
fn suppressed_by(result: &serde_json::Value) -> Option<String> {
    let first = result["suppressions"].as_array()?.first()?;
    let place = first["location"]["physicalLocation"]["artifactLocation"]["uri"].as_str();
    Some(match (first["kind"].as_str(), place) {
        (_, Some(file)) => format!("in `{file}`"),
        (Some("inSource"), None) => "by a comment on the line".to_owned(),
        _ => "outside the code".to_owned(),
    })
}

/// Strips the app folder from a path a tool reported, leaving it as the owner would name it.
fn relative_to(file: &str, app_dir: &Path) -> String {
    if app_dir.as_os_str().is_empty() {
        return file.to_owned();
    }
    // The folder as it was given, then cleaned of `.` parts and trailing separators, then as the
    // system resolves it: a tool may echo any of the three. `sv report app/.` left every Bandit
    // path absolute until 29 September 2026, because Bandit wrote `…/app/backend/x.py`, which
    // `…/app/.` is not a prefix of, and the fingerprints then differed from a scan of `app`.
    let cleaned = clean_folder(app_dir);
    let canonical = std::fs::canonicalize(app_dir).ok();
    for prefix in [Some(app_dir.to_path_buf()), Some(cleaned), canonical]
        .into_iter()
        .flatten()
    {
        let prefix = prefix.to_string_lossy().into_owned();
        if prefix.is_empty() {
            continue;
        }
        // Only when the prefix really matched, and ended at a separator. Trimming the separator
        // unconditionally turned `/elsewhere/lib.py` into `elsewhere/lib.py` for an app somewhere
        // else entirely — a path that looks relative, is not, and points at nothing.
        let Some(rest) = file.strip_prefix(prefix.as_str()) else {
            continue;
        };
        if !(rest.is_empty() || rest.starts_with(['/', '\\']) || prefix.ends_with(['/', '\\'])) {
            continue;
        }
        let trimmed = rest.trim_start_matches(['/', '\\']);
        if !trimmed.is_empty() {
            return trimmed.to_owned();
        }
    }
    file.to_owned()
}

/// A folder without its `.` parts or a trailing separator: `app/.` and `./app/` are `app`, and `.`
/// is itself. The one form the command line passes on, so the reports of one folder, however it
/// was typed, are the same report.
pub fn clean_folder(folder: &Path) -> std::path::PathBuf {
    let cleaned: std::path::PathBuf = folder
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    if cleaned.as_os_str().is_empty() {
        std::path::PathBuf::from(".")
    } else {
        cleaned
    }
}

fn severity_of(level: &str) -> Severity {
    match level {
        "error" => Severity::High,
        "warning" => Severity::Medium,
        "note" => Severity::Low,
        _ => Severity::Info,
    }
}

/// The CWE ids in a result's tags, or a rule's: `CWE-79` as most tools write it, or
/// `external/cwe/cwe-079` as CodeQL does, which is read as `CWE-79`.
fn cwes_of(tagged: &serde_json::Value) -> Vec<String> {
    tagged["properties"]["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str())
                .filter_map(|t| {
                    let t = t.strip_prefix("external/cwe/").unwrap_or(t);
                    if t.starts_with("CWE-") {
                        Some(t.to_owned())
                    } else {
                        t.strip_prefix("cwe-")
                            .map(|n| format!("CWE-{}", n.trim_start_matches('0')))
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A rule's own severity score, where the tool gives one: CodeQL's `security-severity`, a CVSS-like
/// number, read on the CVSS bands.
fn scored_severity(rule: &serde_json::Value) -> Option<Severity> {
    let score: f64 = match &rule["properties"]["security-severity"] {
        serde_json::Value::String(s) => s.parse().ok()?,
        serde_json::Value::Number(n) => n.as_f64()?,
        _ => return None,
    };
    Some(match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0 => Severity::Low,
        _ => Severity::Info,
    })
}

fn last_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("it said nothing")
        .trim()
        .chars()
        .take(200)
        .collect()
}

/// Where to put a tool's report while it is being read.
pub fn scratch_dir() -> PathBuf {
    std::env::temp_dir()
}

#[cfg(test)]
mod folder_tests {
    use super::*;

    #[test]
    fn a_path_under_the_app_folder_is_made_relative_however_the_folder_was_typed() {
        let dir = std::env::temp_dir().join(format!("sv-folder-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("backend")).unwrap();
        let abs = dir.display().to_string();
        let file = format!("{abs}/backend/app.py");
        for typed in [
            abs.clone(),
            format!("{abs}/"),
            format!("{abs}/."),
            format!("{abs}/./"),
        ] {
            assert_eq!(
                relative_to(&file, Path::new(&typed)),
                "backend/app.py",
                "{typed}"
            );
        }
        // A tool that echoes the folder as it was given, relative.
        assert_eq!(
            relative_to("./app/backend/x.py", Path::new("./app")),
            "backend/x.py"
        );
        assert_eq!(
            relative_to("app/backend/x.py", Path::new("app/.")),
            "backend/x.py"
        );
        // The controls: a path elsewhere stays as it is, and so does one that only shares the
        // folder's name as the start of a longer one.
        assert_eq!(
            relative_to("/elsewhere/lib.py", Path::new(&abs)),
            "/elsewhere/lib.py"
        );
        let sibling = format!("{abs}-other/x.py");
        assert_eq!(relative_to(&sibling, Path::new(&abs)), sibling);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_folder_is_cleaned_of_its_dots_and_trailing_separator() {
        for (typed, clean) in [
            ("app", "app"),
            ("app/", "app"),
            ("app/.", "app"),
            ("./app", "app"),
            ("./app/./", "app"),
            (".", "."),
            ("./", "."),
            ("/srv/app/.", "/srv/app"),
        ] {
            assert_eq!(clean_folder(Path::new(typed)), Path::new(clean), "{typed}");
        }
    }
}

#[cfg(test)]
mod presence_tests {
    use super::*;

    #[test]
    fn a_silent_127_is_missing_and_one_that_says_why_is_broken() {
        assert_eq!(judge_presence(None), Presence::Missing);
        assert_eq!(
            judge_presence(Some((Some(0), String::new()))),
            Presence::Ready
        );
        assert_eq!(
            judge_presence(Some((Some(127), "\n  \n".into()))),
            Presence::Missing
        );
        assert_eq!(
            judge_presence(Some((
                Some(127),
                "env: 'python3': No such file or directory".into()
            ))),
            Presence::Broken {
                detail: "env: 'python3': No such file or directory".into()
            }
        );
        assert!(matches!(
            judge_presence(Some((Some(1), String::new()))),
            Presence::Broken { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_starts_and_exits_127_in_silence_reads_as_missing() {
        // What emulation does to a program that does not exist, played by a real one.
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sv-presence-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let silent = dir.join("gone");
        std::fs::write(&silent, "#!/bin/sh\nexit 127\n").unwrap();
        std::fs::set_permissions(&silent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let loud = dir.join("broken");
        std::fs::write(
            &loud,
            "#!/bin/sh\necho 'its interpreter is gone' >&2\nexit 127\n",
        )
        .unwrap();
        std::fs::set_permissions(&loud, std::fs::Permissions::from_mode(0o755)).unwrap();
        let adapter = |command: &std::path::Path| {
            let file: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(
                    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("../../data/adapters.json"),
                )
                .unwrap(),
            )
            .unwrap();
            let mut a: Adapter =
                serde_json::from_value(file["adapters"][0].clone()).expect("a real adapter");
            a.version.command = command.display().to_string();
            a.version.args = Vec::new();
            a
        };
        let silent_presence = presence(&adapter(&silent));
        let loud_presence = presence(&adapter(&loud));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(silent_presence, Presence::Missing);
        assert!(
            matches!(loud_presence, Presence::Broken { ref detail } if detail.contains("interpreter")),
            "{loud_presence:?}"
        );
    }
}

#[cfg(all(test, unix))]
mod stand_in_tests {
    //! The stand-in, with each program a script named by its full path, so nothing here depends on
    //! `PATH` (`tests/stand_in.rs` runs the real semgrep entry through it instead). The stand-in
    //! refuses `--refused`, and answers or writes a report only when the adapter's environment
    //! reached it.
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const OTHER: &str = r#"#!/bin/sh
if [ "$1" = --version ]; then
  [ "$SV_TEST_SWITCH" = off ] && exit 0
  echo "the switch did not reach the version question" >&2; exit 1
fi
for a in "$@"; do [ "$a" = --refused ] && { echo "unknown option --refused" >&2; exit 2; }; done
[ "$SV_TEST_SWITCH" = off ] || exit 3
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Other","rules":[{"id":"%s"}]}},"results":[]}]}' "$RULE" > "$1"
"#;

    fn script(dir: &Path, name: &str, text: &str) -> String {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path.display().to_string()
    }

    /// An adapter named Primary whose program is `primary`, with Other standing in, and one of
    /// semgrep's real mapped Python rules so a clean run has something to credit.
    fn adapter(dir: &Path, primary: &str) -> (Adapter, String) {
        let file: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let semgrep = file["adapters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["id"] == "semgrep")
            .unwrap();
        let (rule, mapped) = semgrep["rules"]
            .as_object()
            .unwrap()
            .iter()
            .find(|(_, r)| {
                r["languages"]
                    .as_array()
                    .is_some_and(|l| l.contains(&"python".into()))
                    && r["requirements"].as_array().is_some_and(|q| !q.is_empty())
            })
            .unwrap();
        let other = script(dir, "other", &OTHER.replace("$RULE", rule));
        let adapter = serde_json::from_value(serde_json::json!({
            "id": "primary",
            "name": "Primary",
            "language": "python",
            "version": { "command": primary, "args": ["--version"] },
            "run": { "command": primary, "args": ["--refused", "{output}"] },
            "install": "get primary",
            "env": { "SV_TEST_SWITCH": "off" },
            "stand_in": { "name": "Other", "command": other, "leave_out": ["--refused"] },
            "rules": { rule: mapped },
        }))
        .unwrap();
        (adapter, rule.clone())
    }

    fn run(dir: &Path, adapter: Adapter) -> AdapterRun {
        let app = dir.join("app");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("app.py"), "print(1)\n").unwrap();
        run_all(
            &Adapters {
                adapters: vec![adapter],
            },
            &app,
            &["python".to_owned()],
            &BTreeSet::new(),
            dir,
        )
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sv-stand-in-unit-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_stand_in_runs_in_a_missing_program_s_place_and_is_named() {
        let dir = scratch("missing");
        let (adapter, rule) = adapter(&dir, &dir.join("not-here").display().to_string());
        let outcome = run(&dir, adapter);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(outcome.ran, ["primary"], "{:?}", outcome.not_run);
        assert_eq!(
            outcome.stood_in,
            [(
                "primary".to_owned(),
                "Other ran in place of Primary, which is not installed on this computer."
                    .to_owned()
            )]
        );
        assert_eq!(outcome.verified.len(), 1, "{rule} credited by a clean run");
        let credit = format!("{:?}", outcome.verified[0]);
        assert!(
            credit.contains("Other (in place of Primary) over the python in this app"),
            "{credit}"
        );
    }

    #[test]
    fn a_broken_program_is_reported_and_its_stand_in_left_alone() {
        let dir = scratch("broken");
        let broken = script(
            &dir,
            "broken",
            "#!/bin/sh\necho 'cannot find its libraries' >&2\nexit 1\n",
        );
        let (adapter, _) = adapter(&dir, &broken);
        let outcome = run(&dir, adapter);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            outcome.ran.is_empty() && outcome.stood_in.is_empty(),
            "{outcome:?}"
        );
        let why = &outcome.not_run[0].1;
        assert!(
            why.starts_with("Primary is installed and would not start"),
            "{why}"
        );
        assert!(why.contains("cannot find its libraries"), "{why}");
    }
}
