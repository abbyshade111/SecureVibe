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
use crate::secrets::{SecretRules, redact_text};
use crate::verified::Verified;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use sv_frameworks::paths::Canonical;

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
    /// The same, for one kind of computer (`macos`, `linux`, as Rust names them), where the general
    /// hint fails there: `pip install` is refused by the Python Homebrew installs on a Mac and by recent
    /// Debian and Ubuntu (PEP 668). Each is the middle of a sentence, `run `…``. Given only for a
    /// package checked to exist where it says (`docs/GAP-ANALYSIS.md`, 5.3).
    #[serde(default)]
    pub install_on: BTreeMap<String, String>,
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
    /// How long this tool may run, in seconds, before it is stopped: `TOOL_SECONDS` when not given.
    #[serde(default)]
    pub time_limit_seconds: Option<u64>,
    /// Another program run in this one's place when this one is not installed.
    #[serde(default)]
    pub stand_in: Option<StandIn>,
    /// The exit codes with which this tool says it ran to the end, whether it found something or
    /// not, from its own source. Any other ending (another code, or a signal) is a failure, and its
    /// report is not read: a tool that stopped part way can leave a report that looks clean.
    pub finished_exits: Vec<i32>,
    /// Set for a tool that reads the app's folder for itself and was shown to follow a link in it
    /// to a file outside the app (gosec 2.22.9 and Brakeman 8.1.0, each given a linked `.go` or
    /// `.rb` file, 8 October 2026; CodeQL 2.27.2 did not). `sv`'s own listing never follows a link,
    /// so such a tool is not run over an app that holds one, with the links named, rather than
    /// reading, and quoting into the report, code that is not the app's. A tool handed `{files}`
    /// never needs it: it reads only what it is given.
    #[serde(default)]
    pub follows_links: bool,
    /// Text on a line of the tool's stderr that is followed by the name of a file it read
    /// (gosec's `Checking file: `), for a tool whose report never says what it read. While set, a
    /// code file of the tool's language the log never names was not read, and a run that names
    /// none read nothing; a log longer than `sv` keeps says so instead of guessing.
    #[serde(default)]
    pub read_log_prefix: Option<String>,
    /// Lines on the tool's stderr that mean part of its run did not happen, each with what it
    /// means in words the owner can act on. A run whose stderr holds one is not credited as
    /// clean; its findings still stand.
    #[serde(default)]
    pub unfinished_when: Vec<Unfinished>,
}

/// A line a tool writes when part of its run did not happen, and what it means.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unfinished {
    /// Text a line of its stderr contains.
    pub contains: String,
    /// What that line means, as the report says it.
    pub means: String,
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
    /// The files the rule reads, from its own `paths.include`, when it reads only some: Rails
    /// template rules read `*.erb`, nginx rules `*.conf`. Semgrep applies these to files named on
    /// its command line as well as to a folder, so a rule none of whose files it was handed ran over
    /// nothing, and a clean run is no evidence about it (ADR-018, Later, 7 October 2026). Empty: any
    /// file of its language.
    #[serde(default)]
    pub targets: Vec<String>,
    /// The files it never reads, from its `paths.exclude`.
    #[serde(default)]
    pub skips: Vec<String>,
}

impl MappedRule {
    /// Whether the rule reads this file, a path relative to the app's folder, as its `targets` and
    /// `skips` say.
    pub fn reads(&self, file: &str) -> bool {
        let any = |globs: &[String]| globs.iter().any(|g| path_matches(g, file));
        (self.targets.is_empty() || any(&self.targets)) && !any(&self.skips)
    }
}

/// A semgrep `paths` pattern against a path relative to the app's folder, as gitignore reads one: a
/// pattern with no `/` in it matches the name of the file or of any folder it is in; one with a `/`
/// matches the whole path. `*` and `?` stay within a name, and `**` crosses folders.
pub fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.trim_start_matches('/').trim_end_matches('/');
    if pattern.contains('/') {
        glob(pattern.as_bytes(), path.as_bytes())
    } else {
        path.split('/')
            .any(|name| glob(pattern.as_bytes(), name.as_bytes()))
    }
}

fn glob(p: &[u8], s: &[u8]) -> bool {
    match p {
        [] => s.is_empty(),
        [b'*', b'*', b'/', rest @ ..] => {
            // No folders, or any number of whole ones.
            glob(rest, s)
                || s.iter()
                    .enumerate()
                    .any(|(i, &c)| c == b'/' && glob(rest, &s[i + 1..]))
        }
        [b'*', b'*', rest @ ..] => (0..=s.len()).any(|i| glob(rest, &s[i..])),
        [b'*', rest @ ..] => (0..=s.len())
            .take_while(|&i| i == 0 || s[i - 1] != b'/')
            .any(|i| glob(rest, &s[i..])),
        [b'?', rest @ ..] => s.first().is_some_and(|&c| c != b'/') && glob(rest, &s[1..]),
        [c, rest @ ..] => s.first() == Some(c) && glob(rest, &s[1..]),
    }
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
///
/// `{config}` is an empty settings file `sv` writes for the run, in the tool's private folder, for
/// a tool that otherwise reads one from the app's own folder (Brakeman's `config/brakeman.yml`,
/// which can turn its checks off with no trace in the report). Given a settings file of `sv`'s, the
/// tool reads the app's not at all.
const PLACEHOLDERS: &[&str] = &[
    "{dir}",
    "{output}",
    "{files}",
    "{scanned}",
    "{database}",
    "{config}",
];

/// What `{config}` holds: a settings file with nothing in it, in the shape every YAML reader takes
/// as an empty table.
pub const EMPTY_SETTINGS: &str = "--- {}\n";

/// How much a list of file names may add to a command line. Well inside the smallest limit of the
/// systems this runs on (macOS allows 1 MiB for arguments and environment together).
const MOST_FILE_ARGUMENT_BYTES: usize = 256 * 1024;

impl Adapters {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: AdapterFile = serde_json::from_str(&text)
            .with_context(|| sv_frameworks::data::not_understood(path))?;

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
            // Only a tool given the folder walks it; one handed the files reads what it is given.
            if adapter.follows_links && adapter.run.args.iter().any(|a| a == "{files}") {
                anyhow::bail!(
                    "adapter `{}` is handed {{files}} and says it follows links, which only a tool \
                     given the folder can do",
                    adapter.id
                );
            }
            if adapter
                .read_log_prefix
                .as_deref()
                .is_some_and(|p| p.trim().is_empty())
            {
                anyhow::bail!(
                    "adapter `{}` names an empty prefix for the files its log says it read",
                    adapter.id
                );
            }
            if let Some(line) = adapter
                .unfinished_when
                .iter()
                .find(|u| u.contains.trim().is_empty() || u.means.trim().is_empty())
            {
                anyhow::bail!(
                    "adapter `{}` names a line that means its run did not finish without the text \
                     or the meaning: {line:?}",
                    adapter.id
                );
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
        /// The files it was handed by name, relative to the app's folder; empty when it was given
        /// the folder. A rule that reads only some files is evidence only when one of these is one.
        handed: Vec<String>,
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
    /// Adapters that ran but did not look at all of the app (told not to, or unable to), and why. One
    /// that also found nothing is in `not_run` as well, as the report has always said it.
    pub partly: Vec<(String, String)>,
    /// Adapters whose stand-in ran in place of their own program, and the sentence saying so.
    pub stood_in: Vec<(String, String)>,
    /// Each adapter asked, by id, with what its tool was and how its run went (`ToolRun`).
    pub tools: Vec<(String, ToolRun)>,
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
    presence_of(adapter, Path::new(&adapter.version.command)).0
}

/// `presence`, asking the program at `program` (where `located` found it), with the first line it
/// answered, stdout before stderr, for the report to say which version ran.
fn presence_of(adapter: &Adapter, program: &Path) -> (Presence, Option<String>) {
    let mut command = Command::new(program);
    command.args(&adapter.version.args);
    let limit = adapter
        .time_limit_seconds
        .unwrap_or(VERSION_SECONDS)
        .min(VERSION_SECONDS);
    let ran = finish(
        prepared(&mut command, adapter).stdout(std::process::Stdio::piped()),
        limit,
    );
    let version = ran.as_ref().ok().and_then(|ran| {
        [&ran.stdout, &ran.stderr]
            .into_iter()
            .flat_map(|text| text.lines())
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned)
    });
    let presence = judge_presence(ran.ok().map(|ran| {
        if ran.timed_out {
            (
                None,
                format!(
                    "it did not answer within {} when asked its version",
                    minutes(limit)
                ),
            )
        } else if ran.interrupted {
            (None, STOPPED_WITH_CTRL_C.to_owned())
        } else {
            (ran.code, ran.stderr)
        }
    }));
    (presence, version)
}

/// How long an outside tool may run before it is stopped, unless its entry says otherwise: half an
/// hour. CodeQL builds a database of the code before it reads it, and on a large app that takes
/// minutes; a tool still running after half an hour is stuck, and `sv` would otherwise wait for it
/// for ever (the deep review's improvement 3).
pub const TOOL_SECONDS: u64 = 30 * 60;
/// How long a tool may take to say its version.
const VERSION_SECONDS: u64 = 60;

/// Why a tool did not run, or did not finish, once somebody asked `sv` to stop.
const STOPPED_WITH_CTRL_C: &str = "the run was stopped with Ctrl-C";

/// The owner's environment variables an outside tool is handed, and no others: where programs are,
/// where the home and temporary folders are, the language, a proxy and certificates the computer
/// needs to reach anything, and where Java, Go, and Python keep what they need. Everything else in
/// the owner's environment (keys for services, tokens, settings for other programs) is left out:
/// a tool reading somebody's code needs none of it, and Semgrep, given a token for its service, would
/// use it.
const PASSED_ON: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TMPDIR",
    "TMP",
    "TEMP",
    "XDG_CACHE_HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "JAVA_HOME",
    "GOPATH",
    "GOROOT",
    "GOCACHE",
    "GOMODCACHE",
    "VIRTUAL_ENV",
    // Windows: where the system is, how programs are found, and where the user's folders are.
    "SystemRoot",
    "PATHEXT",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "ComSpec",
];

/// `command` with the environment an outside tool is given: only `PASSED_ON` from the owner's, then
/// `GOTOOLCHAIN=local`, so a Go tool uses the Go installed here rather than fetching and running the
/// one an app's `go.mod` asks for, then the adapter's own settings, and last git's override of the
/// program an app's repository may name (`git::ENV_OVERRIDES`, ADR-032), which no adapter can undo.
fn prepared<'c>(command: &'c mut Command, adapter: &Adapter) -> &'c mut Command {
    command.env_clear();
    for name in PASSED_ON {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("GOTOOLCHAIN", "local");
    command.envs(&adapter.env);
    command.envs(crate::git::ENV_OVERRIDES);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(command, 0);
    command
}

/// A limit as a person says it: "30 minutes", "2 seconds".
fn minutes(seconds: u64) -> String {
    match seconds {
        1 => "1 second".to_owned(),
        s if s < 120 => format!("{s} seconds"),
        s => format!("{} minutes", s / 60),
    }
}

/// What became of a tool run under a time limit.
struct Finished {
    /// Its exit code: `None` when it was stopped by a signal, by the limit, or by Ctrl-C.
    code: Option<i32>,
    stderr: String,
    /// What it wrote to stdout, when stdout was piped: only the version question pipes it, since a
    /// tool's version is its first line there (backlog 226, part 2, item 14).
    stdout: String,
    timed_out: bool,
    /// Stopped, with everything it started, because the person pressed Ctrl-C (`stop_when`).
    interrupted: bool,
}

/// What `sv` says when somebody has asked it to stop: set once, by the program, before any tool
/// runs (`sv` passes `sv_run::interrupted`, whose handler catches Ctrl-C). Until it is set, nothing
/// is asked to stop.
static ASKED_TO_STOP: std::sync::OnceLock<fn() -> bool> = std::sync::OnceLock::new();

/// From here on, a tool still running when `asked` says so is stopped with everything it started,
/// and no other tool is started. A tool leads a process group of its own (`prepared`), so Ctrl-C at
/// the terminal reaches `sv` alone: before this, `sv` ended where it stood and the tool ran on with
/// no limit, its private folder and the report folder's lock left behind (the review of 8 October
/// 2026, item 1).
pub fn stop_when(asked: fn() -> bool) {
    let _ = ASKED_TO_STOP.set(asked);
}

/// Whether somebody has asked `sv` to stop (`stop_when`).
pub fn asked_to_stop() -> bool {
    ASKED_TO_STOP.get().is_some_and(|asked| asked())
}

/// How much of a tool's stderr is kept; the rest is read and let go, so the tool never waits on a
/// full pipe.
const STDERR_KEPT: usize = 64 * 1024;

/// Runs `command`, stopping it, and everything it started, when it has run for `seconds` or when
/// somebody asks `sv` to stop.
fn finish(command: &mut Command, seconds: u64) -> std::io::Result<Finished> {
    finish_unless(command, seconds, &asked_to_stop)
}

/// `finish`, stopping the command early once `asked` says so, and not starting it at all when it
/// already has: every program a tool is (its version, its preparing, its run) starts here, so no
/// tool starts after Ctrl-C.
fn finish_unless(
    command: &mut Command,
    seconds: u64,
    asked: &dyn Fn() -> bool,
) -> std::io::Result<Finished> {
    use std::io::Read;
    if asked() {
        return Ok(Finished {
            code: None,
            stderr: String::new(),
            stdout: String::new(),
            timed_out: false,
            interrupted: true,
        });
    }
    let mut child = command.spawn()?;
    let (sent_out, received_out) = std::sync::mpsc::channel();
    if let Some(mut stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buffer = [0u8; 8192];
            while let Ok(n) = stdout.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let room = STDERR_KEPT.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..n.min(room)]);
            }
            let _ = sent_out.send(kept);
        });
    }
    let (sent, received) = std::sync::mpsc::channel();
    if let Some(mut stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buffer = [0u8; 8192];
            while let Ok(n) = stderr.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                let room = STDERR_KEPT.saturating_sub(kept.len());
                kept.extend_from_slice(&buffer[..n.min(room)]);
            }
            let _ = sent.send(kept);
        });
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let (status, timed_out, interrupted) = loop {
        if let Some(status) = child.try_wait()? {
            break (Some(status), false, false);
        }
        if asked() {
            stop(&mut child);
            break (child.wait().ok(), false, true);
        }
        if std::time::Instant::now() >= deadline {
            stop(&mut child);
            break (child.wait().ok(), true, false);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    // A program the tool started may hold its stderr open after it ends; what came is enough.
    let stderr = received
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_default();
    let stdout = received_out
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap_or_default();
    Ok(Finished {
        code: if timed_out || interrupted {
            None
        } else {
            status.and_then(|s| s.code())
        },
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        timed_out,
        interrupted,
    })
}

/// Stops a tool and every process it started: on Unix it leads a group of its own (`prepared`), and
/// the whole group is stopped, since Semgrep's work is done by a second program it starts.
fn stop(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", "--", &format!("-{}", child.id())])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    let _ = child.kill();
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
    // The whole line: it is cut to length only after the credentials in it are, by `said`, since
    // a value cut short loses the quote that marks where it ends, and with it its redaction.
    let detail = said
        .unwrap_or("it exited with an error and said nothing")
        .trim()
        .to_owned();
    Presence::Broken { detail }
}

pub fn is_installed(adapter: &Adapter) -> bool {
    presence(adapter) == Presence::Ready
}

/// Where the program a command names is, found through `PATH` as the system would find it, and
/// whether it is one `sv` runs over the app.
///
/// An adapter's command is a plain name, and a name is whatever `PATH` says. The tools are started
/// in the app's folder with the owner's `PATH` passed on, and that `PATH` can point into the app: a
/// virtual environment activated there puts `.venv/bin` first, and a relative entry (`.`, or an
/// empty one) names whatever is in the folder a program runs in. Either way `sv report --tools`
/// would run a program the app's author put there, with the owner's rights, in place of the tool
/// (the review of 8 October 2026, item 4). So the program is found here first, and refused when it
/// is inside the app or reachable only through a relative entry.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Located {
    /// At this path, outside the app.
    At(PathBuf),
    /// Nowhere `sv` looks; `presence` then says the tool is not installed.
    Nowhere,
    /// Only through this `PATH` entry, which is relative.
    OnlyRelative(String),
    /// Inside the app's folder (links followed), at this path.
    InsideApp(PathBuf),
}

/// `located`, with `PATH` given rather than read, so it can be tested without changing the
/// process's own.
#[cfg(unix)]
fn located(command: &str, app_dir: &Path, path: Option<&std::ffi::OsStr>) -> Located {
    let app = app_dir
        .canonical()
        .unwrap_or_else(|_| app_dir.to_path_buf());
    let judge = |candidate: &Path| -> Option<Located> {
        if !runnable(candidate) {
            return None;
        }
        let real = candidate
            .canonical()
            .unwrap_or_else(|_| candidate.to_path_buf());
        Some(if real.starts_with(&app) {
            Located::InsideApp(real)
        } else {
            Located::At(real)
        })
    };
    // A path rather than a name is run as it is (the tests name their scripts this way; the data
    // file never does), and judged the same.
    if command.contains(['/', '\\']) {
        return judge(Path::new(command)).unwrap_or(Located::Nowhere);
    }
    let mut relative = None;
    for entry in path.map(std::env::split_paths).into_iter().flatten() {
        if entry.as_os_str().is_empty() || entry.is_relative() {
            // What such an entry names depends on the folder the program is started in, which
            // for most tools is the app's; `sv`'s own is the other possibility.
            if relative.is_none()
                && (runnable(&app_dir.join(&entry).join(command)) || runnable(&entry.join(command)))
            {
                relative = Some(if entry.as_os_str().is_empty() {
                    ".".to_owned()
                } else {
                    entry.display().to_string()
                });
            }
            continue;
        }
        if let Some(found) = judge(&entry.join(command)) {
            return found;
        }
    }
    match relative {
        Some(entry) => Located::OnlyRelative(entry),
        None => Located::Nowhere,
    }
}

/// Not unix: the program is run by name, as before. Windows finds programs through `PATHEXT` as
/// well as `PATH`, which this does not read.
#[cfg(not(unix))]
fn located(command: &str, _app_dir: &Path, _path: Option<&std::ffi::OsStr>) -> Located {
    Located::At(PathBuf::from(command))
}

/// A file somebody may run: the test `execvp` applies.
#[cfg(unix)]
fn runnable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// An adapter's programs, each where `located` found it, or the name as given when it found
/// nothing (so `presence` says the tool is missing, as it always has).
#[derive(Debug, Clone)]
struct Programs {
    version: PathBuf,
    run: PathBuf,
    prepare: Option<PathBuf>,
}

impl Programs {
    /// Or, in words the owner can act on, why this adapter is not run: a program of its is inside
    /// the app, or on `PATH` only through a relative entry.
    fn of(adapter: &Adapter, app_dir: &Path) -> Result<Self, String> {
        let path = std::env::var_os("PATH");
        let find = |command: &str| -> Result<PathBuf, String> {
            match located(command, app_dir, path.as_deref()) {
                Located::At(program) => Ok(program),
                Located::Nowhere => Ok(PathBuf::from(command)),
                Located::OnlyRelative(entry) => Err(format!(
                    "{} is on PATH only through a relative entry (`{entry}`), which `sv` does not \
                     use to find a program: what it names depends on the folder a program happens \
                     to run in, and for the tools that is the app's. Put the folder {} is in on \
                     PATH in full, and run this again.",
                    adapter.name, adapter.name
                )),
                Located::InsideApp(program) => Err(format!(
                    "{} would run from inside the app ({}), and a program the app's folder holds \
                     is not one `sv` runs over it: whoever wrote the app could have put anything \
                     there. Install {} outside the app (to install it, {}), and run this again.",
                    adapter.name,
                    program.display(),
                    adapter.name,
                    adapter.install_hint()
                )),
            }
        };
        Ok(Programs {
            version: find(&adapter.version.command)?,
            run: find(&adapter.run.command)?,
            prepare: adapter
                .prepare
                .as_ref()
                .map(|p| find(&p.command))
                .transpose()?,
        })
    }
}

/// How to install a tool, as the middle of a sentence: a command to type is quoted and introduced,
/// and steps already written in words (CodeQL's download) are left as they are.
impl Adapter {
    /// How to install this tool on the computer `sv` is running on, as the middle of a sentence. In
    /// `sv`'s own container the computer is not the person's, so the general hint is given.
    pub fn install_hint(&self) -> String {
        let here = (std::env::var_os("SV_IN_CONTAINER").is_none()).then_some(std::env::consts::OS);
        self.install_hint_on(here)
    }

    /// How to install this tool on `os` (`macos`, `linux`), or anywhere when `None`.
    pub fn install_hint_on(&self, os: Option<&str>) -> String {
        match os.and_then(|os| self.install_on.get(os)) {
            Some(hint) => hint.clone(),
            None => install_step(&self.install),
        }
    }
}

fn install_step(install: &str) -> String {
    let program = install.split_whitespace().next().unwrap_or("");
    if ["pip", "pip3", "pipx", "go", "gem", "npm", "brew", "cargo"].contains(&program) {
        format!("run `{install}`")
    } else {
        install.to_owned()
    }
}

/// Runs one adapter over an app folder.
///
/// Never through a shell. The arguments are passed as a list, so nothing in a path can end the
/// command and start another — and the app folder's path is the one thing here that a stranger
/// might have chosen.
///
/// Everything the tool said that reaches the result is redacted with `rules`, as `sv`'s own findings
/// are: its findings' text and anything it wrote to stderr (see `redact_tool_text`).
pub fn run_one(
    adapter: &Adapter,
    app_dir: &Path,
    report_path: &Path,
    rules: &SecretRules,
) -> Outcome {
    run_one_for(adapter, app_dir, report_path, &BTreeSet::new(), rules)
}

/// `run_one`, leaving out the conditional arguments whose condition is known not to hold.
pub fn run_one_for(
    adapter: &Adapter,
    app_dir: &Path,
    report_path: &Path,
    not_holding: &BTreeSet<String>,
    rules: &SecretRules,
) -> Outcome {
    run_one_in(
        adapter,
        &sv_scan::files::Listing::of(app_dir),
        report_path,
        not_holding,
        rules,
    )
}

/// `run_one_for`, with the app's files from a listing already made.
pub fn run_one_in(
    adapter: &Adapter,
    listing: &sv_scan::files::Listing,
    report_path: &Path,
    not_holding: &BTreeSet<String>,
    rules: &SecretRules,
) -> Outcome {
    let mut record = ToolRun::default();
    run_one_recorded(
        adapter,
        listing,
        report_path,
        not_holding,
        rules,
        &mut record,
    )
}

/// What one outside tool was and how its run went, for a program reading the report (backlog 226,
/// part 2, item 14): enough to tell two runs apart when a tool's answer changed, and nothing of the
/// app. The arguments are the adapter's own, with `{dir}` and the like left unfilled, so no path
/// of the person's computer is kept; the version line is redacted like anything a tool says.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct ToolRun {
    /// The program that ran: the adapter's own, or the stand-in that ran in its place.
    pub program: String,
    /// The first line it answered when asked its version.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// The arguments it was given, as the adapter writes them.
    pub args: Vec<String>,
    /// Its exit code, when it ran to the end; `None` when it did not run or was stopped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    /// From asking its version to reading its report, in milliseconds.
    pub took_ms: u64,
}

/// `run_one_in`, writing down in `record` which program ran, its version, its arguments, and its
/// exit code, as far as the run got.
fn run_one_recorded(
    adapter: &Adapter,
    listing: &sv_scan::files::Listing,
    report_path: &Path,
    not_holding: &BTreeSet<String>,
    rules: &SecretRules,
    record: &mut ToolRun,
) -> Outcome {
    let app_dir = listing.root.as_path();
    let subject = adapter.subject();
    // Where each program is, before anything is asked of it: one inside the app is never started,
    // not even for its version.
    let programs = match Programs::of(adapter, app_dir) {
        Ok(programs) => programs,
        Err(why) => return Outcome::NotRun { why },
    };
    let (own, own_version) = presence_of(adapter, &programs.version);
    // Asked only when the adapter's own program is missing, so a stand-in never runs beside it.
    let other = match own {
        Presence::Missing => adapter.standing_in().map(|other| {
            let found = Programs::of(&other, app_dir).map(|programs| {
                let (presence, version) = presence_of(&other, &programs.version);
                (presence, programs, version)
            });
            (found, other)
        }),
        _ => None,
    };
    let (adapter, own, stood_in, programs, version) = match &other {
        Some((Ok((Presence::Ready, theirs, their_version)), other)) => (
            other,
            Presence::Ready,
            Some(StoodIn {
                name: other.name.clone(),
                why: format!(
                    "{} ran in place of {}, which is not installed on this computer.",
                    other.name, adapter.name
                ),
            }),
            theirs.clone(),
            their_version.clone(),
        ),
        _ => (adapter, own, None, programs, own_version),
    };
    let run_args = adapter.run_args(not_holding);
    record.program = adapter.name.clone();
    record.version = version.map(|line| said(rules, &line, PRESENCE_CHARS));
    record.args = run_args.clone();
    match own {
        Presence::Ready => {}
        Presence::Missing => {
            let also = match &other {
                Some((Ok((Presence::Missing, _, _)), other)) => format!(
                    " {}, which can run in its place, is not installed either.",
                    other.name
                ),
                Some((Ok((Presence::Broken { detail }, _, _)), other)) => format!(
                    " {}, which can run in its place, is installed and would not start. It said: \
                     {}",
                    other.name,
                    said(rules, detail, PRESENCE_CHARS)
                ),
                // The stand-in is inside the app, or only on a relative PATH entry; `why` names it.
                Some((Err(why), _)) => format!(" {why}"),
                _ => String::new(),
            };
            return Outcome::NotRun {
                why: format!(
                    "{} is not installed on this computer, so nothing here has checked the \
                     {subject} in this app the way it would have. To install it, {}; then run \
                     this again.{also}",
                    adapter.name,
                    adapter.install_hint()
                ),
            };
        }
        Presence::Broken { detail } => {
            return Outcome::NotRun {
                why: format!(
                    "{} is installed and would not start, so nothing here has checked the \
                     {subject} in this app the way it would have. It said: {}",
                    adapter.name,
                    said(rules, &detail, PRESENCE_CHARS)
                ),
            };
        }
    }

    // A tool that walks the folder itself follows a link to wherever it points; `sv` never does,
    // and what is on the other side is not the app's code to read, or to quote into its report.
    if adapter.follows_links && !listing.links.is_empty() {
        let shown: Vec<String> = listing
            .links
            .iter()
            .take(5)
            .map(|l| format!("`{l}`"))
            .collect();
        let more = listing.links.len().saturating_sub(shown.len());
        let one = listing.links.len() == 1;
        return Outcome::NotRun {
            why: format!(
                "{} was not run: it reads the app's folder for itself and follows a link to \
                 wherever it points, which `sv` never does, and this app holds {} link{} ({}{}). \
                 Remove {}, or put a copy of what {} points at in {} place, then run this again.",
                adapter.name,
                listing.links.len(),
                if one { "" } else { "s" },
                shown.join(", "),
                if more > 0 {
                    format!(", and {more} more")
                } else {
                    String::new()
                },
                if one { "it" } else { "them" },
                if one { "it" } else { "each" },
                if one { "its" } else { "their" },
            ),
        };
    }

    let scanned_path = report_path.with_extension("scanned.json");
    let names_files = run_args.iter().any(|a| a == "{files}");
    let lists_scanned = run_args.iter().any(|a| a.contains("{scanned}"));
    // A list left behind by an earlier run would vouch for files this one never read.
    std::fs::remove_file(&scanned_path).ok();
    let files = if names_files {
        handed_files(listing, adapter)
    } else {
        Vec::new()
    };
    if names_files {
        if files.is_empty() {
            return Outcome::NotRun {
                why: if adapter.language == "*" {
                    format!(
                        "there is no code in this app in a language `sv` reads, so {} was given \
                         nothing to read",
                        adapter.name
                    )
                } else {
                    format!(
                        "there is no {} code in this app that `sv` reads, so {} was given nothing \
                         to read",
                        adapter.language, adapter.name
                    )
                },
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
    // The empty settings file, written only for a tool that asks for one. Written now, before the
    // report's place is checked, so a failure to write it is reported as the tool not running.
    let settings = report_path.with_extension("settings.yml");
    let wants_settings = run_args
        .iter()
        .chain(adapter.prepare.iter().flat_map(|p| &p.args))
        .any(|a| a.contains("{config}"));
    if wants_settings && let Err(e) = std::fs::write(&settings, EMPTY_SETTINGS) {
        return Outcome::NotRun {
            why: format!(
                "{} is given a settings file of `sv`'s own so that it reads none from the app, and \
                 that file could not be written ({}): {e}",
                adapter.name,
                settings.display()
            ),
        };
    }
    // Only a report the tool writes in this run is read. One already there, left by an earlier run
    // or put there by somebody else, would be read as this run's.
    std::fs::remove_file(report_path).ok();
    if std::fs::symlink_metadata(report_path).is_ok() {
        return Outcome::NotRun {
            why: format!(
                "something is already at the place {}'s report is written ({}) and could not be \
                 removed, so a report read from there might not be this run's",
                adapter.name,
                report_path.display()
            ),
        };
    }
    let limit = adapter.time_limit_seconds.unwrap_or(TOOL_SECONDS);
    let fill = |arg: &str| {
        arg.replace("{dir}", &app_dir.to_string_lossy())
            .replace("{output}", &report_path.to_string_lossy())
            .replace("{scanned}", &scanned_path.to_string_lossy())
            .replace("{database}", &database.to_string_lossy())
            .replace("{config}", &settings.to_string_lossy())
    };
    if let Some(prepare) = &adapter.prepare {
        let mut command = Command::new(
            programs
                .prepare
                .clone()
                .unwrap_or_else(|| PathBuf::from(&prepare.command)),
        );
        command.args(prepare.args.iter().map(|a| fill(a)));
        if adapter.working_directory.is_some() {
            command.current_dir(app_dir);
        }
        let failed = match finish(prepared(&mut command, adapter), limit) {
            Ok(ran) if ran.timed_out => Some(format!(
                "it was stopped after {}, the most `sv` gives one tool",
                minutes(limit)
            )),
            Ok(ran) if ran.interrupted => Some(STOPPED_WITH_CTRL_C.to_owned()),
            Ok(ran) if ran.code == Some(0) => None,
            Ok(ran) => Some(said(rules, &last_line(&ran.stderr), LINE_CHARS)),
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
    let mut command = Command::new(&programs.run);
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

    let output = finish(prepared(&mut command, adapter), limit);
    std::fs::remove_dir_all(&database).ok();
    std::fs::remove_file(&settings).ok();
    record.exit_code = output.as_ref().ok().and_then(|ran| ran.code);
    let output = match output {
        Ok(output) => output,
        Err(e) => {
            return Outcome::NotRun {
                why: format!("{} could not be started: {e}", adapter.name),
            };
        }
    };
    if output.interrupted {
        std::fs::remove_file(report_path).ok();
        return Outcome::NotRun {
            why: format!(
                "{} was stopped before it finished ({STOPPED_WITH_CTRL_C}), so whatever it had \
                 written is not read",
                adapter.name
            ),
        };
    }
    if output.timed_out {
        std::fs::remove_file(report_path).ok();
        return Outcome::NotRun {
            why: format!(
                "{} was stopped after {}, the most `sv` gives one tool, so whatever it had \
                 written is not read",
                adapter.name,
                minutes(limit)
            ),
        };
    }

    // A non-zero exit is how most of these tools say "I found something", not "I failed", so each
    // adapter names the codes that mean it ran to the end. Any other is a failure, whatever report it
    // left. Gosec says both with 1; for it, the report is what decides.
    let detail = output.stderr.as_str();
    let detail = said(
        rules,
        detail.lines().next().unwrap_or("no output").trim(),
        LINE_CHARS,
    );
    match output.code {
        Some(code) if adapter.finished_exits.contains(&code) => {}
        Some(code) => {
            std::fs::remove_file(report_path).ok();
            return Outcome::NotRun {
                why: format!(
                    "{} stopped with exit code {code}, which it uses for a failure rather than for \
                     finishing, so its report is not read ({detail})",
                    adapter.name
                ),
            };
        }
        None => {
            std::fs::remove_file(report_path).ok();
            return Outcome::NotRun {
                why: format!(
                    "{} was stopped before it finished, so its report is not read ({detail})",
                    adapter.name
                ),
            };
        }
    }
    // A link in the report's place is not a report the tool wrote: it points at a file that was
    // there before.
    let written = std::fs::symlink_metadata(report_path).is_ok_and(|m| m.file_type().is_file());
    let Some(text) = written
        .then(|| std::fs::read_to_string(report_path).ok())
        .flatten()
    else {
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
            findings: {
                let mut findings = without_stored_hashes(findings, listing, rules);
                for finding in &mut findings {
                    redact_tool_text(rules, finding);
                }
                findings
            },
            loaded: loaded_rules(&text),
            looked_away: {
                let mut reasons = looked_away(adapter, &text, app_dir);
                reasons.extend(did_not_finish(rules, &text, app_dir));
                reasons.extend(read_log(adapter, &output.stderr, listing));
                reasons.extend(unfinished(adapter, &output.stderr));
                if lists_scanned {
                    let loaded = loaded_rules(&text);
                    let reads = |file: &str| read_by_a_loaded_rule(adapter, &loaded, file);
                    reasons.extend(unread_files(&files, scanned.as_deref(), &reads));
                }
                reasons
            },
            stood_in,
            handed: files,
        },
        Err(e) => Outcome::NotRun {
            why: format!("{}'s report could not be read: {e}", adapter.name),
        },
    }
}

/// The tools' rules that judge a value written in the code to be a credential, by the start of the
/// rule id as `sv` names it: Semgrep's secret rules (and Opengrep's, which keep semgrep's id),
/// Bandit's three for a password written as a string, and gosec's for a credential. Each fires on a
/// stored hash under a password's name as readily as on the password.
const SECRET_RULES: &[&str] = &[
    "semgrep.generic.secrets.",
    "bandit.B105",
    "bandit.B106",
    "bandit.B107",
    "gosec.G101",
];

/// `findings`, less those of a tool's secret rule on a line that holds a stored password hash and
/// nothing else that could be a credential (`secrets::holds_only_stored_hashes`): the exception
/// `sv`'s own assignment rule makes, so the two agree. A line that cannot be read again keeps its
/// finding, as does every finding of every other rule.
pub fn without_stored_hashes(
    findings: Vec<Finding>,
    listing: &sv_scan::files::Listing,
    rules: &SecretRules,
) -> Vec<Finding> {
    let mut read: BTreeMap<String, Option<String>> = BTreeMap::new();
    findings
        .into_iter()
        .filter(|f| {
            if !SECRET_RULES.iter().any(|p| f.rule_id.starts_with(p)) {
                return true;
            }
            let text = read.entry(f.location.file.clone()).or_insert_with(|| {
                listing
                    .files
                    .iter()
                    .find(|e| e.relative == f.location.file)
                    .and_then(|e| e.read_text().ok())
            });
            let line = text
                .as_deref()
                .and_then(|t| t.lines().nth(f.location.line.saturating_sub(1)));
            !line.is_some_and(|line| {
                crate::secrets::holds_only_stored_hashes(rules, &f.location.file, line)
            })
        })
        .collect()
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
    rules: &SecretRules,
) -> AdapterRun {
    run_all_in(
        adapters,
        &sv_scan::files::Listing::of(app_dir),
        languages,
        not_holding,
        scratch,
        rules,
    )
}

/// `run_all`, with the app's files from a listing already made.
pub fn run_all_in(
    adapters: &Adapters,
    listing: &sv_scan::files::Listing,
    languages: &[String],
    not_holding: &BTreeSet<String>,
    scratch: &Path,
    rules: &SecretRules,
) -> AdapterRun {
    let mut run = AdapterRun::default();
    // The reports go in a folder of this run's own, made new, readable by this user alone, and with
    // a name nobody can guess, never under fixed names in a folder others can write to: there, a
    // file put in place beforehand was read as a tool's report, and two runs read each other's.
    let private = match PrivateFolder::new_in(scratch) {
        Ok(private) => private,
        Err(e) => {
            for adapter in adapters.for_languages(languages) {
                run.not_run.push((
                    adapter.id.clone(),
                    format!(
                        "{} was not run: `sv` could not make a private folder for its report in \
                         {} ({e})",
                        adapter.name,
                        scratch.display()
                    ),
                ));
            }
            return run;
        }
    };
    for adapter in adapters.for_languages(languages) {
        let report_path = private.path().join(format!("{}.sarif", adapter.id));
        let mut record = ToolRun::default();
        let began = std::time::Instant::now();
        let outcome = run_one_recorded(
            adapter,
            listing,
            &report_path,
            not_holding,
            rules,
            &mut record,
        );
        record.took_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX);
        if record.program.is_empty() {
            record.program = adapter.name.clone();
        }
        run.tools.push((adapter.id.clone(), record));
        match outcome {
            Outcome::Ran {
                findings,
                loaded,
                looked_away,
                stood_in,
                handed,
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
                            "{} did not look at all of this app: {}.",
                            name,
                            looked_away.join("; ")
                        ),
                    ));
                }
                if findings.is_empty() && !looked_away.is_empty() {
                    run.not_run.push((
                        adapter.id.clone(),
                        format!(
                            "{} ran and found nothing, but it did not look at all of \
                             this app, so finding nothing is not counted as a clean result: {}.",
                            name,
                            looked_away.join("; ")
                        ),
                    ));
                } else if findings.is_empty() {
                    let ids = clean_run_evidence(adapter, &loaded, languages, &handed);
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
/// zip slip that ran over a Python app has said nothing about the Python. And a rule that reads only
/// some files counts only if the tool was handed one of them (`handed`): a Rails template rule that
/// was loaded over an app with no `.erb` file in what semgrep was given ran over nothing.
pub fn clean_run_evidence(
    adapter: &Adapter,
    loaded: &BTreeSet<String>,
    app_languages: &[String],
    handed: &[String],
) -> Vec<String> {
    let counts = |rule_id: &str, rule: &MappedRule| {
        let ran =
            !(adapter.language == "*" || adapter.credit_loaded_only) || loaded.contains(rule_id);
        let for_this_app = adapter.language != "*"
            || rule
                .languages
                .iter()
                .any(|l| l == "*" || app_languages.iter().any(|a| a == l));
        let over_its_files = (rule.targets.is_empty() && rule.skips.is_empty())
            || handed.iter().any(|f| rule.reads(f));
        ran && for_this_app && over_its_files
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
    code_files_for(listing, "*")
}

/// What a tool is handed by name: the app's code files in the tool's language, and, for a tool of
/// every language, the other files one of its rules in the map names in its `paths.include` too
/// (`*.conf`, `web.config`, `*.tf`). Semgrep reads only the files it is given, so a rule for an
/// nginx configuration ran over nothing until the configuration was handed to it (gap analysis,
/// item 34).
pub fn handed_files(listing: &sv_scan::files::Listing, adapter: &Adapter) -> Vec<String> {
    let mut out = code_files_for(listing, &adapter.language);
    if adapter.language == "*" {
        let named = |file: &str| {
            adapter
                .rules
                .values()
                .any(|r| !r.targets.is_empty() && r.reads(file))
        };
        out.extend(
            listing
                .app_files()
                .filter(|e| e.language.is_none() && named(&e.relative))
                .map(|e| e.relative.clone()),
        );
        out.sort();
        out.dedup();
    }
    out
}

/// The extensions each of Semgrep's parsers reads, in `sv`'s names for the languages, as semgrep
/// 1.180.0 took them when handed a file of each (8 October 2026). Its JavaScript parser reads
/// TypeScript too; neither reads `.mts` or `.cts`. A language not here is one `sv` hands no file in.
const SEMGREP_EXTENSIONS: &[(&str, &[&str])] = &[
    ("python", &["py", "pyi"]),
    ("javascript", &["js", "jsx", "mjs", "cjs", "ts", "tsx"]),
    ("typescript", &["ts", "tsx"]),
    ("java", &["java"]),
    ("kotlin", &["kt", "kts"]),
    ("go", &["go"]),
    ("rust", &["rs"]),
    ("ruby", &["rb"]),
    ("php", &["php"]),
    ("csharp", &["cs"]),
    ("c", &["c", "h"]),
    ("cpp", &["cc", "cpp", "cxx", "h", "hh", "hpp"]),
    ("dart", &["dart"]),
    ("swift", &["swift"]),
    ("shell", &["sh", "bash"]),
    ("html", &["html", "htm"]),
    ("vue", &["vue"]),
];

/// Whether a rule the tool loaded, and that the map knows, reads this file: one of the files its
/// `paths.include` names, or a file its language's parser reads, or, for a rule of any language
/// (Semgrep's `generic` and `regex`), every file. Rules the map does not know are left out: a clean
/// run credits only rules in the map, and none of those is the worse for a file only another rule
/// would have read.
pub fn read_by_a_loaded_rule(adapter: &Adapter, loaded: &BTreeSet<String>, file: &str) -> bool {
    let extension = file
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let parses = |language: &str| {
        language == "*"
            || SEMGREP_EXTENSIONS
                .iter()
                .any(|(l, exts)| *l == language && exts.contains(&extension.as_str()))
    };
    adapter
        .rules
        .iter()
        .filter(|(id, _)| loaded.contains(*id))
        .any(|(_, rule)| {
            rule.reads(file)
                && (!rule.targets.is_empty() || rule.languages.iter().any(|l| parses(l)))
        })
}

/// The code files of one language, or of every language for `*`: what a tool that reads one
/// language is given in place of the folder. `sv`'s own listing has already left out links, folders
/// of installed or built code (`vendor/`, `node_modules/`), and anything it would not read itself
/// (S7 of the deep review: Bandit given the folder followed a link out of the app and read `vendor/`).
pub fn code_files_for(listing: &sv_scan::files::Listing, language: &str) -> Vec<String> {
    let mut out: Vec<String> = listing
        .code_files()
        .filter(|e| language == "*" || e.language == Some(language))
        .map(|e| e.relative.clone())
        .collect();
    out.sort();
    out
}

/// What a tool's own report says about the parts of its run that did not succeed.
///
/// H7 of the deep review: Bandit skipped a file it could not parse, said so in its SARIF
/// (`executionSuccessful` false, and a notification naming the file), and the clean result was
/// credited because nothing read either. An error-level notification, or a run marked unsuccessful,
/// keeps the run from counting as clean; its findings still stand. What a tool says in it is quoted
/// as any line a tool writes is (`said`), every credential redacted, since a tool's message may quote
/// the line it could not read (item 24 of the review of 1 to 4 October).
pub fn did_not_finish(rules: &SecretRules, sarif: &str, app_dir: &Path) -> Vec<String> {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(sarif) else {
        return Vec::new();
    };
    let mut unsuccessful = false;
    let mut errors: Vec<String> = Vec::new();
    for invocation in document["runs"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|run| run["invocations"].as_array().into_iter().flatten())
    {
        if invocation["executionSuccessful"] == serde_json::Value::Bool(false) {
            unsuccessful = true;
        }
        for kind in [
            "toolExecutionNotifications",
            "toolConfigurationNotifications",
        ] {
            for note in invocation[kind].as_array().into_iter().flatten() {
                if note["level"].as_str() != Some("error") {
                    continue;
                }
                let file = note["locations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find_map(|l| l["physicalLocation"]["artifactLocation"]["uri"].as_str())
                    .map(|uri| relative_uri(uri, app_dir));
                let message = note["message"]["text"].as_str().unwrap_or("").trim();
                errors.push(match (file, message.is_empty()) {
                    (Some(file), false) => {
                        format!(
                            "`{file}` ({})",
                            said(rules, first_line(message), LINE_CHARS)
                        )
                    }
                    (Some(file), true) => format!("`{file}`"),
                    (None, false) => said(rules, first_line(message), LINE_CHARS),
                    (None, true) => "an error it did not describe".to_owned(),
                });
            }
        }
    }
    let mut out = Vec::new();
    if !errors.is_empty() {
        let shown: Vec<&str> = errors.iter().take(5).map(String::as_str).collect();
        let more = errors.len().saturating_sub(shown.len());
        out.push(format!(
            "its report names {} problem{} it could not get past: {}{}",
            errors.len(),
            if errors.len() == 1 { "" } else { "s" },
            shown.join("; "),
            if more > 0 {
                format!("; and {more} more")
            } else {
                String::new()
            }
        ));
    } else if unsuccessful {
        out.push("its report says its run did not succeed, without saying why".to_owned());
    }
    out
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or("").trim()
}

/// A SARIF location as a path from the app folder: `file://` taken off, and the folder too.
fn relative_uri(uri: &str, app_dir: &Path) -> String {
    let path = uri.strip_prefix("file://").unwrap_or(uri);
    let dir = app_dir.to_string_lossy();
    path.strip_prefix(dir.as_ref())
        .map(|p| p.trim_start_matches('/'))
        .unwrap_or(path)
        .trim_start_matches("./")
        .to_owned()
}

/// Which of the app's code files in a tool's language its log never says it read, for a tool whose
/// report does not say (`read_log_prefix`): a reason not to credit its clean run, naming them.
///
/// gosec's SARIF names only what it found; its log names each file it checked, and a file it left
/// out (one that uses cgo while the C compiler is kept from running, or a package it could not
/// load) otherwise reads as clean. A file is named as gosec names it, by its full path, and is
/// matched to the listing as any tool's path is (`relative_to`). The log `sv` keeps is capped
/// (`STDERR_KEPT`); a log that reached the cap may have named the rest, and says so rather than
/// counting them unread.
pub fn read_log(adapter: &Adapter, stderr: &str, listing: &sv_scan::files::Listing) -> Vec<String> {
    let Some(prefix) = adapter.read_log_prefix.as_deref() else {
        return Vec::new();
    };
    let expected = code_files_for(listing, &adapter.language);
    if expected.is_empty() {
        return Vec::new();
    }
    if stderr.len() >= STDERR_KEPT {
        return vec![
            "its log was longer than `sv` keeps, so which files it read is not known".to_owned(),
        ];
    }
    let read: BTreeSet<String> = stderr
        .lines()
        .filter_map(|line| line.split_once(prefix))
        .map(|(_, file)| relative_to(file.trim(), &listing.root))
        .collect();
    let unread: Vec<&str> = expected
        .iter()
        .map(String::as_str)
        .filter(|f| !read.contains(*f))
        .collect();
    if unread.is_empty() {
        return Vec::new();
    }
    if unread.len() == expected.len() {
        return vec![format!(
            "its log names none of the {} {} file{} in this app as read",
            expected.len(),
            adapter.language,
            if expected.len() == 1 { "" } else { "s" }
        )];
    }
    let shown: Vec<String> = unread.iter().take(5).map(|f| format!("`{f}`")).collect();
    vec![format!(
        "its log does not say it read {} of the {} {} files in this app ({}{})",
        unread.len(),
        expected.len(),
        adapter.language,
        shown.join(", "),
        if unread.len() > shown.len() {
            ", and others"
        } else {
            ""
        }
    )]
}

/// What a tool's stderr says did not happen (`unfinished_when`), in the words the entry gives it.
pub fn unfinished(adapter: &Adapter, stderr: &str) -> Vec<String> {
    adapter
        .unfinished_when
        .iter()
        .filter(|u| stderr.lines().any(|line| line.contains(&u.contains)))
        .map(|u| u.means.clone())
        .collect()
}

/// Which of the files a tool was given it did not read, as a reason not to credit its clean run.
///
/// `scanned` is the tool's own list (semgrep's `--json-output`, `paths.scanned`). No list at all is a
/// reason too: a tool that does not say what it read has not shown it read anything.
///
/// Only a file `reads` says a rule it loaded reads counts. Semgrep leaves a handed file out of its
/// list, without a word, when no rule it loaded reads it: a `.hbs` page, with no rule for one
/// loaded, was never going to be read, and missing it says nothing about the rules that ran
/// (`read_by_a_loaded_rule`; gap analysis, item 34).
pub fn unread_files(
    given: &[String],
    scanned: Option<&str>,
    reads: &dyn Fn(&str) -> bool,
) -> Option<String> {
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
    let expected: Vec<&str> = given
        .iter()
        .map(String::as_str)
        .filter(|f| reads(f))
        .collect();
    let unread: Vec<&str> = expected
        .iter()
        .copied()
        .filter(|f| !read.contains(f))
        .collect();
    if unread.is_empty() {
        return None;
    }
    let shown: Vec<String> = unread.iter().take(5).map(|f| format!("`{f}`")).collect();
    Some(format!(
        "it did not read {} of the {} files it was given that a rule it loaded reads ({}{})",
        unread.len(),
        expected.len(),
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
            out.push(crate::finding::found(Finding {
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                earlier_fingerprints: Vec::new(),
                marked_test_code: false,
                bundled_library: None,
                outranked: None,
                also_on_this_line: Vec::new(),
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
            }));
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
    let canonical = sv_frameworks::paths::canonical(app_dir).ok();
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

/// The last line a tool wrote, whole: `said` cuts it to length once its credentials are cut.
fn last_line(text: &str) -> String {
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("it said nothing")
        .trim()
        .to_owned()
}

/// How much of a tool's answer to its version question a report quotes.
const PRESENCE_CHARS: usize = 160;
/// How much of a line a tool wrote to stderr a report quotes.
const LINE_CHARS: usize = 200;

/// A line a tool wrote, as a report may quote it: every credential in it redacted, then cut to
/// `most` characters. In that order, because a value cut short loses the quote that marks where
/// it ends, and with it the redaction (deep review S8).
fn said(rules: &SecretRules, line: &str, most: usize) -> String {
    redact_text(rules, line).0.chars().take(most).collect()
}

/// A tool's finding with every credential in its words redacted, the way `redact_text` cuts a failing
/// test's output.
///
/// A tool's message is the tool's, and some quote the value they found: Bandit's B105 says "Possible
/// hardcoded password: '…'" with the password in it. `sv`'s own findings carry a credential only as a
/// `Secret`, redacted when it is made; a tool's came through whole, into every report, the SARIF, the
/// bundle (which had left the file itself out so that the zip carried no secret), and the terminal
/// (deep review S8). The title, description and fix are the tool's text; the impact is `sv`'s, made from
/// the adapter's name, and is redacted too, because a redaction that is not needed costs four
/// characters and one that is missed cannot be taken back.
pub fn redact_tool_text(rules: &SecretRules, finding: &mut Finding) {
    for text in [
        &mut finding.title,
        &mut finding.description,
        &mut finding.impact,
        &mut finding.fix,
    ] {
        *text = redact_text(rules, text).0;
    }
}

/// Where the private folder for the tools' reports is made.
pub fn scratch_dir() -> PathBuf {
    std::env::temp_dir()
}

/// A folder made new for one run, readable and writable by this user alone, with a name nobody can
/// guess, and removed with everything in it when dropped.
#[derive(Debug)]
pub struct PrivateFolder {
    path: PathBuf,
}

impl PrivateFolder {
    pub fn new_in(parent: &Path) -> std::io::Result<Self> {
        use std::hash::{BuildHasher, Hasher};
        let mut last = None;
        for attempt in 0u32..8 {
            // `RandomState` is seeded from the system's randomness, so the name is not the process
            // id and the time, which anyone on the computer can work out.
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            hasher.write_u32(attempt);
            let path = parent.join(format!(
                "sv-tools-{:016x}{:016x}",
                hasher.finish(),
                std::collections::hash_map::RandomState::new()
                    .build_hasher()
                    .finish()
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            // `create`, not `create_all`: it fails on anything already there, a link included, so
            // the folder used is always the one made here.
            match builder.create(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("no free name")))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateFolder {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.path).ok();
    }
}

#[cfg(test)]
mod folder_tests;

#[cfg(test)]
mod presence_tests;

#[cfg(all(test, unix))]
mod stand_in_tests;

#[cfg(all(test, unix))]
mod program_tests;

#[cfg(all(test, unix))]
mod interrupt_tests;

#[cfg(all(test, unix))]
mod fence_tests;
#[cfg(all(test, unix))]
mod tool_run_tests;
