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
    /// The language this tool reads, or `*` for one that reads several.
    pub language: String,
    /// How to ask whether the tool is here at all.
    pub version: Invocation,
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
const PLACEHOLDERS: &[&str] = &["{dir}", "{output}"];

impl Adapters {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: AdapterFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        for adapter in &file.adapters {
            // The commands come from this repository rather than from the app, so this is not the
            // last line of defence — but a security tool that can be made to run something else by
            // an edit to a data file would be a poor advertisement, and the check costs nothing.
            for command in [&adapter.version.command, &adapter.run.command] {
                if command.is_empty()
                    || command.contains(['/', '\\', ';', '|', '&', '$', '`', '\n', '\r', ' '])
                {
                    anyhow::bail!(
                        "adapter `{}` names a command that is not a plain program name: {command:?}",
                        adapter.id
                    );
                }
            }
            for arg in &adapter.run.args {
                let unknown = arg
                    .match_indices('{')
                    .filter_map(|(i, _)| arg[i..].find('}').map(|j| &arg[i..=i + j]))
                    .find(|p| !PLACEHOLDERS.contains(p));
                if let Some(p) = unknown {
                    anyhow::bail!("adapter `{}` uses an unknown placeholder {p}", adapter.id);
                }
            }
        }
        Ok(Adapters {
            adapters: file.adapters,
        })
    }

    pub fn all(&self) -> &[Adapter] {
        &self.adapters
    }

    /// The adapters worth trying for an app containing these languages.
    pub fn for_languages<'a>(&'a self, languages: &[String]) -> Vec<&'a Adapter> {
        self.adapters
            .iter()
            .filter(|a| a.language == "*" || languages.iter().any(|l| l == &a.language))
            .collect()
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
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    match output {
        Err(_) => Presence::Missing,
        Ok(out) if out.status.success() => Presence::Ready,
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let detail = stderr
                .lines()
                .find(|l| !l.trim().is_empty())
                .unwrap_or("it exited with an error and said nothing")
                .trim()
                .chars()
                .take(160)
                .collect();
            Presence::Broken { detail }
        }
    }
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
    let subject = if adapter.language == "*" {
        "code".to_owned()
    } else {
        adapter.language.clone()
    };
    match presence(adapter) {
        Presence::Ready => {}
        Presence::Missing => {
            return Outcome::NotRun {
                why: format!(
                    "{} is not installed on this computer, so nothing here has checked the \
                     {subject} in this app the way it would have. Install it with `{}` and run \
                     this again.",
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

    let fill = |arg: &str| {
        arg.replace("{dir}", &app_dir.to_string_lossy())
            .replace("{output}", &report_path.to_string_lossy())
    };
    let mut command = Command::new(&adapter.run.command);
    command.args(adapter.run.args.iter().map(|a| fill(a)));
    if adapter.working_directory.is_some() {
        command.current_dir(app_dir);
    }
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::piped());

    let output = match command.output() {
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
    match parse_sarif_relative_to(adapter, &text, app_dir) {
        Ok(findings) => Outcome::Ran {
            findings,
            loaded: loaded_rules(&text),
            looked_away: looked_away(adapter, &text, app_dir),
        },
        Err(e) => Outcome::NotRun {
            why: format!("{}'s report could not be read: {e}", adapter.name),
        },
    }
}

/// Runs every adapter that suits this app, and records the ones that could not run.
pub fn run_all(
    adapters: &Adapters,
    app_dir: &Path,
    languages: &[String],
    scratch: &Path,
) -> AdapterRun {
    let mut run = AdapterRun::default();
    for adapter in adapters.for_languages(languages) {
        let report_path = scratch.join(format!("sv-{}.sarif", adapter.id));
        std::fs::remove_file(&report_path).ok();
        match run_one(adapter, app_dir, &report_path) {
            Outcome::Ran {
                findings,
                loaded,
                looked_away,
            } => {
                if findings.is_empty() && !looked_away.is_empty() {
                    run.not_run.push((
                        adapter.id.clone(),
                        format!(
                            "{} ran and found nothing, but it was told not to look at part of \
                             this app, so finding nothing is not counted as a clean result: {}.",
                            adapter.name,
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
                            format!(
                                "{} over the {} in this app",
                                adapter.name,
                                if adapter.language == "*" {
                                    "code".to_owned()
                                } else {
                                    adapter.language.clone()
                                }
                            ),
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
        adapter.language != "*"
            || (loaded.contains(rule_id)
                && rule
                    .languages
                    .iter()
                    .any(|l| l == "*" || app_languages.iter().any(|a| a == l)))
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
                .map(|r| r.requirements.clone())
                .unwrap_or_default();
            out.push(Finding {
                rule_id: format!("{}.{}", adapter.id, rule_id),
                title: if short.is_empty() {
                    format!("{} reported {rule_id}", adapter.name)
                } else {
                    short.to_owned()
                },
                severity: severity_of(result["level"].as_str().unwrap_or("warning")),
                // Somebody else's rule fired. `sv` did not decide it was right, and saying so is
                // more useful than a confidence this code is in no position to judge.
                confidence: Confidence::Medium,
                location: Location { file, line },
                secret: None,
                requirement_ids,
                cwe: cwes_of(result),
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
                    if adapter.language == "*" {
                        "code"
                    } else {
                        &adapter.language
                    }
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
    let prefix = app_dir.to_string_lossy();
    // Only when the prefix really matched. Trimming the separator unconditionally turned
    // `/elsewhere/lib.py` into `elsewhere/lib.py` for an app somewhere else entirely — a path that
    // looks relative, is not, and points at nothing.
    let Some(rest) = file.strip_prefix(prefix.as_ref()) else {
        return file.to_owned();
    };
    let trimmed = rest.trim_start_matches(['/', '\\']);
    if trimmed.is_empty() {
        file.to_owned()
    } else {
        trimmed.to_owned()
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

fn cwes_of(result: &serde_json::Value) -> Vec<String> {
    result["properties"]["tags"]
        .as_array()
        .map(|tags| {
            tags.iter()
                .filter_map(|t| t.as_str())
                .filter(|t| t.starts_with("CWE-") || t.starts_with("cwe-"))
                .map(|t| t.to_uppercase())
                .collect()
        })
        .unwrap_or_default()
}

/// Where to put a tool's report while it is being read.
pub fn scratch_dir() -> PathBuf {
    std::env::temp_dir()
}
