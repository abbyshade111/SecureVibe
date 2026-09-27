//! The app's GitHub Actions workflows, read for what AISVS Appendix C warns about.
//!
//! A workflow is code that runs with the repository's credentials, and the dangerous shapes are few
//! and well known. A workflow started by `pull_request_target` or `workflow_run` runs with the
//! repository's secrets and a token that can write, even when a stranger's pull request started it,
//! so checking out that pull request's code there hands the stranger both (AC.12.1, AC.12.3). A
//! checkout that keeps its token on disk leaves it for whatever runs next in the job (AC.12.2).
//!
//! What a file cannot show is left alone rather than guessed at. Whether a job needs a person's
//! approval before it gets secrets, and whether a private repository sends secrets to pull requests
//! from forks, are repository settings. So AC.12.3 is only ever a finding here, and a clean run is
//! never credited for it.
//!
//! The files are read with tree-sitter's YAML grammar rather than a YAML crate: the established serde
//! one is archived (DESIGN, "pnpm, and a dependency not taken"), and tree-sitter is already how `sv`
//! reads code. Anything a plain reading of the file cannot settle — an anchor, an alias, a tag, a
//! second document, a parse error — leaves the file unread, and an unread workflow credits nothing.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;
use std::path::Path;
use tree_sitter::{Node, Parser};

/// What reading the workflows concluded. The same three answers as every configuration check.
#[derive(Debug, Default)]
pub struct WorkflowReport {
    pub findings: Vec<Finding>,
    pub passed: Vec<Verified>,
    pub not_assessed: Vec<(String, String)>,
}

pub const FORK_CODE: &str = "config.workflow-runs-fork-code";
pub const FORK_SECRETS: &str = "config.workflow-secrets-with-fork-code";
pub const CHECKOUT_TOKEN: &str = "config.workflow-checkout-keeps-token";
pub const TOKEN_PERMISSIONS: &str = "config.workflow-token-permissions";

/// Pipelines of other kinds. While one of these is present, a clean set of GitHub workflows is not a
/// clean pipeline, because part of it was never read.
const OTHER_PIPELINES: &[&str] = &[
    ".gitlab-ci.yml",
    "Jenkinsfile",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    "bitbucket-pipelines.yml",
    ".travis.yml",
    ".buildkite/pipeline.yml",
];

/// Triggers that run with the repository's secrets and a writable token when a pull request from a
/// fork starts them.
const PRIVILEGED_TRIGGERS: &[&str] = &["pull_request_target", "workflow_run"];

/// Ways a workflow names the pull request's own code rather than the repository's. Compared with the
/// text lowered and its spaces taken out, so `${{ github.head_ref }}` and `${{github.head_ref}}` match
/// alike.
const UNTRUSTED_REFS: &[&str] = &[
    "pull_request.head",
    "github.head_ref",
    "workflow_run.head",
    "refs/pull/",
    "merge_commit_sha",
];

/// Commands in a `run:` step that fetch the pull request's code without `actions/checkout`.
const UNTRUSTED_FETCHES: &[&str] = &["ghprcheckout", "refs/pull/", "pull/${{"];

/// A YAML value, as far as a workflow needs one: every scalar keeps the line it is on.
#[derive(Debug, Clone)]
enum Value {
    Scalar(String, usize),
    Seq(Vec<Value>),
    Map(Vec<(String, Value)>),
    Null,
}

impl Value {
    fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn text(&self) -> Option<&str> {
        match self {
            Value::Scalar(s, _) => Some(s),
            _ => None,
        }
    }

    /// The line of the first scalar in this value, for a finding to point at.
    fn line(&self) -> Option<usize> {
        match self {
            Value::Scalar(_, line) => Some(*line),
            Value::Seq(items) => items.iter().find_map(Value::line),
            Value::Map(pairs) => pairs.iter().find_map(|(_, v)| v.line()),
            Value::Null => None,
        }
    }

    /// Every scalar inside this value, keys included.
    fn scalars<'a>(&'a self, keys: bool, out: &mut Vec<&'a str>) {
        match self {
            Value::Scalar(s, _) => out.push(s),
            Value::Seq(items) => items.iter().for_each(|v| v.scalars(keys, out)),
            Value::Map(pairs) => {
                for (k, v) in pairs {
                    if keys {
                        out.push(k);
                    }
                    v.scalars(keys, out);
                }
            }
            Value::Null => {}
        }
    }
}

/// Reads one workflow file into a [`Value`], or says why it could not.
fn parse(source: &str) -> Result<Value, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_yaml::LANGUAGE.into())
        .map_err(|_| "the YAML grammar could not be loaded".to_owned())?;
    let tree = parser
        .parse(source, None)
        .ok_or_else(|| "the file could not be parsed".to_owned())?;
    let root = tree.root_node();
    if root.has_error() {
        return Err("the file is not YAML the grammar can read".to_owned());
    }
    let mut cursor = root.walk();
    let documents: Vec<Node> = root
        .named_children(&mut cursor)
        .filter(|n| n.kind() == "document")
        .collect();
    match documents.as_slice() {
        [] => Ok(Value::Null),
        [one] => {
            let mut cursor = one.walk();
            let content: Vec<Node> = one
                .named_children(&mut cursor)
                .filter(|n| n.kind() != "comment")
                .collect();
            match content.as_slice() {
                [] => Ok(Value::Null),
                [node] => value(*node, source),
                _ => Err("the file holds something besides one document".to_owned()),
            }
        }
        _ => Err("the file holds more than one YAML document".to_owned()),
    }
}

fn value(node: Node, source: &str) -> Result<Value, String> {
    let text = |n: Node| {
        n.utf8_text(source.as_bytes())
            .unwrap_or_default()
            .to_owned()
    };
    let line = node.start_position().row + 1;
    match node.kind() {
        "block_node" | "flow_node" => {
            let mut cursor = node.walk();
            let children: Vec<Node> = node
                .named_children(&mut cursor)
                .filter(|n| n.kind() != "comment")
                .collect();
            if children
                .iter()
                .any(|n| matches!(n.kind(), "anchor" | "tag" | "alias"))
            {
                // An alias makes one value stand for another written elsewhere, and a tag can change
                // what a value means. Following either is where a reading goes wrong quietly.
                return Err("the file uses a YAML anchor, alias, or tag".to_owned());
            }
            match children.as_slice() {
                [] => Ok(Value::Null),
                [inner] => value(*inner, source),
                _ => Err(format!("a value on line {line} could not be read")),
            }
        }
        "block_mapping" | "flow_mapping" => {
            let mut pairs = Vec::new();
            let mut cursor = node.walk();
            for pair in node.named_children(&mut cursor) {
                match pair.kind() {
                    "comment" => {}
                    "block_mapping_pair" | "flow_pair" => {
                        let key = match pair.child_by_field_name("key") {
                            Some(k) => match value(k, source)? {
                                Value::Scalar(s, _) => s,
                                _ => return Err(format!("a key on line {line} is not plain text")),
                            },
                            None => String::new(),
                        };
                        let val = match pair.child_by_field_name("value") {
                            Some(v) => value(v, source)?,
                            None => Value::Null,
                        };
                        pairs.push((key, val));
                    }
                    // A flow mapping entry with a key and no value: `{ push }`.
                    "flow_node" => {
                        if let Value::Scalar(s, _) = value(pair, source)? {
                            pairs.push((s, Value::Null));
                        }
                    }
                    other => return Err(format!("unexpected `{other}` on line {line}")),
                }
            }
            Ok(Value::Map(pairs))
        }
        "block_sequence" | "flow_sequence" => {
            let mut items = Vec::new();
            let mut cursor = node.walk();
            for item in node.named_children(&mut cursor) {
                match item.kind() {
                    "comment" => {}
                    "block_sequence_item" => {
                        let mut inner_cursor = item.walk();
                        let inner: Vec<Node> = item
                            .named_children(&mut inner_cursor)
                            .filter(|n| n.kind() != "comment")
                            .collect();
                        items.push(match inner.as_slice() {
                            [] => Value::Null,
                            [one] => value(*one, source)?,
                            _ => {
                                return Err(format!(
                                    "a list item on line {line} could not be read"
                                ));
                            }
                        });
                    }
                    _ => items.push(value(item, source)?),
                }
            }
            Ok(Value::Seq(items))
        }
        "plain_scalar" => Ok(Value::Scalar(text(node).trim().to_owned(), line)),
        "single_quote_scalar" => {
            let raw = text(node);
            let inner = raw
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(&raw);
            Ok(Value::Scalar(inner.replace("''", "'"), line))
        }
        "double_quote_scalar" => {
            let raw = text(node);
            let inner = raw
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&raw);
            Ok(Value::Scalar(
                inner.replace("\\\"", "\"").replace("\\\\", "\\"),
                line,
            ))
        }
        // `run: |` and `run: >`. Only ever searched for text, so the indicator line is harmless.
        "block_scalar" => Ok(Value::Scalar(text(node), line)),
        other => Err(format!("unexpected `{other}` on line {line}")),
    }
}

/// Lowered, with every space taken out, for comparing expressions however they were spaced.
fn squashed(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

fn names_untrusted_code(text: &str) -> bool {
    let s = squashed(text);
    UNTRUSTED_REFS.iter().any(|p| s.contains(p))
}

/// The events that start a workflow: `on: push`, `on: [push, pull_request]`, or `on:` with a map.
fn triggers(workflow: &Value) -> Vec<String> {
    let Some(on) = workflow.get("on").or_else(|| workflow.get("true")) else {
        return Vec::new();
    };
    match on {
        Value::Scalar(s, _) => vec![s.clone()],
        Value::Seq(items) => items
            .iter()
            .filter_map(|v| v.text().map(str::to_owned))
            .collect(),
        Value::Map(pairs) => pairs.iter().map(|(k, _)| k.clone()).collect(),
        Value::Null => Vec::new(),
    }
}

fn is_checkout(step: &Value) -> bool {
    step.get("uses").and_then(Value::text).is_some_and(|u| {
        u.trim()
            .to_ascii_lowercase()
            .starts_with("actions/checkout@")
    })
}

/// Where a step brings the pull request's code into the job, if it does.
fn untrusted_code_at(step: &Value) -> Option<usize> {
    if is_checkout(step) {
        let with = step.get("with")?;
        for key in ["ref", "repository"] {
            if let Some(v) = with.get(key)
                && v.text().is_some_and(names_untrusted_code)
            {
                return v.line();
            }
        }
        return None;
    }
    let run = step.get("run")?;
    let script = squashed(run.text()?);
    UNTRUSTED_FETCHES
        .iter()
        .any(|p| script.contains(p))
        .then(|| run.line())
        .flatten()
}

/// Whether anything in a job reads a secret other than the job's own token.
fn reads_secrets(job: &Value) -> bool {
    if job
        .get("secrets")
        .and_then(Value::text)
        .is_some_and(|s| s.trim() == "inherit")
    {
        return true;
    }
    let mut all = Vec::new();
    job.scalars(false, &mut all);
    all.iter().any(|s| {
        let s = squashed(s);
        s.match_indices("secrets.")
            .any(|(at, _)| !s[at..].starts_with("secrets.github_token"))
    })
}

fn steps(job: &Value) -> &[Value] {
    match job.get("steps") {
        Some(Value::Seq(items)) => items,
        _ => &[],
    }
}

fn jobs(workflow: &Value) -> Vec<(&str, &Value)> {
    match workflow.get("jobs") {
        Some(Value::Map(pairs)) => pairs.iter().map(|(k, v)| (k.as_str(), v)).collect(),
        _ => Vec::new(),
    }
}

fn finding(
    rule_id: &str,
    title: String,
    severity: Severity,
    location: Location,
    requirement_ids: &[&str],
    cwe: &[&str],
    text: [String; 3],
) -> Finding {
    let [description, impact, fix] = text;
    Finding {
        also_reported_by: Vec::new(),
        rule_id: rule_id.into(),
        title,
        severity,
        confidence: Confidence::High,
        location,
        secret: None,
        requirement_ids: requirement_ids.iter().map(|s| (*s).to_owned()).collect(),
        cwe: cwe.iter().map(|s| (*s).to_owned()).collect(),
        description,
        impact,
        fix,
    }
}

fn at(file: &str, line: usize) -> Location {
    Location {
        file: file.to_owned(),
        line,
    }
}

/// Reads every workflow in `.github/workflows` and reports what it found.
pub fn check(app_dir: &Path) -> WorkflowReport {
    let mut report = WorkflowReport::default();
    let dir = app_dir.join(".github").join("workflows");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        // No workflows: nothing here to read. Whether the app has a pipeline somewhere else is the
        // manifest's question (`ci-cd`), not this check's.
        return report;
    };
    let mut files: Vec<(String, std::path::PathBuf)> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension().is_some_and(|x| {
                    x.eq_ignore_ascii_case("yml") || x.eq_ignore_ascii_case("yaml")
                })
        })
        .map(|p| {
            let name = p.file_name().unwrap_or_default().to_string_lossy();
            (format!(".github/workflows/{name}"), p)
        })
        .collect();
    files.sort();
    if files.is_empty() {
        return report;
    }

    let mut unread = Vec::new();
    let mut privileged = Vec::new();
    let mut checkouts = 0usize;
    let mut kept_token = 0usize;
    for (name, path) in &files {
        let parsed = std::fs::read_to_string(path)
            .map_err(|_| "the file could not be opened".to_owned())
            .and_then(|text| parse(&text));
        let workflow = match parsed {
            Ok(w) => w,
            Err(why) => {
                unread.push(format!("`{name}` ({why})"));
                continue;
            }
        };
        let on = triggers(&workflow);
        let fork_aware: Vec<&str> = PRIVILEGED_TRIGGERS
            .iter()
            .copied()
            .filter(|t| on.iter().any(|o| o == t))
            .collect();
        if !fork_aware.is_empty() {
            privileged.push(name.clone());
        }

        let mut fork_code_at = None;
        let mut secrets_with_fork_code_at = None;
        let mut first_kept_token = None;
        let mut kept_in_file = 0usize;
        for (_, job) in jobs(&workflow) {
            let mut job_runs_fork_code = None;
            for step in steps(job) {
                if is_checkout(step) {
                    checkouts += 1;
                    let off = step
                        .get("with")
                        .and_then(|w| w.get("persist-credentials"))
                        .and_then(Value::text)
                        .is_some_and(|v| v.trim().eq_ignore_ascii_case("false"));
                    if !off {
                        kept_in_file += 1;
                        first_kept_token = first_kept_token.or(step.line());
                    }
                }
                if !fork_aware.is_empty()
                    && let Some(line) = untrusted_code_at(step)
                {
                    job_runs_fork_code = job_runs_fork_code.or(Some(line));
                }
            }
            if let Some(line) = job_runs_fork_code {
                fork_code_at = fork_code_at.or(Some(line));
                if reads_secrets(job) {
                    secrets_with_fork_code_at = secrets_with_fork_code_at.or(Some(line));
                }
            }
        }
        kept_token += kept_in_file;
        let trigger = fork_aware.join("` and `");

        if let Some(line) = fork_code_at {
            report.findings.push(finding(
                FORK_CODE,
                format!("A workflow started by `{trigger}` runs the pull request's own code"),
                Severity::Critical,
                at(name, line),
                &["AC.12.1"],
                &["CWE-829"],
                [
                    format!(
                        "`{name}` is started by `{trigger}`, which runs with this repository's \
                         secrets and a token that can write to it even when a stranger's pull request \
                         started it, and on line {line} it brings in that pull request's code."
                    ),
                    "Anybody who opens a pull request can change what runs here, and what runs \
                     here can push to the repository, publish a release, or send the secrets \
                     anywhere."
                        .into(),
                    "Build and test pull requests in a separate workflow started by `pull_request`, \
                     which gets no secrets and a read-only token. If something privileged has to \
                     follow, pass it only files that workflow produced, and treat them as data."
                        .into(),
                ],
            ));
        }
        if let Some(line) = secrets_with_fork_code_at {
            report.findings.push(finding(
                FORK_SECRETS,
                "Secrets are available to a job that runs a pull request's code".into(),
                Severity::Critical,
                at(name, line),
                &["AC.12.3"],
                &["CWE-200"],
                [
                    format!(
                        "A job in `{name}` brings in the pull request's code (line {line}) and reads \
                         this repository's secrets in the same job."
                    ),
                    "The pull request's code runs where the secrets are, so whoever wrote it can \
                     read them."
                        .into(),
                    "Keep secrets out of any job that runs code from a pull request, and put a job \
                     that needs them behind an environment that requires a person's approval."
                        .into(),
                ],
            ));
        }
        if let Some(line) = first_kept_token {
            report.findings.push(finding(
                CHECKOUT_TOKEN,
                "A checkout leaves its access token on disk for the rest of the job".into(),
                Severity::Medium,
                at(name, line),
                &["AC.12.2"],
                &["CWE-522"],
                [
                    format!(
                        "{} in `{name}` use `actions/checkout` without \
                         `persist-credentials: false`, so the token it used stays in the \
                         checked-out folder's git settings.",
                        if kept_in_file == 1 {
                            "One step".to_owned()
                        } else {
                            format!("{kept_in_file} steps")
                        }
                    ),
                    "Every later step in the job can read that token, including build scripts, \
                     test code, and packages installed from outside, and an AI coding tool's \
                     changes run there too."
                        .into(),
                    "Add `persist-credentials: false` under `with:` on each checkout step. A step \
                     that has to push can pass a token to that one command instead."
                        .into(),
                ],
            ));
        }
        token_permissions(&workflow, name, &mut report);
    }

    let other: Vec<&str> = OTHER_PIPELINES
        .iter()
        .copied()
        .filter(|p| app_dir.join(p).exists())
        .collect();
    let read = files.len() - unread.len();
    let scope = format!(
        "{read} GitHub Actions workflow file{} in .github/workflows",
        if read == 1 { "" } else { "s" }
    );

    // What keeps a clean result from being credited, in the order an owner would fix it.
    let blocked = if !unread.is_empty() {
        Some(format!(
            "`sv` could not read {}, so a clean result for the others is not a clean pipeline.",
            unread.join(", ")
        ))
    } else if !other.is_empty() {
        Some(format!(
            "This app also has {}, which `sv` does not read, so clean GitHub workflows are not a \
             clean pipeline.",
            other
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ))
    } else {
        None
    };

    // AC.12.1: credited only when nothing can start a workflow with the repository's secrets on a
    // stranger's behalf. A privileged trigger with no checkout this recognizes is not clean: an
    // artifact downloaded from the pull request's run is its code too, in another form.
    if !report.findings.iter().any(|f| f.rule_id == FORK_CODE) {
        match &blocked {
            Some(why) => report.not_assessed.push((FORK_CODE.into(), why.clone())),
            None if !privileged.is_empty() => report.not_assessed.push((
                FORK_CODE.into(),
                format!(
                    "{} {} started by `pull_request_target` or `workflow_run`, and `sv` found no \
                     step bringing in the pull request's code. That is not the same as none: a \
                     workflow can also run what it downloads from the pull request's own run, \
                     which `sv` does not follow.",
                    privileged
                        .iter()
                        .map(|p| format!("`{p}`"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if privileged.len() == 1 { "is" } else { "are" }
                ),
            )),
            None => report.passed.push(Verified::new(
                FORK_CODE,
                &["AC.12.1"],
                format!(
                    "{scope}, none started by `pull_request_target` or `workflow_run`; a setting \
                     that sends secrets to pull requests from forks is not in any file"
                ),
            )),
        }
    }

    // AC.12.2: credited only when there is at least one checkout and every one turns the token off.
    // With no checkout there is nothing this reading shows.
    if kept_token == 0 {
        match &blocked {
            Some(why) => report.not_assessed.push((CHECKOUT_TOKEN.into(), why.clone())),
            None if checkouts == 0 => report.passed.push(Verified::new(
                CHECKOUT_TOKEN,
                &[],
                format!("{scope}, none of them checking out the repository"),
            )),
            None => report.passed.push(Verified::new(
                CHECKOUT_TOKEN,
                &["AC.12.2"],
                format!(
                    "{scope}: every checkout sets `persist-credentials: false`; credentials kept on \
                     the runner some other way are not in any file"
                ),
            )),
        }
    }

    // AC.12.3 turns on approvals that are repository settings, so a clean reading credits nothing.
    if !report.findings.iter().any(|f| f.rule_id == FORK_SECRETS) && blocked.is_none() {
        report.passed.push(Verified::new(
            FORK_SECRETS,
            &[],
            format!("{scope}; whether a person must approve a job before it gets secrets is a repository setting"),
        ));
    }
    report
}

/// A workflow whose token can write to everything, or that never says what its token may do.
///
/// Evidence about no requirement. AC.7.4 names `permissions:` blocks, but what it asks is that
/// changes to them get dual control and a security review, which no file shows; the block itself is
/// good practice rather than something a requirement here asks for, and is reported as that.
fn token_permissions(workflow: &Value, name: &str, report: &mut WorkflowReport) {
    let broad = |v: &Value| v.text().is_some_and(|t| t.trim() == "write-all");
    let top = workflow.get("permissions");
    let jobs = jobs(workflow);
    let unset: Vec<&str> = if top.is_some() {
        Vec::new()
    } else {
        jobs.iter()
            .filter(|(_, job)| job.get("permissions").is_none())
            .map(|(id, _)| *id)
            .collect()
    };
    let write_all = top.is_some_and(broad)
        || jobs
            .iter()
            .any(|(_, job)| job.get("permissions").is_some_and(broad));
    if unset.is_empty() && !write_all {
        return;
    }
    let line = top
        .and_then(Value::line)
        .or_else(|| workflow.get("jobs").and_then(Value::line))
        .unwrap_or(1);
    let description = if write_all {
        format!(
            "`{name}` gives its token `write-all`, so every step can change anything in the repository."
        )
    } else {
        format!(
            "`{name}` does not say what its token may do (no `permissions:` for the workflow or for \
             job{} {}), so the token gets the repository's default, which can include writing.",
            if unset.len() == 1 { "" } else { "s" },
            unset
                .iter()
                .map(|j| format!("`{j}`"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    report.findings.push(finding(
        TOKEN_PERMISSIONS,
        "A workflow's token may do more than the workflow needs".into(),
        Severity::Low,
        at(name, line),
        &[],
        &["CWE-250"],
        [
            description,
            "If anything in the workflow is tricked into running someone else's commands, they \
             run with whatever the token allows."
                .into(),
            "Add `permissions: contents: read` at the top of the workflow, and give a job more only \
             where it needs it."
                .into(),
        ],
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An app folder holding these workflow files, and any other files named.
    fn app(name: &str, workflows: &[(&str, &str)], other: &[&str]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-workflows-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".github/workflows")).unwrap();
        for (file, text) in workflows {
            std::fs::write(dir.join(".github/workflows").join(file), text).unwrap();
        }
        for file in other {
            std::fs::write(dir.join(file), "stages: [test]\n").unwrap();
        }
        dir
    }

    fn run(name: &str, workflows: &[(&str, &str)], other: &[&str]) -> WorkflowReport {
        let dir = app(name, workflows, other);
        let report = check(&dir);
        std::fs::remove_dir_all(&dir).ok();
        report
    }

    fn found(report: &WorkflowReport) -> Vec<&str> {
        report.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn credited(report: &WorkflowReport) -> Vec<&str> {
        report
            .passed
            .iter()
            .flat_map(|v| v.requirement_ids.iter().map(String::as_str))
            .collect()
    }

    fn unassessed(report: &WorkflowReport) -> Vec<&str> {
        report
            .not_assessed
            .iter()
            .map(|(id, _)| id.as_str())
            .collect()
    }

    const SAFE: &str = "\
name: CI
on: [push, pull_request]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: npm test
";

    const DANGEROUS: &str = "\
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: npm ci && npm test
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
";

    #[test]
    fn a_workflow_that_runs_a_strangers_code_with_the_secrets_is_found() {
        let report = run("dangerous", &[("pr.yml", DANGEROUS)], &[]);
        let ids = found(&report);
        for rule in [FORK_CODE, FORK_SECRETS, CHECKOUT_TOKEN, TOKEN_PERMISSIONS] {
            assert!(ids.contains(&rule), "{rule} missing from {ids:?}");
        }
        let fork = report
            .findings
            .iter()
            .find(|f| f.rule_id == FORK_CODE)
            .unwrap();
        assert_eq!(fork.location.file, ".github/workflows/pr.yml");
        assert_eq!(
            fork.location.line, 10,
            "the line that names the pull request's code"
        );
        assert_eq!(fork.requirement_ids, vec!["AC.12.1"]);
        assert!(credited(&report).is_empty(), "{:?}", report.passed);
    }

    #[test]
    fn a_safe_workflow_is_credited_for_what_a_file_can_show_and_no_more() {
        let report = run("safe", &[("ci.yml", SAFE)], &[]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert!(report.not_assessed.is_empty(), "{:?}", report.not_assessed);
        let mut got = credited(&report);
        got.sort();
        assert_eq!(got, vec!["AC.12.1", "AC.12.2"]);
        // AC.12.3 turns on approvals that are repository settings: the check ran and credits nothing.
        let secrets = report
            .passed
            .iter()
            .find(|v| v.check_id == FORK_SECRETS)
            .unwrap();
        assert!(secrets.requirement_ids.is_empty());
    }

    #[test]
    fn every_way_of_writing_the_trigger_is_recognized() {
        let body = "\
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{github.head_ref}}
          persist-credentials: false
";
        for on in [
            "on: pull_request_target\n",
            "on: [push, pull_request_target]\n",
            "\"on\": [pull_request_target]\n",
            "on: { pull_request_target: { types: [opened] } }\n",
            "on:\n  workflow_run:\n    workflows: [CI]\n    types: [completed]\n",
            "on:  # a comment\n  pull_request_target:\n",
        ] {
            let report = run("triggers", &[("pr.yml", &format!("{on}{body}"))], &[]);
            assert!(
                report.not_assessed.iter().all(|(id, _)| id != FORK_CODE),
                "{on}"
            );
            assert_eq!(
                found(&report),
                vec![FORK_CODE],
                "{on:?}: {:?}",
                report.findings
            );
        }
    }

    #[test]
    fn a_pull_request_fetched_by_a_command_counts_too() {
        let text = "\
on: workflow_run
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          gh pr checkout ${{ github.event.workflow_run.pull_requests[0].number }}
          ./deploy.sh
";
        let report = run("command", &[("deploy.yml", text)], &[]);
        assert_eq!(found(&report), vec![FORK_CODE], "{:?}", report.findings);
    }

    #[test]
    fn a_privileged_trigger_with_no_recognized_checkout_is_not_called_clean() {
        let text = "\
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
";
        let report = run("labeler", &[("label.yml", text)], &[]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(unassessed(&report), vec![FORK_CODE]);
        assert!(!credited(&report).contains(&"AC.12.1"));
    }

    #[test]
    fn the_jobs_own_token_is_not_a_secret_here() {
        let text = DANGEROUS.replace("secrets.NPM_TOKEN", "secrets.GITHUB_TOKEN");
        let report = run("own-token", &[("pr.yml", &text)], &[]);
        let ids = found(&report);
        assert!(
            ids.contains(&FORK_CODE),
            "the setup still runs fork code: {ids:?}"
        );
        assert!(!ids.contains(&FORK_SECRETS), "{ids:?}");

        let inherit = DANGEROUS.replace(
            "    runs-on: ubuntu-latest\n",
            "    runs-on: ubuntu-latest\n    secrets: inherit\n",
        );
        let inherit = inherit.replace("secrets.NPM_TOKEN", "secrets.GITHUB_TOKEN");
        let report = run("inherit", &[("pr.yml", &inherit)], &[]);
        assert!(
            found(&report).contains(&FORK_SECRETS),
            "`secrets: inherit` passes them all"
        );
    }

    #[test]
    fn a_checkout_keeping_its_token_is_found_however_it_is_written() {
        let quoted = SAFE.replace(
            "persist-credentials: false",
            "persist-credentials: \"false\"",
        );
        let report = run("quoted", &[("ci.yml", &quoted)], &[]);
        assert!(
            report.findings.is_empty(),
            "a quoted false is still false: {:?}",
            report.findings
        );

        let kept = SAFE.replace("        with:\n          persist-credentials: false\n", "");
        let report = run("kept", &[("ci.yml", &kept)], &[]);
        assert_eq!(found(&report), vec![CHECKOUT_TOKEN]);
        assert_eq!(report.findings[0].location.line, 9);
        assert!(!credited(&report).contains(&"AC.12.2"));
    }

    #[test]
    fn what_cannot_be_read_plainly_leaves_the_workflows_unread() {
        let anchored = "\
on: [push]
permissions: { contents: read }
x: &steps
  - uses: actions/checkout@v4
jobs:
  test:
    runs-on: ubuntu-latest
    steps: *steps
";
        // Each with the reason it gives, because the reason is the only part of some guards that
        // nothing else repeats: a tag or an alias already fails the one-value-per-node reading, and
        // the guard for them exists so the owner is told what to change.
        for (name, text, why) in [
            ("anchor", anchored, "anchor, alias, or tag"),
            (
                "broken",
                "on: [push\njobs:\n  test: {\n",
                "not YAML the grammar can read",
            ),
            (
                "two",
                "on: [push]\n---\njobs: {}\n",
                "more than one YAML document",
            ),
            // A tag can change what a value means.
            (
                "tag",
                "on: !custom [push]\npermissions: { contents: read }\njobs: {}\n",
                "anchor, alias, or tag",
            ),
        ] {
            let report = run(name, &[("ci.yml", text), ("clean.yml", SAFE)], &[]);
            assert!(credited(&report).is_empty(), "{name}: {:?}", report.passed);
            let mut ids = unassessed(&report);
            ids.sort();
            assert_eq!(ids, vec![CHECKOUT_TOKEN, FORK_CODE], "{name}");
            let reason = &report.not_assessed[0].1;
            assert!(
                reason.contains("ci.yml"),
                "{name}: says which file: {reason}"
            );
            assert!(reason.contains(why), "{name}: says why: {reason}");
        }
    }

    #[test]
    fn another_pipeline_beside_the_workflows_keeps_them_from_being_credited() {
        let report = run("gitlab", &[("ci.yml", SAFE)], &[".gitlab-ci.yml"]);
        assert!(credited(&report).is_empty(), "{:?}", report.passed);
        assert!(
            report
                .not_assessed
                .iter()
                .all(|(_, why)| why.contains(".gitlab-ci.yml"))
        );
    }

    #[test]
    fn a_token_that_may_do_anything_is_named_and_cites_nothing() {
        let broad = SAFE.replace(
            "permissions:\n  contents: read\n",
            "permissions: write-all\n",
        );
        let report = run("write-all", &[("ci.yml", &broad)], &[]);
        assert_eq!(found(&report), vec![TOKEN_PERMISSIONS]);
        assert!(report.findings[0].requirement_ids.is_empty());
        assert!(report.findings[0].description.contains("write-all"));

        let unset = SAFE.replace("permissions:\n  contents: read\n", "");
        let report = run("unset", &[("ci.yml", &unset)], &[]);
        assert_eq!(found(&report), vec![TOKEN_PERMISSIONS]);
        assert!(report.findings[0].description.contains("`test`"));
    }

    #[test]
    fn no_workflows_is_nothing_to_say() {
        let dir = std::env::temp_dir().join(format!("sv-workflows-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let report = check(&dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            report.findings.is_empty()
                && report.passed.is_empty()
                && report.not_assessed.is_empty()
        );
    }
}
