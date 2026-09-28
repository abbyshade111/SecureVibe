//! Finding credentials that were left in the code.
//!
//! Two kinds of rule, and the split is the point. The **pattern** rules live in
//! `data/secret-rules.json` because a well-known credential format is data: adding Azure or Twilio should
//! be a data-file entry, not a Rust change. The **judgment** rules are Rust, because deciding whether a
//! high-entropy string is a credential or a content hash is not something a regex can do.
//!
//! What stops this being noise:
//!
//! * A placeholder is not a secret. `your-api-key-here`, `changeme`, `${SOMETHING}` and an empty value are
//!   what a template looks like, and reporting them teaches an owner to ignore the scanner.
//! * `.env` is *expected* to hold real, high-entropy credentials, so the judgment rules do not run there.
//!   What matters about `.env` is whether it is committed, which is its own rule.
//! * Nothing that did not get read is reported as clean. The caller is told which files were skipped.

use crate::finding::{Confidence, Finding, Location, Secret, Severity};
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;
use sv_scan::files::{Entry, Unread};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PatternRule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub pattern: String,
    pub cwe: Vec<String>,
    pub requirement_ids: Vec<String>,
    pub description: String,
    pub impact: String,
    pub fix: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleFile {
    #[serde(rename = "_comment", default)]
    pub comment: String,
    pub rules: Vec<PatternRule>,
}

pub struct SecretRules {
    rules: Vec<(PatternRule, Regex)>,
}

/// What the credential-assignment rule cites. A constant rather than a literal in the finding, so the
/// citation guard can read it alongside the data file's rules.
pub const ASSIGNMENT_REQUIREMENTS: &[&str] = &["V13.3.1", "V13.2.3", "SBD-AC-05"];

/// The assignment rule's own words, for the same guard.
pub const ASSIGNMENT_WHAT: &str =
    "A value that looks like a credential, a secret or a password is written into the code";

impl SecretRules {
    /// Every rule as it was loaded, for the citation guard.
    pub fn rules(&self) -> impl Iterator<Item = &PatternRule> {
        self.rules.iter().map(|(rule, _)| rule)
    }

    /// Every requirement any credential rule is about, deduplicated.
    ///
    /// The union is right here and would be wrong for a per-rule claim: a scan that found no
    /// credentials of *any* listed shape is one piece of evidence about keeping credentials out of
    /// the code, not eight separate ones.
    pub fn requirement_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self
            .rules
            .iter()
            .flat_map(|(rule, _)| rule.requirement_ids.iter().map(String::as_str))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

impl SecretRules {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: RuleFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let mut rules = Vec::new();
        for rule in file.rules {
            let compiled = Regex::new(&rule.pattern)
                .with_context(|| format!("rule {} has a pattern Rust cannot compile", rule.id))?;
            rules.push((rule, compiled));
        }
        Ok(SecretRules { rules })
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn ids(&self) -> Vec<&str> {
        self.rules.iter().map(|(r, _)| r.id.as_str()).collect()
    }
}

/// What a scan covered, so "nothing found" can be read correctly.
#[derive(Debug, Default, Clone)]
pub struct Coverage {
    pub files_read: usize,
    /// Of `files_read`, the files over 2 MB that were read in pieces rather than refused. Counted so
    /// the report can say so: an assignment found in one is reported with low confidence.
    pub read_in_pieces: Vec<String>,
    /// Files that exist but were not read, with the reason. A scan that skipped something is not a clean one.
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct SecretScan {
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
    /// Set when the scan read every file it found and turned up nothing.
    pub verified: Vec<crate::Verified>,
}

/// Values that mean "fill this in", not a credential.
fn looks_like_placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    let lower = v.to_lowercase();
    const MARKERS: &[&str] = &[
        "example",
        "placeholder",
        "changeme",
        "change-me",
        "change_me",
        "replace",
        "your-",
        "your_",
        "yourkey",
        "todo",
        "xxx",
        "dummy",
        "sample",
        "test-key",
        "generate_with",
        "insert",
    ];
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // `${VAR}`, `<something>`, `{{ var }}` — a template, not a value.
    v.contains("${") || (v.starts_with('<') && v.ends_with('>')) || v.contains("{{")
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in s.chars() {
        *counts.entry(ch).or_default() += 1;
    }
    let len = s.chars().count() as f64;
    -counts
        .values()
        .map(|&n| {
            let p = n as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// Whether a name says its value is a credential.
fn is_secret_name(name: &str) -> bool {
    let n = name.to_lowercase();
    const NAMES: &[&str] = &[
        "secret",
        "password",
        "passwd",
        "pwd",
        "apikey",
        "api_key",
        "api-key",
        "accesskey",
        "access_key",
        "access-key",
        "privatekey",
        "private_key",
        "private-key",
        "authtoken",
        "auth_token",
        "access_token",
        "refresh_token",
        "client_secret",
        "signing_key",
        "encryption_key",
        "token",
        "credential",
        "salt",
        "hmac",
    ];
    NAMES.iter().any(|k| n.ends_with(k) || n.contains(k))
}

/// `.env` is meant to hold real credentials, so the judgment rules would fire on every line of it.
fn is_env_file(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    name == ".env" || name.starts_with(".env.")
}

/// Runs every rule over one file's text.
pub fn scan_text(rules: &SecretRules, relative: &str, text: &str) -> Vec<Finding> {
    scan_piece(rules, relative, text, 1, 0..text.len(), false)
}

/// Runs every rule over one piece of a file: `text` starts on line `first_line`, and only a match that
/// starts inside `keep` is this piece's to report (see `sv_scan::files::Piece`). `large` marks a file
/// over 2 MB, where the assignment rule's judgment is weaker: such a file is generated or vendored, and
/// a long random-looking value in it is as likely to be a hash as a key, so what that rule finds there
/// is reported with low confidence. The vendor rules keep theirs; a hash does not look like `AKIA` or
/// `sk-ant-`.
fn scan_piece(
    rules: &SecretRules,
    relative: &str,
    text: &str,
    first_line: usize,
    keep: std::ops::Range<usize>,
    large: bool,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let env_file = is_env_file(relative);

    for (rule, re) in &rules.rules {
        for m in re.find_iter(text) {
            if !keep.contains(&m.start()) {
                continue;
            }
            let value = m.as_str();
            if looks_like_placeholder(value) {
                continue;
            }
            out.push(Finding {
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                marked_test_code: false,
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity,
                confidence: rule.confidence,
                location: Location {
                    file: relative.to_owned(),
                    line: first_line - 1 + line_of(text, m.start()),
                },
                secret: Some(Secret::redact(value)),
                requirement_ids: rule.requirement_ids.clone(),
                cwe: rule.cwe.clone(),
                description: rule.description.clone(),
                impact: rule.impact.clone(),
                fix: rule.fix.clone(),
            });
        }
    }

    if !env_file {
        // The generic rule fires on the same line as a vendor rule whenever a key is assigned to a
        // well-named variable, which is most of the time. Two findings for one secret is noise, and the
        // vendor rule is the better of the two: it names what the credential is and how to revoke it.
        let already: Vec<usize> = out.iter().map(|f| f.location.line).collect();
        out.extend(
            assignment_findings(relative, text, first_line, &keep)
                .into_iter()
                .filter(|f| !already.contains(&f.location.line))
                .map(|mut f| {
                    if large {
                        f.confidence = Confidence::Low;
                    }
                    f
                }),
        );
    }
    out
}

/// A name that says "credential" assigned a value that looks like one.
///
/// This is the rule that earns its keep and the rule most able to cry wolf, so it asks for three things at
/// once: a name that means a secret, a value that is not a placeholder, and enough entropy that it is not
/// an English word or an identifier.
fn assignment_findings(
    relative: &str,
    text: &str,
    first_line: usize,
    keep: &std::ops::Range<usize>,
) -> Vec<Finding> {
    // name = "value" / name: 'value' / NAME=value — the shapes an assignment takes across languages.
    static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?m)([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*["']([^"'\n]{8,200})["']"#)
            .expect("static pattern")
    });
    let mut out = Vec::new();
    for caps in ASSIGNMENT.captures_iter(text) {
        if !keep.contains(&caps.get(0).expect("group 0 is the match").start()) {
            continue;
        }
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let value_match = caps.get(2).expect("group 2 is not optional");
        let value = value_match.as_str();
        if !is_secret_name(name) || looks_like_placeholder(value) {
            continue;
        }
        // A reference to another variable, a path or a URL is not a credential.
        if value.starts_with('/')
            || value.contains("://")
            || value.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        {
            continue;
        }
        if shannon_entropy(value) < 3.5 {
            continue;
        }
        out.push(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            marked_test_code: false,
            rule_id: "secrets.credential-assignment".into(),
            title: format!("A value that looks like a credential is written into the code (`{name}`)"),
            severity: Severity::High,
            confidence: Confidence::Medium,
            location: Location {
                file: relative.to_owned(),
                line: first_line - 1 + line_of(text, value_match.start()),
            },
            secret: Some(Secret::redact(value)),
            requirement_ids: ASSIGNMENT_REQUIREMENTS.iter().map(|r| (*r).to_owned()).collect(),
            cwe: vec!["CWE-798".into(), "CWE-259".into()],
            description: format!(
                "`{name}` is set to a value in the code itself. The name says it holds a credential, and the \
                 value is not a placeholder."
            ),
            impact: "Anyone who can read the code — or the history it is kept in — has the credential."
                .into(),
            fix: "Move the value into the app's environment or secret store, and change the credential: \
                  anything committed should be treated as known."
                .into(),
        });
    }
    out
}

/// `text` with every credential in it cut down to what a finding would show of it, and how many
/// were.
///
/// For text `sv` passes on rather than scans: a failing test suite's last lines go into a report
/// that may be handed to somebody, and a runner that prints its environment, or a request it made,
/// prints the keys in it. Every rule's matches are cut, and so is any value given to a name that
/// says it is a credential (`API_KEY=…`, `"password": "…"`), quoted or not, whatever its entropy:
/// a redaction that is not needed costs a reader four characters, and one that is missed cannot
/// be taken back.
pub fn redact_text(rules: &SecretRules, text: &str) -> (String, usize) {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (_, re) in &rules.rules {
        for m in re.find_iter(text) {
            if !looks_like_placeholder(m.as_str()) {
                spans.push((m.start(), m.end()));
            }
        }
    }
    static NAMED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*(?:"([^"\n]+)"|'([^'\n]+)'|([^\s"',;&]+))"#,
        )
        .expect("static pattern")
    });
    for caps in NAMED.captures_iter(text) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let Some(value) = caps.get(2).or(caps.get(3)).or(caps.get(4)) else {
            continue;
        };
        if is_secret_name(name) && !looks_like_placeholder(value.as_str()) {
            spans.push((value.start(), value.end()));
        }
    }
    spans.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (start, end) in &merged {
        out.push_str(&text[at..*start]);
        out.push_str(&format!(
            "[redacted: {}]",
            Secret::redact(&text[*start..*end]).as_str()
        ));
        at = *end;
    }
    out.push_str(&text[at..]);
    (out, merged.len())
}

fn line_of(text: &str, byte_offset: usize) -> usize {
    text[..byte_offset.min(text.len())]
        .bytes()
        .filter(|b| *b == b'\n')
        .count()
        + 1
}

/// Runs the secret rules over every readable text file in `app_dir`.
///
/// Coverage is recorded, not assumed. A file that could not be read, or that is not text, is listed with
/// the reason — because "no secrets found" in a folder half of which was skipped is not the same claim as
/// "no secrets found", and only one of them is true.
pub fn scan_dir(rules: &SecretRules, app_dir: &Path) -> SecretScan {
    scan_listing(rules, &sv_scan::files::Listing::of(app_dir))
}

/// `scan_dir`, over a listing already made: every file in it is read, and every one that could not
/// be is named, so a link `sv` did not follow and a file over the size limit are gaps with names
/// rather than a clean result.
pub fn scan_listing(rules: &SecretRules, listing: &sv_scan::files::Listing) -> SecretScan {
    let mut scan = SecretScan::default();
    for dir in &listing.unopened {
        scan.coverage
            .skipped
            .push((dir.clone(), "the folder could not be opened".to_owned()));
    }
    for entry in &listing.files {
        let read = match entry.read_text() {
            Ok(text) => Ok(scan_text(rules, &entry.relative, &text)),
            // A file over 2 MB is read a piece at a time: every rule is one line long, so a piece
            // that overlaps the next by far more than the longest match misses nothing.
            Err(Unread::TooLarge) => scan_large(rules, entry).inspect(|_| {
                scan.coverage.read_in_pieces.push(entry.relative.clone());
            }),
            Err(why) => Err(why),
        };
        match read {
            Ok(found) => {
                scan.coverage.files_read += 1;
                scan.findings.extend(found);
            }
            Err(why) => scan
                .coverage
                .skipped
                .push((entry.relative.clone(), why.explain().to_owned())),
        }
    }
    scan.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });
    scan.verified = clean_scan(rules, &scan);
    scan
}

/// One file over 2 MB, in pieces of 1 MB overlapping by 64 KB: longer than any credential or any line
/// the assignment rule reads, so each is inside some piece whole and counted by exactly one.
fn scan_large(rules: &SecretRules, entry: &Entry) -> Result<Vec<Finding>, Unread> {
    let mut found = Vec::new();
    entry.in_pieces(1024 * 1024, 64 * 1024, |piece| {
        found.extend(scan_piece(
            rules,
            &entry.relative,
            piece.text,
            piece.first_line,
            piece.keep,
            true,
        ));
    })?;
    Ok(found)
}

/// Whether this scan is evidence that the app holds no credentials.
///
/// Fail closed on anything skipped. A file that could not be read might be the one holding the key,
/// and "48 of 52 files were clean" belongs in the gap list, not beside a requirement as a green
/// line. The scope says how many rules were behind it, because a credential in a shape nobody
/// listed would still not have been found — that bound holds however complete the file coverage is,
/// so it is stated rather than left for the reader to remember.
fn clean_scan(rules: &SecretRules, scan: &SecretScan) -> Vec<crate::Verified> {
    if !scan.findings.is_empty()
        || !scan.coverage.skipped.is_empty()
        || scan.coverage.files_read == 0
    {
        return Vec::new();
    }
    let ids = rules.requirement_ids();
    vec![crate::Verified::new(
        "secrets.scan",
        &ids,
        format!(
            "{} file{}{}, against {} known credential formats plus the assignment rule",
            scan.coverage.files_read,
            if scan.coverage.files_read == 1 {
                ""
            } else {
                "s"
            },
            match scan.coverage.read_in_pieces.len() {
                0 => String::new(),
                n => format!(" ({n} over 2 MB, read in pieces)"),
            },
            rules.len()
        ),
    )]
}

/// Above this, a file is not something a person typed and reading it all costs more than it finds.
#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a credential-shaped string at run time, from pieces.
    ///
    /// Written this way because a literal here that looks like a real key is one GitHub's push protection
    /// blocks — it blocked this branch once already, on this crate's own test data. The alternative is
    /// clicking "allow this secret" on a repository whose subject is not leaking secrets, which teaches
    /// exactly the reflex this scanner exists to make unnecessary. The rules still see a whole key: it is
    /// assembled before it is scanned.
    fn credential_shaped(parts: &[&str], separator: &str) -> String {
        parts.join(separator)
    }

    #[test]
    fn redacting_cuts_a_known_key_anywhere_and_a_value_by_its_name() {
        let key = credential_shaped(&["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb"], "-");
        let text = format!(
            "Authorization failed for {key} at /v1/messages\n\
             password: 'S3cr3t-Value-99'\n\
             SECRET_KEY=changeme\n"
        );
        let (out, n) = redact_text(&rules(), &text);
        assert_eq!(n, 2);
        // No message prints `out`: were a cut missed, it would hold the credential.
        assert!(!out.contains(&key), "the key was not cut short");
        assert!(
            !out.contains("S3cr3t-Value-99"),
            "the password was not cut short"
        );
        assert!(out.contains("Authorization failed for [redacted: sk-a…"));
        assert!(out.contains("password: '[redacted: S3cr…"));
        // A placeholder is not a credential, and cutting it would hide the mistake it points at.
        assert!(out.contains("SECRET_KEY=changeme"));
    }

    fn rules() -> SecretRules {
        SecretRules::load(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../data/secret-rules.json"),
        )
        .expect("rules load")
    }

    #[test]
    fn every_pattern_in_the_data_file_compiles() {
        // A pattern Rust cannot compile would otherwise be a rule that silently never fires.
        let r = rules();
        assert!(r.len() >= 8, "only {} rules loaded", r.len());
    }

    #[test]
    fn it_finds_a_key_and_does_not_repeat_it() {
        let key = credential_shaped(&["sk", "ant", "api03", "REALLOOKINGKEYVALUE123456"], "-");
        let text = format!("ANTHROPIC = '{key}'\n");
        let text = text.as_str();
        let found = scan_text(&rules(), "src/app.py", text);
        let key = found
            .iter()
            .find(|f| f.rule_id == "secrets.anthropic-key")
            .expect("key found");
        assert_eq!(key.location.line, 1);
        assert!(key.requirement_ids.contains(&"V13.3.1".to_string()));
        let rendered = serde_json::to_string(&found).unwrap();
        assert!(
            !rendered.contains("REALLOOKINGKEYVALUE"),
            "the key reached the finding"
        );
    }

    /// `n` characters from `alphabet`, in a fixed order, for building key-shaped test values. Fixed
    /// so a failing test fails the same way twice; built at run time so no file holds a key.
    fn filler(n: usize, alphabet: &str) -> String {
        alphabet.chars().cycle().take(n).collect()
    }

    const MIXED: &str = "Qm7Rz2Kv9Lp4Wn8Hs3Jd6Tf1Gb5Yc0";
    const LETTERS: &str = "QmRzKvLpWnHsJdTfGbYcAeBi";

    /// OpenAI's middle marker, in two pieces, so this file does not hold a key's shape whole.
    fn openai_marker() -> String {
        ["T3Bl", "bkFJ"].concat()
    }

    /// A project key ending in `-`, which a trailing word boundary would have missed, and a
    /// legacy key: the two shapes in gitleaks' rule that a person is likely to have.
    fn openai_keys() -> Vec<String> {
        let tail = format!("{}-", filler(73, MIXED));
        vec![
            credential_shaped(
                &[
                    "sk",
                    "proj",
                    &format!("{}{}{tail}", filler(74, MIXED), openai_marker()),
                ],
                "-",
            ),
            credential_shaped(
                &[
                    "sk",
                    &format!(
                        "{}{}{}",
                        filler(20, MIXED),
                        openai_marker(),
                        filler(20, MIXED)
                    ),
                ],
                "-",
            ),
        ]
    }

    fn huggingface_tokens() -> Vec<String> {
        vec![
            credential_shaped(&["hf", &filler(34, LETTERS)], "_"),
            credential_shaped(&["api", "org", &filler(34, LETTERS)], "_"),
        ]
    }

    #[test]
    fn openai_and_hugging_face_keys_are_found_where_nothing_found_them_before() {
        // Where the generic assignment rule does not reach: an env file other than .env itself,
        // which it skips on purpose, and a shell line with no quotes. Before these rules an OpenAI
        // key in `.env.production` or a Dockerfile's ENV line was reported by nothing.
        let cases: Vec<(String, &str)> = openai_keys()
            .into_iter()
            .map(|k| (k, "secrets.openai-key"))
            .chain(
                huggingface_tokens()
                    .into_iter()
                    .map(|k| (k, "secrets.huggingface-token")),
            )
            .collect();
        for (key, rule) in &cases {
            for (file, text) in [
                (".env.production", format!("OPENAI_API_KEY={key}\n")),
                ("deploy.sh", format!("export TOKEN={key}\n")),
                (
                    "Dockerfile",
                    format!("FROM python:3.12\nENV HF_TOKEN {key}\n"),
                ),
            ] {
                let found = scan_text(&rules(), file, &text);
                let hits: Vec<&Finding> = found.iter().filter(|f| f.rule_id == *rule).collect();
                assert_eq!(
                    hits.len(),
                    1,
                    "{rule} in {file}: {:?}",
                    found.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
                );
                let hit = hits[0];
                assert!(hit.requirement_ids.contains(&"V13.3.1".to_string()));
                // Four characters and the length, never the key.
                let rendered = serde_json::to_string(&found).unwrap();
                assert!(
                    !rendered.contains(key.as_str()),
                    "{rule}: the key reached the finding"
                );
                assert_eq!(
                    hit.secret.as_ref().map(|s| s.length()),
                    Some(key.len()),
                    "{rule} in {file}: the whole key, and only the key, was matched"
                );
            }
        }
    }

    #[test]
    fn redaction_cuts_openai_and_hugging_face_keys_from_output() {
        // What a failing test suite printed goes into the report; a key in it must not.
        for key in openai_keys().into_iter().chain(huggingface_tokens()) {
            let text = format!("request failed: Bearer {key} was refused\n");
            let (out, n) = redact_text(&rules(), &text);
            assert_eq!(n, 1, "one credential in the line");
            assert!(!out.contains(key.as_str()), "the key was not cut short");
        }
    }

    #[test]
    fn each_ai_vendors_key_is_reported_by_its_own_rule_alone() {
        // Anthropic's keys start sk-ant-, OpenAI's sk-proj- or sk-: a pattern for one that
        // forgot its marker would claim the other's keys too, and one key would read as two.
        let anthropic = credential_shaped(&["sk", "ant", "api03", &filler(40, MIXED)], "-");
        let cases: Vec<(String, &str)> = std::iter::once((anthropic, "secrets.anthropic-key"))
            .chain(openai_keys().into_iter().map(|k| (k, "secrets.openai-key")))
            .chain(
                huggingface_tokens()
                    .into_iter()
                    .map(|k| (k, "secrets.huggingface-token")),
            )
            .collect();
        for (key, rule) in &cases {
            let text = format!("key: {key}\n");
            let found = scan_text(&rules(), "notes.txt", &text);
            let ids: Vec<&str> = found.iter().map(|f| f.rule_id.as_str()).collect();
            assert_eq!(ids, [*rule], "{}…: {ids:?}", &key[..8]);
        }
    }

    #[test]
    fn near_misses_are_not_openai_or_hugging_face_keys() {
        // Shapes close to the rules that are not keys: a Hugging Face identifier, a token one
        // letter short or long, and an sk- string with no marker in it.
        for text in [
            "from huggingface_hub import hf_hub_download\n".to_owned(),
            format!("x = 'hf_{}'\n", filler(33, LETTERS)),
            format!("x = 'hf_{}'\n", filler(35, LETTERS)),
            format!("x = 'sk-{}'\n", filler(48, MIXED)),
        ] {
            let found = scan_text(&rules(), "src/app.py", &text);
            assert!(
                !found.iter().any(|f| f.rule_id == "secrets.openai-key"
                    || f.rule_id == "secrets.huggingface-token"),
                "{text:?}: {:?}",
                found.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
            );
        }
    }

    fn big_scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-secrets-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn aws_key(tail: &str) -> String {
        credential_shaped(&["AKIA", tail], "")
    }

    #[test]
    fn keys_in_a_large_one_line_file_are_found_once_each_wherever_the_pieces_fall() {
        // cato-pipeline's case: a vendored catalog of several MB, on one line as JSON often is. Three
        // keys: one across the boundary where the first piece's own part ends (1 MB less 64 KB), one
        // across the first piece's physical end (1 MB), and one past the 2 MB mark.
        let keys = [
            aws_key("Q7RZ2KV9LP4WN8HA"),
            aws_key("Q7RZ2KV9LP4WN8HB"),
            aws_key("Q7RZ2KV9LP4WN8HC"),
        ];
        let mib = 1024 * 1024;
        let at = [mib - 64 * 1024 - 5, mib - 10, 2 * mib + mib / 2];
        let mut line = String::from("{\"text\": \"");
        for (key, offset) in keys.iter().zip(at) {
            line.push_str(&"y".repeat(offset - line.len()));
            line.push(' ');
            line.push_str(key);
            line.push(' ');
        }
        line.push_str(&"y".repeat(3 * mib - line.len()));
        line.push_str("\"}\n");
        let dir = big_scratch("one-line");
        std::fs::write(dir.join("catalog.json"), &line).unwrap();
        let listing = sv_scan::files::Listing::of(&dir);
        assert!(listing.files[0].too_large(), "the setup: over 2 MB");
        let scan = scan_listing(&rules(), &listing);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            scan.coverage.skipped.is_empty(),
            "{:?}",
            scan.coverage.skipped
        );
        assert_eq!(scan.coverage.read_in_pieces, ["catalog.json"]);
        let aws: Vec<&Finding> = scan
            .findings
            .iter()
            .filter(|f| f.rule_id == "secrets.aws-access-key")
            .collect();
        assert_eq!(aws.len(), 3, "each key once, none twice, none cut in half");
        for f in &aws {
            assert_eq!(f.location.line, 1);
            assert_eq!(
                f.secret.as_ref().map(|s| s.length()),
                Some(20),
                "a whole key"
            );
            assert_eq!(
                f.confidence,
                Confidence::High,
                "a vendor shape keeps its confidence"
            );
        }
        let rendered = serde_json::to_string(&scan.findings).unwrap();
        for key in &keys {
            assert!(
                !rendered.contains(key.as_str()),
                "a key reached the finding"
            );
        }
    }

    #[test]
    fn a_piece_reports_only_what_starts_in_its_own_part() {
        // One piece, three lines: the first is look-behind, the last look-ahead, and only the
        // middle is the piece's own. A key or an assignment outside the middle belongs to the piece
        // before or after, and is reported there; here it must not be, or it is reported twice.
        let key = aws_key("Q7RZ2KV9LP4WN8HE");
        let value = credential_shaped(&["Zq8", "Lm2", "Vx7", "Rt4", "Wp9", "Kd3"], "");
        let behind = format!("aws = {key}\npassword = \"{value}\"\n");
        let own = format!("aws = {key}\npassword = \"{value}\"\n");
        let ahead = format!("aws = {key}\npassword = \"{value}\"\n");
        let text = format!("{behind}{own}{ahead}");
        let keep = behind.len()..behind.len() + own.len();
        let found = scan_piece(&rules(), "dump.txt", &text, 100, keep, true);
        let mut got: Vec<(&str, usize)> = found
            .iter()
            .map(|f| (f.rule_id.as_str(), f.location.line))
            .collect();
        got.sort();
        // `text` starts on line 100, so its own part is lines 102 and 103.
        assert_eq!(
            got,
            [
                ("secrets.aws-access-key", 102),
                ("secrets.credential-assignment", 103)
            ]
        );
    }

    #[test]
    fn a_piece_sees_the_character_before_its_own_part() {
        // `AKIA…` glued to the letter before it is not a key: the rule asks for a word boundary.
        // Placed so that `AKIA` is the first byte of the second piece's own part, a piece with no
        // look-behind would see a boundary that the file does not have, and report it.
        let mib = 1024 * 1024;
        let own_starts = mib - 64 * 1024;
        let glued = format!("y{}", aws_key("Q7RZ2KV9LP4WN8HF"));
        let mut line = "y".repeat(own_starts - 1);
        line.push_str(&glued);
        line.push_str(&" y".repeat(mib));
        line.push('\n');
        assert_eq!(
            &line[own_starts..own_starts + 4],
            "AKIA",
            "the setup: at the boundary"
        );
        let dir = big_scratch("glued");
        std::fs::write(dir.join("catalog.txt"), &line).unwrap();
        let scan = scan_dir(&rules(), &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            scan.coverage.read_in_pieces,
            ["catalog.txt"],
            "the setup: read in pieces"
        );
        assert!(
            !scan
                .findings
                .iter()
                .any(|f| f.rule_id == "secrets.aws-access-key"),
            "a key the file does not have: {:?}",
            scan.findings.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_large_file_gives_the_line_an_editor_shows_and_a_weaker_assignment() {
        // Many short lines, so the pieces start mid-file on counted lines. A key on line 45,000 must
        // say 45,000. An assignment in a large file is reported with low confidence: a long
        // random-looking value in generated data is as likely a hash as a key.
        let key = aws_key("Q7RZ2KV9LP4WN8HD");
        let value = credential_shaped(&["Zq8", "Lm2", "Vx7", "Rt4", "Wp9", "Kd3"], "");
        let mut text = String::new();
        for i in 1..=60_000 {
            match i {
                45_000 => text.push_str(&format!("aws = {key}\n")),
                50_000 => text.push_str(&format!("password = \"{value}\"\n")),
                _ => text.push_str(&format!("{i:>8} a line of generated data, nothing in it\n")),
            }
        }
        let dir = big_scratch("many-lines");
        std::fs::write(dir.join("dump.txt"), &text).unwrap();
        let listing = sv_scan::files::Listing::of(&dir);
        assert!(listing.files[0].too_large(), "the setup: over 2 MB");
        let scan = scan_listing(&rules(), &listing);
        std::fs::remove_dir_all(&dir).ok();
        let aws = scan
            .findings
            .iter()
            .find(|f| f.rule_id == "secrets.aws-access-key")
            .expect("the key is found");
        assert_eq!(aws.location.line, 45_000);
        let assigned = scan
            .findings
            .iter()
            .find(|f| f.rule_id == "secrets.credential-assignment")
            .expect("the assignment is found");
        assert_eq!(assigned.location.line, 50_000);
        assert_eq!(assigned.confidence, Confidence::Low);
        // The same line in an ordinary file keeps the rule's usual confidence.
        let small = scan_text(&rules(), "src/app.py", &format!("password = \"{value}\"\n"));
        assert_eq!(small[0].confidence, Confidence::Medium);
    }

    #[test]
    fn a_large_file_with_nothing_in_it_leaves_the_scan_clean_and_says_how_it_was_read() {
        let dir = big_scratch("clean");
        std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
        std::fs::write(
            dir.join("catalog.json"),
            format!("{{\"text\": \"{}\"}}\n", "y".repeat(3 * 1024 * 1024)),
        )
        .unwrap();
        let scan = scan_dir(&rules(), &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(scan.coverage.files_read, 2);
        assert!(scan.coverage.skipped.is_empty());
        let clean = scan
            .verified
            .first()
            .expect("a clean scan, not an unfinished one");
        assert!(
            clean
                .scope
                .contains("2 files (1 over 2 MB, read in pieces)"),
            "{}",
            clean.scope
        );
    }

    #[test]
    fn a_placeholder_is_not_reported() {
        // The rule that decides whether anybody keeps using the scanner.
        for value in [
            "your-api-key-here",
            "sk-ant-changeme",
            "${ANTHROPIC_API_KEY}",
            "<your key>",
            "",
        ] {
            let text = format!("api_key = \"{value}\"\n");
            let found = scan_text(&rules(), "src/app.py", &text);
            assert!(
                found.is_empty(),
                "reported a placeholder {value:?}: {found:?}"
            );
        }
    }

    #[test]
    fn a_credential_assignment_is_found_by_name_and_entropy_together() {
        let text = "db_password = \"Xk7#mQ92vLpR4sTz\"\n";
        let found = scan_text(&rules(), "src/config.py", text);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule_id, "secrets.credential-assignment");
    }

    #[test]
    fn an_ordinary_string_with_a_harmless_name_is_left_alone() {
        for line in [
            "greeting = \"hello there friend\"",
            "path = \"/usr/local/share/app\"",
            "endpoint = \"https://api.example.com/v1\"",
            "title = \"Client's habit tracker\"",
        ] {
            let found = scan_text(&rules(), "src/app.py", &format!("{line}\n"));
            assert!(found.is_empty(), "reported {line:?}: {found:?}");
        }
    }

    #[test]
    fn a_secret_name_with_a_low_entropy_value_is_not_reported() {
        // "password = 'password'" is a bad password, not a leaked credential, and calling it one would
        // bury the findings that are.
        let found = scan_text(&rules(), "src/app.py", "password = \"aaaaaaaaaaaa\"\n");
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn dot_env_is_not_scanned_for_assignments_because_that_is_what_it_is_for() {
        let text = "SESSION_SECRET=\"Xk7#mQ92vLpR4sTzAAbb\"\n";
        assert!(scan_text(&rules(), ".env", text).is_empty());
        // The same line anywhere else is a finding.
        assert!(!scan_text(&rules(), "src/config.ts", text).is_empty());
    }

    #[test]
    fn a_known_format_is_still_reported_inside_dot_env() {
        // A vendor key in .env is expected. A vendor key is also the thing most worth knowing about when
        // the file turns out to be committed, so the pattern rules still run there.
        let key = credential_shaped(&["sk", "ant", "api03", "REALLOOKINGKEYVALUE123456"], "-");
        let text = format!("ANTHROPIC_API_KEY={key}\n");
        let text = text.as_str();
        let found = scan_text(&rules(), ".env", text);
        assert!(
            found.iter().any(|f| f.rule_id == "secrets.anthropic-key"),
            "{found:?}"
        );
    }

    #[test]
    fn one_secret_produces_one_finding() {
        // A vendor key assigned to a well-named variable matches both the vendor rule and the generic
        // assignment rule. Reporting it twice doubles the apparent problem and halves the attention each
        // finding gets; the vendor rule wins because it can say how to revoke the thing.
        let key = credential_shaped(&["sk", "live", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
        let text = format!("STRIPE_SECRET_KEY = \"{key}\"\n");
        let text = text.as_str();
        let found = scan_text(&rules(), "src/config.py", text);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].rule_id, "secrets.stripe-key");
    }

    #[test]
    fn two_different_secrets_on_two_lines_are_two_findings() {
        // The other side of it: de-duplication must not swallow a real second finding.
        let key = credential_shaped(&["sk", "live", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
        let text =
            format!("STRIPE_SECRET_KEY = \"{key}\"\nsession_secret = \"Xk7#mQ92vLpR4sTzWwYy\"\n");
        let text = text.as_str();
        let found = scan_text(&rules(), "src/config.py", text);
        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn a_whole_example_env_file_is_silent() {
        // The file every project ships to show what to fill in. If the scanner shouts at this, an owner
        // learns on their first run that its findings are noise — which costs more than the rule is worth.
        // A different shape from the single-value placeholder test: several rules, several lines, at once.
        let example = "\
# Copy to .env and fill in.
ANTHROPIC_API_KEY=sk-ant-your-key-here
AWS_ACCESS_KEY_ID=AKIAEXAMPLEEXAMPLE12
STRIPE_SECRET_KEY=sk_test_replace_me
DATABASE_PASSWORD=changeme
SESSION_SECRET=${SESSION_SECRET}
GITHUB_TOKEN=<your token>
SIGNING_KEY=generate_with_openssl_rand
";
        let found = scan_text(&rules(), "README.env.example", example);
        assert!(
            found.is_empty(),
            "an example file produced findings: {found:?}"
        );
    }

    #[test]
    fn repetitive_values_under_credential_names_are_not_credentials() {
        // Low entropy, not placeholders: the entropy gate is the only thing standing between these and a
        // wall of false findings. Deliberately different values from the single-case test above.
        for line in [
            "auth_token = \"abcabcabcabcabcabc\"",
            "client_secret = \"111111111111111111\"",
            "signing_key = \"aaaaaaaaaaaaaaaaaaaa\"",
            "encryption_key = \"abababababababababab\"",
        ] {
            let found = scan_text(&rules(), "src/settings.rb", &format!("{line}\n"));
            assert!(found.is_empty(), "reported {line:?}: {found:?}");
        }
    }

    #[test]
    fn entropy_tells_a_random_string_from_a_word() {
        assert!(shannon_entropy("aaaaaaaaaa") < 1.0);
        assert!(shannon_entropy("password") < 3.5);
        assert!(shannon_entropy("Xk7#mQ92vLpR4sTz") > 3.5);
    }

    #[test]
    fn line_numbers_are_what_an_editor_shows() {
        let text = "one\ntwo\napi_key = \"Xk7#mQ92vLpR4sTz\"\n";
        let found = scan_text(&rules(), "src/app.py", text);
        assert_eq!(found[0].location.line, 3);
    }

    #[test]
    fn a_committed_credential_is_a_finding_against_no_secrets_in_code() {
        // SBD-AC-05 asks, among other things, for no secrets in code. A key in a file is that failing,
        // from the data file's rules and from the assignment rule alike.
        let rules = SecretRules::load(
            &std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../data/secret-rules.json"),
        )
        .unwrap();
        for rule in rules.rules() {
            assert!(
                rule.requirement_ids.iter().any(|r| r == "SBD-AC-05"),
                "{} does not cite SBD-AC-05",
                rule.id
            );
        }
        assert!(ASSIGNMENT_REQUIREMENTS.contains(&"SBD-AC-05"));
        assert!(
            rules.requirement_ids().contains(&"SBD-AC-05"),
            "a clean scan has to offer itself as supporting evidence for it"
        );
    }
}
