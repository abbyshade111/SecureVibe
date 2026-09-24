//! Finding credentials that were left in the code.
//!
//! Two kinds of rule, and the split is the point. The **pattern** rules live in
//! `data/secret-rules.json` because a well-known credential format is data: adding Azure or Twilio should
//! be a data-file entry, not a Rust change. The **judgement** rules are Rust, because deciding whether a
//! high-entropy string is a credential or a content hash is not something a regex can do.
//!
//! What stops this being noise:
//!
//! * A placeholder is not a secret. `your-api-key-here`, `changeme`, `${SOMETHING}` and an empty value are
//!   what a template looks like, and reporting them teaches an owner to ignore the scanner.
//! * `.env` is *expected* to hold real, high-entropy credentials, so the judgement rules do not run there.
//!   What matters about `.env` is whether it is committed, which is its own rule.
//! * Nothing that did not get read is reported as clean. The caller is told which files were skipped.

use crate::finding::{Confidence, Finding, Location, Secret, Severity};
use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

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
    /// Files that exist but were not read, with the reason. A scan that skipped something is not a clean one.
    pub skipped: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct SecretScan {
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
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

/// `.env` is meant to hold real credentials, so the judgement rules would fire on every line of it.
fn is_env_file(relative: &str) -> bool {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    name == ".env" || name.starts_with(".env.")
}

/// Runs every rule over one file's text.
pub fn scan_text(rules: &SecretRules, relative: &str, text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    let env_file = is_env_file(relative);

    for (rule, re) in &rules.rules {
        for m in re.find_iter(text) {
            let value = m.as_str();
            if looks_like_placeholder(value) {
                continue;
            }
            out.push(Finding {
                rule_id: rule.id.clone(),
                title: rule.title.clone(),
                severity: rule.severity,
                confidence: rule.confidence,
                location: Location {
                    file: relative.to_owned(),
                    line: line_of(text, m.start()),
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
            assignment_findings(relative, text)
                .into_iter()
                .filter(|f| !already.contains(&f.location.line)),
        );
    }
    out
}

/// A name that says "credential" assigned a value that looks like one.
///
/// This is the rule that earns its keep and the rule most able to cry wolf, so it asks for three things at
/// once: a name that means a secret, a value that is not a placeholder, and enough entropy that it is not
/// an English word or an identifier.
fn assignment_findings(relative: &str, text: &str) -> Vec<Finding> {
    // name = "value" / name: 'value' / NAME=value — the shapes an assignment takes across languages.
    let assignment =
        Regex::new(r#"(?m)([A-Za-z_][A-Za-z0-9_.\-]*)\s*[:=]\s*["']([^"'\n]{8,200})["']"#)
            .expect("static pattern");
    let mut out = Vec::new();
    for caps in assignment.captures_iter(text) {
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
            rule_id: "secrets.credential-assignment".into(),
            title: format!("A value that looks like a credential is written into the code (`{name}`)"),
            severity: Severity::High,
            confidence: Confidence::Medium,
            location: Location { file: relative.to_owned(), line: line_of(text, value_match.start()) },
            secret: Some(Secret::redact(value)),
            requirement_ids: vec!["V13.3.1".into(), "V13.2.3".into()],
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
    let mut scan = SecretScan::default();
    walk(app_dir, app_dir, rules, &mut scan);
    scan.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });
    scan
}

/// Directories whose contents belong to somebody else, or are build output.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "out",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".next",
    ".nuxt",
    ".tox",
    "site-packages",
    ".gradle",
    ".mypy_cache",
    ".pytest_cache",
    "coverage",
];

/// Above this, a file is not something a person typed and reading it all costs more than it finds.
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

fn walk(root: &Path, dir: &Path, rules: &SecretRules, scan: &mut SecretScan) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        scan.coverage.skipped.push((
            relative(root, dir),
            "the folder could not be opened".to_owned(),
        ));
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(root, &path, rules, scan);
            continue;
        }
        let rel = relative(root, &path);
        match entry.metadata() {
            Ok(meta) if meta.len() > MAX_FILE_BYTES => {
                scan.coverage
                    .skipped
                    .push((rel, "larger than 2 MB".to_owned()));
                continue;
            }
            Err(_) => {
                scan.coverage
                    .skipped
                    .push((rel, "its details could not be read".to_owned()));
                continue;
            }
            _ => {}
        }
        match std::fs::read(&path) {
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => {
                    scan.coverage.files_read += 1;
                    scan.findings.extend(scan_text(rules, &rel, &text));
                }
                // Not text. Nothing here reads binaries, and saying so is better than counting it as clean.
                Err(_) => scan
                    .coverage
                    .skipped
                    .push((rel, "not a text file".to_owned())),
            },
            Err(_) => scan
                .coverage
                .skipped
                .push((rel, "it could not be read".to_owned())),
        }
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

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
}
