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

/// The rule that reports a value that looks like a credential assigned to a name that says so. It
/// is written here rather than in `data/secret-rules.json`.
pub const ASSIGNMENT_RULE: &str = "secrets.credential-assignment";

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
    /// Files recognized by their contents as holding no text a person writes (an image, a font, a
    /// `.DS_Store`), with what each is. Not read, and named, but not a gap: there is no text in them
    /// for a credential to be written in.
    pub no_written_text: Vec<(String, String)>,
}

#[derive(Debug, Default)]
pub struct SecretScan {
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
    /// Set when the scan read every file it found and turned up nothing.
    pub verified: Vec<crate::Verified>,
}

/// Whether `value`, written under `name`, is a stored password hash rather than a credential: a
/// bcrypt hash (`$2b$12$` and 53 more characters) under a name that says password, hash, or digest,
/// or a hex digest (an MD5, SHA-1, or SHA-2 length: 32, 40, 56, 64, 96, or 128 hex digits) under a
/// name that says hash or digest. A stored hash is what an app keeps in place of a password; it is
/// not something to move into a secret store and change, which is what a credential finding asks.
///
/// Kept narrow on purpose, because it removes a finding. Measured on 4 October 2026
/// (`docs/SEMGREP-FALSE-ALARMS.md`, filters C and C2): skipping every hex-shaped value hid a real
/// 64-hex-digit token secret (`TokenSecret = "…"`), and a password made of hex digits is still a
/// password, so a hex value under a name that says only password is still reported. A name that
/// also says key, secret, token, salt, pepper, seed, or HMAC is still reported whatever the value: a
/// key for hashing is a key. Other hash formats (Argon2, PBKDF2, `crypt`) are not taken in.
pub fn is_stored_hash(name: &str, value: &str) -> bool {
    static BCRYPT: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$").expect("static pattern")
    });
    let n = name.to_lowercase();
    let says = |words: &[&str]| words.iter().any(|w| n.contains(w));
    if says(&["key", "secret", "token", "salt", "pepper", "seed", "hmac"]) {
        return false;
    }
    let says_hash = says(&["hash", "digest"]);
    let says_password = says(&["password", "passwd", "pwd"]);
    let hex_digest = matches!(value.len(), 32 | 40 | 56 | 64 | 96 | 128)
        && value.chars().all(|c| c.is_ascii_hexdigit());
    (BCRYPT.is_match(value) && (says_hash || says_password)) || (hex_digest && says_hash)
}

/// Whether one line of a file holds a stored password hash (`is_stored_hash`) and nothing else that
/// could be a credential: for a finding from another tool's secret rule, which names the line and not
/// the value. With the hash taken out, the line must give `sv`'s own secret rules nothing, and hold
/// no run of 16 or more letters and digits mixed that could be a key in a shape nobody listed. A line
/// with a hash and a key on it keeps its finding.
pub fn holds_only_stored_hashes(rules: &SecretRules, relative: &str, line: &str) -> bool {
    static TOKEN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/=_\-]{16,}").expect("static pattern"));
    let mut hashes: Vec<std::ops::Range<usize>> = named_values(relative, line)
        .into_iter()
        .filter(|n| is_stored_hash(n.name.as_str(), n.value.as_str()))
        .map(|n| n.value.range())
        .collect();
    if hashes.is_empty() {
        return false;
    }
    hashes.sort_by_key(|r| std::cmp::Reverse(r.start));
    hashes.dedup();
    let mut rest = line.to_owned();
    for range in hashes {
        rest.replace_range(range, "");
    }
    let token_shaped = TOKEN.find_iter(&rest).any(|m| {
        let t = m.as_str();
        t.chars().any(|c| c.is_ascii_digit())
            && t.chars().any(|c| c.is_ascii_alphabetic())
            && shannon_entropy(t) >= 3.0
    });
    !token_shaped && scan_text(rules, relative, &rest).is_empty()
}

/// Values that mean "fill this in", not a credential.
/// Whether the whole value is one reference to something kept elsewhere, in the shapes shells and
/// build files write one: `$NAME`, `${NAME}`, `$(command)` or backticks, Windows' `%NAME%`, and
/// PowerShell's `$env:NAME`. Only the whole value: `$NAME-extra-4f9a` or `pa$$w0rd…` carry text of
/// their own and are still judged. `export CF_ZONE_API_TOKEN="$CF_DNS_API_TOKEN"` was a HIGH finding
/// until 29 September 2026 (reported from cato-pipeline's CI), telling the owner to rotate a
/// credential that was never in the file.
fn is_whole_reference(value: &str) -> bool {
    static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)^(\$[a-z_][a-z0-9_]*|\$\{[a-z_][a-z0-9_]*(:?[-=?+][^}]*)?\}|%[a-z_][a-z0-9_]*%|\$env:[a-z_][a-z0-9_]*)$",
        )
        .expect("static pattern")
    });
    let v = value.trim();
    REFERENCE.is_match(v)
        || (v.starts_with("$(") && v.ends_with(')'))
        || (v.len() > 2 && v.starts_with('`') && v.ends_with('`'))
}

fn looks_like_placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    // `{new_password}`, `{code}`: the single-brace blanks `sv`'s own securevibe.toml fills in, whole.
    // `sv init`'s template raised a HIGH finding at its own commented example until 29 September
    // 2026 (found by the owner's comparison study). `{new_password}x9Q2vL` has text of its own.
    // `{html.escape(csrf_token)}`, `{session.csrf}`, `{tokens[0]}`: the whole value is one expression
    // a template or an f-string fills in, the way a page writes the anti-forgery token it made for
    // that request. One Haiku app drew eight high findings at such lines until 7 October 2026 (the
    // start-of-build test). Names, dots, calls, and indexes only: a quote inside the braces could
    // hold a literal, and text outside them is text of its own, so both are still judged.
    if let Some(expression) = v.strip_prefix('{').and_then(|r| r.strip_suffix('}'))
        && expression.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && expression.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '(' | ')' | '[' | ']' | ',' | ' ')
        })
    {
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
    // A short marker is spelled by chance among a real key's random characters often enough to
    // matter (`xxx`, `todo`), so it counts only as a word of its own; a longer one practically
    // never is, and counts anywhere, as `AKIAEXAMPLEEXAMPLE12` needs.
    if MARKERS.iter().any(|m| {
        if m.len() < 5 {
            has_word(&lower, m)
        } else {
            lower.contains(m)
        }
    }) {
        return true;
    }
    // `[redacted: Qv7r… (16 more characters)]`: `sv`'s own redaction of a value, as `redact_text`
    // writes it into a report. A report read back, as `sv bundle` reads its own before zipping it
    // (deep review S8), would otherwise find every credential it had redacted a second time. In
    // Markdown its brackets, and any in the four characters it shows, are escaped (R13), so
    // `\[redacted: Qv7r… (16 more characters)\]` is the same marker.
    static REDACTED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\\?\[redacted: (?:\\.|[^\\]){1,4}(… \(\d+ more characters\))?\\?\]$")
            .expect("static pattern")
    });
    if REDACTED.is_match(v) {
        return true;
    }
    // `${VAR}`, `<something>`, `{{ var }}` — a template, not a value.
    v.contains("${") || (v.starts_with('<') && v.ends_with('>')) || v.contains("{{")
}

/// Whether `word` appears in `text` as a word of its own: not after a letter or digit, and not
/// before a letter (a digit may follow, as in `todo1`). A short marker found inside a run of random
/// characters, `…aXxXb…` in a real key, is not a placeholder: until 5 October 2026 any occurrence
/// counted, and about one random JWT in a hundred was dropped as one (A4 of the deep review).
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        let starts_word = !word.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !before.is_some_and(|c| c.is_ascii_alphanumeric());
        let ends_word = !word.ends_with(|c: char| c.is_ascii_alphanumeric())
            || !after.is_some_and(|c| c.is_ascii_alphabetic());
        starts_word && ends_word
    })
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
            out.push(crate::finding::found(Finding {
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                earlier_fingerprints: Vec::new(),
                marked_test_code: false,
                bundled_library: None,
                outranked: None,
                also_on_this_line: Vec::new(),
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
            }));
        }
    }

    if !env_file {
        // A password in a web address; in a `.env` file it is where it belongs, as for the
        // assignment rule below.
        let already: Vec<usize> = out.iter().map(|f| f.location.line).collect();
        out.extend(
            url_password_findings(relative, text, first_line, &keep)
                .into_iter()
                .filter(|f| !already.contains(&f.location.line)),
        );
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

/// A password written into a web address's user part: `postgresql://admin:<password>@db.host/app`.
/// The assignment rule passes over any value holding `://`, since an address is usually not a
/// credential, so until 7 October 2026 a database address with its password was reported by nothing
/// (gap analysis 3.7).
static URL_PASSWORD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"\b[A-Za-z][A-Za-z0-9+.\-]{1,20}://(?P<user>[^\s:/@'"`<>]+):(?P<password>[^\s@/'"`<>]+)@[A-Za-z0-9_.\-\[]"#,
    )
    .expect("static pattern")
});

/// Passwords the stock images and examples ship with, which local development files are full of:
/// reported, they would bury the real ones. A password that only repeats the user name is set aside
/// the same way (`postgres:postgres`).
const STOCK_PASSWORDS: &[&str] = &[
    "password",
    "pass",
    "passwd",
    "secret",
    "postgres",
    "root",
    "admin",
    "changeme",
    "test",
    "user",
    "guest",
    "mysql",
    "redis",
    "rabbitmq",
    "minio",
    "minioadmin",
];

/// The password in a web address, if it is one to report: not a placeholder, a reference to a
/// setting (`${DB_PASSWORD}`, `%(password)s`, `<password>`), a stock one, or the user name again.
fn url_password<'t>(caps: &regex::Captures<'t>) -> Option<regex::Match<'t>> {
    let user = caps.name("user")?.as_str();
    let password = caps.name("password")?;
    let p = password.as_str();
    let lower = p.to_lowercase();
    let reference = p.starts_with(['$', '%', '<', '{', '*'])
        || p.contains("${")
        || p.contains("{{")
        || p.chars().all(|c| c == 'x' || c == 'X' || c == '*');
    // A real password almost never spells out the word itself; an example's does
    // (`mypassword`, `db_password`, `supersecret`).
    let says_so = ["password", "passwd", "secret"]
        .iter()
        .any(|w| lower.contains(w));
    if reference
        || says_so
        || looks_like_placeholder(p)
        || STOCK_PASSWORDS.contains(&lower.as_str())
        || lower == user.to_lowercase()
    {
        return None;
    }
    Some(password)
}

fn url_password_findings(
    relative: &str,
    text: &str,
    first_line: usize,
    keep: &std::ops::Range<usize>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for caps in URL_PASSWORD.captures_iter(text) {
        let Some(password) = url_password(&caps) else {
            continue;
        };
        if !keep.contains(&password.start()) {
            continue;
        }
        out.push(crate::finding::found(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
            rule_id: URL_PASSWORD_RULE.into(),
            title: "A password is written into a web address in a file".into(),
            severity: Severity::High,
            confidence: Confidence::Medium,
            location: Location {
                file: relative.to_owned(),
                line: first_line - 1 + line_of(text, password.start()),
            },
            secret: Some(Secret::redact(password.as_str())),
            requirement_ids: vec!["V13.3.1".into(), "SBD-AC-05".into()],
            cwe: vec!["CWE-798".into()],
            description: "A web address in this file carries a password in its user part \
                          (`scheme://user:password@host`), the way a database or message queue \
                          address is often written. A credential in a file is a secret kept in the \
                          app's code, where anyone who can read the code, or its history, can use it."
                .into(),
            impact: "Anyone with the file can sign in to that service as that user: for a database, \
                     read and change everything in it."
                .into(),
            fix: "Change the password on the service, then keep the whole address in .env (or a \
                  secret store) and read it from there, as `DATABASE_URL` usually is."
                .into(),
        }));
    }
    out
}

pub const URL_PASSWORD_RULE: &str = "secrets.password-in-url";

/// The shapes a name given a quoted value takes across languages, each with a `name` and a `value`
/// group. Separate patterns rather than one, because the typed shapes read a word between the name and
/// the `=`: in one pattern, Java's `String password = "…"` would be read as the name `String` with the
/// type `password`, and the line passed over.
///
/// The first shape is the one read until 4 October 2026, `name = "v"` and `name: "v"`, kept as it was;
/// a JSON or dict key, PHP's and Ruby's `=>`, Go's `:=`, a typed declaration, and a default given to an
/// environment variable in the code were reported by nothing (the deep review's H3). Each shape says
/// whether any text in it is a value: the first, as it always was, and a default given to a setting
/// whose name says it is a credential, which is that credential whatever it reads like
/// (`process.env.SESSION_SECRET || 'dev-session-secret'`). What the others find is judged once
/// more (`reads_as_text_or_a_name`).
static QUOTED_SHAPES: LazyLock<Vec<(Regex, bool)>> = LazyLock::new(|| {
    // The value runs to the quote that opened it, so `"Your password isn't right."` is read whole;
    // until 4 October 2026 either quote ended it, and the rule judged `Your password isn` instead.
    const VALUE: &str = r#"(?:"(?P<value>[^"\n]{8,200})"|'(?P<value1>[^'\n]{8,200})')"#;
    const NAME: &str = r"(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)";
    [
        // The shape read before: name = "v", name: "v".
        (format!(r#"{NAME}\s*[:=]\s*{VALUE}"#), true),
        // And "name": "v", 'name' => 'v', name := "v".
        (
            format!(r#"["']?{NAME}["']?\s*(?:=>|:=|:|=)\s*{VALUE}"#),
            false,
        ),
        // TypeScript, Kotlin, Swift, and Rust: `apiKey: string = "v"`, `API_KEY: &'static str = "v"`.
        (
            format!(
                r#"{NAME}\s*:\s*&?(?:'[a-z]+\s+)?[A-Za-z_][A-Za-z0-9_.<>\[\]?]*\s*=\s*{VALUE}"#
            ),
            false,
        ),
        // Go: `var password string = "v"`.
        (
            format!(r#"{NAME}[ \t]+[A-Za-z_][A-Za-z0-9_.\[\]*]*[ \t]*=\s*{VALUE}"#),
            false,
        ),
        // A default given in the code to a setting read from the environment, which is the
        // credential itself whenever the setting is not there: `os.getenv("X", "v")`,
        // `os.environ.get("X", "v")`, `ENV.fetch("X", "v")`, `env('X', 'v')`.
        (
            format!(
                r#"(?:getenv|environ\.get|environ\.setdefault|ENV\.fetch|getOrDefault|\benv)\s*\(\s*["']{NAME}["']\s*,\s*{VALUE}"#
            ),
            true,
        ),
        // The same default after the read: `process.env.X || "v"`, `process.env["X"] ?? "v"`,
        // `ENV["X"] || "v"`, `getenv('X') ?: 'v'`, `os.environ.get("X") or "v"`.
        (
            format!(
                r#"(?:process\.env\.{NAME}|(?:process\.env|ENV)\[\s*["']{NAME2}["']\s*\]|(?:getenv|environ\.get)\(\s*["']{NAME3}["']\s*\))\s*(?:\|\||\?\?|\?:|\bor\b)\s*{VALUE}"#,
                NAME2 = r"(?P<name2>[A-Za-z_][A-Za-z0-9_.\-]*)",
                NAME3 = r"(?P<name3>[A-Za-z_][A-Za-z0-9_.\-]*)",
            ),
            true,
        ),
    ]
    .into_iter()
    .map(|(p, any_text_is_a_value)| (Regex::new(&p).expect("static pattern"), any_text_is_a_value))
    .collect()
});

/// A name given a value with no quotes, read only in configuration files, where that is how a value
/// is written: YAML's `password: v`, and `password=v` in `.properties` and `.ini`. In code the same
/// shape is a call or another variable (`password = read_password()`), so it is not read there.
static UNQUOTED: LazyLock<Regex> = LazyLock::new(|| {
    // The value's first character leaves out YAML's other meanings: an anchor or alias (`&`, `*`),
    // a tag (`!secret db_password`), a block (`|`, `>`), a flow collection, and a quote.
    Regex::new(
        r#"(?m)^[ \t]*(?:-[ \t]+)?["']?(?P<name>[A-Za-z_][A-Za-z0-9_.\-]*)["']?[ \t]*[:=][ \t]*(?P<value>[^\s"'&*!|>{\[%@`#][^\s]{7,199})[ \t]*(?:[ \t]#.*)?\r?$"#,
    )
    .expect("static pattern")
});

/// A shell variable given a value with no quotes, in a shell script: `TOKEN=v`, `export TOKEN=v`,
/// and the same before a command (`DB_PASSWORD=v ./migrate`). A quoted value is the quoted shapes'
/// to read, so it is left to them and reported once. A value that is wholly another variable or a
/// command's output (`$X`, `${X}`, `$(…)`) is read and passed over as a reference, as in every shape.
static SHELL_UNQUOTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?m)^[ \t]*(?:(?:export|readonly|local|declare(?:[ \t]+-[A-Za-z]+)?)[ \t]+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^\s"'][^\s"']{7,199})(?:[ \t].*)?\r?$"#,
    )
    .expect("static pattern")
});

/// A Dockerfile's `ENV` or `ARG` given a value with no quotes: `ENV DB_PASSWORD=v`, `ENV DB_PASSWORD v`,
/// `ARG TOKEN=v`. Only the first name on a line is read. A value that is wholly a build argument
/// (`$TOKEN`) is passed over as a reference.
static DOCKERFILE_UNQUOTED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?mi)^[ \t]*(?:ENV|ARG)[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=|[ \t]+)(?P<value>[^\s"'][^\s"']{7,199})(?:[ \t].*)?\r?$"#,
    )
    .expect("static pattern")
});

/// The shape of a value written without quotes in this file, if its kind writes values so: see
/// `UNQUOTED`, `SHELL_UNQUOTED`, and `DOCKERFILE_UNQUOTED`. A shell script and a Dockerfile were read
/// only for quoted values until 5 October 2026 (H3's leftovers), so `export API_KEY=…` was found only
/// when a vendor's own rule knew the key.
fn unquoted_shape(relative: &str) -> Option<&'static Regex> {
    let name = relative
        .rsplit('/')
        .next()
        .unwrap_or(relative)
        .to_lowercase();
    if [".yml", ".yaml", ".properties", ".ini", ".cfg", ".conf"]
        .iter()
        .any(|ext| name.ends_with(ext))
    {
        return Some(&UNQUOTED);
    }
    if [".sh", ".bash", ".zsh", ".ksh"]
        .iter()
        .any(|ext| name.ends_with(ext))
    {
        return Some(&SHELL_UNQUOTED);
    }
    if name == "dockerfile"
        || name == "containerfile"
        || name.starts_with("dockerfile.")
        || name.ends_with(".dockerfile")
    {
        return Some(&DOCKERFILE_UNQUOTED);
    }
    None
}

/// A name given a value, and whether its shape takes any text as a value (see `QUOTED_SHAPES`).
struct Named<'t> {
    name: regex::Match<'t>,
    value: regex::Match<'t>,
    any_text_is_a_value: bool,
}

/// Every name given a value in `text`, in the shapes above, in the order the values come. One value
/// can come with more than one name: in `var password string = "v"` the first shape reads the type,
/// `string`, as the name, and the Go shape reads `password`. Both are kept, so the caller can judge
/// each name and report the value once.
fn named_values<'t>(relative: &str, text: &'t str) -> Vec<Named<'t>> {
    let unquoted = unquoted_shape(relative);
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let unquoted = unquoted.map(|shape| (shape, false));
    let quoted = QUOTED_SHAPES.iter().map(|(shape, any)| (shape, *any));
    for (shape, any_text_is_a_value) in quoted.chain(unquoted) {
        for caps in shape.captures_iter(text) {
            let name = ["name", "name2", "name3"]
                .iter()
                .find_map(|g| caps.name(g))
                .expect("every shape names its name");
            let value = caps
                .name("value")
                .or(caps.name("value1"))
                .expect("every shape names its value");
            // The first shape goes first, so a pair it found is judged as it was before.
            if seen.insert((name.start(), value.start())) {
                out.push(Named {
                    name,
                    value,
                    any_text_is_a_value,
                });
            }
        }
    }
    out.sort_by_key(|n| (n.value.start(), n.name.start()));
    out
}

/// Whether a value a newer shape found is text or a name rather than a credential: words with a
/// space between them, text with a letter outside ASCII (Japanese and Chinese put no space between
/// words, and a generated key or token is ASCII), a relative path (`./lib/tokenize.js`), or an identifier in lower case
/// (`config.workflow-fork-secrets`), as the upper-case one is already passed over. Reading JSON and
/// dict keys brought in every message catalog and schema whose key holds "token" or "password"
/// (TypeScript's "Unexpected token…" in thirteen languages, CycloneDX's "A secret word, phrase…"):
/// 90 false alarms in v1's `node_modules` and 17 in this repository and v1's code, before this.
/// A random credential has none of these shapes. A passphrase of words with spaces written as a
/// JSON value is the cost: it was not found before the newer shapes, and is not found now.
fn reads_as_text_or_a_name(value: &str) -> bool {
    value.chars().any(char::is_whitespace)
        || !value.is_ascii()
        || value.starts_with("./")
        || value.starts_with("../")
        || value
            .chars()
            .all(|c| c.is_ascii_lowercase() || matches!(c, '.' | '-' | '_'))
}

/// Whether a value reads like a sentence: three or more ordinary words, one space apart, the last
/// ending in `.`, `?`, or `!`. An ordinary word is letters only, with an apostrophe or hyphen
/// between letters (`isn't`, `sign-in`), a comma after it allowed on any but the last word, and
/// written in lowercase, with a capital first letter, or all in capitals. A digit, any other
/// symbol, a letter case mixed inside a word (`pAsS`), two spaces, or no closing mark and it is not
/// a sentence. Kept narrow on purpose: it lowers a finding, so what it takes in must look like a
/// message and nothing else, and a passphrase without closing punctuation, a key, or a token keeps
/// its severity.
fn reads_like_sentence(value: &str) -> bool {
    let Some(body) = value
        .strip_suffix('.')
        .or_else(|| value.strip_suffix('?'))
        .or_else(|| value.strip_suffix('!'))
    else {
        return false;
    };
    let words: Vec<&str> = body.split(' ').collect();
    if words.len() < 3 {
        return false;
    }
    let last = words.len() - 1;
    words.iter().enumerate().all(|(i, word)| {
        let word = if i < last {
            word.strip_suffix(',').unwrap_or(word)
        } else {
            word
        };
        is_ordinary_word(word)
    })
}

fn is_ordinary_word(word: &str) -> bool {
    let chars: Vec<char> = word.chars().collect();
    let (Some(first), Some(end)) = (chars.first(), chars.last()) else {
        return false;
    };
    if !first.is_alphabetic() || !end.is_alphabetic() {
        return false;
    }
    let joins_letters = |i: usize| chars[i - 1].is_alphabetic() && chars[i + 1].is_alphabetic();
    let shape_ok = chars.iter().enumerate().all(|(i, c)| {
        c.is_alphabetic() || (matches!(c, '\'' | '\u{2019}' | '-') && joins_letters(i))
    });
    let letters: Vec<char> = chars
        .iter()
        .copied()
        .filter(|c| c.is_alphabetic())
        .collect();
    let lower = letters.iter().all(|c| c.is_lowercase());
    let capitalized = letters[0].is_uppercase() && letters[1..].iter().all(|c| c.is_lowercase());
    let capitals = letters.iter().all(|c| c.is_uppercase());
    shape_ok && (lower || capitalized || capitals)
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
    let mut out = Vec::new();
    let mut reported = std::collections::HashSet::new();
    for Named {
        name: name_match,
        value: value_match,
        any_text_is_a_value,
    } in named_values(relative, text)
    {
        if !keep.contains(&name_match.start()) || reported.contains(&value_match.start()) {
            continue;
        }
        let name = name_match.as_str();
        let value = value_match.as_str();
        if !is_secret_name(name) || looks_like_placeholder(value) {
            continue;
        }
        if !any_text_is_a_value && reads_as_text_or_a_name(value) {
            continue;
        }
        // A reference to another variable, a path or a URL is not a credential, and nor is a value
        // kept encrypted in the file, as SOPS writes one (`ENC[AES256_GCM,data:…]`).
        if value.starts_with('/')
            || value.contains("://")
            || value.chars().all(|c| c.is_ascii_uppercase() || c == '_')
            || is_whole_reference(value)
            || value.starts_with("ENC[")
        {
            continue;
        }
        // Nor is a stored password hash, under a name that says so (see `is_stored_hash`).
        if is_stored_hash(name, value) {
            continue;
        }
        if shannon_entropy(value) < 3.5 {
            continue;
        }
        reported.insert(value_match.start());
        // A sentence under a credential's name is usually a message about the credential
        // (`WRONG_PASSWORD = "Your current password isn't right."`, family-hub, 3 October 2026), but
        // a real passphrase can be a sentence too. So it is still reported, low and "possible", and
        // says why, rather than left out. The redaction is the same either way: were it a
        // passphrase, the report must not hold it.
        let sentence = reads_like_sentence(value);
        let (severity, confidence) = if sentence {
            (Severity::Low, Confidence::Low)
        } else {
            (Severity::High, Confidence::Medium)
        };
        let (title, description, fix) = if sentence {
            (
                format!(
                    "A value written under a credential's name is in the code, but it reads like a \
                     sentence (`{name}`)"
                ),
                format!(
                    "`{name}` is set to a value in the code itself. The name says it holds a credential, \
                     and the value is not a placeholder, but this reads like a sentence: several \
                     ordinary words ending in a period, question mark, or exclamation mark. That is \
                     most often a message shown to people, such as an error message, and sometimes a \
                     passphrase."
                ),
                "This reads like a sentence, so read the line first. If it is a message shown to \
                 people, nothing needs changing: record it as a false alarm. If it is a passphrase, \
                 move it into the app's environment or secret store and change it: anything committed \
                 should be treated as known."
                    .to_owned(),
            )
        } else {
            (
                format!("A value that looks like a credential is written into the code (`{name}`)"),
                format!(
                    "`{name}` is set to a value in the code itself. The name says it holds a credential, \
                     and the value is not a placeholder."
                ),
                "Move the value into the app's environment or secret store, and change the credential: \
                 anything committed should be treated as known."
                    .to_owned(),
            )
        };
        out.push(crate::finding::found(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
            rule_id: ASSIGNMENT_RULE.into(),
            title,
            severity,
            confidence,
            location: Location {
                file: relative.to_owned(),
                line: first_line - 1 + line_of(text, value_match.start()),
            },
            secret: Some(Secret::redact(value)),
            requirement_ids: ASSIGNMENT_REQUIREMENTS.iter().map(|r| (*r).to_owned()).collect(),
            cwe: vec!["CWE-798".into(), "CWE-259".into()],
            description,
            impact: if sentence {
                "If it is a passphrase, anyone who can read the code — or the history it is kept in — \
                 has it. If it is a message, there is no harm."
            } else {
                "Anyone who can read the code — or the history it is kept in — has the credential."
            }
            .into(),
            fix,
        }));
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
    redact_text_in(rules, "", text)
}

/// `redact_text`, for text from the file at `relative` in the app: a value written without quotes
/// is then masked in the shapes that file's kind is read for (`unquoted_shape`), as the scan finds it
/// there: YAML's `password: v&w`, `.properties`' `secret=v,w`, a Dockerfile's `ENV TOKEN v`. Text
/// whose file is not known is masked as code is (item 17 of the review of 1 to 4 October, where those
/// were found in their files and masked only up to the `&` or `,`, or not at all).
pub fn redact_text_in(rules: &SecretRules, relative: &str, text: &str) -> (String, usize) {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (_, re) in &rules.rules {
        for m in re.find_iter(text) {
            if !looks_like_placeholder(m.as_str()) {
                spans.push((m.start(), m.end()));
            }
        }
    }
    // A single-quoted value runs on past a quote with a letter after it: Bandit's B105 quotes a
    // value as `'…'` whatever it holds, and in `'You've been signed out.'` the value does not end at
    // `You'` (deep review S8; the rest of a value that held a quote was left showing).
    static NAMED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*(?:"([^"\n]+)"|'((?:[^'\n]|'\w)+)'|([^\s"',;&]+))"#,
        )
        .expect("static pattern")
    });
    for caps in NAMED.captures_iter(text) {
        let name = caps.get(1).map_or("", |m| m.as_str());
        let Some(value) = caps.get(2).or(caps.get(3)).or(caps.get(4)) else {
            continue;
        };
        // Not a value of punctuation alone: in `password := "v"` and `password => "v"` this
        // pattern reads the `=` or `>` as the value, and the shapes below cut the real one.
        if is_secret_name(name)
            && !looks_like_placeholder(value.as_str())
            && value.as_str().chars().any(char::is_alphanumeric)
        {
            spans.push((value.start(), value.end()));
        }
    }
    // A password in a web address, cut wherever it is, a `.env` file included.
    for caps in URL_PASSWORD.captures_iter(text) {
        if let Some(password) = url_password(&caps) {
            spans.push((password.start(), password.end()));
        }
    }
    // And every shape the assignment rule reads (`:=`, `=>`, a typed declaration, a default given to
    // an environment variable), which the pattern above cuts short or misses.
    for Named { name, value, .. } in named_values(relative, text) {
        if is_secret_name(name.as_str()) && !looks_like_placeholder(value.as_str()) {
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
            Err(Unread::NoWrittenText(what)) => {
                scan.coverage
                    .no_written_text
                    .push((entry.relative.clone(), what.to_owned()));
                continue;
            }
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
            "{} file{}{}{}, against {} known credential formats plus the assignment rule",
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
            match scan.coverage.no_written_text.len() {
                0 => String::new(),
                n => format!(
                    "; {n} more not read, being images, fonts, or other files that hold no text a \
                     person writes"
                ),
            },
            rules.len()
        ),
    )]
}

/// Above this, a file is not something a person typed and reading it all costs more than it finds.
#[cfg(test)]
mod tests;
