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
    if let Some(name) = v.strip_prefix('{').and_then(|r| r.strip_suffix('}'))
        && !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
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
    if MARKERS.iter().any(|m| lower.contains(m)) {
        return true;
    }
    // `[redacted: Qv7r… (16 more characters)]`: `sv`'s own redaction of a value, as `redact_text`
    // writes it into a report. A report read back, as `sv bundle` reads its own before zipping it
    // (deep review S8), would otherwise find every credential it had redacted a second time.
    static REDACTED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^\[redacted: .{1,4}(… \(\d+ more characters\))?\]$").expect("static pattern")
    });
    if REDACTED.is_match(v) {
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

/// The files whose values are written without quotes: see `UNQUOTED`.
fn writes_values_unquoted(relative: &str) -> bool {
    let name = relative
        .rsplit('/')
        .next()
        .unwrap_or(relative)
        .to_lowercase();
    [".yml", ".yaml", ".properties", ".ini", ".cfg", ".conf"]
        .iter()
        .any(|ext| name.ends_with(ext))
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
    let unquoted = writes_values_unquoted(relative).then_some(&*UNQUOTED);
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
        out.push(Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            marked_test_code: false,
            rule_id: "secrets.credential-assignment".into(),
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
    // And every shape the assignment rule reads (`:=`, `=>`, a typed declaration, a default given to
    // an environment variable), which the pattern above cuts short or misses.
    for Named { name, value, .. } in named_values("", text) {
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
    #[test]
    fn sv_init_s_own_template_raises_no_credential_finding() {
        let found = scan_text(
            &rules(),
            "securevibe.toml",
            sv_manifest::spec::STARTER_MANIFEST,
        );
        assert!(
            found.is_empty(),
            "{:?}",
            found
                .iter()
                .map(|f| (&f.rule_id, f.location.line))
                .collect::<Vec<_>>()
        );
        // The setup: the template really has the line that tripped it.
        assert!(sv_manifest::spec::STARTER_MANIFEST.contains(r#"password = "{new_password}""#));
    }

    #[test]
    fn a_blank_in_sv_s_own_braces_is_a_placeholder_and_a_value_around_one_is_not() {
        let judged = |line: &str| {
            !assignment_findings("securevibe.toml", line, 1, &(0..usize::MAX)).is_empty()
        };
        assert!(!judged(r#"password = "{new_password}""#));
        assert!(!judged(r#"token = "{code}""#));
        // The control: the same blank with text of its own is still reported. Named, not printed.
        let with_text = ["{new_password}", "x9Q2vL7kP"].concat();
        assert!(
            judged(&format!(r#"password = "{with_text}""#)),
            "a value around a blank was passed over"
        );
    }

    #[test]
    fn a_value_that_is_wholly_a_reference_is_not_a_credential_and_one_that_contains_one_is() {
        let judged =
            |line: &str| !assignment_findings("run.sh", line, 1, &(0..usize::MAX)).is_empty();
        // Built from pieces, so no line here reads as a key to anything scanning this file.
        let suffix = ["4f9a", "2c7b"].concat();
        let password = ["pa$$w0rd", "Q7xZ9k2L"].concat();
        for line in [
            r#"export CF_ZONE_API_TOKEN="$CF_DNS_API_TOKEN""#.to_owned(),
            r#"TOKEN="$(cat /run/secrets/token)""#.to_owned(),
            r#"API_KEY="%API_KEY%""#.to_owned(),
            r#"$Password = "$env:DB_PASSWORD""#.to_owned(),
            "SECRET=\"`vault read -field=value secret/app`\"".to_owned(),
        ] {
            assert!(!judged(&line), "a reference was reported: {line}");
        }
        // The controls: a value with text of its own is still reported, so the lines above were
        // passed over for being references and not for the shape of the line.
        // Named rather than printed on failure: even a made-up credential is not written to output.
        for (case, line) in [
            (
                "a reference with text after it",
                format!(r#"API_KEY="$CF_DNS_API_TOKEN-extra-{suffix}""#),
            ),
            (
                "a password with dollar signs in it",
                format!(r#"PASSWORD="{password}""#),
            ),
        ] {
            assert!(judged(&line), "not reported: {case}");
        }
    }

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
        let snippets: [(usize, &str); 3] = [
            (mib - 64 * 1024 - 5, keys[0].as_str()),
            (mib - 10, keys[1].as_str()),
            (2 * mib + mib / 2, keys[2].as_str()),
        ];
        let mut line = String::from("{\"text\": \"");
        for (offset, snippet) in snippets {
            line.push_str(&"y".repeat(offset - line.len()));
            line.push(' ');
            line.push_str(snippet);
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
    fn an_assignment_in_the_overlap_is_reported_once_and_weaker() {
        // Alone on its line, since the assignment rule stands aside for a vendor key on the same
        // line. Inside the overlap: the first piece reads it as look-ahead and the second owns it,
        // so it is reported once, and with low confidence, as a large file's assignment is.
        let value = credential_shaped(&["Zq8", "Lm2", "Vx7", "Rt4", "Wp9", "Kd3"], "");
        let mib = 1024 * 1024;
        let mut line = String::from("{\"text\": \"");
        line.push_str(&"y".repeat(mib - 30_000 - line.len()));
        line.push_str(&format!(" password = '{value}' "));
        line.push_str(&"y".repeat(3 * mib - line.len()));
        line.push_str("\"}\n");
        let dir = big_scratch("overlap-assignment");
        std::fs::write(dir.join("catalog.json"), &line).unwrap();
        let scan = scan_dir(&rules(), &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            scan.coverage.read_in_pieces,
            ["catalog.json"],
            "the setup: read in pieces"
        );
        let assigned: Vec<&Finding> = scan
            .findings
            .iter()
            .filter(|f| f.rule_id == "secrets.credential-assignment")
            .collect();
        assert_eq!(assigned.len(), 1, "the assignment in the overlap, once");
        assert_eq!(assigned[0].confidence, Confidence::Low);
        let rendered = serde_json::to_string(&scan.findings).unwrap();
        assert!(
            !rendered.contains(value.as_str()),
            "the value reached the finding"
        );
    }

    #[test]
    fn a_large_file_of_accented_text_is_read_and_not_called_binary() {
        // Two- and four-byte characters throughout, so pieces end in the middle of one: the scan
        // must read on, and find the key past the 2 MB mark, rather than refuse the file.
        let key = aws_key("Q7RZ2KV9LP4WN8HG");
        let mut text = "Détails 🔑 réglementés ü\n".repeat(100_000);
        text.push_str(&format!("aws = {key}\n"));
        let dir = big_scratch("accented");
        std::fs::write(dir.join("catalogue.txt"), &text).unwrap();
        let scan = scan_dir(&rules(), &dir);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            text.len() as u64 > sv_scan::files::MAX_FILE_BYTES,
            "the setup: over 2 MB"
        );
        assert!(
            scan.coverage.skipped.is_empty(),
            "{:?}",
            scan.coverage.skipped
        );
        let aws = scan
            .findings
            .iter()
            .find(|f| f.rule_id == "secrets.aws-access-key")
            .expect("the key past 2 MB is found");
        assert_eq!(aws.location.line, 100_001);
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

    /// The deep review's H3: the shapes a credential is written in that only `name = "v"` and
    /// `name: "v"` were read in until 4 October 2026. `{v}` is replaced by a made-up value built at
    /// run time; findings are named, never printed, on failure.
    const SHAPES_CAUGHT: &[(&str, &str, &str)] = &[
        ("a JSON key", "config.json", r#"{ "password": "{v}" }"#),
        (
            "a Python dict key",
            "app.py",
            r#"CONFIG = {"api_key": "{v}"}"#,
        ),
        ("PHP's =>", "config.php", r#"'password' => '{v}',"#),
        ("Ruby's =>", "config.rb", r#"{ :secret_key => "{v}" }"#),
        ("Go's :=", "main.go", r#"	dbPassword := "{v}""#),
        (
            "Go's var with a type",
            "main.go",
            r#"var dbPassword string = "{v}""#,
        ),
        (
            "TypeScript's typed const",
            "app.ts",
            r#"const apiKey: string = "{v}";"#,
        ),
        // Read twice, once with the type as the name: reported once.
        (
            "a TypeScript type named like a key",
            "app.ts",
            r#"const apiKey: ApiKey = "{v}";"#,
        ),
        (
            "Kotlin's typed val",
            "App.kt",
            r#"val password: String = "{v}""#,
        ),
        (
            "Rust's typed const",
            "main.rs",
            r#"const API_KEY: &'static str = "{v}";"#,
        ),
        (
            "Java's typed field",
            "App.java",
            r#"private static final String DB_PASSWORD = "{v}";"#,
        ),
        (
            "unquoted YAML",
            "config.yml",
            "database:\n  password: {v}\n",
        ),
        (
            "unquoted YAML in a list",
            "compose.yaml",
            "  - token: {v}  # prod\n",
        ),
        ("a .properties line", "app.properties", "db.password={v}\n"),
        (
            "Python's getenv default",
            "app.py",
            r#"os.getenv("DB_PASSWORD", "{v}")"#,
        ),
        (
            "Python's environ.get default",
            "app.py",
            r#"os.environ.get('SECRET_KEY', '{v}')"#,
        ),
        (
            "Python's or default",
            "app.py",
            r#"os.environ.get("SECRET_KEY") or "{v}""#,
        ),
        (
            "Ruby's ENV.fetch default",
            "app.rb",
            r#"ENV.fetch("API_KEY", "{v}")"#,
        ),
        (
            "Ruby's ENV[] || default",
            "app.rb",
            r#"ENV["API_KEY"] || "{v}""#,
        ),
        (
            "Node's || default",
            "app.js",
            r#"const s = process.env.JWT_SECRET || "{v}";"#,
        ),
        (
            "Node's ?? default",
            "app.ts",
            r#"process.env["JWT_SECRET"] ?? '{v}'"#,
        ),
        (
            "Laravel's env default",
            "config.php",
            r#"'password' => env('DB_PASSWORD', '{v}'),"#,
        ),
        (
            "PHP's getenv ?: default",
            "db.php",
            r#"$p = getenv('DB_PASSWORD') ?: '{v}';"#,
        ),
    ];

    /// A made-up credential: mixed case and digits, no quote, `#`, or space, so every shape can hold it.
    fn made_up_value() -> String {
        ["Xk7mQ92v", "LpR4sTzW"].concat()
    }

    #[test]
    fn a_credential_is_found_in_every_shape_it_is_commonly_written_in() {
        let value = made_up_value();
        let mut missed = Vec::new();
        for (case, file, template) in SHAPES_CAUGHT {
            let text = template.replace("{v}", &value);
            let found = scan_text(&rules(), file, &format!("{text}\n"));
            let assigned: Vec<&Finding> = found
                .iter()
                .filter(|f| f.rule_id == "secrets.credential-assignment")
                .collect();
            if assigned.len() != 1 {
                missed.push(format!("{case}: {} findings", assigned.len()));
                continue;
            }
            let rendered = serde_json::to_string(&found).unwrap();
            assert!(
                !rendered.contains(&value),
                "{case}: the value reached the finding"
            );
        }
        assert!(missed.is_empty(), "not found exactly once: {missed:?}");
    }

    #[test]
    fn the_new_shapes_pass_over_what_is_not_a_credential_in_the_clear() {
        let value = made_up_value();
        // The setup: the made-up value is one the rule reports, so each line below is passed over for
        // what it is and not for the value.
        assert!(!scan_text(&rules(), "app.py", &format!("password = \"{value}\"\n")).is_empty());
        for (case, file, text) in [
            (
                "a getenv with no default",
                "app.py",
                r#"os.getenv("DB_PASSWORD")"#.to_owned(),
            ),
            (
                "a getenv default that is a placeholder",
                "app.py",
                r#"os.getenv("DB_PASSWORD", "changeme-please")"#.to_owned(),
            ),
            (
                "a default under a harmless name",
                "app.py",
                format!(r#"os.getenv("LOG_LEVEL", "{value}")"#),
            ),
            (
                "a typed value under a harmless name",
                "app.ts",
                format!(r#"const greeting: string = "{value}";"#),
            ),
            (
                "a Go value under a harmless name",
                "main.go",
                format!(r#"var greeting string = "{value}""#),
            ),
            (
                "a JSON key with a harmless name",
                "package.json",
                format!(r#"{{ "version": "{value}" }}"#),
            ),
            (
                "YAML read from a reference",
                "config.yml",
                "password: ${DB_PASSWORD}\n".to_owned(),
            ),
            (
                "a Home Assistant secret",
                "configuration.yaml",
                "password: !secret db_password\n".to_owned(),
            ),
            (
                "a YAML alias",
                "config.yml",
                "password: *db_password_value\n".to_owned(),
            ),
            (
                "a SOPS-encrypted value",
                "secrets.yaml",
                format!("password: ENC[AES256_GCM,data:{value},iv:{value},type:str]\n"),
            ),
            (
                "an unquoted value in code, which is a call",
                "app.py",
                "password = read_password_from_vault()\n".to_owned(),
            ),
            (
                "an unquoted value in a file that is not configuration",
                "notes.md",
                format!("password: {value}\n"),
            ),
        ] {
            let found = scan_text(&rules(), file, &format!("{text}\n"));
            assert!(
                found.is_empty(),
                "reported {case}: {} findings",
                found.len()
            );
        }
    }

    #[test]
    fn what_only_the_new_shapes_find_is_passed_over_when_it_is_text_or_a_name() {
        // The false alarms reading JSON and dict keys first brought in, each from v1's code or its
        // `node_modules` on 4 October 2026.
        for (case, file, line) in [
            (
                "a message catalog",
                "diagnosticMessages.generated.json",
                r#""Unexpected_token_1012": "Unexpected token. A constructor, method, accessor, or property was expected.","#,
            ),
            (
                "a message catalog with no spaces between words",
                "diagnosticMessages.generated.json",
                "\"Unexpected_token_1012\": \"\u{4e88}\u{671f}\u{3057}\u{306a}\u{3044}\u{30c8}\u{30fc}\u{30af}\u{30f3}\u{3067}\u{3059}\u{3002}\",",
            ),
            (
                "a package's export map",
                "package.json",
                r#""./lib/tokenize": "./lib/tokenize.js","#,
            ),
            (
                "a rule id in a typed constant",
                "workflows.rs",
                r#"pub const FORK_SECRETS: &str = "config.workflow-fork-secrets";"#,
            ),
            (
                "a sentence under a quoted key",
                "metrics.ts",
                r#"'auth_token_issued': 'Sign-in tokens issued today',"#,
            ),
        ] {
            let found = scan_text(&rules(), file, &format!("{line}\n"));
            assert!(
                found.is_empty(),
                "reported {case}: {} findings",
                found.len()
            );
        }
        // The controls. The shape read before 4 October 2026 is judged as it was, so a passphrase it
        // found is still found; written as a JSON value, it is the stated cost, and not found.
        let passphrase = ["Tr0ub4dor", "and 3 horses"].join(" ");
        assert!(
            !scan_text(
                &rules(),
                "app.py",
                &format!("password = \"{passphrase}\"\n")
            )
            .is_empty(),
            "the shape read before lost a passphrase"
        );
        assert!(
            scan_text(
                &rules(),
                "config.json",
                &format!("{{\"password\": \"{passphrase}\"}}\n")
            )
            .is_empty()
        );
        // An assignment inside a JSON string, as a report's example holds one. A wider first shape
        // read `"example": "// Before\nconst apiKey = '` as one name and value, and the regex went on
        // past the real assignment: found in v1's self-assessment report before, lost by that version.
        let in_a_string = format!(
            r#""example": "// Before\nconst apiKey = '{}';\n// After","#,
            made_up_value()
        );
        assert_eq!(
            scan_text(&rules(), "report.json", &format!("{in_a_string}\n")).len(),
            1,
            "an assignment inside a JSON string"
        );
        // A default given to a secret setting is a value whatever it reads like: lower case and
        // hyphens is how a made-up fallback secret is written (v1's planted fixture is one).
        let fallback = ["dev", "session", "secret", "for", "local"].join("-");
        assert_eq!(
            scan_text(
                &rules(),
                "app.js",
                &format!("const s = process.env.SESSION_SECRET || '{fallback}';\n"),
            )
            .len(),
            1,
            "a lower-case default for a secret setting"
        );
        assert_eq!(
            scan_text(
                &rules(),
                "app.py",
                &format!("os.getenv('SESSION_SECRET', '{fallback}')\n")
            )
            .len(),
            1,
            "a lower-case default given to getenv"
        );
        // And a credential with no space, path, or lower-case-only shape is still found in a JSON key.
        let value = made_up_value();
        assert!(
            !scan_text(
                &rules(),
                "config.json",
                &format!("{{\"password\": \"{value}\"}}\n")
            )
            .is_empty()
        );
    }

    #[test]
    fn redacting_cuts_a_value_in_the_new_shapes_too() {
        let value = made_up_value();
        for template in [
            r#"dbPassword := "{v}""#,
            r#"'password' => '{v}'"#,
            r#"os.getenv("DB_PASSWORD", "{v}")"#,
            r#"const apiKey: string = "{v}";"#,
        ] {
            let (out, n) = redact_text(&rules(), &template.replace("{v}", &value));
            // No message prints `out`: were a cut missed, it would hold the value.
            assert!(!out.contains(&value), "not cut: {template}");
            assert!(n >= 1, "{template}: nothing cut");
            // The older pattern reads the `=` of `:=` and the `>` of `=>` as a value; cutting those
            // tells the reader nothing.
            assert!(
                !out.contains("[redacted: =") && !out.contains("[redacted: >"),
                "{template}: punctuation cut as a value"
            );
        }
    }

    /// The one assignment finding on `line`, which must be there: a control that is not reported
    /// at all would pass "keeps its severity" for the wrong reason.
    fn the_assignment(line: &str) -> Finding {
        let found = assignment_findings("app/views.py", line, 1, &(0..usize::MAX));
        assert_eq!(
            found.len(),
            1,
            "expected one finding on a line of {} characters",
            line.len()
        );
        found.into_iter().next().expect("one finding")
    }

    #[test]
    fn a_message_under_a_password_name_is_reported_low_and_says_it_reads_like_a_sentence() {
        // family-hub, 3 October 2026: this line was rated high, with advice to change the credential.
        let message = "Your current password isn't right.";
        let line = format!(r#"WRONG_PASSWORD = "{message}""#);
        let f = the_assignment(&line);
        assert_eq!(f.severity, Severity::Low);
        assert_eq!(f.certainty(), "possible");
        assert!(f.title.contains("reads like a sentence"), "{}", f.title);
        assert!(f.description.contains("reads like a sentence"));
        assert!(f.fix.contains("reads like a sentence"));
        assert!(!f.fix.starts_with("Move the value"), "{}", f.fix);
        // The whole message was judged, not the part before the apostrophe, and it is still
        // redacted: a passphrase can be a sentence, so the report holds four characters of it.
        let secret = f.secret.as_ref().expect("the value is recorded, redacted");
        assert_eq!(secret.length(), message.chars().count());
        assert_eq!(secret.as_str(), "Your… (30 more characters)");
        let rendered = serde_json::to_string(&f).unwrap();
        assert!(
            !rendered.contains("current password isn"),
            "the value reached the finding"
        );

        // Other messages an app shows, under names of every kind the rule reads. Each must clear
        // the entropy gate first, or "not reported high" would say nothing.
        for line in [
            r#"PASSWORD_MISMATCH = "Passwords do not match!""#,
            r#"token_prompt: 'Is this the token you were sent?'"#,
            r#"API_KEY_HELP = "Please paste your key here, then press save.""#,
            r#"secret_hint = "We'll never share your secret.""#,
            r#"RESET_PASSWORD = "Check your email for a sign-in link.""#,
        ] {
            let f = the_assignment(line);
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::Low, Confidence::Low),
                "{line}"
            );
        }
    }

    #[test]
    fn passphrases_keys_and_tokens_that_are_not_sentences_keep_their_severity() {
        // Built at run time, so this file holds no key-shaped literal.
        let key = filler(32, MIXED);
        let token = credential_shaped(&[&filler(12, MIXED), &filler(20, LETTERS)], ".");
        for (case, value) in [
            // A passphrase is words too; without the closing mark it is not a sentence.
            (
                "a passphrase without closing punctuation",
                "violet harbor quickly juggles nine lanterns".to_owned(),
            ),
            (
                "a capitalized passphrase without closing punctuation",
                "Violet Harbor Quickly Juggles Nine Lanterns".to_owned(),
            ),
            (
                "a passphrase with a digit in it",
                "violet harbor juggles 9 lanterns.".to_owned(),
            ),
            (
                "a passphrase with a digit inside a word",
                "violet harb0r quickly juggles lanterns.".to_owned(),
            ),
            (
                "a passphrase with symbols for letters",
                "v1olet h@rbor jugg!es lanterns.".to_owned(),
            ),
            (
                "a passphrase joined by hyphens",
                "violet-harbor-quickly-juggles.".to_owned(),
            ),
            (
                "words whose letter case is mixed",
                "vIoLeT harBOR juggles lanterns.".to_owned(),
            ),
            (
                "words two spaces apart",
                "violet  harbor juggles lanterns.".to_owned(),
            ),
            ("two words only", "Wrong password.".to_owned()),
            ("a key", key.clone()),
            ("a key ending in a period", format!("{key}.")),
            ("a token with a dot in it", token),
        ] {
            let f = the_assignment(&format!(r#"db_password = "{value}""#));
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::High, Confidence::Medium),
                "{case}"
            );
            assert!(!f.description.contains("sentence"), "{case}");
        }
    }

    #[test]
    fn what_reads_like_a_sentence_is_narrow() {
        for yes in [
            "Your current password isn't right.",
            "Your current password isn\u{2019}t right.",
            "Is this your password?",
            "Passwords do not match!",
            "Sorry, that sign-in link has expired.",
            "The API key is missing.",
            "Ce mot de passe est trop court.",
        ] {
            assert!(reads_like_sentence(yes), "{yes:?}");
        }
        for no in [
            "Your current password isn't right",
            "Your password.",
            "Your password .",
            " Your current password is wrong.",
            "Your current password is wrong. ",
            "Your current password is wrong..",
            "Your current password, is wrong,.",
            "Your current passw0rd is wrong.",
            "Your current pass_word is wrong.",
            "Your current 'password' is wrong.",
            "Your current password is - wrong.",
            "Your current password is wrong\t.",
            "Your cuRRent password is wrong.",
        ] {
            assert!(!reads_like_sentence(no), "{no:?}");
        }
    }

    #[test]
    fn a_value_runs_to_the_quote_that_opened_it() {
        // Until 4 October 2026 either quote ended a value, so an apostrophe cut a message short and
        // the rule judged a fragment. Each quote now ends only a value it opened.
        let quoted = r#"She said "keep it" twice"#;
        let f = the_assignment(&format!("secret_note = '{quoted}'"));
        assert_eq!(
            f.secret.as_ref().map(Secret::length),
            Some(quoted.chars().count())
        );
        // A sentence redacted when `sv` passes text on, whatever its severity as a finding.
        let message = "Your current password isn't right.";
        let (out, n) = redact_text(&rules(), &format!(r#"WRONG_PASSWORD = "{message}""#));
        assert_eq!(n, 1);
        assert!(!out.contains(message));
    }

    #[test]
    fn a_tool_s_quoted_value_with_an_apostrophe_in_it_is_redacted_whole() {
        // Bandit's B105, as it read in a real report on 4 October 2026: the value is a message, and
        // the redaction stopped at `You'`, leaving the rest of it showing (deep review S8).
        let value = [
            "Pass",
            "word changed. You've been ",
            "signed out everywhere else.",
        ]
        .concat();
        let (out, n) = redact_text(&rules(), &format!("Possible hardcoded password: '{value}'"));
        assert_eq!(n, 1, "{out}");
        assert_eq!(
            out,
            format!(
                "Possible hardcoded password: '[redacted: Pass… ({} more characters)]'",
                value.chars().count() - 4
            )
        );
        // Two values side by side are still two: a quote with no letter after it ends the first.
        let (out, n) = redact_text(&rules(), "{'password': 'Qv7rLm2x', 'token': 'Tz9kWp4n'}");
        assert_eq!(n, 2, "{out}");
        assert!(out.contains("'token': '[redacted: Tz9k"), "{out}");
    }

    #[test]
    fn sv_s_own_redaction_read_back_is_not_a_credential() {
        // A report holding what `redact_text` wrote, scanned again as `sv bundle` scans its own
        // report: the marker is not a value, so finding it would refuse every such bundle.
        let password = ["Qv7r", "Lm2x", "Tz9k"].concat();
        let (redacted, n) = redact_text(
            &rules(),
            &format!("Possible hardcoded password: '{password}'"),
        );
        assert_eq!(n, 1);
        for text in [
            redacted.clone(),
            format!("password = \"{}\"", redacted.split('\'').nth(1).unwrap()),
            "PASSWORD: \"[redacted: abc]\"".to_owned(),
        ] {
            let found = scan_text(&rules(), "report/security.md", &format!("{text}\n"));
            assert!(found.is_empty(), "{text}: {found:?}");
        }
        // The control: the value itself is found there, and a marker with text of its own is a value.
        for text in [
            format!("Possible hardcoded password: '{password}'"),
            format!("password = \"[redacted: Qv7r… (8 more characters)]{password}\""),
        ] {
            assert!(
                !scan_text(&rules(), "report/security.md", &format!("{text}\n")).is_empty(),
                "not found: the scan does not read this shape, so the test proves nothing"
            );
        }
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
    fn the_rule_data_finds_what_it_promises_and_grades_a_test_key_below_a_live_one() {
        // A5 of the deep review. Every value is put together here, so the file holds no key.
        let found = |text: &str| scan_text(&rules(), "src/config.txt", text);
        let rule_of = |text: &str| {
            let f = found(text);
            assert_eq!(f.len(), 1, "{f:?}");
            (f[0].rule_id.clone(), f[0].severity)
        };
        // Slack's app-level token, which the rule's own description named and its pattern missed.
        let xapp = credential_shaped(
            &[
                "xapp",
                "1",
                "A0123456789",
                "1234567890123",
                "0a1b2c3d4e5f6a7b8c9d",
            ],
            "-",
        );
        assert_eq!(
            rule_of(&format!("SLACK_APP_TOKEN={xapp}\n")).0,
            "secrets.slack-token"
        );
        // A PGP private key block, beside the PEM ones it already found.
        let pgp = format!("-----BEGIN PGP {} KEY BLOCK-----\nlQOYBF\n", "PRIVATE");
        assert_eq!(rule_of(&pgp).0, "secrets.private-key-block");
        let pem = format!("-----BEGIN {} KEY-----\nMIIE\n", "PRIVATE");
        assert_eq!(rule_of(&pem).0, "secrets.private-key-block");
        // A public PGP block is not a secret.
        let public = format!("-----BEGIN PGP {} KEY BLOCK-----\nmQIN\n", "PUBLIC");
        assert!(found(&public).is_empty(), "{:?}", found(&public));
        // Stripe's test key cannot move money; its live key can.
        let live = credential_shaped(&["sk", "live", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
        let test = credential_shaped(&["sk", "test", "51HxaMpLeKeyV4lu3Abcdefghijk"], "_");
        assert_eq!(
            rule_of(&format!("STRIPE_KEY={live}\n")),
            ("secrets.stripe-key".to_owned(), Severity::Critical)
        );
        assert_eq!(
            rule_of(&format!("STRIPE_KEY={test}\n")),
            ("secrets.stripe-test-key".to_owned(), Severity::Medium)
        );
        // The private key rule says what it found, not only why it matters.
        let block = rules()
            .rules()
            .find(|r| r.id == "secrets.private-key-block")
            .map(|r| r.description.clone())
            .unwrap();
        assert!(block.starts_with("A private key"), "{block}");
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
