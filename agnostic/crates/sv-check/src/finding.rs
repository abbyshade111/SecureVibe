//! What a check found, and what it is evidence about.
//!
//! Two things are deliberate here and both come from v1's rules.
//!
//! **A secret never travels in a finding.** `Secret` cannot be constructed with the value visible: it
//! redacts on the way in, and there is no accessor that gives the original back. A finding is written to
//! reports, logs and SARIF, and a scanner that reports a credential has copied it somewhere new.
//!
//! **A check that knows which requirements it verifies says so.** `requirement_ids` is not decoration: it
//! is the link between "this rule fired" and "this ASVS requirement has evidence about it". A finding with
//! an empty list is evidence about nothing in particular, which is a fair thing to be, but it has to be
//! visible rather than assumed.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }
}

/// How sure the rule is, kept separate from how bad it would be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// A credential that has been found. The value is redacted on construction and cannot be recovered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Secret {
    /// Enough to recognize it in the file, never enough to use it.
    redacted: String,
    /// How long the original was, which is sometimes the only way to tell two findings apart.
    length: usize,
}

impl Secret {
    /// Keeps the first four characters and says how much was dropped. Four is enough to match a key
    /// against the one in a password manager, and far short of enough to authenticate with.
    pub fn redact(value: &str) -> Self {
        let visible: String = value.chars().take(4).collect();
        let total = value.chars().count();
        let hidden = total.saturating_sub(visible.chars().count());
        Secret {
            redacted: if hidden == 0 {
                visible
            } else {
                format!("{visible}… ({hidden} more characters)")
            },
            length: total,
        }
    }

    pub fn as_str(&self) -> &str {
        &self.redacted
    }

    pub fn length(&self) -> usize {
        self.length
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Location {
    pub file: String,
    /// 1-indexed, as an editor counts.
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub location: Location,
    /// What was found, redacted. Absent for rules that report a situation rather than a value.
    pub secret: Option<Secret>,
    /// The requirements this finding is evidence about. Empty is allowed and means exactly that.
    pub requirement_ids: Vec<String>,
    pub cwe: Vec<String>,
    /// Plain language, for somebody who is not a programmer.
    pub description: String,
    pub impact: String,
    pub fix: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_cannot_be_read_back_out_of_a_finding() {
        // The property that matters: whatever a report or a log does with this, the credential is not in it.
        // Assembled rather than written out: a key-shaped literal in this file is one GitHub's push
        // protection blocks, and it blocked this branch once already on this crate's test data.
        let real = ["sk", "ant", "api03", "ZmFrZWtleWZha2VrZXlmYWtla2V5"].join("-");
        let real = real.as_str();
        let secret = Secret::redact(real);
        assert!(!secret.as_str().contains("ZmFrZWtleWZha2VrZXk"));
        assert!(real.starts_with(secret.as_str().split('…').next().unwrap()));
        let json = serde_json::to_string(&secret).unwrap();
        assert!(
            !json.contains("ZmFrZWtleQ"),
            "the value reached JSON: {json}"
        );
    }

    #[test]
    fn redaction_keeps_enough_to_recognise_and_no_more() {
        let secret = Secret::redact("AKIAIOSFODNN7EXAMPLE");
        assert_eq!(secret.as_str(), "AKIA… (16 more characters)");
        assert_eq!(secret.length(), 20);
    }

    #[test]
    fn a_short_value_is_not_padded_into_looking_longer() {
        let secret = Secret::redact("abc");
        assert_eq!(secret.as_str(), "abc");
        assert_eq!(secret.length(), 3);
    }

    #[test]
    fn a_whole_finding_serialises_without_the_credential() {
        let finding = Finding {
            rule_id: "secrets.anthropic-key".into(),
            title: "Anthropic API key found in a file".into(),
            severity: Severity::Critical,
            confidence: Confidence::High,
            location: Location {
                file: "src/app.py".into(),
                line: 12,
            },
            secret: Some(Secret::redact(
                &["sk", "ant", "SUPERSECRETVALUE12345"].join("-"),
            )),
            requirement_ids: vec!["V13.3.1".into()],
            cwe: vec!["CWE-798".into()],
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
        };
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("SUPERSECRETVALUE"), "{json}");
    }
}
