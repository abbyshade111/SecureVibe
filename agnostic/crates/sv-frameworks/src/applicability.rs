//! The applicability engine: which requirements apply to this app.
//!
//! A port of v1's `server/src/frameworks/applicability.ts`, reading the same
//! `data/knowledge/applicability.json`. Resolution for a requirement id is unchanged:
//!
//!   1. requirements above the target level are out-of-level;
//!   2. the most specific rule scope wins: requirement id > section id > chapter id;
//!   3. several rules at the same scope are OR-ed, which is how "V12.3 applies with external APIs,
//!      AI or email" is expressed with a single-condition schema;
//!   4. no rule at all means the requirement applies.
//!
//! Rule 4 is the one that makes the whole thing safe to drive from a manifest instead of a wizard:
//! silence means applies, so a claim that goes missing costs the user a requirement they must meet,
//! never one they are wrongly told to skip.

use crate::load::{Frameworks, RequirementInfo, chapter_id_of, section_id_of};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

/// The conditions an applicability rule can test. Identical to v1's enum, so the same
/// `applicability.json` loads in both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Condition {
    Always,
    Never,
    Auth,
    NoAuth,
    Uploads,
    Ai,
    AiActions,
    AiHistory,
    AiModeration,
    Email,
    ExternalApis,
    PublicApi,
    Payments,
    Scheduler,
    Tls,
    Internet,
    Level2,
    Oauth,
    Webrtc,
    Jwt,
    Rag,
    Mcp,
    MultiTenant,
    Training,
    SelfAssessment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VerificationClass {
    Automatable,
    AiAssistable,
    DocGenerated,
    ScannerClean,
    ManualOnly,
    DeploymentTime,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    /// Requirement id, section id ("V10.1") or chapter id ("V17"). Most specific wins.
    pub scope: String,
    pub condition: Condition,
    #[serde(default)]
    pub not_applicable_reason: Option<String>,
    #[serde(default)]
    pub verification_class: Option<VerificationClass>,
    #[serde(default)]
    pub deployment_note: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApplicabilityConfig {
    pub rules: Vec<Rule>,
    /// Requirement ids that can never be `pass`.
    pub manual_only: Vec<String>,
    pub default_verification_class: VerificationClass,
}

impl ApplicabilityConfig {
    pub fn load(knowledge_dir: &Path) -> Result<Self> {
        let path = knowledge_dir.join("applicability.json");
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    /// The rules at the most specific scope covering `id`; empty when none.
    pub fn rules_for(&self, id: &str) -> Vec<&Rule> {
        for scope in [id, section_id_of(id), chapter_id_of(id)] {
            let matching: Vec<&Rule> = self.rules.iter().filter(|r| r.scope == scope).collect();
            if !matching.is_empty() {
                return matching;
            }
        }
        Vec::new()
    }

    /// Manual-only list first, then the most specific rule that states one, then the default.
    pub fn verification_class_for(&self, id: &str) -> VerificationClass {
        if self.manual_only.iter().any(|m| m == id) {
            return VerificationClass::ManualOnly;
        }
        self.rules_for(id)
            .into_iter()
            .find_map(|r| r.verification_class)
            .unwrap_or(self.default_verification_class)
    }

    pub fn deployment_note_for(&self, id: &str) -> Option<&str> {
        self.rules_for(id)
            .into_iter()
            .find_map(|r| r.deployment_note.as_deref())
    }
}

/// Which conditions hold for this app. Built from the manifest's claims after corroboration, where
/// v1 built it from wizard answers.
#[derive(Debug, Clone, Default)]
pub struct ConditionContext {
    holds: HashMap<Condition, bool>,
}

impl ConditionContext {
    pub fn set(&mut self, condition: Condition, value: bool) {
        self.holds.insert(condition, value);
    }

    /// An unset condition is false, which — with rule 4 above — means a requirement gated on it
    /// still applies unless a rule says otherwise.
    pub fn holds(&self, condition: Condition) -> bool {
        match condition {
            Condition::Always => true,
            Condition::Never => false,
            other => self.holds.get(&other).copied().unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotApplicable {
    pub id: String,
    pub reason: String,
    /// The condition that switched this requirement off. Carried so a report can say *why* a
    /// requirement was excluded, and so `never` rules can be counted rather than trusted: their
    /// reasons in `applicability.json` were written about v1's Node template and are claims about
    /// a stack `sv` cannot assume.
    pub condition: Condition,
}

#[derive(Debug, Default)]
pub struct Buckets {
    pub applicable: Vec<String>,
    pub not_applicable: Vec<NotApplicable>,
    pub out_of_level: Vec<String>,
}

/// Plain-language fallback when a rule gives no reason. Written for someone who is not a programmer,
/// as everything user-facing in this project is.
pub fn default_not_applicable_reason(condition: Condition) -> &'static str {
    use Condition::*;
    match condition {
        Always => "This requirement always applies.",
        Never => "This requirement covers a technology or setup this app does not use.",
        Auth => {
            "This app has no sign-in, so there are no accounts, passwords or sessions to protect."
        }
        NoAuth => {
            "This app has sign-in, so this requirement for apps without accounts does not apply."
        }
        Uploads => "This app does not accept file uploads.",
        Ai => "This app has no AI features.",
        AiActions => "The AI can only answer questions; it cannot change data or take actions.",
        AiHistory => "The AI does not keep conversation history between visits.",
        AiModeration => "Content moderation is not turned on for the AI.",
        Email => "This app does not send email.",
        ExternalApis => "This app does not call other services over the network.",
        PublicApi => "This app does not offer API keys for other programs to connect.",
        Payments => "This app does not take payments.",
        Scheduler => "This app has no scheduled background jobs.",
        Tls => {
            "This app runs on one computer only, without HTTPS, so there is no network connection to encrypt."
        }
        Internet => "This app is not intended to go on the internet.",
        Level2 => "This only applies at level 2, and this app targets level 1.",
        Oauth => {
            "This app uses its own accounts, not sign-in through another provider (OAuth or OpenID Connect)."
        }
        Webrtc => "This app has no real-time audio or video calls (WebRTC).",
        Jwt => "This app does not issue self-contained tokens such as JWTs.",
        Rag => {
            "The AI does not search a document store or vector database (no retrieval-augmented generation)."
        }
        Mcp => "The AI does not use the Model Context Protocol (MCP) to talk to tools.",
        MultiTenant => {
            "This app serves one organisation, not several separate customer organisations sharing one system."
        }
        Training => {
            "This app does not train or fine-tune any AI model; it uses a ready-made model from a vendor."
        }
        SelfAssessment => "This is only evaluated when SecureVibe assesses itself.",
    }
}

/// Sorts every requirement in `frameworks` into applies / does not apply / above the target level.
pub fn bucket(
    frameworks: &Frameworks,
    config: &ApplicabilityConfig,
    ctx: &ConditionContext,
    target_level: u8,
) -> Buckets {
    let mut out = Buckets::default();
    for req in frameworks.requirements.values() {
        if req.level > target_level {
            out.out_of_level.push(req.id.clone());
            continue;
        }
        let matching = config.rules_for(&req.id);
        if matching.is_empty() || matching.iter().any(|r| ctx.holds(r.condition)) {
            out.applicable.push(req.id.clone());
        } else {
            out.not_applicable.push(not_applicable_for(req, &matching));
        }
    }
    out
}

fn not_applicable_for(req: &RequirementInfo, matching: &[&Rule]) -> NotApplicable {
    // Several rules can share a scope; the reason shown is the first that states one, falling back
    // to the plain-language default for that rule's condition.
    let rule = matching[0];
    let reason = rule
        .not_applicable_reason
        .clone()
        .unwrap_or_else(|| default_not_applicable_reason(rule.condition).to_owned());
    NotApplicable {
        id: req.id.clone(),
        reason,
        condition: rule.condition,
    }
}

impl Condition {
    /// The name as it appears in `applicability.json`.
    pub fn name(self) -> &'static str {
        use Condition::*;
        match self {
            Always => "always",
            Never => "never",
            Auth => "auth",
            NoAuth => "no-auth",
            Uploads => "uploads",
            Ai => "ai",
            AiActions => "ai-actions",
            AiHistory => "ai-history",
            AiModeration => "ai-moderation",
            Email => "email",
            ExternalApis => "external-apis",
            PublicApi => "public-api",
            Payments => "payments",
            Scheduler => "scheduler",
            Tls => "tls",
            Internet => "internet",
            Level2 => "level2",
            Oauth => "oauth",
            Webrtc => "webrtc",
            Jwt => "jwt",
            Rag => "rag",
            Mcp => "mcp",
            MultiTenant => "multi-tenant",
            Training => "training",
            SelfAssessment => "self-assessment",
        }
    }
}
