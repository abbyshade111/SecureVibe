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
//! Rule 4 is what makes this safe to drive from a manifest instead of a wizard: silence means
//! applies, so a claim that goes missing costs the user a requirement they must meet, never one
//! they are wrongly told to skip.
//!
//! v2 adds a fifth: **a condition nobody can answer yet produces `not assessed`, not `does not
//! apply`.** v1 could treat every condition as known because the wizard asked about all of them.
//! `sv` cannot, and the difference between "this does not apply to you" and "nothing here has
//! checked" is the difference this whole project exists to keep.

use crate::condition::{Condition, Source};
use crate::load::{Frameworks, RequirementInfo, chapter_id_of, section_id_of};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

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
    /// Stated only by the v2 overlay; otherwise the condition's own source stands.
    #[serde(default)]
    pub source: Option<Source>,
}

impl Rule {
    pub fn source(&self) -> Source {
        self.source.unwrap_or_else(|| self.condition.source())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OverlayFile {
    rules: Vec<Rule>,
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

    /// Replaces the rules at every scope the overlay mentions.
    ///
    /// Replacement, not merging: the overlay exists because the base rule at that scope is a
    /// statement about v1's template, and a wrong reason that survives alongside a right one is
    /// still a wrong reason that can be printed.
    pub fn apply_overlay(&mut self, overlay_path: &Path) -> Result<usize> {
        let text = std::fs::read_to_string(overlay_path)
            .with_context(|| format!("reading {}", overlay_path.display()))?;
        let overlay: OverlayFile = serde_json::from_str(&text)
            .with_context(|| format!("parsing {}", overlay_path.display()))?;
        let replaced: Vec<String> = overlay.rules.iter().map(|r| r.scope.clone()).collect();
        self.rules.retain(|r| !replaced.contains(&r.scope));
        let n = overlay.rules.len();
        self.rules.extend(overlay.rules);
        Ok(n)
    }

    /// Loads the shared rules and applies the v2 overlay beside them.
    pub fn load_v2(knowledge_dir: &Path, overlay_path: &Path) -> Result<Self> {
        let mut config = Self::load(knowledge_dir)?;
        config.apply_overlay(overlay_path)?;
        Ok(config)
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

/// What is known about each condition. `None` means nothing has answered it yet — which is a
/// reportable state, not a false.
#[derive(Debug, Clone, Default)]
pub struct ConditionContext {
    known: HashMap<Condition, bool>,
}

impl ConditionContext {
    pub fn set(&mut self, condition: Condition, value: bool) {
        self.known.insert(condition, value);
    }

    /// `Some(true)` holds, `Some(false)` does not, `None` is unanswered.
    pub fn get(&self, condition: Condition) -> Option<bool> {
        match condition {
            Condition::Always => Some(true),
            Condition::Never => Some(false),
            other => self.known.get(&other).copied(),
        }
    }

    /// Every condition nothing has answered. What `sv` has to admit to, in as many words.
    pub fn unanswered(&self) -> Vec<Condition> {
        Condition::ALL
            .iter()
            .copied()
            .filter(|c| self.get(*c).is_none())
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct NotApplicable {
    pub id: String,
    pub reason: String,
    /// The condition that switched this requirement off, so a report can say why — and so an
    /// exclusion resting on somebody's word can be told from one resting on their dependencies.
    pub condition: Condition,
    pub source: Source,
}

#[derive(Debug, Clone)]
pub struct NotAssessed {
    pub id: String,
    /// The conditions that would have decided it, none of which anything has answered.
    pub blocked_on: Vec<Condition>,
}

#[derive(Debug, Default)]
pub struct Buckets {
    pub applicable: Vec<String>,
    pub not_applicable: Vec<NotApplicable>,
    /// Requirements whose gating condition nothing has answered. Never reported as passing, and
    /// never as not applying.
    pub not_assessed: Vec<NotAssessed>,
    pub out_of_level: Vec<String>,
}

/// Sorts every requirement into applies / does not apply / not assessed / above the target level.
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
        if matching.is_empty() {
            out.applicable.push(req.id.clone());
            continue;
        }
        // Rules at a scope are OR-ed. One condition known to hold settles it; otherwise anything
        // unanswered leaves the whole requirement unanswered, because that condition holding
        // would have brought it into scope.
        if matching.iter().any(|r| ctx.get(r.condition) == Some(true)) {
            out.applicable.push(req.id.clone());
        } else if matching.iter().any(|r| ctx.get(r.condition).is_none()) {
            out.not_assessed.push(NotAssessed {
                id: req.id.clone(),
                blocked_on: matching
                    .iter()
                    .filter(|r| ctx.get(r.condition).is_none())
                    .map(|r| r.condition)
                    .collect(),
            });
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
        .unwrap_or_else(|| rule.condition.default_not_applicable_reason().to_owned());
    NotApplicable {
        id: req.id.clone(),
        reason,
        condition: rule.condition,
        source: rule.source(),
    }
}

/// How many in-scope requirements turn on a condition.
///
/// Some conditions gate nothing at all: `payments` and `scheduler` are asked about, have
/// plain-language reasons written for them, and no rule in the OWASP data keys on either. Anything
/// reporting a claim as wrong needs this, or it announces a consequence that does not exist.
pub fn requirements_gated_on(
    frameworks: &Frameworks,
    config: &ApplicabilityConfig,
    condition: Condition,
    target_level: u8,
) -> usize {
    frameworks
        .requirements
        .values()
        .filter(|r| r.level <= target_level)
        .filter(|r| {
            config
                .rules_for(&r.id)
                .iter()
                .any(|rule| rule.condition == condition)
        })
        .count()
}
