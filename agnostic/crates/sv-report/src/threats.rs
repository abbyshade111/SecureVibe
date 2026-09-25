//! The threat model: what could go wrong with this app, and what the evidence says about each.
//!
//! Rules, not a model's opinion: `data/knowledge/threats.json` lists threats by the part of the app
//! they concern and the conditions under which they apply, each with the ASVS and AISVS requirements
//! that answer it. Nothing here says a threat is handled. `sv` did not write the app, and a threat is
//! only ever as settled as the requirements under it, which are themselves only as settled as the
//! checks that spoke to them — so a threat is *found*, *checked in part*, *not verified*, or cannot
//! be placed, and never *mitigated*. See `docs/THREAT-MODELING.md`.

use crate::{RequirementLine, Status};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use sv_frameworks::{Condition, ConditionContext};

const STRIDE: &[&str] = &[
    "spoofing",
    "tampering",
    "repudiation",
    "information-disclosure",
    "denial-of-service",
    "elevation-of-privilege",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Element {
    pub id: String,
    pub name: String,
    pub description: String,
    /// Conditions that must all hold for this part of the app to exist.
    #[serde(default)]
    pub when: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreatRule {
    pub id: String,
    pub stride: String,
    pub element: String,
    /// Conditions that must all hold for the threat to apply, beyond its element's own.
    #[serde(default)]
    pub when: Vec<String>,
    pub description: String,
    /// The requirements that answer this threat. Their evidence is the threat's evidence.
    pub requirements: Vec<Citation>,
}

/// One requirement that answers a threat, with the few words the two share.
///
/// A threat is written as what an attacker does ("steals a session cookie"), a requirement as a
/// control ("session tokens verified by a backend service"), so the two rarely share a word even when
/// the citation is right. The phrase is what the citation guard holds against both, as for the
/// crosswalk between the Secure by Design checklist and ASVS.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Citation {
    pub id: String,
    pub because: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreatFile {
    #[serde(rename = "_comment", default)]
    _comment: String,
    elements: Vec<Element>,
    threats: Vec<ThreatRule>,
}

#[derive(Debug)]
pub struct ThreatRules {
    pub elements: Vec<Element>,
    pub threats: Vec<ThreatRule>,
}

impl ThreatRules {
    /// Loads the rules and refuses any that could not mean what they say: an unknown STRIDE
    /// category, element, or condition, a repeated id, or a threat answered by nothing.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: ThreatFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let mut ids = BTreeSet::new();
        for element in &file.elements {
            anyhow::ensure!(
                ids.insert(element.id.clone()),
                "element {} is listed twice",
                element.id
            );
            for c in &element.when {
                anyhow::ensure!(
                    Condition::from_name(c).is_some(),
                    "element {} needs `{c}`, which is not a condition sv knows",
                    element.id
                );
            }
        }
        let mut threat_ids = BTreeSet::new();
        for t in &file.threats {
            anyhow::ensure!(
                threat_ids.insert(t.id.clone()),
                "threat {} is listed twice",
                t.id
            );
            anyhow::ensure!(
                STRIDE.contains(&t.stride.as_str()),
                "threat {} has `{}`, which is not a STRIDE category",
                t.id,
                t.stride
            );
            anyhow::ensure!(
                ids.contains(&t.element),
                "threat {} concerns `{}`, which is not an element",
                t.id,
                t.element
            );
            for c in &t.when {
                anyhow::ensure!(
                    Condition::from_name(c).is_some(),
                    "threat {} needs `{c}`, which is not a condition sv knows",
                    t.id
                );
            }
            anyhow::ensure!(
                !t.requirements.is_empty(),
                "threat {} names no requirement, so nothing could ever be said about it",
                t.id
            );
        }
        Ok(ThreatRules {
            elements: file.elements,
            threats: file.threats,
        })
    }

    fn element(&self, id: &str) -> Option<&Element> {
        self.elements.iter().find(|e| e.id == id)
    }
}

/// What the evidence says about one threat. There is no "mitigated".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ThreatStatus {
    /// A requirement that answers it needs attention: the threat is real in this app.
    Found,
    /// Nothing has looked at any requirement that answers it.
    NotVerified,
    /// Some requirements that answer it were checked, and none needs attention.
    CheckedInPart,
    /// A condition it depends on is unanswered, so whether it applies is not known.
    CannotPlace,
}

impl ThreatStatus {
    pub fn label(self) -> &'static str {
        match self {
            ThreatStatus::Found => "found",
            ThreatStatus::NotVerified => "not verified",
            ThreatStatus::CheckedInPart => "checked in part",
            ThreatStatus::CannotPlace => "cannot place",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatLine {
    pub id: String,
    pub stride: String,
    pub element: String,
    pub element_name: String,
    pub description: String,
    pub status: ThreatStatus,
    /// The answering requirements that need attention.
    pub found: Vec<String>,
    /// The answering requirements that were checked.
    pub checked: Vec<String>,
    /// The answering requirements that apply and nothing has looked at.
    pub not_verified: Vec<String>,
    /// Answering requirements that are not among this app's, at its level: above the target level,
    /// or ruled out by what the app does.
    pub not_at_this_level: Vec<String>,
    /// For `CannotPlace`: the conditions nothing answered.
    pub unanswered: Vec<String>,
}

/// Whether a set of conditions holds: all true, one false, or some unknown and none false.
fn holds(ctx: &ConditionContext, when: &[String]) -> (Option<bool>, Vec<String>) {
    let mut unknown = Vec::new();
    for name in when {
        let Some(condition) = Condition::from_name(name) else {
            return (Some(false), unknown);
        };
        match ctx.get(condition) {
            Some(false) => return (Some(false), Vec::new()),
            Some(true) => {}
            None => unknown.push(name.clone()),
        }
    }
    if unknown.is_empty() {
        (Some(true), unknown)
    } else {
        (None, unknown)
    }
}

/// The threats that apply to this app, or might, each with what the evidence says about it.
///
/// Ordered by what the owner should look at first: found, then not verified, then checked in
/// part, then those that cannot be placed; within each, by the part of the app, in the order the
/// data file lists them, and then by id. No likelihood or impact score, at the owner's decision.
pub fn evaluate(
    rules: &ThreatRules,
    ctx: &ConditionContext,
    requirements: &[RequirementLine],
) -> Vec<ThreatLine> {
    let mut out = Vec::new();
    for t in &rules.threats {
        let Some(element) = rules.element(&t.element) else {
            continue;
        };
        // The element's conditions and the threat's own, each once: a threat may repeat its
        // element's to be read on its own, and an unanswered one is still one question.
        let mut when: Vec<String> = Vec::new();
        for c in element.when.iter().chain(&t.when) {
            if !when.contains(c) {
                when.push(c.clone());
            }
        }
        let (applies, unanswered) = holds(ctx, &when);
        if applies == Some(false) {
            continue;
        }
        let mut line = ThreatLine {
            id: t.id.clone(),
            stride: t.stride.clone(),
            element: element.id.clone(),
            element_name: element.name.clone(),
            description: t.description.clone(),
            status: ThreatStatus::CannotPlace,
            found: Vec::new(),
            checked: Vec::new(),
            not_verified: Vec::new(),
            not_at_this_level: Vec::new(),
            unanswered,
        };
        for id in t.requirements.iter().map(|c| &c.id) {
            match requirements.iter().find(|r| &r.id == id).map(|r| r.status) {
                Some(Status::NeedsAttention) => line.found.push(id.clone()),
                Some(Status::Checked) => line.checked.push(id.clone()),
                Some(Status::NotVerified) => line.not_verified.push(id.clone()),
                None => line.not_at_this_level.push(id.clone()),
            }
        }
        line.status = if applies.is_none() {
            ThreatStatus::CannotPlace
        } else if !line.found.is_empty() {
            ThreatStatus::Found
        } else if !line.checked.is_empty() {
            ThreatStatus::CheckedInPart
        } else {
            ThreatStatus::NotVerified
        };
        out.push(line);
    }
    let order = |element: &str| {
        rules
            .elements
            .iter()
            .position(|e| e.id == element)
            .unwrap_or(usize::MAX)
    };
    out.sort_by(|a, b| {
        a.status
            .cmp(&b.status)
            .then_with(|| order(&a.element).cmp(&order(&b.element)))
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}
