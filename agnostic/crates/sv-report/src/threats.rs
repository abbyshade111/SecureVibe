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

/// What the threat section can and cannot say, at its head in every report.
pub const INTRO: &str = "What could go wrong with an app like this one, by the part of it each threat concerns, and what the checks showed about each. These are the threats sv has rules for, for what was found in this app: not every threat there is. None is called handled. A threat is only as settled as the requirements that answer it, and each of those is one automated check at most, so the best a threat can be here is checked in part. Found threats come first, then those nothing has looked at.";

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
    /// The answering requirements the owner answered in the security notes.
    ///
    /// Shown, and deliberately not counted toward *checked in part*: a written decision about how
    /// the app is meant to work is not evidence that it does. Letting it lift a threat's status
    /// would let an app talk its way out of a threat.
    pub documented: Vec<String>,
    /// The answering requirements the owner answered a design question about. Counted toward
    /// nothing, for the same reason as `documented` and more strongly: this is their word about a
    /// property of the app, and a threat is settled by evidence or not at all.
    pub attested: Vec<String>,
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
            documented: Vec::new(),
            attested: Vec::new(),
            not_verified: Vec::new(),
            not_at_this_level: Vec::new(),
            unanswered,
        };
        for id in t.requirements.iter().map(|c| &c.id) {
            match requirements.iter().find(|r| &r.id == id).map(|r| r.status) {
                Some(Status::NeedsAttention) => line.found.push(id.clone()),
                Some(Status::Checked) => line.checked.push(id.clone()),
                Some(Status::Documented) => line.documented.push(id.clone()),
                Some(Status::Attested) => line.attested.push(id.clone()),
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

/// A part of the app, as the outline in the report shows it.
#[derive(Debug, Clone, Serialize)]
pub struct PartLine {
    pub id: String,
    pub name: String,
    pub description: String,
    /// `Some(true)` there, `None` not known; parts that are not there are left out.
    pub present: Option<bool>,
    /// For a part not known to be there: the conditions nobody answered.
    pub unanswered: Vec<String>,
}

/// The parts of this app the threats concern: those there, and those nobody has said are not.
pub fn parts(rules: &ThreatRules, ctx: &ConditionContext) -> Vec<PartLine> {
    rules
        .elements
        .iter()
        .filter_map(|e| {
            let (present, unanswered) = holds(ctx, &e.when);
            (present != Some(false)).then(|| PartLine {
                id: e.id.clone(),
                name: e.name.clone(),
                description: e.description.clone(),
                present,
                unanswered,
            })
        })
        .collect()
}

/// The STRIDE category in plain words, for somebody who has not met the acronym.
pub fn stride_words(stride: &str) -> &'static str {
    match stride {
        "spoofing" => "pretending to be someone else",
        "tampering" => "changing what should not change",
        "repudiation" => "denying having done something",
        "information-disclosure" => "exposing information",
        "denial-of-service" => "making the app unavailable",
        "elevation-of-privilege" => "gaining more access than allowed",
        _ => "",
    }
}

/// "30 threats: 2 found, 20 not verified, 5 checked in part, 3 cannot place."
pub fn count_line(lines: &[ThreatLine]) -> String {
    let n = |s: ThreatStatus| lines.iter().filter(|l| l.status == s).count();
    format!(
        "{} threat{}: {} found, {} not verified, {} checked in part, {} cannot place.",
        lines.len(),
        if lines.len() == 1 { "" } else { "s" },
        n(ThreatStatus::Found),
        n(ThreatStatus::NotVerified),
        n(ThreatStatus::CheckedInPart),
        n(ThreatStatus::CannotPlace)
    )
}

/// The requirements under a threat, grouped by what is known about them, in words.
pub fn evidence_words(line: &ThreatLine) -> String {
    if line.status == ThreatStatus::CannotPlace {
        return format!(
            "whether this applies is not known: answer {} in securevibe.toml",
            line.unanswered.join(", ")
        );
    }
    let mut parts = Vec::new();
    for (label, ids) in [
        ("needs attention", &line.found),
        ("checked", &line.checked),
        (
            "you documented, which is not evidence about this threat",
            &line.documented,
        ),
        (
            "you answered yes about, which is not evidence about this threat",
            &line.attested,
        ),
        ("not verified", &line.not_verified),
        (
            "not among this app's requirements at its level",
            &line.not_at_this_level,
        ),
    ] {
        if !ids.is_empty() {
            parts.push(format!("{label}: {}", ids.join(", ")));
        }
    }
    parts.join("; ")
}
