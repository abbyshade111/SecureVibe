//! The reports: what `sv` found, what it did not look at, and what nobody has answered.
//!
//! Everything else in this workspace prints to a terminal, where a line scrolls past and is gone.
//! A report is kept, sent to somebody, and read by a person who was not there when it ran — which is
//! exactly why it is the most dangerous thing here to get wrong. A terminal line saying "not
//! assessed" that nobody reads costs nothing; the same omission in a document that somebody files as
//! evidence of a security review is how an app ships believing it was checked.
//!
//! Three rules, and every one of them has a test that fails when it is broken:
//!
//! 1. **There is no `pass`.** An applicable requirement is either *needs attention* — a check found
//!    something and cited it — or *checked*, meaning one automated check looked at it and was
//!    satisfied, or *not verified*, meaning nothing has produced evidence either way. `Checked` is
//!    deliberately not called a pass: one config check being happy is not an ASVS requirement met,
//!    and the report says so in the words around the number.
//! 2. **Not-verified is counted and printed, not implied.** The reports lead with how much was *not*
//!    examined, because a report that leads with findings reads as thorough in proportion to how
//!    little it looked.
//! 3. **A requirement nobody could even decide the applicability of is its own bucket.** Not
//!    applicable, not failing, not verified: *not assessed*, with the question that would settle it.

pub mod html;
pub mod markdown;
pub mod sarif;

use serde::Serialize;
use sv_check::Finding;
use sv_frameworks::applicability::Buckets;
use sv_frameworks::{Condition, Frameworks, Source};
use sv_manifest::{ClaimState, ResolvedClaim};

/// What is known about one applicable requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// A check found something and named this requirement.
    NeedsAttention,
    /// A check that names this requirement ran and was satisfied. One automated check, not a pass.
    Checked,
    /// Nothing has produced evidence about this either way. The honest default, and the common one.
    NotVerified,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::NeedsAttention => "needs attention",
            Status::Checked => "checked",
            Status::NotVerified => "not verified",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RequirementLine {
    pub id: String,
    pub description: String,
    pub chapter: String,
    pub status: Status,
    /// Rule ids of the findings that cite this requirement.
    pub findings: Vec<String>,
    /// Ids of the checks that looked at this requirement and were satisfied.
    pub checked_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExcludedRequirement {
    pub id: String,
    pub description: String,
    pub reason: String,
    pub condition: String,
    /// `claim` when the exclusion rests on the manifest's word, `derived` when on the code.
    pub rests_on: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct UndecidedRequirement {
    pub id: String,
    pub description: String,
    /// The questions that would settle it, in the words they are asked in.
    pub blocked_on: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimLine {
    pub name: String,
    pub claimed: Option<bool>,
    pub found_in_code: Option<bool>,
    pub state: String,
    /// One sentence a person can act on.
    pub note: String,
}

/// A check found something and named a requirement this app is not being assessed against.
///
/// Worth its own section rather than a silent drop. It means one of two things and both matter: the
/// requirement was excluded when it should not have been, or a check is citing a requirement that
/// has nothing to do with it. Dropping the line quietly hides a wrong exclusion behind a clean
/// count, which is the failure this whole report is arranged to prevent.
#[derive(Debug, Clone, Serialize)]
pub struct OutOfScopeFinding {
    pub rule_id: String,
    pub requirement_id: String,
    /// Which bucket the requirement actually landed in.
    pub landed_in: &'static str,
}

/// Something `sv` did not examine, and why. Never folded into a clean result.
#[derive(Debug, Clone, Serialize)]
pub struct Gap {
    pub what: String,
    pub why: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Counts {
    pub applicable: usize,
    pub needs_attention: usize,
    pub checked: usize,
    pub not_verified: usize,
    pub not_applicable: usize,
    pub not_assessed: usize,
    pub out_of_level: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub app_name: String,
    pub target_level: u8,
    /// Passed in rather than read from a clock, so the same app twice produces the same bytes.
    pub generated: Option<String>,
    pub counts: Counts,
    pub requirements: Vec<RequirementLine>,
    pub excluded: Vec<ExcludedRequirement>,
    pub undecided: Vec<UndecidedRequirement>,
    pub claims: Vec<ClaimLine>,
    pub findings: Vec<Finding>,
    pub out_of_scope: Vec<OutOfScopeFinding>,
    /// Checks that ran, were satisfied, and are evidence about no requirement in any loaded
    /// framework. Shown rather than dropped: work that was done and produced nothing the tables
    /// above can hold is still work that was done, and leaving it out makes the tool look like it
    /// ran fewer checks than it did.
    pub satisfied_about_nothing: Vec<String>,
    pub gaps: Vec<Gap>,
}

/// Everything the renderers need, gathered from the crates that produced it.
pub struct Inputs<'a> {
    pub app_name: &'a str,
    pub target_level: u8,
    pub generated: Option<String>,
    pub frameworks: &'a Frameworks,
    pub buckets: &'a Buckets,
    pub claims: &'a [ResolvedClaim],
    pub findings: Vec<Finding>,
    /// Check ids that ran and were satisfied, with the requirements each is evidence about.
    pub passed_checks: &'a [sv_check::config::Passed],
    /// What was not examined, and why — from every checker that knows it fell short.
    pub gaps: Vec<Gap>,
}

pub fn build(inputs: Inputs<'_>) -> Report {
    let describe = |id: &str| {
        inputs
            .frameworks
            .requirements
            .get(id)
            .map(|r| (r.description.clone(), r.chapter_name.clone()))
            .unwrap_or_else(|| (String::new(), String::new()))
    };

    let mut requirements = Vec::new();
    for id in &inputs.buckets.applicable {
        let findings: Vec<String> = inputs
            .findings
            .iter()
            .filter(|f| f.requirement_ids.iter().any(|r| r == id))
            .map(|f| f.rule_id.clone())
            .collect();
        let checked_by: Vec<String> = inputs
            .passed_checks
            .iter()
            .filter(|p| p.requirement_ids.iter().any(|r| r == id))
            .map(|p| p.id.clone())
            .collect();
        // A finding beats a satisfied check: one check being happy says nothing about what another
        // one found, and the report must never let the happier of two answers hide the other.
        let status = if !findings.is_empty() {
            Status::NeedsAttention
        } else if !checked_by.is_empty() {
            Status::Checked
        } else {
            Status::NotVerified
        };
        let (description, chapter) = describe(id);
        requirements.push(RequirementLine {
            id: id.clone(),
            description,
            chapter,
            status,
            findings,
            checked_by,
        });
    }
    requirements.sort_by(|a, b| a.status.cmp(&b.status).then_with(|| a.id.cmp(&b.id)));

    let excluded: Vec<ExcludedRequirement> = inputs
        .buckets
        .not_applicable
        .iter()
        .map(|na| ExcludedRequirement {
            id: na.id.clone(),
            description: describe(&na.id).0,
            reason: na.reason.clone(),
            condition: na.condition.name().to_owned(),
            rests_on: match na.source {
                Source::Claim => "claim",
                Source::Derived => "derived",
            },
        })
        .collect();

    let undecided: Vec<UndecidedRequirement> = inputs
        .buckets
        .not_assessed
        .iter()
        .map(|na| UndecidedRequirement {
            id: na.id.clone(),
            description: describe(&na.id).0,
            blocked_on: na
                .blocked_on
                .iter()
                .map(|c| question_for(*c).to_owned())
                .collect(),
        })
        .collect();

    let claims = inputs.claims.iter().map(claim_line).collect();

    let counts = Counts {
        applicable: requirements.len(),
        needs_attention: count(&requirements, Status::NeedsAttention),
        checked: count(&requirements, Status::Checked),
        not_verified: count(&requirements, Status::NotVerified),
        not_applicable: excluded.len(),
        not_assessed: undecided.len(),
        out_of_level: inputs.buckets.out_of_level.len(),
    };

    // Anything a check pointed at that the buckets did not place under "applies".
    let mut out_of_scope = Vec::new();
    for finding in &inputs.findings {
        for requirement_id in &finding.requirement_ids {
            if inputs
                .buckets
                .applicable
                .iter()
                .any(|a| a == requirement_id)
            {
                continue;
            }
            let landed_in = if inputs
                .buckets
                .not_applicable
                .iter()
                .any(|na| &na.id == requirement_id)
            {
                "excluded as not applicable"
            } else if inputs
                .buckets
                .not_assessed
                .iter()
                .any(|na| &na.id == requirement_id)
            {
                "not assessed — nobody answered the question that places it"
            } else if inputs
                .buckets
                .out_of_level
                .iter()
                .any(|o| o == requirement_id)
            {
                "above the ASVS level this app targets"
            } else {
                "not a requirement in any loaded framework"
            };
            out_of_scope.push(OutOfScopeFinding {
                rule_id: finding.rule_id.clone(),
                requirement_id: requirement_id.clone(),
                landed_in,
            });
        }
    }
    out_of_scope.sort_by(|a, b| {
        a.requirement_id
            .cmp(&b.requirement_id)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let satisfied_about_nothing: Vec<String> = inputs
        .passed_checks
        .iter()
        .filter(|p| p.requirement_ids.is_empty())
        .map(|p| p.id.clone())
        .collect();

    let mut findings = inputs.findings;
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    Report {
        app_name: inputs.app_name.to_owned(),
        target_level: inputs.target_level,
        generated: inputs.generated,
        counts,
        requirements,
        excluded,
        undecided,
        claims,
        findings,
        out_of_scope,
        satisfied_about_nothing,
        gaps: inputs.gaps,
    }
}

fn count(lines: &[RequirementLine], status: Status) -> usize {
    lines.iter().filter(|l| l.status == status).count()
}

impl PartialOrd for Status {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Status {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        fn rank(s: Status) -> u8 {
            match s {
                Status::NeedsAttention => 0,
                Status::NotVerified => 1,
                Status::Checked => 2,
            }
        }
        rank(*self).cmp(&rank(*other))
    }
}

fn claim_line(claim: &ResolvedClaim) -> ClaimLine {
    let note = match claim.state {
        ClaimState::Contradicted => {
            "The code says otherwise, and the code wins: the requirements this would have switched \
             off are switched on."
        }
        ClaimState::Unsupported => {
            "Claimed, and nothing in the code shows it. The requirements still apply — a claim is \
             never weakened by failing to corroborate it."
        }
        ClaimState::Unverifiable => {
            "Taken on the manifest's word. `sv` looked and found nothing, which for this is not the \
             same as finding it absent."
        }
        ClaimState::Unanswered => {
            "Nobody has said. Requirements that turn on this are not assessed rather than excluded."
        }
        ClaimState::Confirmed => "The manifest and the code agree.",
    };
    ClaimLine {
        name: claim.condition.name().to_owned(),
        claimed: claim.claimed,
        found_in_code: claim.found_in_code,
        state: format!("{:?}", claim.state).to_lowercase(),
        note: note.to_owned(),
    }
}

/// The question a condition really asks, for a reader who has never seen its name.
fn question_for(condition: Condition) -> &'static str {
    // The condition's own reason is written as the *exclusion* — "this app has no sign-in, so…" —
    // which is the wrong voice for a list of open questions. Turning it round here keeps one
    // wording in the data and the right one in the report.
    condition.default_not_applicable_reason()
}
