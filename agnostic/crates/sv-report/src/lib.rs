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
//!    something and cited it — or *checked*, meaning at least one automated check looked at it and was
//!    satisfied, or *not verified*, meaning nothing has produced evidence either way. `Checked` is
//!    deliberately not called a pass: one config check being happy is not an ASVS requirement met,
//!    and the report says so in the words around the number.
//! 2. **Not-verified is counted and printed, not implied.** The reports lead with how much was *not*
//!    examined, because a report that leads with findings reads as thorough in proportion to how
//!    little it looked.
//! 3. **A requirement nobody could even decide the applicability of is its own bucket.** Not
//!    applicable, not failing, not verified: *not assessed*, with the question that would settle it.

pub mod bluf;
pub mod groups;
pub mod html;
pub mod markdown;
pub mod sarif;
pub mod threats;

use serde::Serialize;
use std::collections::BTreeSet;
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
    /// The owner answered a design question about this requirement in securevibe.toml.
    ///
    /// The weakest tier there is, below *documented*, because the owner asserting a property is not
    /// the property: writing a document is what a documentation requirement asks for, and writing
    /// "yes, authorization is on the server" is not authorization being on the server. It stays on
    /// the list of tests to write for exactly that reason.
    Attested,
    /// The owner answered this requirement's question in the security notes.
    ///
    /// Its own tier, below *checked* and above *not verified*, because it is a different kind of
    /// thing: a person's written decision, not a machine's reading of the code. Nothing here reads
    /// whether the answer is right, or whether the app does what it says — several of these
    /// requirements have a twin that asks exactly that, and the twins stay not verified.
    Documented,
    /// Nothing has produced evidence about this either way. The honest default, and the common one.
    NotVerified,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::NeedsAttention => "needs attention",
            Status::Checked => "checked",
            Status::Documented => "documented by the owner",
            Status::Attested => "attested by the owner",
            Status::NotVerified => "not verified",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RequirementLine {
    pub id: String,
    pub description: String,
    pub chapter: String,
    /// The ASVS level, so the short version can say how much of the work is at level 1. Zero for a
    /// Secure by Design control or an AISVS appendix entry, which have no ASVS level.
    pub level: u8,
    pub status: Status,
    /// Rule ids of the findings that cite this requirement.
    pub findings: Vec<String>,
    /// The checks that looked at this requirement and were satisfied, each with what it covered.
    pub checked_by: Vec<CheckedBy>,
    /// Checks that were satisfied about part of a requirement no check can settle.
    ///
    /// A design-review requirement asks several things, and a scanner can answer one of them at
    /// most: SBD-AC-05 asks for a secret manager, automatic key rotation *and* no secrets in the
    /// code, and a clean credential scan says something true about the third alone. Filed as
    /// "checked", it would claim the other two; dropped, it would hide the part that was examined.
    /// So it is shown here, and the requirement stays not verified until a person answers it.
    pub supported_by: Vec<CheckedBy>,
    /// Where in the security notes the owner answered this requirement's question.
    pub documented_by: Vec<CheckedBy>,
    /// The owner's answer to a design question about this requirement.
    pub attested_by: Vec<CheckedBy>,
}

/// One check that was satisfied about a requirement, and what it examined to say so.
///
/// The scope travels with the claim rather than being looked up elsewhere, because "checked" without
/// "over what" is the part of a report that gets skimmed and believed.
#[derive(Debug, Clone, Serialize)]
pub struct CheckedBy {
    pub check_id: String,
    pub scope: String,
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
    pub landed_in: String,
}

/// A check that was satisfied about nothing the tables above can hold.
#[derive(Debug, Clone, Serialize)]
pub struct SatisfiedElsewhere {
    pub check_id: String,
    pub scope: String,
    /// Why it is here rather than against a requirement.
    pub why: String,
}

/// A Secure by Design control above this app's target level, and where its level came from.
///
/// Listed rather than only counted. The checklist has no levels; each control's is either an ASVS
/// counterpart's or `sv`'s own, and a reader deciding whether to look at one anyway needs to know
/// which.
#[derive(Debug, Clone, Serialize)]
pub struct ChecklistAboveLevel {
    pub id: String,
    pub description: String,
    pub basis: String,
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
    /// Requirements the owner answered in the security notes. Never folded into `checked`.
    pub documented: usize,
    /// Requirements the owner answered a design question about. Never folded into either.
    pub attested: usize,
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
    /// One sentence about the app having been started, and under which fence.
    ///
    /// Absent when it was not started, in which case the gap list says so. Present and prominent
    /// when it was, because a report whose evidence came from a *running* app is a different kind
    /// of document from one that only read files, and the reader should not have to work that out
    /// from which sections happen to be populated.
    pub run_note: Option<String>,
    /// Everything the checks did while the app ran, one step per entry.
    ///
    /// Kept apart from `run_note` rather than joined into it. Thirty steps crammed into one
    /// sentence made a 381-word paragraph, and it was the first thing on the page: the reader met a
    /// wall of semicolons before they met a single finding. A list can be skimmed, and the HTML
    /// report folds it away until somebody wants it.
    pub run_steps: Vec<String>,
    pub counts: Counts,
    pub requirements: Vec<RequirementLine>,
    pub excluded: Vec<ExcludedRequirement>,
    pub undecided: Vec<UndecidedRequirement>,
    pub claims: Vec<ClaimLine>,
    pub findings: Vec<Finding>,
    pub out_of_scope: Vec<OutOfScopeFinding>,
    /// Checks that ran, were satisfied, and whose requirements are not in the tables above —
    /// because they name no requirement at all, or name ones this app is not being assessed against.
    ///
    /// Shown rather than dropped. The first version of this held only the first case, and the
    /// consequence showed up the moment the probes were folded in: they verified three requirements
    /// that are above this app's target level, the count said "0 checked", and a reader would have
    /// concluded the probes never ran. A vanishing positive claim is safer than a vanishing finding
    /// and still tells the reader something untrue.
    pub satisfied_elsewhere: Vec<SatisfiedElsewhere>,
    pub checklist_above_level: Vec<ChecklistAboveLevel>,
    /// Applicable requirements with no evidence of any kind and no test in the app naming them,
    /// lowest level first. A test that names a requirement and passes is the one route to evidence
    /// for every requirement, including the ones no check here can reach, so this is the list of
    /// what to write.
    pub tests_to_write: Vec<TestToWrite>,
    /// Applicable requirements a test in the app names, still without evidence: the tests were not
    /// run, or did not pass.
    pub named_not_credited: Vec<String>,
    /// How many unverified requirements were left out of `tests_to_write` because a test cannot
    /// show them: documentation, deployment, a development process, or design review.
    pub not_for_tests: usize,
    /// The applicable requirements only a person can settle, each with what doing something about
    /// it involves. Empty when the catalogs were not given.
    pub only_you_can_check: Vec<sv_check::human::Item>,
    /// How many of those no catalog has an instruction for: the design-review controls, which are
    /// standards that are checklists already. Counted rather than listed.
    pub no_instructions_yet: usize,
    /// What could go wrong with this app, and what the evidence says about each. Empty when the
    /// threat rules were not given.
    pub threats: Vec<threats::ThreatLine>,
    /// The parts of the app the threats concern, and whether each is there.
    pub threat_parts: Vec<threats::PartLine>,
    pub gaps: Vec<Gap>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestToWrite {
    pub id: String,
    pub level: u8,
    pub description: String,
}

/// Everything the renderers need, gathered from the crates that produced it.
pub struct Inputs<'a> {
    pub app_name: &'a str,
    pub target_level: u8,
    pub generated: Option<String>,
    pub run_note: Option<String>,
    /// One entry per thing the checks did while the app ran. See `Report::run_steps`.
    pub run_steps: Vec<String>,
    pub frameworks: &'a Frameworks,
    pub buckets: &'a Buckets,
    pub claims: &'a [ResolvedClaim],
    pub findings: Vec<Finding>,
    /// Everything that ran, looked at what it needed to, and found nothing wrong.
    pub verified: &'a [sv_check::Verified],
    /// What was not examined, and why — from every checker that knows it fell short.
    pub gaps: Vec<Gap>,
    /// Requirements no check can settle: design review, answered by a person. A satisfied check
    /// about one of these is supporting evidence, never "checked".
    pub manual_only: BTreeSet<String>,
    /// Requirement ids written into the app's test files, whether or not the tests ran.
    pub named_in_tests: BTreeSet<String>,
    /// Requirements an application's own tests cannot show: ones that ask for documentation, a
    /// deployment setting, or a development process. Left out of the tests to write, and counted.
    pub not_for_tests: BTreeSet<String>,
    /// The requirements the owner answered in the security notes, each with where the answer is.
    ///
    /// Kept apart from `verified` rather than folded in, because this is a person's written
    /// decision and everything in `verified` is a machine reading the app. Folding them together
    /// would be the one mistake this tier exists to prevent.
    pub documented: &'a [sv_check::Verified],
    /// Design questions the owner answered `yes`. The weakest evidence here, and still not evidence
    /// about the app: see `sv_check::design`.
    pub attested: &'a [sv_check::Verified],
    /// The three catalogs of what a person can do about a requirement no check settles. Absent
    /// leaves the checklist out of the report.
    pub human: Option<(
        &'a sv_check::notes::Catalog,
        &'a sv_check::design::Questions,
        &'a sv_check::human::HumanChecks,
    )>,
    /// The threat rules, and what is known about the app's conditions, for the threat model. Either
    /// absent leaves the section out of the report and says why.
    pub threats: Option<(
        &'a threats::ThreatRules,
        &'a sv_frameworks::ConditionContext,
    )>,
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
        let satisfied: Vec<CheckedBy> = inputs
            .verified
            .iter()
            .filter(|v| v.requirement_ids.iter().any(|r| r == id))
            .map(|v| CheckedBy {
                check_id: v.check_id.clone(),
                scope: v.scope.clone(),
            })
            .collect();
        let (checked_by, mut supported_by) = if inputs.manual_only.contains(id) {
            (Vec::new(), satisfied)
        } else {
            (satisfied, Vec::new())
        };
        // Evidence about a requirement the crosswalk says asks the same thing. Supporting only,
        // whatever this requirement's class: it is evidence about the counterpart, and at most part
        // of what this one asks.
        let counterparts = inputs
            .frameworks
            .get(id)
            .map(|r| r.counterparts.as_slice())
            .unwrap_or_default();
        for v in inputs.verified {
            for counterpart in counterparts {
                if v.requirement_ids.iter().any(|r| r == counterpart)
                    && !supported_by.iter().any(|c| c.check_id == v.check_id)
                    && !checked_by.iter().any(|c| c.check_id == v.check_id)
                {
                    supported_by.push(CheckedBy {
                        check_id: v.check_id.clone(),
                        scope: format!("{}, as evidence about {counterpart}", v.scope),
                    });
                }
            }
        }
        let attested_by: Vec<CheckedBy> = inputs
            .attested
            .iter()
            .filter(|v| v.requirement_ids.iter().any(|r| r == id))
            .map(|v| CheckedBy {
                check_id: v.check_id.clone(),
                scope: v.scope.clone(),
            })
            .collect();
        let documented_by: Vec<CheckedBy> = inputs
            .documented
            .iter()
            .filter(|v| v.requirement_ids.iter().any(|r| r == id))
            .map(|v| CheckedBy {
                check_id: v.check_id.clone(),
                scope: v.scope.clone(),
            })
            .collect();
        // A finding beats a satisfied check: one check being happy says nothing about what another
        // one found, and the report must never let the happier of two answers hide the other. An
        // answer in the notes comes last of the three, because it is the owner's word about the app
        // rather than anything read from it.
        let status = if !findings.is_empty() {
            Status::NeedsAttention
        } else if !checked_by.is_empty() {
            Status::Checked
        } else if !documented_by.is_empty() {
            Status::Documented
        } else if !attested_by.is_empty() {
            Status::Attested
        } else {
            Status::NotVerified
        };
        let (description, chapter) = describe(id);
        requirements.push(RequirementLine {
            id: id.clone(),
            description,
            chapter,
            level: inputs
                .frameworks
                .requirements
                .get(id)
                .map(|r| r.level)
                .unwrap_or(0),
            status,
            findings,
            checked_by,
            supported_by,
            documented_by,
            attested_by,
        });
    }
    requirements.sort_by(|a, b| a.status.cmp(&b.status).then_with(|| a.id.cmp(&b.id)));

    // What a test could still answer: nothing produced evidence, and a person is not the only one
    // who can. Design review is left out; a test cannot settle how a system was designed.
    let mut tests_to_write = Vec::new();
    let mut named_not_credited = Vec::new();
    let mut not_for_tests = 0;
    for line in &requirements {
        // Attested stays on this list beside not-verified, and that is the honest half of the tier.
        // An attestation is the owner's word that a control exists; a test naming the requirement is
        // how it would be shown. Letting the word retire the test is how "attested" would quietly
        // become "checked" without anyone deciding to make it so.
        if line.status != Status::NotVerified && line.status != Status::Attested {
            continue;
        }
        if inputs.manual_only.contains(&line.id) || inputs.not_for_tests.contains(&line.id) {
            not_for_tests += 1;
            continue;
        }
        if inputs.named_in_tests.contains(&line.id) {
            named_not_credited.push(line.id.clone());
            continue;
        }
        tests_to_write.push(TestToWrite {
            id: line.id.clone(),
            level: inputs.frameworks.get(&line.id).map_or(0, |r| r.level),
            description: line.description.clone(),
        });
    }
    let natural = |id: &str| -> Vec<u32> {
        id.split(|c: char| !c.is_ascii_digit())
            .filter_map(|n| n.parse().ok())
            .collect()
    };
    // ASVS before AISVS at the same level: the web application's own requirements first.
    let framework = |id: &str| u8::from(!id.starts_with('V'));
    tests_to_write.sort_by(|a, b| {
        a.level
            .cmp(&b.level)
            .then_with(|| framework(&a.id).cmp(&framework(&b.id)))
            .then_with(|| natural(&a.id).cmp(&natural(&b.id)))
    });

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
        documented: count(&requirements, Status::Documented),
        attested: count(&requirements, Status::Attested),
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
            out_of_scope.push(OutOfScopeFinding {
                rule_id: finding.rule_id.clone(),
                requirement_id: requirement_id.clone(),
                landed_in: where_it_landed(inputs.buckets, inputs.frameworks, requirement_id),
            });
        }
    }
    out_of_scope.sort_by(|a, b| {
        a.requirement_id
            .cmp(&b.requirement_id)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let satisfied_elsewhere: Vec<SatisfiedElsewhere> = inputs
        .verified
        .iter()
        .filter(|v| {
            !v.requirement_ids
                .iter()
                .any(|id| inputs.buckets.applicable.iter().any(|a| a == id))
        })
        .map(|v| SatisfiedElsewhere {
            check_id: v.check_id.clone(),
            scope: v.scope.clone(),
            why: if v.requirement_ids.is_empty() {
                "it names no requirement in any loaded framework".to_owned()
            } else {
                // Grouped by where each one landed, not by where the first one did. A check that
                // names three requirements can easily have them in three different buckets, and
                // reporting the first one's fate as though it were all of theirs is the kind of
                // small untruth a reader has no way to catch.
                let mut by_place: Vec<(String, Vec<&str>)> = Vec::new();
                for id in &v.requirement_ids {
                    let place = where_it_landed(inputs.buckets, inputs.frameworks, id);
                    match by_place.iter_mut().find(|(p, _)| *p == place) {
                        Some((_, ids)) => ids.push(id),
                        None => by_place.push((place, vec![id])),
                    }
                }
                by_place
                    .into_iter()
                    .map(|(place, ids)| format!("{} — {place}", ids.join(", ")))
                    .collect::<Vec<_>>()
                    .join("; ")
            },
        })
        .collect();

    let mut findings = inputs.findings;
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let checklist_above_level: Vec<ChecklistAboveLevel> = inputs
        .buckets
        .out_of_level
        .iter()
        .filter_map(|id| {
            let r = inputs.frameworks.get(id)?;
            Some(ChecklistAboveLevel {
                id: id.clone(),
                description: r.description.clone(),
                basis: r.level_basis.clone()?,
            })
        })
        .collect();

    let (threats, threat_parts) = match inputs.threats {
        Some((rules, ctx)) => (
            threats::evaluate(rules, ctx, &requirements),
            threats::parts(rules, ctx),
        ),
        None => (Vec::new(), Vec::new()),
    };

    // The checklist: every applicable requirement nothing has settled and no test would, with what
    // doing something about it involves. Membership is exactly the set the short version counts, so
    // the number at the top and the list below it cannot disagree.
    let a_test_could: BTreeSet<&str> = tests_to_write.iter().map(|t| t.id.as_str()).collect();
    let only_a_person: BTreeSet<String> = requirements
        .iter()
        .filter(|r| r.status == Status::NotVerified && !a_test_could.contains(r.id.as_str()))
        .map(|r| r.id.clone())
        .collect();
    let (only_you_can_check, no_instructions_yet) = match inputs.human {
        Some((notes, design, human)) => (
            sv_check::human::checklist(notes, design, human, &only_a_person),
            sv_check::human::without_instructions(notes, design, human, &only_a_person).len(),
        ),
        None => (Vec::new(), 0),
    };

    Report {
        app_name: inputs.app_name.to_owned(),
        target_level: inputs.target_level,
        generated: inputs.generated,
        run_note: inputs.run_note,
        run_steps: inputs.run_steps,
        counts,
        requirements,
        excluded,
        undecided,
        claims,
        findings,
        out_of_scope,
        satisfied_elsewhere,
        checklist_above_level,
        tests_to_write,
        only_you_can_check,
        no_instructions_yet,
        named_not_credited,
        not_for_tests,
        threats,
        threat_parts,
        gaps: inputs.gaps,
    }
}

/// Which bucket a requirement ended up in, for saying so beside a claim about it.
fn where_it_landed(buckets: &Buckets, frameworks: &Frameworks, requirement_id: &str) -> String {
    if buckets
        .not_applicable
        .iter()
        .any(|na| na.id == requirement_id)
    {
        "excluded as not applicable".to_owned()
    } else if buckets
        .not_assessed
        .iter()
        .any(|na| na.id == requirement_id)
    {
        "not assessed — nobody answered the question that places it".to_owned()
    } else if buckets.out_of_level.iter().any(|o| o == requirement_id) {
        // A checklist control's level is not an ASVS level, and saying "above the ASVS level" about
        // one put a number on it that ASVS never gave. Its basis says where the number came from.
        match frameworks
            .get(requirement_id)
            .and_then(|r| r.level_basis.as_deref())
        {
            Some(basis) => format!("above this app's target level ({basis})"),
            None => "above this app's target level".to_owned(),
        }
    } else {
        "not a requirement in any loaded framework".to_owned()
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
                Status::Attested => 2,
                Status::Documented => 3,
                Status::Checked => 4,
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
