//! The threat model: the rules in `data/knowledge/threats.json`, and what the evidence says about
//! each threat. The one thing it must never do is call a threat handled.

use std::path::PathBuf;
use sv_check::suite::shares_no_words;
use sv_frameworks::{Condition, ConditionContext, Frameworks};
use sv_report::threats::{ThreatRules, ThreatStatus, evaluate};
use sv_report::{RequirementLine, Status};

fn data() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data")
}

fn rules() -> ThreatRules {
    ThreatRules::load(&data().join("knowledge/threats.json")).expect("the threat rules load")
}

fn line(id: &str, status: Status) -> RequirementLine {
    RequirementLine {
        id: id.into(),
        description: String::new(),
        chapter: String::new(),
        status,
        findings: Vec::new(),
        checked_by: Vec::new(),
        supported_by: Vec::new(),
    }
}

fn context(set: &[(&str, bool)]) -> ConditionContext {
    let mut ctx = ConditionContext::default();
    for (name, value) in set {
        ctx.set(Condition::from_name(name).unwrap(), *value);
    }
    ctx
}

/// Every condition the rules name, set to one value.
fn everything(value: bool) -> ConditionContext {
    let names: Vec<String> = {
        let r = rules();
        r.elements
            .iter()
            .flat_map(|e| e.when.clone())
            .chain(r.threats.iter().flat_map(|t| t.when.clone()))
            .collect()
    };
    let mut ctx = ConditionContext::default();
    for n in names {
        ctx.set(Condition::from_name(&n).unwrap(), value);
    }
    ctx
}

// ---- the rules themselves ----

#[test]
fn every_requirement_a_threat_names_exists() {
    let frameworks = Frameworks::load(&data().join("frameworks")).unwrap();
    for t in &rules().threats {
        for c in &t.requirements {
            assert!(
                frameworks.get(&c.id).is_some(),
                "{} names {}, which does not exist",
                t.id,
                c.id
            );
        }
    }
}

#[test]
fn every_citation_s_phrase_shares_vocabulary_with_the_threat_and_the_requirement() {
    // The citation guard, as for the crosswalk: the phrase naming what a threat and a requirement
    // share must share a word with each. Written against v1's citations it found 54 of 107 sharing
    // nothing directly, which is why the phrase exists, and reading them one by one found five that
    // were wrong (SameSite cited for a stolen cookie, an outbound allowlist for a forged payment
    // message, among them).
    let frameworks = Frameworks::load(&data().join("frameworks")).unwrap();
    let mut wrong = Vec::new();
    for t in &rules().threats {
        for c in &t.requirements {
            let text = &frameworks.get(&c.id).unwrap().description;
            if shares_no_words(&c.because, text) {
                wrong.push(format!(
                    "{} {}: `{}` shares nothing with `{text}`",
                    t.id, c.id, c.because
                ));
            }
            if shares_no_words(&c.because, &t.description) {
                wrong.push(format!(
                    "{} {}: `{}` shares nothing with the threat `{}`",
                    t.id, c.id, c.because, t.description
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} citation(s):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_rules_are_v1_s_thirty_across_ten_parts_of_the_app() {
    let r = rules();
    assert_eq!(r.threats.len(), 30);
    assert_eq!(r.elements.len(), 10);
    assert_eq!(
        r.threats
            .iter()
            .map(|t| t.requirements.len())
            .sum::<usize>(),
        90
    );
}

// ---- what the evidence says about each threat ----

fn status_of(lines: &[sv_report::threats::ThreatLine], id: &str) -> Option<ThreatStatus> {
    lines.iter().find(|t| t.id == id).map(|t| t.status)
}

#[test]
fn a_requirement_that_needs_attention_makes_its_threat_found() {
    // T-01, signing in as somebody else: a short password accepted is the threat, found.
    let lines = evaluate(
        &rules(),
        &context(&[("auth", true)]),
        &[
            line("V6.2.1", Status::NeedsAttention),
            line("V6.2.4", Status::Checked),
            line("V7.2.3", Status::NotVerified),
        ],
    );
    let t = lines.iter().find(|t| t.id == "T-01").unwrap();
    assert_eq!(t.status, ThreatStatus::Found);
    assert_eq!(t.found, ["V6.2.1"]);
    assert_eq!(t.checked, ["V6.2.4"]);
    assert_eq!(t.not_verified, ["V7.2.3"]);
    // Those not among this app's requirements (above its level, or ruled out) are named apart.
    assert!(t.not_at_this_level.contains(&"V3.3.4".to_owned()));
}

#[test]
fn checked_requirements_make_a_threat_checked_in_part_and_never_more() {
    // Every requirement under T-01 checked: still "checked in part". A threat is only as settled as
    // the requirements under it, and each of those is one check, not a pass.
    let all: Vec<RequirementLine> = rules()
        .threats
        .iter()
        .find(|t| t.id == "T-01")
        .unwrap()
        .requirements
        .iter()
        .map(|c| line(&c.id, Status::Checked))
        .collect();
    let lines = evaluate(&rules(), &context(&[("auth", true)]), &all);
    assert_eq!(status_of(&lines, "T-01"), Some(ThreatStatus::CheckedInPart));
    let labels: Vec<&str> = [
        ThreatStatus::Found,
        ThreatStatus::NotVerified,
        ThreatStatus::CheckedInPart,
        ThreatStatus::CannotPlace,
    ]
    .iter()
    .map(|s| s.label())
    .collect();
    assert!(
        !labels
            .iter()
            .any(|l| l.contains("mitigat") || l.contains("pass")),
        "{labels:?}"
    );
}

#[test]
fn a_threat_nothing_has_looked_at_is_not_verified() {
    let lines = evaluate(
        &rules(),
        &context(&[("auth", true)]),
        &[line("V6.2.1", Status::NotVerified)],
    );
    assert_eq!(status_of(&lines, "T-01"), Some(ThreatStatus::NotVerified));
}

#[test]
fn a_threat_whose_condition_does_not_hold_is_left_out_and_an_unanswered_one_cannot_be_placed() {
    let no = evaluate(
        &rules(),
        &context(&[("auth", false), ("uploads", false)]),
        &[],
    );
    assert_eq!(
        status_of(&no, "T-01"),
        None,
        "no sign-in, no stolen sign-in"
    );
    assert_eq!(status_of(&no, "T-13"), None);
    // Unanswered is not "no": the threat is listed, and says which question would place it.
    let unknown = evaluate(&rules(), &ConditionContext::default(), &[]);
    let t = unknown.iter().find(|t| t.id == "T-13").unwrap();
    assert_eq!(t.status, ThreatStatus::CannotPlace);
    assert_eq!(t.unanswered, ["uploads"]);
    // A threat that needs nothing always applies.
    assert_eq!(status_of(&unknown, "T-04"), Some(ThreatStatus::NotVerified));
}

#[test]
fn an_element_s_condition_counts_as_well_as_the_threat_s_own() {
    // T-11 needs ai-actions; its element, the AI model, needs ai. AI switched off leaves it out
    // even with actions claimed.
    let lines = evaluate(
        &rules(),
        &context(&[("ai", false), ("ai-actions", true)]),
        &[],
    );
    assert_eq!(status_of(&lines, "T-11"), None);
    let lines = evaluate(
        &rules(),
        &context(&[("ai", true), ("ai-actions", true)]),
        &[],
    );
    assert_eq!(status_of(&lines, "T-11"), Some(ThreatStatus::NotVerified));
}

#[test]
fn found_comes_first_then_not_verified_then_checked_in_part_then_cannot_place() {
    let ctx = everything(true);
    let lines = evaluate(
        &rules(),
        &ctx,
        &[
            line("V2.3.3", Status::NeedsAttention),  // T-26, stored data
            line("V16.4.1", Status::Checked),        // T-29, the app
            line("V1.3.11", Status::NeedsAttention), // T-16, email
        ],
    );
    let statuses: Vec<ThreatStatus> = lines.iter().map(|t| t.status).collect();
    let mut sorted = statuses.clone();
    sorted.sort();
    assert_eq!(statuses, sorted, "grouped by status in order");
    // Within "found", by the part of the app in the data file's order: stored data before email.
    let found: Vec<&str> = lines
        .iter()
        .filter(|t| t.status == ThreatStatus::Found)
        .map(|t| t.id.as_str())
        .collect();
    assert_eq!(found, ["T-26", "T-16"]);
}

// ---- rules that could not mean what they say ----

fn load_doctored(change: impl Fn(&mut serde_json::Value)) -> anyhow::Result<ThreatRules> {
    let mut file: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(data().join("knowledge/threats.json")).unwrap(),
    )
    .unwrap();
    change(&mut file);
    let dir = std::env::temp_dir().join(format!(
        "sv-threats-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("threats.json");
    std::fs::write(&path, file.to_string()).unwrap();
    let loaded = ThreatRules::load(&path);
    std::fs::remove_dir_all(&dir).ok();
    loaded
}

#[test]
fn a_malformed_rule_is_refused_at_load() {
    let refused = |change: &dyn Fn(&mut serde_json::Value), says: &str| {
        let Err(e) = load_doctored(change) else {
            panic!("accepted a rule that should say: {says}");
        };
        assert!(e.to_string().contains(says), "{e}");
    };
    refused(
        &|f| f["threats"][0]["stride"] = "sneaking".into(),
        "not a STRIDE category",
    );
    refused(
        &|f| f["threats"][0]["element"] = "moon".into(),
        "not an element",
    );
    refused(
        &|f| f["threats"][0]["when"] = serde_json::json!(["telepathy"]),
        "not a condition",
    );
    refused(
        &|f| f["elements"][3]["when"] = serde_json::json!(["telepathy"]),
        "not a condition",
    );
    refused(
        &|f| f["threats"][0]["requirements"] = serde_json::json!([]),
        "names no requirement",
    );
    refused(&|f| f["threats"][1]["id"] = "T-01".into(), "listed twice");
    assert!(load_doctored(|_| {}).is_ok(), "the file itself loads");
}

// ---- in the report ----

fn report_with_threats(findings: Vec<sv_check::Finding>) -> sv_report::Report {
    let f = Frameworks::load(&data().join("frameworks")).unwrap();
    let buckets = sv_frameworks::applicability::Buckets {
        applicable: vec!["V6.2.1".into(), "V6.2.4".into(), "V1.2.4".into()],
        ..Default::default()
    };
    let r = rules();
    let ctx = context(&[("auth", true), ("uploads", false)]);
    sv_report::build(sv_report::Inputs {
        app_name: "Threats",
        target_level: 1,
        generated: None,
        run_note: None,
        frameworks: &f,
        buckets: &buckets,
        claims: &[],
        findings,
        verified: &[],
        gaps: vec![],
        manual_only: Default::default(),
        named_in_tests: Default::default(),
        not_for_tests: Default::default(),
        threats: Some((&r, &ctx)),
    })
}

fn finding_on(requirement: &str) -> sv_check::Finding {
    sv_check::Finding {
        rule_id: "probe.short-password-accepted".into(),
        title: "t".into(),
        severity: sv_check::Severity::Medium,
        confidence: sv_check::Confidence::High,
        location: sv_check::Location {
            file: "the running app".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec![requirement.into()],
        cwe: vec![],
        description: "d".into(),
        impact: "i".into(),
        fix: "f".into(),
    }
}

#[test]
fn a_finding_in_the_report_makes_its_threat_found_there_first() {
    let report = report_with_threats(vec![finding_on("V6.2.1")]);
    assert_eq!(report.threats[0].id, "T-01");
    assert_eq!(report.threats[0].status, ThreatStatus::Found);
    assert!(
        report
            .threats
            .iter()
            .all(|t| !t.element.starts_with("files")),
        "no uploads, no upload threats"
    );
    let md = sv_report::markdown::compliance(&report);
    let threats = &md[md.find("## Threats").expect("the section is there")..];
    assert!(
        threats.contains("| T-01 (pretending to be someone else) | found |"),
        "{threats}"
    );
    assert!(threats.contains("needs attention: V6.2.1"), "{threats}");
    let html = sv_report::html::page(&report);
    assert!(html.contains("<h2>Threats</h2>"));
    for text in [&md, &html] {
        let lower = text.to_lowercase();
        assert!(
            !lower.contains("mitigated"),
            "a threat is never called mitigated"
        );
    }
}

#[test]
fn a_part_nobody_answered_for_is_named_with_the_question() {
    let report = report_with_threats(vec![]);
    let md = sv_report::markdown::compliance(&report);
    assert!(
        md.contains("The AI model (not known: securevibe.toml does not answer `ai`)"),
        "{md}"
    );
    // Uploads were answered no, so their part is not listed at all.
    assert!(!md.contains("Uploaded files"), "{md}");
}

#[test]
fn without_threat_rules_the_report_has_no_threat_section() {
    let f = Frameworks::load(&data().join("frameworks")).unwrap();
    let buckets = sv_frameworks::applicability::Buckets::default();
    let report = sv_report::build(sv_report::Inputs {
        app_name: "None",
        target_level: 1,
        generated: None,
        run_note: None,
        frameworks: &f,
        buckets: &buckets,
        claims: &[],
        findings: vec![],
        verified: &[],
        gaps: vec![],
        manual_only: Default::default(),
        named_in_tests: Default::default(),
        not_for_tests: Default::default(),
        threats: None,
    });
    assert!(report.threats.is_empty());
    assert!(!sv_report::markdown::compliance(&report).contains("## Threats"));
}
