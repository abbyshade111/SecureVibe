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
        level: 1,
        status,
        findings: Vec::new(),
        checked_by: Vec::new(),
        supported_by: Vec::new(),
        documented_by: Vec::new(),
        attested_by: Vec::new(),
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
fn the_rules_are_v1_s_thirty_and_twelve_for_what_v1_did_not_model() {
    let r = rules();
    assert_eq!(r.threats.len(), 42);
    assert_eq!(r.elements.len(), 14);
    let v1: Vec<&str> = r
        .threats
        .iter()
        .take(30)
        .map(|t| t.element.as_str())
        .collect();
    for new in ["mcp-tools", "document-store", "services", "websockets"] {
        assert!(!v1.contains(&new), "{new} is not one of v1's parts");
    }
    assert_eq!(
        r.threats
            .iter()
            .map(|t| t.requirements.len())
            .sum::<usize>(),
        115
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
fn an_answer_in_the_security_notes_does_not_settle_a_threat() {
    // The threat model reads the requirement statuses, and one of those is now the owner's own
    // written answer. Writing down how sign-in is meant to be protected is not evidence that it is,
    // so a documented requirement must not lift a threat from "not verified" to "checked in part" —
    // otherwise an app talks its way out of a threat by describing itself.
    let documented = evaluate(
        &rules(),
        &context(&[("auth", true)]),
        &[line("V6.2.1", Status::Documented)],
    );
    assert_eq!(
        status_of(&documented, "T-01"),
        Some(ThreatStatus::NotVerified),
        "a written answer is not evidence about the threat"
    );
    let t = documented.iter().find(|t| t.id == "T-01").unwrap();
    assert!(
        t.documented.contains(&"V6.2.1".to_owned()),
        "it is still shown, just not counted: {t:?}"
    );
    assert!(
        t.checked.is_empty(),
        "nothing the owner wrote may land in the checked list: {t:?}"
    );
    // The same requirement, actually checked, does lift it — otherwise the test above would pass
    // with the threat model ignoring evidence altogether.
    let checked = evaluate(
        &rules(),
        &context(&[("auth", true)]),
        &[line("V6.2.1", Status::Checked)],
    );
    assert_eq!(
        status_of(&checked, "T-01"),
        Some(ThreatStatus::CheckedInPart)
    );
}

#[test]
fn an_answer_to_a_design_question_does_not_settle_a_threat_either() {
    // The same rule as the security notes, and it matters more here: a document at least exists,
    // while an attestation is only the owner saying the control is there. If this lifted a threat,
    // the threat model could be cleared by answering yes sixteen times.
    let attested = evaluate(
        &rules(),
        &context(&[("auth", true)]),
        &[line("V6.2.1", Status::Attested)],
    );
    assert_eq!(
        status_of(&attested, "T-01"),
        Some(ThreatStatus::NotVerified),
        "your word about the app is not evidence about the threat"
    );
    let t = attested.iter().find(|t| t.id == "T-01").unwrap();
    assert!(
        t.attested.contains(&"V6.2.1".to_owned()),
        "still shown: {t:?}"
    );
    assert!(t.checked.is_empty(), "and counted toward nothing: {t:?}");
    let words = sv_report::threats::evidence_words(t);
    assert!(words.contains("not evidence"), "{words}");
}

#[test]
fn the_threat_table_says_an_answer_is_not_evidence() {
    let documented = evaluate(
        &rules(),
        &context(&[("auth", true)]),
        &[line("V6.2.1", Status::Documented)],
    );
    let t = documented.iter().find(|t| t.id == "T-01").unwrap();
    let words = sv_report::threats::evidence_words(t);
    assert!(
        words.contains("not evidence") && words.contains("V6.2.1"),
        "a reader must not mistake it for a check: {words}"
    );
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
        run_steps: Vec::new(),
        frameworks: &f,
        buckets: &buckets,
        claims: &[],
        findings,
        verified: &[],
        gaps: vec![],
        manual_only: Default::default(),
        named_in_tests: Default::default(),
        not_for_tests: Default::default(),
        documented: &[],
        attested: &[],
        human: None,
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
        run_steps: Vec::new(),
        frameworks: &f,
        buckets: &buckets,
        claims: &[],
        findings: vec![],
        verified: &[],
        gaps: vec![],
        manual_only: Default::default(),
        named_in_tests: Default::default(),
        not_for_tests: Default::default(),
        documented: &[],
        attested: &[],
        human: None,
        threats: None,
    });
    assert!(report.threats.is_empty());
    assert!(!sv_report::markdown::compliance(&report).contains("## Threats"));
}

#[test]
fn the_new_parts_appear_only_when_their_conditions_hold() {
    let parts = |set: &[(&str, bool)]| -> Vec<String> {
        evaluate(&rules(), &context(set), &[])
            .into_iter()
            .filter(|t| t.status != ThreatStatus::CannotPlace)
            .map(|t| t.element)
            .collect()
    };
    let conditions = [
        "mcp",
        "rag",
        "multiple-services",
        "websockets",
        "multi-tenant",
    ];
    let set = |value: bool| -> Vec<(&str, bool)> {
        std::iter::once(("ai", true))
            .chain(conditions.iter().map(|c| (*c, value)))
            .collect()
    };
    let without = parts(&set(false));
    let with = parts(&set(true));
    for part in ["mcp-tools", "document-store", "services", "websockets"] {
        assert!(
            !without.iter().any(|e| e == part),
            "{part} without its condition"
        );
        assert!(with.iter().any(|e| e == part), "{part} with its condition");
    }
    // MCP and retrieval need AI too: claimed with AI answered no, they place nothing.
    let no_ai = parts(&[("ai", false), ("mcp", true), ("rag", true)]);
    assert!(
        !no_ai
            .iter()
            .any(|e| e == "mcp-tools" || e == "document-store")
    );
    // The tenant threat on the document store needs AI, retrieval, and several tenants at once.
    let lines = evaluate(
        &rules(),
        &context(&[("ai", true), ("rag", true), ("multi-tenant", false)]),
        &[],
    );
    assert!(!lines.iter().any(|t| t.id == "T-42"));
    assert!(lines.iter().any(|t| t.id == "T-35"));
}

// ---- MITRE ATLAS references, for a security reviewer ----

fn atlas_text() -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/atlas-references.json"),
    )
    .expect("the ATLAS references read")
}

fn is_about_ai(t: &sv_report::threats::ThreatRule) -> bool {
    t.when.iter().any(|c| c == "ai" || c.starts_with("ai-"))
}

#[test]
fn every_threat_about_ai_has_an_atlas_reference_and_no_other_threat_does() {
    let r = rules().with_atlas().expect("the ATLAS references load");
    let atlas = r.atlas.as_ref().unwrap();
    assert_eq!(atlas.release, "2026.09");
    let about_ai: Vec<&str> = r
        .threats
        .iter()
        .filter(|t| is_about_ai(t))
        .map(|t| t.id.as_str())
        .collect();
    assert_eq!(about_ai.len(), 6, "{about_ai:?}");
    for id in &about_ai {
        assert!(
            atlas
                .by_threat
                .get(*id)
                .is_some_and(|refs| !refs.is_empty()),
            "{id} is about AI and has no ATLAS reference"
        );
    }
    assert_eq!(atlas.by_threat.len(), about_ai.len());
}

#[test]
fn every_atlas_phrase_shares_vocabulary_with_the_threat_and_the_technique() {
    // The same guard as the requirements': a phrase that matched only one side could join any
    // threat to any technique. And a phrase with no word the comparison can use would pass both.
    let r = rules().with_atlas().unwrap();
    let mut wrong = Vec::new();
    let mut pairs = 0;
    for t in &r.threats {
        for a in r
            .atlas
            .as_ref()
            .unwrap()
            .by_threat
            .get(&t.id)
            .into_iter()
            .flatten()
        {
            pairs += 1;
            // Compared with nothing, a phrase with a word reads as sharing nothing; one without, as
            // agreeing with everything.
            if !shares_no_words(&a.because, "") {
                wrong.push(format!(
                    "{} {}: `{}` has no word to compare",
                    t.id, a.id, a.because
                ));
            }
            if shares_no_words(&a.because, &t.description) {
                wrong.push(format!(
                    "{} {}: `{}` shares nothing with the threat",
                    t.id, a.id, a.because
                ));
            }
            if shares_no_words(&a.because, &a.name) {
                wrong.push(format!(
                    "{} {}: `{}` shares nothing with `{}`",
                    t.id, a.id, a.because, a.name
                ));
            }
        }
    }
    assert!(pairs >= 8, "only {pairs} references read");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // And the guard sees a reference pointing at the wrong technique: prompt injection's phrase
    // against unsecured credentials.
    let atlas = r.atlas.as_ref().unwrap();
    let because = &atlas.by_threat["T-07"][0].because;
    let credentials = &atlas.by_threat["T-10"][0].name;
    assert!(
        shares_no_words(because, credentials),
        "`{because}` against `{credentials}`"
    );
}

#[test]
fn atlas_references_that_could_not_mean_what_they_say_are_refused() {
    use sv_report::threats::AtlasReferences;
    let r = rules();
    let doctored = |change: &dyn Fn(&mut serde_json::Value)| {
        let mut v: serde_json::Value = serde_json::from_str(&atlas_text()).unwrap();
        change(&mut v);
        AtlasReferences::parse(&v.to_string(), &r)
    };
    let refused = |change: &dyn Fn(&mut serde_json::Value), says: &str| {
        let err = doctored(change).expect_err(says).to_string();
        assert!(err.contains(says), "{says}: {err}");
    };
    assert!(doctored(&|_| {}).is_ok(), "the file itself loads");
    refused(
        &|v| {
            v["threats"]["T-99"] =
                serde_json::json!([{ "id": "AML.T0051", "because": "prompt injection" }])
        },
        "not in the threat model",
    );
    refused(
        &|v| {
            v["threats"]["T-01"] =
                serde_json::json!([{ "id": "AML.T0051", "because": "prompt injection" }])
        },
        "not a threat about AI",
    );
    refused(
        &|v| v["threats"]["T-07"][0]["id"] = "AML.T0015".into(),
        "whose name was not read",
    );
    refused(
        &|v| v["techniques"]["AML.T0015"] = "Evade AI Model".into(),
        "which no threat cites",
    );
    refused(
        &|v| v["threats"]["T-07"][0]["because"] = " ".into(),
        "no `because`",
    );
    refused(
        &|v| v["threats"]["T-07"] = serde_json::json!([]),
        "no ATLAS technique",
    );
    refused(&|v| v["release"] = "2026.10".into(), "read from");
}

#[test]
fn the_report_lists_atlas_references_for_a_reviewer_only_where_ai_threats_apply() {
    let f = Frameworks::load(&data().join("frameworks")).unwrap();
    let buckets = sv_frameworks::applicability::Buckets::default();
    let build = |r: &ThreatRules, ai: bool| {
        let ctx = context(&[("auth", true), ("ai", ai)]);
        sv_report::build(sv_report::Inputs {
            app_name: "Atlas",
            target_level: 1,
            generated: None,
            run_note: None,
            run_steps: Vec::new(),
            frameworks: &f,
            buckets: &buckets,
            claims: &[],
            findings: vec![],
            verified: &[],
            gaps: vec![],
            manual_only: Default::default(),
            named_in_tests: Default::default(),
            not_for_tests: Default::default(),
            documented: &[],
            attested: &[],
            human: None,
            threats: Some((r, &ctx)),
        })
    };
    let with = rules().with_atlas().unwrap();
    let report = build(&with, true);
    let md = sv_report::markdown::compliance(&report);
    let html = sv_report::html::page(&report);
    for text in [&md, &html] {
        assert!(
            text.contains("For a security reviewer: these threats in MITRE ATLAS"),
            "{text}"
        );
        assert!(text.contains("AML.T0051"), "{text}");
        assert!(text.contains("LLM Prompt Injection"));
        assert!(text.contains("release 2026.09"));
        assert!(text.contains("references, not checks"));
    }
    // A reference changes no status: the same app without the references has the same threats.
    let without = build(&rules(), true);
    let statuses = |r: &sv_report::Report| {
        r.threats
            .iter()
            .map(|t| (t.id.clone(), t.status))
            .collect::<Vec<_>>()
    };
    assert_eq!(statuses(&report), statuses(&without));
    assert!(!sv_report::markdown::compliance(&without).contains("MITRE ATLAS"));
    // No AI, no AI threats, and no table.
    let no_ai = build(&with, false);
    assert!(!sv_report::markdown::compliance(&no_ai).contains("MITRE ATLAS"));
    assert!(!sv_report::html::page(&no_ai).contains("MITRE ATLAS"));
}
