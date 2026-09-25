//! Tests against the real OWASP data files, not fixtures. The engine's whole job is to read those
//! files correctly, so a fixture that agrees with the engine proves nothing about ASVS.

use std::path::PathBuf;
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, ConditionContext, bucket};
use sv_frameworks::{Condition, Source};

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data")
}

/// The v2 overlay that replaces the rules describing v1's own template.
fn overlay() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/applicability-v2.json")
}

fn v2_config() -> ApplicabilityConfig {
    ApplicabilityConfig::load_v2(&data_dir().join("knowledge"), &overlay()).unwrap()
}

#[test]
fn loads_every_framework() {
    let f = Frameworks::load(&data_dir().join("frameworks")).expect("frameworks load");
    // ASVS, AISVS, Appendix C and the Secure by Design checklist. The exact count moves when OWASP
    // data is updated; the assertion is that all four files parsed, not a frozen number.
    assert!(f.len() > 500, "only {} requirements loaded", f.len());
    assert!(f.get("V6.2.1").is_some(), "ASVS missing");
    assert!(f.get("C9.2.1").is_some(), "AISVS missing");
    assert!(f.get("AC.4.1").is_some(), "Appendix C missing");
    assert!(
        f.get("SBD-AC-01").is_some(),
        "Secure by Design checklist missing"
    );
}

#[test]
fn the_checklist_loads_whole_and_namespaced() {
    // `sv --help` and the README claimed this was checked while nothing loaded it, so the count is
    // asserted rather than the presence of one id: a reader of that claim is owed all 36.
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let controls: Vec<&str> = f
        .requirements
        .keys()
        .filter(|id| id.starts_with("SBD-"))
        .map(String::as_str)
        .collect();
    assert_eq!(controls.len(), 36, "{controls:?}");

    // The namespace is the point. Appendix C owns `AC.5`; the checklist owns `AC-05`, and five
    // checkers here once cited one for the other. Neither may be reachable under the other's name.
    assert!(
        f.get("AC-01").is_none(),
        "the checklist must not claim a bare AC id"
    );
    assert!(f.get("SBD-AC.1.1").is_none());
    assert_eq!(f.get("AC.1.1").map(|r| r.chapter_id.as_str()), Some("AC.1"));

    // The derived level, on real data rather than a hand-built control.
    assert_eq!(
        f.get("SBD-AS-01").map(|r| r.level),
        Some(1),
        "critical and high"
    );
    assert_eq!(
        f.get("SBD-AC-03").map(|r| r.level),
        Some(1),
        "high, not critical"
    );
    assert_eq!(f.get("SBD-DM-01").map(|r| r.level), Some(2), "medium");
    assert_eq!(f.get("SBD-AS-02").map(|r| r.level), Some(3), "low");
}

#[test]
fn no_two_requirement_ids_differ_only_by_how_they_are_punctuated() {
    // The guard for the mistake this namespace exists to prevent. `AC-05` and `AC.5` are different
    // strings that a person reads as the same thing, and a citation that resolves to the wrong
    // framework is worse than one that resolves to nothing, because nothing looks wrong.
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let flatten = |id: &str| -> String {
        id.split(['.', '-', '_'])
            .map(|part| part.trim_start_matches('0'))
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("|")
            .to_uppercase()
    };
    let mut seen: std::collections::BTreeMap<String, &str> = std::collections::BTreeMap::new();
    let mut clashes = Vec::new();
    for id in f.requirements.keys() {
        if let Some(other) = seen.insert(flatten(id), id) {
            clashes.push(format!("{other} and {id} read as the same id"));
        }
    }
    assert!(clashes.is_empty(), "{}", clashes.join("\n"));
}

#[test]
fn appendix_c_requirements_land_in_their_family() {
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let ac = f.get("AC.4.1").unwrap();
    assert_eq!(ac.chapter_id, "AC.4");
    assert!(
        ac.section_id.is_none(),
        "Appendix C families have no section level"
    );
}

#[test]
fn silence_in_the_rules_means_the_requirement_applies() {
    // The property the whole manifest-driven design rests on: a requirement nobody wrote a rule
    // for is in scope. A claim that goes missing must cost the user a requirement they must meet,
    // never one they are wrongly told to skip.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let ctx = ConditionContext::default(); // nothing answered
    let buckets = bucket(&f, &config, &ctx, 2);

    let unruled: Vec<&String> = buckets
        .applicable
        .iter()
        .filter(|id| config.rules_for(id).is_empty())
        .collect();
    assert!(
        !unruled.is_empty(),
        "with every condition false, requirements with no rule must still apply"
    );
}

#[test]
fn the_overlay_leaves_almost_no_inherited_never_rules() {
    // 39 rules in the shared applicability.json use the `never` condition, and their reasons are
    // statements about v1's Node template: "this app is written in TypeScript for Node.js", "all
    // data lives in its own SQLite database file", "the model is hosted and maintained by the
    // vendor (Anthropic)". For an app `sv` did not write, those are not reasons — they are wrong
    // statements in a report, which is what ADR-012 exists to prevent.
    //
    // The overlay replaces 37 of them. The two left are V15.4 and C5.1, whose reasons say the
    // requirements are ASVS level 3 — honest, and nothing to do with v1.
    let base = ApplicabilityConfig::load(&data_dir().join("knowledge")).unwrap();
    let before = base
        .rules
        .iter()
        .filter(|r| r.condition == Condition::Never)
        .count();
    let after = v2_config()
        .rules
        .iter()
        .filter(|r| r.condition == Condition::Never)
        .count();
    assert!(
        before > 30,
        "expected the v1 rules to still carry their `never` rules"
    );
    assert_eq!(after, 2, "only the two level-3 rules may keep `never`");
}

#[test]
fn no_requirement_is_excluded_by_an_inherited_reason() {
    // The property that matters to a reader of the report, rather than to the data file: with the
    // overlay applied, nothing is excluded on the strength of a sentence about v1's template.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = ConditionContext::default();
    // Answer everything, so the only exclusions left are ones a rule really made.
    for c in Condition::ALL {
        ctx.set(*c, false);
    }
    let buckets = bucket(&f, &config, &ctx, 2);
    let inherited: Vec<&str> = buckets
        .not_applicable
        .iter()
        .filter(|na| na.condition == Condition::Never)
        .map(|na| na.id.as_str())
        .collect();
    assert!(
        inherited.is_empty(),
        "still excluded by a v1-template reason: {inherited:?}"
    );
}

#[test]
fn an_unanswered_condition_is_not_assessed_rather_than_not_applicable() {
    // The distinction this whole project exists to keep: "this does not apply to you" and
    // "nothing here has checked" are different answers, and only one of them is safe to guess.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let ctx = ConditionContext::default(); // nothing answered at all
    let buckets = bucket(&f, &config, &ctx, 2);
    assert!(
        !buckets.not_assessed.is_empty(),
        "with nothing answered, gated requirements must be not-assessed"
    );
    assert!(
        buckets.not_applicable.is_empty(),
        "nothing may be excluded when nothing has been answered"
    );
}

#[test]
fn every_overlay_rule_names_where_its_answer_comes_from() {
    // An exclusion resting on the owner's word is weaker than one read out of their dependencies.
    // A report that prints them identically overstates the first, so the source is not optional.
    let base: Vec<String> = ApplicabilityConfig::load(&data_dir().join("knowledge"))
        .unwrap()
        .rules
        .iter()
        .filter(|r| r.condition == Condition::Never)
        .map(|r| r.scope.clone())
        .collect();
    for rule in &v2_config().rules {
        if base.contains(&rule.scope) && rule.condition != Condition::Never {
            assert!(
                rule.source.is_some(),
                "overlay rule for {} states no source",
                rule.scope
            );
            assert!(matches!(rule.source(), Source::Claim | Source::Derived));
        }
    }
}

#[test]
fn manual_only_requirements_get_the_manual_only_class() {
    use sv_frameworks::VerificationClass;
    let config = v2_config();
    // Listed in applicability.json's manualOnly array.
    assert_eq!(
        config.verification_class_for("V2.3.1"),
        VerificationClass::ManualOnly
    );
}

#[test]
fn the_most_specific_scope_wins() {
    let config = v2_config();
    // V1.2.6 has its own requirement-level rule; it must not resolve to V1.2's or V1's.
    let rules = config.rules_for("V1.2.6");
    assert!(
        rules.iter().all(|r| r.scope == "V1.2.6"),
        "a requirement-level rule must replace its section and chapter rules"
    );
}

#[test]
fn a_partly_answered_app_leaves_the_technology_questions_not_assessed() {
    // The realistic case, and the one the CLI actually runs: securevibe.toml answers every claim,
    // and nothing yet reads the dependency manifests, so the technology conditions stay unknown.
    // Those requirements must land in not-assessed and must not appear among the exclusions.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = ConditionContext::default();
    for c in Condition::ALL
        .iter()
        .filter(|c| c.source() == Source::Claim)
    {
        ctx.set(*c, false);
    }
    let buckets = bucket(&f, &config, &ctx, 2);

    // V4.3 is GraphQL, V1.5.1 is XXE, V1.3.8 is JNDI — all read from dependencies, none readable yet.
    for id in ["V4.3.1", "V1.5.1", "V1.3.8"] {
        assert!(
            buckets.not_assessed.iter().any(|na| na.id == id),
            "{id} should be not-assessed while nothing reads the dependencies"
        );
        assert!(
            !buckets.not_applicable.iter().any(|na| na.id == id),
            "{id} must not be excluded on the strength of a scanner that does not exist"
        );
    }
}

#[test]
fn nothing_a_scanner_cannot_yet_answer_is_reported_as_an_exclusion() {
    // The general form of the test above: every exclusion must rest on a condition something
    // actually answered. If a derived condition is unknown, its requirements cannot be excluded.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = ConditionContext::default();
    for c in Condition::ALL
        .iter()
        .filter(|c| c.source() == Source::Claim)
    {
        ctx.set(*c, false);
    }
    let buckets = bucket(&f, &config, &ctx, 2);
    for na in &buckets.not_applicable {
        assert!(
            ctx.get(na.condition).is_some(),
            "{} excluded by {}, which nothing answered",
            na.id,
            na.condition.name()
        );
    }
    assert!(
        !buckets.not_assessed.is_empty(),
        "the derived conditions are unanswered here"
    );
}

#[test]
fn every_requirement_lands_in_exactly_one_bucket() {
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = ConditionContext::default();
    for c in Condition::ALL
        .iter()
        .filter(|c| c.source() == Source::Claim)
    {
        ctx.set(*c, false);
    }
    let buckets = bucket(&f, &config, &ctx, 2);
    let mut seen: Vec<&str> = buckets.applicable.iter().map(String::as_str).collect();
    seen.extend(buckets.not_applicable.iter().map(|na| na.id.as_str()));
    seen.extend(buckets.not_assessed.iter().map(|na| na.id.as_str()));
    seen.extend(buckets.out_of_level.iter().map(String::as_str));
    assert_eq!(
        seen.len(),
        f.len(),
        "a requirement was dropped or double-counted"
    );
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(
        before,
        seen.len(),
        "a requirement is in two buckets at once"
    );
}

#[test]
fn the_conditions_that_gate_nothing_are_exactly_the_ones_we_think() {
    // `payments` and `scheduler` are asked about in securevibe.toml, have plain-language reasons
    // written for them, and no rule in the OWASP data keys on either. That is worth pinning: it
    // is surprising, `sv` tells the owner about it, and if a future data update gives one of them
    // a rule, or takes a rule away from something else, somebody should have to notice.
    //
    // `internet` was on this list until the Secure by Design checklist was loaded, and came off it
    // because two of its controls — rate limits and caching at the edge — are the first rules in
    // any of the data to key on it. That is the test doing its job: the list is meant to change
    // only when somebody means it to.
    use sv_frameworks::applicability::requirements_gated_on;
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();

    let inert: Vec<&str> = Condition::ALL
        .iter()
        .filter(|c| requirements_gated_on(&f, &config, **c, 2) == 0)
        .map(|c| c.name())
        .collect();

    assert_eq!(
        inert,
        vec![
            "never",
            "no-auth",
            "public-api",
            "payments",
            "scheduler",
            "level2",
            "self-assessment",
        ],
        "the set of conditions that decide nothing has changed"
    );
}

#[test]
fn the_conditions_that_do_gate_things_gate_a_sensible_number_of_them() {
    // The other half: a condition that gates a great deal is where a wrong answer is expensive,
    // and `auth` is the most expensive of all. This is why no corroborator may ever rule it out.
    use sv_frameworks::applicability::requirements_gated_on;
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let auth = requirements_gated_on(&f, &config, Condition::Auth, 2);
    assert!(
        auth > 40,
        "auth should gate a large part of ASVS; it gates {auth}"
    );
}
