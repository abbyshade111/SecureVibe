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
    //
    // Requirement ids alone are not enough, and assuming they were is a mistake this test made on
    // the way in. `AC.5` is a *family* — a chapter — and not a requirement at all, so comparing
    // only requirement ids would have let the original `AC-05` collision through while looking
    // like it covered it. Applicability rules scope to chapters and sections as well, so every id
    // anything can be addressed by has to be in the comparison.
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let flatten = |id: &str| -> String {
        id.split(['.', '-', '_'])
            .map(|part| part.trim_start_matches('0'))
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("|")
            .to_uppercase()
    };
    let mut addressable: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for (id, info) in &f.requirements {
        addressable.insert(id.clone());
        addressable.insert(info.chapter_id.clone());
        if let Some(section) = &info.section_id {
            addressable.insert(section.clone());
        }
    }
    assert!(
        addressable.contains("AC.5"),
        "the family the original mistake cited has to be in the comparison"
    );

    let mut seen: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    let mut clashes = Vec::new();
    for id in &addressable {
        if let Some(other) = seen.insert(flatten(id), id.clone()) {
            clashes.push(format!("{other} and {id} read as the same id"));
        }
    }
    assert!(clashes.is_empty(), "{}", clashes.join("\n"));
}

#[test]
fn the_design_review_count_a_report_would_print_is_a_real_subset() {
    // The second witness, at the level the CLI actually works: it filters `buckets.applicable` by
    // the verification class to build the gap that says how many requirements no check can reach.
    // The first witness asks the config directly, which would still pass if bucketing dropped the
    // class on the way through.
    use sv_frameworks::VerificationClass;
    use sv_frameworks::applicability::bucket;
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let ctx = ConditionContext::default(); // nothing answered
    let buckets = bucket(&f, &config, &ctx, 3);

    let design_review: Vec<&String> = buckets
        .applicable
        .iter()
        .filter(|id| config.verification_class_for(id) == VerificationClass::ManualOnly)
        .collect();
    let checklist = design_review
        .iter()
        .filter(|id| id.starts_with("SBD-"))
        .count();

    assert!(checklist > 0, "no checklist control survived bucketing");
    assert!(
        design_review.len() > checklist,
        "the count has to include the requirements already on the manualOnly list, not only the \
         checklist: {} design review, {checklist} of them from the checklist",
        design_review.len()
    );
    assert!(
        design_review.len() < buckets.applicable.len(),
        "a count covering everything applicable would tell a reader nothing"
    );
}

#[test]
fn every_checklist_control_is_design_review_and_not_everything_is() {
    // The claim that makes loading the checklist honest rather than noisy: these are applicable and
    // unverified, like many ASVS requirements, but unlike those they cannot be reached by any check
    // that could ever be written. Without this the class was set by a line of code nothing tested.
    use sv_frameworks::VerificationClass;
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();

    let checklist: Vec<&String> = f
        .requirements
        .keys()
        .filter(|id| id.starts_with("SBD-"))
        .collect();
    assert_eq!(checklist.len(), 36);
    for id in &checklist {
        assert_eq!(
            config.verification_class_for(id),
            VerificationClass::ManualOnly,
            "{id} is a design-review control and has to be classed as one"
        );
    }

    // And the other half: a class that applied to everything would say nothing. Something a check
    // really can reach must not come back manual-only.
    assert_ne!(
        config.verification_class_for("V1.2.4"),
        VerificationClass::ManualOnly,
        "parameterized queries are reachable by a scanner; the class must discriminate"
    );
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
    // Conditions asked about in securevibe.toml that no rule in the data keys on. That is worth
    // pinning: it is surprising, `sv` tells the owner about it, and if a future data update gives
    // one of them a rule, or takes a rule away from something else, somebody should have to notice.
    //
    // `payments` and `scheduler` were on this list until 25 September 2026, when they became the
    // second question behind two Secure by Design controls: a single service still needs
    // repeat-safe handlers when a payment provider retries its webhooks (DM-03), and durable
    // messaging when it runs a job queue (AS-06, RR-03). "Runs as one service" alone had been
    // switching those off.
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

#[test]
fn a_single_service_still_gets_the_controls_its_other_answers_call_for() {
    // Found in review on 25 September 2026. "Runs as one service" was the only question behind
    // controls a single app can plainly still need, and `tls = off` alone switched off "all
    // communications use TLS" for an app on the internet. Each case here is one control, the
    // condition that now keeps it, and a word its exclusion reason has to carry — a reason that
    // named only "one service" would be telling a reader half of why.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let cases: &[(&str, Condition, Condition, &str)] = &[
        (
            "SBD-RR-02",
            Condition::MultipleServices,
            Condition::ExternalApis,
            "outside services",
        ),
        (
            "SBD-DM-03",
            Condition::MultipleServices,
            Condition::Payments,
            "payments",
        ),
        (
            "SBD-DM-03",
            Condition::MultipleServices,
            Condition::Scheduler,
            "background jobs",
        ),
        (
            "SBD-AS-06",
            Condition::MultipleServices,
            Condition::Scheduler,
            "job queue",
        ),
        (
            "SBD-RR-03",
            Condition::MultipleServices,
            Condition::Scheduler,
            "job queue",
        ),
        (
            "SBD-AC-01",
            Condition::Tls,
            Condition::Internet,
            "not on the internet",
        ),
    ];
    let every_gate =
        |id: &str| -> Vec<Condition> { config.rules_for(id).iter().map(|r| r.condition).collect() };
    for (id, first, second, word) in cases {
        let gates = every_gate(id);
        assert!(
            gates.contains(first) && gates.contains(second),
            "{id}: {gates:?}"
        );

        // Everything it turns on says no: excluded, with a reason naming the second question too.
        let mut all_no = ConditionContext::default();
        for c in &gates {
            all_no.set(*c, false);
        }
        let buckets = bucket(&f, &config, &all_no, 3);
        let excluded = buckets
            .not_applicable
            .iter()
            .find(|na| na.id == *id)
            .unwrap_or_else(|| panic!("{id} should be excluded when every answer is no"));
        assert!(
            excluded.reason.contains(word),
            "{id}: the reason has to say why the second question does not apply either: {}",
            excluded.reason
        );

        // One service, but the other answer is yes: it applies.
        let mut ctx = all_no.clone();
        ctx.set(*second, true);
        let buckets = bucket(&f, &config, &ctx, 3);
        assert!(
            buckets.applicable.iter().any(|a| a == id),
            "{id} has to apply when {} holds, even on one service",
            second.name()
        );

        // One service, the other question unanswered: not assessed, never excluded.
        let mut unanswered = ConditionContext::default();
        unanswered.set(*first, false);
        let buckets = bucket(&f, &config, &unanswered, 3);
        assert!(
            buckets.not_assessed.iter().any(|na| na.id == *id),
            "{id} with {} unanswered must be not assessed",
            second.name()
        );
    }

    // Startup with a missing dependency applies to anything with a database, which is nearly
    // everything, so it has no gate at all.
    assert!(
        every_gate("SBD-AS-07").is_empty(),
        "{:?}",
        every_gate("SBD-AS-07")
    );
    let mut one_service = ConditionContext::default();
    one_service.set(Condition::MultipleServices, false);
    let buckets = bucket(&f, &config, &one_service, 3);
    assert!(buckets.applicable.iter().any(|a| a == "SBD-AS-07"));
}

#[test]
fn the_checklist_for_a_single_service_web_shop() {
    // The second witness, from the other direction: not one control at a time, but the whole
    // checklist for the commonest app `sv` will see — one web service on the internet, over HTTPS,
    // taking card payments and calling outside APIs, with no job queue. Every control about the
    // space between services is excluded; every control a single app still needs is not.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = ConditionContext::default();
    for (c, v) in [
        (Condition::MultipleServices, false),
        (Condition::Internet, true),
        (Condition::Tls, true),
        (Condition::Payments, true),
        (Condition::ExternalApis, true),
        (Condition::Scheduler, false),
        (Condition::Auth, true),
        (Condition::CiCd, true),
    ] {
        ctx.set(c, v);
    }
    let buckets = bucket(&f, &config, &ctx, 3);
    let applies = |id: &str| buckets.applicable.iter().any(|a| a == id);
    let excluded = |id: &str| buckets.not_applicable.iter().find(|na| na.id == id);

    for id in ["SBD-AC-01", "SBD-RR-02", "SBD-DM-03", "SBD-AS-07"] {
        assert!(
            applies(id),
            "{id} is needed by a single web shop and must apply"
        );
    }
    for id in [
        "SBD-AS-01",
        "SBD-AS-02",
        "SBD-AS-03",
        "SBD-AS-04",
        "SBD-AS-05",
        "SBD-AS-08",
        "SBD-AC-04",
        "SBD-DM-04",
        "SBD-DM-06",
        "SBD-RR-04",
    ] {
        assert!(
            excluded(id).is_some(),
            "{id} is about the space between services"
        );
    }
    for id in ["SBD-AS-06", "SBD-RR-03"] {
        let na = excluded(id).unwrap_or_else(|| panic!("{id}: no services and no job queue"));
        assert!(
            na.reason.contains("job queue"),
            "{id} is excluded on two answers and has to say so: {}",
            na.reason
        );
    }
    assert!(
        buckets
            .not_assessed
            .iter()
            .all(|na| !na.id.starts_with("SBD-")),
        "every question the checklist turns on was answered here"
    );

    // The same shop with its manifest saying `tls = off`: the case the AC-01 fix exists for. An
    // app on the internet without HTTPS is exactly the one "all communications use TLS" is about.
    let mut no_tls = ctx.clone();
    no_tls.set(Condition::Tls, false);
    let buckets = bucket(&f, &config, &no_tls, 3);
    assert!(
        buckets.applicable.iter().any(|a| a == "SBD-AC-01"),
        "an internet app claiming no HTTPS must still be asked whether its traffic is encrypted"
    );
}

#[test]
fn the_requirements_a_clean_scan_cannot_settle_include_the_ones_it_was_settling() {
    // A clean credential scan was reported as having checked V13.3.1 (use a key vault) and V11.1.1
    // (a documented key-management policy). Neither is something reading source files establishes.
    // Both are on the manual-only list, and SBD-AC-05 is manual-only by construction; the set the
    // report is handed has to contain all three for an app they apply to.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let buckets = bucket(&f, &config, &ConditionContext::default(), 3);
    let manual = buckets.manual_only(&config);
    for id in ["V13.3.1", "V11.1.1", "SBD-AC-05"] {
        assert!(
            !buckets.applicable.iter().any(|a| a == id) || manual.contains(id),
            "{id} applies and is not in the manual-only set"
        );
        assert!(
            buckets.applicable.iter().any(|a| a == id),
            "{id} should apply here"
        );
    }
    assert!(
        !manual.contains("V1.2.4"),
        "a scanner can settle parameterized queries"
    );
}

// ---- the checklist's levels, grounded in ASVS ----

fn crosswalk() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/sbd-asvs-crosswalk.json")
}

#[test]
fn the_crosswalk_only_ever_lowers_a_controls_level() {
    // The rule the whole crosswalk rests on: it can bring a control into an app's scope sooner and
    // can never take one out. A control whose level went up would be one some app no longer sees.
    let before = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut after = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    after.apply_crosswalk(&crosswalk()).unwrap();
    let mut lowered = 0;
    for (id, info) in after
        .requirements
        .iter()
        .filter(|(id, _)| id.starts_with("SBD-"))
    {
        let was = before.get(id).unwrap().level;
        assert!(
            info.level <= was,
            "{id} went from level {was} to {}",
            info.level
        );
        if info.level < was {
            lowered += 1;
        }
        assert!(
            info.level_basis.is_some(),
            "{id} does not say where its level came from"
        );
    }
    assert!(
        lowered > 0,
        "the crosswalk changed nothing, so this test is not testing it"
    );
    // ASVS itself is untouched.
    assert_eq!(
        after.get("V13.3.1").unwrap().level,
        before.get("V13.3.1").unwrap().level
    );
    assert!(after.get("V13.3.1").unwrap().level_basis.is_none());
}

#[test]
fn each_control_says_where_its_level_came_from() {
    let mut f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    f.apply_crosswalk(&crosswalk()).unwrap();
    let basis = |id: &str| {
        (
            f.get(id).unwrap().level,
            f.get(id).unwrap().level_basis.clone().unwrap(),
        )
    };

    // Nothing in ASVS asks for unified service discovery, and the checklist rates it low severity,
    // which `sv` turned into level 3. With no ASVS level to take, it is shown at every level.
    let (level, why) = basis("SBD-AS-02");
    assert_eq!(level, 1, "was level 3 from severity alone");
    assert!(why.contains("nothing in ASVS"), "{why}");

    // Data classification is V14.1.1's question, at V14.1.1's level.
    let (level, why) = basis("SBD-DM-01");
    assert_eq!(level, 2);
    assert_eq!(why, "level 2, as V14.1.1");

    // Secrets: the checklist calls it high severity, which already puts it at level 1, below its
    // ASVS counterparts at level 2. The lower one wins and the reason says both.
    let (level, why) = basis("SBD-AC-05");
    assert_eq!(level, 1);
    assert!(why.contains("severity") && why.contains("V13.3.1"), "{why}");
    assert_eq!(
        f.get("SBD-AC-05").unwrap().counterparts,
        vec!["V13.3.1", "V13.3.2", "V13.3.4"]
    );
}

fn write_crosswalk(name: &str, json: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("sv-crosswalk-{}-{name}.json", std::process::id()));
    std::fs::write(&path, json).unwrap();
    path
}

#[test]
fn a_crosswalk_that_leaves_a_control_out_or_cites_nothing_real_is_refused() {
    // A control missing from the file would keep its derived level silently, which is the state of
    // affairs the crosswalk exists to end; a citation that resolves to nothing is the AC-NN fault.
    let real = std::fs::read_to_string(crosswalk()).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&real).unwrap();
    v["controls"].as_object_mut().unwrap().remove("SBD-MT-06");
    let missing = write_crosswalk("missing", &v.to_string());
    let mut f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let error = format!("{:#}", f.apply_crosswalk(&missing).unwrap_err());
    assert!(error.contains("SBD-MT-06"), "{error}");

    let mut v: serde_json::Value = serde_json::from_str(&real).unwrap();
    v["controls"]["SBD-AC-05"] = serde_json::json!({"V13.3.99": "secrets somewhere"});
    let unknown = write_crosswalk("unknown", &v.to_string());
    let mut f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let error = format!("{:#}", f.apply_crosswalk(&unknown).unwrap_err());
    assert!(error.contains("V13.3.99"), "{error}");
    std::fs::remove_file(missing).ok();
    std::fs::remove_file(unknown).ok();
}

#[test]
fn a_crosswalk_missing_a_control_with_counterparts_is_refused_too() {
    // Second witness for the completeness rule, on a control that has ASVS counterparts: leaving
    // it out would quietly drop its evidence as well as its level.
    let real = std::fs::read_to_string(crosswalk()).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&real).unwrap();
    v["controls"].as_object_mut().unwrap().remove("SBD-AC-05");
    let missing = write_crosswalk("missing-ac05", &v.to_string());
    let mut f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let result = f.apply_crosswalk(&missing);
    std::fs::remove_file(missing).ok();
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("SBD-AC-05"), "{error}");
}

/// An app that signs people in with "Sign in with Google" answers `oauth`, not
/// `authorization-server`.
fn oauth_client_context() -> ConditionContext {
    let mut ctx = ConditionContext::default();
    for c in Condition::ALL {
        ctx.set(*c, false);
    }
    ctx.set(Condition::Oauth, true);
    ctx
}

#[test]
fn an_oauth_client_is_not_asked_about_the_authorization_server_it_does_not_run() {
    // The fault this condition was added for. ASVS V10.4, V10.6, and V10.7 are written for
    // whoever *runs* the authorization server — pre-registered redirect URI allowlists, single-use
    // authorization codes, refresh token replay, consent screens. An app with a "Sign in with
    // Google" button runs none of that, and was being handed all of it because it answered
    // `oauth = true`.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let buckets = bucket(&f, &config, &oauth_client_context(), 2);

    let excluded: Vec<&str> = buckets
        .not_applicable
        .iter()
        .filter(|na| na.condition == Condition::AuthorizationServer)
        .map(|na| na.id.as_str())
        .collect();
    // The five Level 1 ones are what the backlog entry named; the rest of V10.4, and all of V10.6
    // and V10.7, are the same mistake at Level 2.
    for id in [
        "V10.4.1", "V10.4.2", "V10.4.3", "V10.4.4", "V10.4.5", "V10.4.11", "V10.6.1", "V10.7.1",
    ] {
        assert!(
            excluded.contains(&id),
            "{id} is the authorization server's requirement and still applies to a client"
        );
    }

    // And the other half: the client's own requirements must survive. Excluding V10.2 along with
    // V10.4 would be the same error pointing the other way, and a great deal worse.
    for id in ["V10.1.1", "V10.2.1", "V10.2.2", "V10.3.1", "V10.5.1"] {
        assert!(
            buckets.applicable.iter().any(|a| a == id),
            "{id} is the OAuth client's own requirement and must still apply"
        );
    }
}

#[test]
fn an_app_that_really_runs_an_authorization_server_is_asked_about_it() {
    // The guard against overcorrecting. Someone running an authorization server must still get
    // every one of these; a condition that switched them off for everybody would pass the test
    // above and be useless.
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = oauth_client_context();
    ctx.set(Condition::AuthorizationServer, true);
    let buckets = bucket(&f, &config, &ctx, 2);
    for id in [
        "V10.4.1", "V10.4.2", "V10.4.3", "V10.4.4", "V10.4.5", "V10.4.11", "V10.6.1", "V10.7.1",
    ] {
        assert!(
            buckets.applicable.iter().any(|a| a == id),
            "{id} must apply to an app that runs an authorization server"
        );
    }
}

#[test]
fn nobody_has_said_whether_this_app_is_an_authorization_server() {
    // The third answer, and the one this project exists to keep separate from the other two. A
    // manifest that says `oauth = true` and nothing else has not said which side of OAuth the app
    // is on, and the honest report is "not assessed", never "does not apply".
    let config = v2_config();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let mut ctx = ConditionContext::default();
    // Everything answered except the one question at issue, which is left unanswered rather than
    // answered `false`.
    for c in Condition::ALL
        .iter()
        .filter(|c| **c != Condition::AuthorizationServer)
    {
        ctx.set(*c, false);
    }
    ctx.set(Condition::Oauth, true);
    let buckets = bucket(&f, &config, &ctx, 2);
    for id in ["V10.4.1", "V10.6.1", "V10.7.1"] {
        assert!(
            buckets.not_assessed.iter().any(|na| na.id == id),
            "{id} should be not-assessed while nothing has said whether the app runs one"
        );
        assert!(
            !buckets.not_applicable.iter().any(|na| na.id == id),
            "{id} must not be excluded on a question nobody answered"
        );
    }
}
