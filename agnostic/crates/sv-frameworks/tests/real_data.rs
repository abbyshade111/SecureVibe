//! Tests against the real OWASP data files, not fixtures. The engine's whole job is to read those
//! files correctly, so a fixture that agrees with the engine proves nothing about ASVS.

use std::path::PathBuf;
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, Condition, ConditionContext, bucket};

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data")
}

#[test]
fn loads_every_framework() {
    let f = Frameworks::load(&data_dir().join("frameworks")).expect("frameworks load");
    // ASVS, AISVS and Appendix C together. The exact count moves when OWASP data is updated;
    // the assertion is that all three files parsed, not a frozen number.
    assert!(f.len() > 500, "only {} requirements loaded", f.len());
    assert!(f.get("V6.2.1").is_some(), "ASVS missing");
    assert!(f.get("C9.2.1").is_some(), "AISVS missing");
    assert!(f.get("AC.4.1").is_some(), "Appendix C missing");
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
    let config = ApplicabilityConfig::load(&data_dir().join("knowledge")).unwrap();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let ctx = ConditionContext::default(); // every condition false
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
fn inherited_v1_exclusions_are_identifiable() {
    // 39 rules in applicability.json use the `never` condition, and their reasons are statements
    // about v1's Node template: "this app is written in TypeScript for Node.js", "all data lives
    // in its own SQLite database file", "there is no CI/CD pipeline in a local build". For an app
    // `sv` did not write, those are not reasons — they are wrong statements in a report, which is
    // precisely what ADR-012 exists to prevent.
    //
    // This test does not assert a count, which would only pin today's data. It asserts that every
    // such exclusion is *distinguishable* from a real one, so v2 can report them as not assessed
    // instead of repeating them. Delete `NotApplicable::condition` and this fails.
    let config = ApplicabilityConfig::load(&data_dir().join("knowledge")).unwrap();
    let f = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let ctx = ConditionContext::default();
    let buckets = bucket(&f, &config, &ctx, 2);

    let inherited = buckets
        .not_applicable
        .iter()
        .filter(|na| na.condition == Condition::Never)
        .count();
    assert!(
        inherited > 0,
        "the `never` rules must be visible as inherited, not blended into honest exclusions"
    );
    assert!(
        inherited < buckets.not_applicable.len(),
        "not every exclusion is inherited; the honest ones must survive the filter"
    );
}

#[test]
fn manual_only_requirements_get_the_manual_only_class() {
    use sv_frameworks::VerificationClass;
    let config = ApplicabilityConfig::load(&data_dir().join("knowledge")).unwrap();
    // Listed in applicability.json's manualOnly array.
    assert_eq!(
        config.verification_class_for("V2.3.1"),
        VerificationClass::ManualOnly
    );
}

#[test]
fn the_most_specific_scope_wins() {
    let config = ApplicabilityConfig::load(&data_dir().join("knowledge")).unwrap();
    // V1.2.6 has its own requirement-level rule; it must not resolve to V1.2's or V1's.
    let rules = config.rules_for("V1.2.6");
    assert!(
        rules.iter().all(|r| r.scope == "V1.2.6"),
        "a requirement-level rule must replace its section and chapter rules"
    );
}
