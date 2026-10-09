//! The briefs for records people own or share, API keys, background jobs, and several customer
//! organizations (the gap analysis of 7 October 2026, finding 22(f)), and the rule they brought: a
//! condition a brief names is one that brings something.

use super::*;

fn setup() -> (Features, Frameworks, ApplicabilityConfig) {
    let data = crate::data_dir().unwrap();
    let frameworks = crate::load_frameworks(&data).unwrap();
    let config =
        ApplicabilityConfig::load_v2(&data.join("knowledge"), &crate::overlay_path()).unwrap();
    (
        Features::load(&crate::feature_briefs_path()).unwrap(),
        frameworks,
        config,
    )
}

#[test]
fn every_condition_a_brief_names_brings_a_requirement() {
    // `public-api` is asked in stackvet.toml and gates nothing: a brief naming it would tell the
    // tool that answering yes brings requirements, and none would come.
    let (all, frameworks, config) = setup();
    for f in &all.features {
        for c in &f.conditions {
            assert!(
                !requirement_ids_gated_on(&frameworks, &config, *c).is_empty(),
                "{}: `{}` gates no requirement",
                f.id,
                c.name()
            );
        }
    }
}

#[test]
fn a_requirement_listed_by_hand_is_not_one_its_conditions_already_bring() {
    let (all, frameworks, config) = setup();
    for f in &all.features {
        let gated = brought(f, &frameworks, &config).gated;
        for r in &f.requirements {
            assert!(
                !gated.contains(r),
                "{}: {r} is brought by a condition",
                f.id
            );
        }
    }
}

#[test]
fn the_four_briefs_bring_what_each_feature_is_held_to_and_no_more() {
    let (all, frameworks, config) = setup();
    let of = |id: &str| brought(all.get(id).unwrap(), &frameworks, &config);

    // Records: who may open and change each one, and the fields a request may set; no sign-in
    // requirement, which is sign-in's own brief.
    let owned = of("owned-records");
    assert!(owned.gated.is_empty());
    for id in ["V8.2.2", "V8.2.3", "V15.3.3", "V1.2.1"] {
        assert!(owned.all.contains(id), "{id}: {:?}", owned.all);
    }
    assert!(!owned.all.contains("V6.2.1"));

    // API keys: nothing gated, since `public-api` gates nothing; a key made unguessable.
    let keys = of("api-keys");
    assert!(keys.gated.is_empty());
    assert!(keys.all.contains("V11.5.1"), "{:?}", keys.all);

    // Background jobs: the three Secure by Design controls gated on `scheduler`.
    let jobs = of("background-jobs");
    for id in ["SBD-AS-06", "SBD-DM-03", "SBD-RR-03"] {
        assert!(jobs.gated.contains(id), "{id}: {:?}", jobs.gated);
    }

    // Organizations: ASVS's cross-tenant control, gated on `multi-tenant`, and AISVS's for an
    // assistant several organizations share.
    let orgs = of("organizations");
    assert!(orgs.gated.contains("V8.4.1"), "{:?}", orgs.gated);
    assert!(
        orgs.gated.iter().any(|id| id.starts_with("C5.3.")),
        "{:?}",
        orgs.gated
    );
}

#[test]
fn each_brief_tells_the_tool_which_answer_in_stackvet_toml_it_turns_on() {
    // The capability a brief's conditions read is a setting it quotes, so the tool is shown the
    // line to answer.
    let all = Features::load(&crate::feature_briefs_path()).unwrap();
    for (id, key) in [
        ("api-keys", "public-api"),
        ("background-jobs", "scheduler"),
        ("organizations", "multi-tenant"),
    ] {
        let f = all.get(id).unwrap();
        assert!(
            f.settings
                .iter()
                .any(|s| s.table == "capabilities" && s.key == key),
            "{id}"
        );
        let lines = setting_lines("capabilities", key).unwrap();
        assert!(lines.starts_with(&format!("# {key} = ?")), "{lines}");
    }
}
