//! What an application's own tests cannot show, read against the real data: each of the rule's four
//! reasons holds on a requirement that only it covers, so a reason dropped fails a test of its own.

use std::path::PathBuf;
use sv_frameworks::Frameworks;
use sv_frameworks::applicability::{ApplicabilityConfig, VerificationClass};

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data")
}

fn loaded() -> (Frameworks, ApplicabilityConfig) {
    let frameworks = Frameworks::load(&data_dir().join("frameworks")).unwrap();
    let config = ApplicabilityConfig::load_v2(
        &data_dir().join("knowledge"),
        &data_dir().join("applicability-v2.json"),
    )
    .unwrap();
    (frameworks, config)
}

/// Whether the requirement's own words ask for documentation.
fn asks_for_documentation(frameworks: &Frameworks, id: &str) -> bool {
    let text = frameworks.get(id).unwrap().description.to_lowercase();
    text.contains("documentation") || text.contains("documented")
}

fn class_is_documentation_or_deployment(config: &ApplicabilityConfig, id: &str) -> bool {
    matches!(
        config.verification_class_for(id),
        VerificationClass::DocGenerated | VerificationClass::DeploymentTime
    )
}

#[test]
fn a_requirement_classed_as_documentation_is_not_for_tests() {
    let (frameworks, config) = loaded();
    // The setup: classed as documentation, and nothing else would put it here.
    let id = "C3.1.1";
    assert_eq!(
        config.verification_class_for(id),
        VerificationClass::DocGenerated
    );
    assert!(!asks_for_documentation(&frameworks, id));
    assert!(config.not_for_tests(&frameworks, id));
}

#[test]
fn a_requirement_classed_as_deployment_is_not_for_tests() {
    let (frameworks, config) = loaded();
    let id = "V4.2.1";
    assert_eq!(
        config.verification_class_for(id),
        VerificationClass::DeploymentTime
    );
    assert!(!asks_for_documentation(&frameworks, id));
    assert!(config.not_for_tests(&frameworks, id));
}

#[test]
fn the_appendix_on_the_development_process_is_not_for_tests() {
    let (frameworks, config) = loaded();
    // Neither its class nor its words put it here; only being in Appendix C does.
    let id = "AC.1.2";
    assert!(!class_is_documentation_or_deployment(&config, id));
    assert!(!asks_for_documentation(&frameworks, id));
    assert!(config.not_for_tests(&frameworks, id));
    // And every requirement of the appendix, whatever its class.
    let appendix: Vec<&String> = frameworks
        .requirements
        .keys()
        .filter(|id| id.starts_with("AC."))
        .collect();
    assert!(appendix.len() > 40, "{}", appendix.len());
    for id in appendix {
        assert!(config.not_for_tests(&frameworks, id), "{id}");
    }
}

#[test]
fn a_requirement_whose_words_ask_for_documentation_is_not_for_tests() {
    let (frameworks, config) = loaded();
    // "a documented plan": classed as one an AI tool can help with, so only its words put it here.
    let id = "V11.1.4";
    assert_eq!(
        config.verification_class_for(id),
        VerificationClass::AiAssistable
    );
    assert!(asks_for_documentation(&frameworks, id));
    assert!(config.not_for_tests(&frameworks, id));
}

#[test]
fn a_requirement_an_apps_tests_can_show_is_for_tests() {
    let (frameworks, config) = loaded();
    // The control: without it, a rule that said "not for tests" of everything would pass the rest.
    for id in ["V6.2.1", "C1.1.1"] {
        assert!(!class_is_documentation_or_deployment(&config, id), "{id}");
        assert!(!asks_for_documentation(&frameworks, id), "{id}");
        assert!(!config.not_for_tests(&frameworks, id), "{id}");
    }
}
