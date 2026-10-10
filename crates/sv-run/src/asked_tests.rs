//! Every suite's steps reach the report and `sv run` (backlog 226, part 1, item 4).

use super::*;

fn suite(step: &str) -> Option<sv_check::signed_in::Outcome> {
    Some(sv_check::signed_in::Outcome {
        steps: vec![step.to_owned()],
        ..Default::default()
    })
}

fn outcome() -> RunOutcome {
    RunOutcome {
        healthy: true,
        tests: None,
        fence: Fence::DockerInternalNetwork,
        probe_responses: Vec::new(),
        probes_rate_limited: Vec::new(),
        signed_in: None,
        oidc: None,
        ai: None,
        mcp_server: None,
        fetch: None,
        left_over_removed: Vec::new(),
        liveness: Vec::new(),
        sidecar_lost: None,
        installed: Vec::new(),
        stand_ins: Default::default(),
        container: Default::default(),
        suite_timings: Vec::new(),
    }
}

#[test]
fn every_suite_asked_is_listed_with_its_steps_in_the_order_asked() {
    let run = RunOutcome {
        signed_in: suite("signed in as A"),
        oidc: suite("signed in through the test provider"),
        ai: suite("asked the AI feature"),
        mcp_server: suite("asked the MCP endpoint"),
        fetch: suite("gave the feature an address"),
        ..outcome()
    };
    let steps: Vec<&str> = run
        .asked()
        .into_iter()
        .flat_map(|(_, o)| o.steps.iter().map(String::as_str))
        .collect();
    assert_eq!(
        steps,
        [
            "signed in as A",
            "signed in through the test provider",
            "asked the AI feature",
            "asked the MCP endpoint",
            "gave the feature an address",
        ],
        "a suite's steps would reach nobody"
    );
    let leads: Vec<&str> = run.asked().into_iter().map(|(lead, _)| lead).collect();
    let mut unique = leads.clone();
    unique.dedup();
    assert_eq!(
        unique.len(),
        5,
        "two suites are introduced alike: {leads:?}"
    );
}

#[test]
fn a_suite_not_asked_is_not_listed() {
    let run = RunOutcome {
        fetch: suite("gave the feature an address"),
        ..outcome()
    };
    let asked = run.asked();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].0.contains("fetches an address"));
    assert!(outcome().asked().is_empty());
}
