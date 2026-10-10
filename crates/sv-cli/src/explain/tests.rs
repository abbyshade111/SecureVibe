use super::*;
use serde_json::json;

struct Data {
    frameworks: Frameworks,
    reach: Value,
    rules: sv_check::coding_rules::CodingRules,
    prompts: sv_check::prompts::Prompts,
    human: sv_check::human::HumanChecks,
}

fn data() -> Data {
    let paths = crate::prompts_paths();
    Data {
        frameworks: crate::load_frameworks(&crate::data_dir().unwrap()).unwrap(),
        reach: serde_json::from_str(
            &std::fs::read_to_string(sv_frameworks::data::file("reach.json")).unwrap(),
        )
        .unwrap(),
        rules: sv_check::coding_rules::CodingRules::load(&crate::coding_rules_path()).unwrap(),
        prompts: sv_check::prompts::Prompts::load_all(&[&paths[0], &paths[1]]).unwrap(),
        human: sv_check::human::HumanChecks::load(&sv_frameworks::data::file("human-checks.json"))
            .unwrap(),
    }
}

fn said(d: &Data, id: &str, report: Option<&Value>) -> String {
    explain(
        &d.frameworks,
        &d.reach,
        &d.rules,
        &d.prompts,
        &d.human,
        id,
        report.map(|r| (r, "last report")),
    )
    .unwrap()
}

#[test]
fn a_requirement_is_given_in_its_own_words_with_every_check_and_its_kind_of_run() {
    let d = data();
    let text = said(&d, "V9.1.2", None);
    let words = &d.frameworks.get("V9.1.2").unwrap().description;
    assert!(text.contains(words.as_str()), "{text}");
    // The code rule that can only find, the running check, and the outside tool, each with its run.
    assert!(
        text.contains("ast.token-none-algorithm (Reads the code; can show it failing, never met)"),
        "{text}"
    );
    assert!(
        text.contains("probe.app-token-alg-none (Signed in)"),
        "{text}"
    );
    assert!(text.contains("semgrep (Outside tools)"), "{text}");
    assert!(text.contains("It credits nothing"), "{text}");
}

#[test]
fn every_requirement_a_check_can_settle_has_its_checks_listed() {
    // reach.json's two halves are written from the same rows; one without the other would leave
    // `sv explain` saying no check speaks to a requirement the report can credit.
    let d = data();
    let settled = d.reach["requirements"].as_object().unwrap();
    assert!(settled.len() > 100, "{}", settled.len());
    for id in settled.keys() {
        let checks = checks_for(&d.reach, id);
        assert!(
            checks.iter().any(|c| !c.finding_only),
            "{id}: settled by a run, and no check that can credit it is listed"
        );
    }
}

#[test]
fn a_requirement_no_check_speaks_to_says_so_and_what_a_person_can_do() {
    let d = data();
    // One only a person can check, from the list of checks by hand, with no check of sv's.
    let by_hand = d
        .human
        .checks
        .iter()
        .find(|h| checks_for(&d.reach, &h.id).is_empty())
        .expect("a check by hand for a requirement no check speaks to");
    let text = said(&d, &by_hand.id, None);
    assert!(text.contains("No check of sv's speaks to it"), "{text}");
    assert!(
        text.contains(&format!("Check it by hand: {}", by_hand.how)),
        "{text}"
    );
}

#[test]
fn the_coding_rules_and_prompts_that_cite_it_are_named() {
    let d = data();
    let rule = d.rules.rules.first().unwrap();
    let id = rule.cites.keys().next().unwrap();
    let text = said(&d, id, None);
    assert!(
        text.contains(&format!("Coding rule `{}`", rule.id)),
        "{text}"
    );
    let prompt = d
        .prompts
        .prompts
        .iter()
        .find(|p| !p.requirements.is_empty())
        .unwrap();
    let text = said(&d, &prompt.requirements[0], None);
    assert!(text.contains(&format!("Prompt `{}`", prompt.id)), "{text}");
}

#[test]
fn an_apps_report_adds_what_it_said_and_what_a_run_it_did_not_have_could_add() {
    let d = data();
    let report = json!({
        "app_name": "Notes",
        "requirements": [
            { "id": "V9.1.2", "status": "not-verified", "checked_by": [], "findings": [] },
            { "id": "V1.2.4", "status": "checked",
              "checked_by": [{ "check_id": "ast.sql-built-by-hand" }], "findings": [] }
        ],
        "not_run_this_time": { "kinds": ["the running app, signed in or not (`sv report --run`)"] }
    });
    let text = said(&d, "V9.1.2", Some(&report));
    assert!(
        text.contains("In Notes's last report, V9.1.2 is not verified: nothing checked it."),
        "{text}"
    );
    assert!(
        text.contains("That report did not include the running app"),
        "{text}"
    );
    let text = said(&d, "V1.2.4", Some(&report));
    assert!(text.contains("is checked: a check"), "{text}");
    assert!(
        text.contains("Checked by: ast.sql-built-by-hand."),
        "{text}"
    );
    // A requirement the report does not list does not apply, or is above the level: said, not guessed.
    let text = said(&d, "V6.2.1", Some(&report));
    assert!(
        text.contains("V6.2.1 is not among the requirements that apply"),
        "{text}"
    );
}

#[test]
fn an_id_no_framework_knows_is_refused() {
    let d = data();
    // Built, not written: an id that resolves to nothing, written out, fails the citations guard.
    let unknown = format!("V{}.9.9", 99);
    let err = explain(
        &d.frameworks,
        &d.reach,
        &d.rules,
        &d.prompts,
        &d.human,
        &unknown,
        None,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains(&format!("{unknown} is not a requirement")),
        "{err}"
    );
}

#[test]
fn every_list_of_credits_is_given_with_whose_word_and_each_finding_with_its_place() {
    // Backlog 226, part 2, item 17: only `checked_by` was printed, and a finding by count alone.
    let report = json!({
        "app_name": "Notes",
        "requirements": [{
            "id": "V9.1.2",
            "status": "needs-attention",
            "findings": ["ast.token-none-algorithm"],
            "checked_by": [{"check_id": "config.something", "scope": "the config"}],
            "tested_by": [{"check_id": "app-tests", "scope": "a test"}],
            "attested_by": [{"check_id": "design.attested", "scope": "yes", "whose": "the owner"}],
            "withheld_by": ["ast.other"]
        }],
        "findings": [{
            "rule_id": "ast.token-none-algorithm",
            "title": "A token accepted with no signature",
            "location": {"file": "app/auth.py", "line": 12},
            "requirement_ids": ["V9.1.2"]
        }]
    });
    let text = from_report(&report, "last report", "V9.1.2", &[]);
    for words in [
        "Checked by: config.something.",
        "Tested by the app's own tests (written by the AI coding tool, not a check of sv's): app-tests.",
        "Answered yes: design.attested (the owner).",
        "Kept from counting: ast.other was set aside as a false alarm",
        "1 finding names it, and a finding outranks every credit, so what passed does not count:",
        "  ast.token-none-algorithm at app/auth.py:12: A token accepted with no signature",
    ] {
        assert!(text.contains(words), "missing {words:?} in:\n{text}");
    }
}
