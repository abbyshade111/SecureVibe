//! The coding rules from OWASP AISVS Appendix C: who they are given to, what every copy says about
//! where they come from, and that writing them never disturbs the owner's own `AGENTS.md`.

use std::path::PathBuf;
use sv_check::coding_rules::{BEGIN, CodingRules, END};

fn rules() -> CodingRules {
    CodingRules::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/coding-rules.json"),
    )
    .expect("the rules load")
}

fn ids(given: &[&sv_check::coding_rules::Rule]) -> Vec<String> {
    given.iter().map(|r| r.id.clone()).collect()
}

#[test]
fn with_nothing_known_about_the_app_every_rule_is_given() {
    let r = rules();
    assert_eq!(r.for_app(None).len(), r.rules.len());
    assert!(r.rules.len() >= 15, "{}", r.rules.len());
}

#[test]
fn a_rule_is_left_out_only_when_everything_it_cites_does_not_apply() {
    let r = rules();
    // No pipeline: every AC.12 requirement is set aside.
    let no_pipeline = |id: &str| id.starts_with("AC.12.");
    let given = ids(&r.for_app(Some(&no_pipeline)));
    assert!(
        !given.contains(&"no-untrusted-code-with-secrets".to_owned()),
        "{given:?}"
    );
    assert!(
        !given.contains(&"least-privilege-workflows".to_owned()),
        "{given:?}"
    );
    // It also cites AC.7.1 and AC.7.2, which still apply: one requirement that applies is enough.
    assert!(
        given.contains(&"label-and-hold-pipeline-files".to_owned()),
        "{given:?}"
    );
    assert!(given.contains(&"keys-stay-out-of-the-chat".to_owned()));
    assert_eq!(given.len(), r.rules.len() - 2);
}

#[test]
fn a_rule_given_to_every_app_says_why_and_is_given_whatever_applies() {
    let r = rules();
    let always: Vec<&str> = r
        .rules
        .iter()
        .filter(|x| x.always.is_some())
        .map(|x| x.id.as_str())
        .collect();
    assert_eq!(always, ["only-packages-that-exist"]);
    let nothing_applies = |_: &str| true;
    assert_eq!(
        ids(&r.for_app(Some(&nothing_applies))),
        ["only-packages-that-exist"]
    );
}

#[test]
fn every_copy_credits_the_source_and_carries_its_license() {
    let r = rules();
    let text = r.markdown(&r.for_app(None), 0);
    for needed in [
        "OWASP AI Security Verification Standard (AISVS) 1.0, Appendix C",
        "https://github.com/OWASP/AISVS/blob/main/1.0/en/0x92-Appendix-C_AI_for_Code_Generation.md",
        "the OWASP AISVS project and its contributors",
        "[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)",
        "rewritten as instructions for an AI coding tool",
        "shared under the same license",
    ] {
        assert!(text.contains(needed), "missing {needed:?}:\n{text}");
    }
    // A single topic is still credited in full.
    let one: Vec<_> = r
        .for_app(None)
        .into_iter()
        .filter(|x| x.topic == "dependencies")
        .collect();
    assert!(r.markdown(&one, 0).contains("CC BY-SA 4.0"));
}

#[test]
fn every_rule_names_what_it_comes_from_and_says_it_is_not_evidence() {
    let r = rules();
    let text = r.markdown(&r.for_app(None), 0);
    for rule in &r.rules {
        let line = text
            .lines()
            .find(|l| l.contains(&rule.rule))
            .unwrap_or_else(|| panic!("{} is not in the text", rule.id));
        for id in rule.cites.keys() {
            assert!(
                line.contains(id.as_str()),
                "{} does not name {id}: {line}",
                rule.id
            );
        }
    }
    assert!(text.contains("not evidence"), "{text}");
    let left_out = r.markdown(&r.for_app(None), 3);
    assert!(left_out.contains("3 more rules are left out"), "{left_out}");
}

#[test]
fn the_rules_stay_short_enough_to_live_in_every_conversation() {
    // Appendix C itself is about 23,000 characters; the point of the rules is to be a fraction.
    let r = rules();
    let chars: usize = r.rules.iter().map(|x| x.rule.len()).sum();
    assert!(chars < 6_000, "{chars} characters of rules");
}

#[test]
fn a_new_agents_file_holds_only_the_section() {
    let r = rules();
    let out = r.into_agents_file(None, "## Rules\n\n- one\n").unwrap();
    assert!(
        out.starts_with(BEGIN) && out.trim_end().ends_with(END),
        "{out}"
    );
}

#[test]
fn the_owners_own_agents_file_is_kept_and_the_section_added_after_it() {
    let r = rules();
    let owner = "# My app\n\nUse tabs, and never touch `legacy/`.\n";
    let out = r
        .into_agents_file(Some(owner), "## Rules\n\n- one\n")
        .unwrap();
    assert!(out.starts_with(owner.trim_end()), "{out}");
    assert_eq!(out.matches(BEGIN).count(), 1);
}

#[test]
fn writing_again_replaces_only_the_section() {
    let r = rules();
    let before = "# My app\n\nUse tabs.\n";
    let after = "\n## Deploying\n\nAsk first.\n";
    let first = r
        .into_agents_file(Some(before), "## Rules\n\n- old\n")
        .unwrap();
    let edited = format!("{first}{after}");
    let second = r
        .into_agents_file(Some(&edited), "## Rules\n\n- new\n")
        .unwrap();
    assert!(
        second.contains("- new") && !second.contains("- old"),
        "{second}"
    );
    assert!(second.starts_with(before.trim_end()), "{second}");
    assert!(
        second.ends_with(after),
        "the owner's text after the section is kept: {second}"
    );
    assert_eq!(second.matches(BEGIN).count(), 1);
    // And writing the same section twice changes nothing.
    let third = r
        .into_agents_file(Some(&second), "## Rules\n\n- new\n")
        .unwrap();
    assert_eq!(third, second);
}

#[test]
fn markers_somebody_broke_are_refused_rather_than_guessed_at() {
    let r = rules();
    for broken in [
        format!("# Mine\n{BEGIN}\nhalf a section, and my notes after it\n"),
        format!("# Mine\n{END}\nmy notes\n{BEGIN}\n"),
    ] {
        assert!(
            r.into_agents_file(Some(&broken), "## Rules\n").is_err(),
            "{broken}"
        );
    }
}

#[test]
fn the_ai_tool_is_told_not_to_rewrite_working_code_to_silence_a_finding() {
    // Gap analysis 4.4: a lesson of the owner's first build, when working code was removed to make
    // a false alarm go away. It rides on the rule against weakening a check, whose citations fit it.
    let all = rules();
    let rule = all
        .rules
        .iter()
        .find(|r| r.id == "never-weaken-a-check")
        .expect("the rule is there");
    assert!(
        rule.rule
            .contains("Never rewrite working code just to make a finding go away"),
        "{}",
        rule.rule
    );
}
