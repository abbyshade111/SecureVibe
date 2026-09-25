//! Every citation in the data files, read against the requirement it names.
//!
//! This guard exists because the citations were wrong and nothing noticed. ASVS 5.0 `V1.2.1` is
//! about output encoding for an HTTP response, HTML or XML document; it was cited for SQL injection
//! and `eval` by seven rules across `adapters.json` and `ast-rules.json`. Nine rules cited `V1.2.2`
//! (URL encoding) for OS command injection. Eight cited `V11.3.1` (block modes and padding) for weak
//! hash functions. The SSRF rule cited the database-query requirement.
//!
//! None of that was visible. A wrong citation produces a finding, or a green line, against a
//! requirement nobody examined, and the report gives its reader no way to tell. It had been found
//! twice before by accident — five checkers citing `AC-NN` ids that did not exist, then every probe
//! citation — and was found a third time only because an example app happened to trip the
//! test-name comparison.
//!
//! So the same comparison runs here, over the data files rather than over somebody's tests. Two
//! checks, and the second is the one that matters:
//!
//! 1. **The id exists.** A citation that resolves to nothing is the `AC-NN` fault exactly.
//! 2. **The words overlap.** A rule about SQL and a requirement about HTML encoding share no
//!    vocabulary, and that is enough to catch every fault listed above.
//!
//! The overlap test is deliberately weak — it asks for one word in common, not agreement — because
//! it must not be a thing people route around. It cannot catch a swap between neighbouring
//! requirements that share vocabulary, and `V1.2.4` against `V1.2.7` (both parameterized queries)
//! would pass. What it does catch is a citation pointing at a different subject altogether, which is
//! every mistake made here so far.

use std::collections::BTreeMap;
use std::path::PathBuf;
use sv_check::adapters::Adapters;
use sv_check::ast::AstRules;
use sv_check::suite::shares_no_words;
use sv_frameworks::Frameworks;

fn data(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

/// The requirement text `sv` itself loads — not a copy, so this cannot pass against stale data.
fn requirements() -> BTreeMap<String, String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/frameworks");
    let frameworks = Frameworks::load(&dir).expect("the frameworks load");
    frameworks
        .requirements
        .iter()
        .map(|(id, info)| (id.clone(), info.description.clone()))
        .collect()
}

/// Every (where, cited id, what the citing thing is about) triple in the data files.
fn every_citation() -> Vec<(String, String, String)> {
    let mut out = Vec::new();

    let adapters = Adapters::load(&data("adapters.json")).expect("the adapters load");
    for adapter in adapters.all() {
        for (rule_id, rule) in &adapter.rules {
            for requirement in &rule.requirements {
                out.push((
                    format!("adapters.json {} {rule_id}", adapter.id),
                    requirement.clone(),
                    rule.what.clone(),
                ));
            }
        }
    }

    let ast = AstRules::load(&data("ast-rules.json")).expect("the rules load");
    for rule in ast.rules() {
        for requirement in &rule.requirement_ids {
            out.push((
                format!("ast-rules.json {}", rule.id),
                requirement.clone(),
                format!("{} {}", rule.title, rule.description),
            ));
        }
    }

    let secrets =
        sv_check::secrets::SecretRules::load(&data("secret-rules.json")).expect("the rules load");
    for rule in secrets.rules() {
        for requirement in &rule.requirement_ids {
            out.push((
                format!("secret-rules.json {}", rule.id),
                requirement.clone(),
                format!("{} {}", rule.title, rule.description),
            ));
        }
    }
    for requirement in sv_check::secrets::ASSIGNMENT_REQUIREMENTS {
        out.push((
            "secrets.rs secrets.credential-assignment".to_owned(),
            (*requirement).to_owned(),
            sv_check::secrets::ASSIGNMENT_WHAT.to_owned(),
        ));
    }

    out
}

#[test]
fn every_cited_requirement_exists() {
    // The `AC-NN` fault: five checkers once cited ids that resolved to nothing, and the reports
    // showed those findings against requirements the app was never assessed on.
    let known = requirements();
    let missing: Vec<String> = every_citation()
        .into_iter()
        .filter(|(_, id, _)| !known.contains_key(id))
        .map(|(where_, id, _)| format!("{where_} cites {id}, which is not a loaded requirement"))
        .collect();
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn every_citation_shares_vocabulary_with_the_requirement_it_names() {
    // The fault this was written for. Each line below is one that was really in the file.
    let known = requirements();
    let mut wrong = Vec::new();
    for (where_, id, what) in every_citation() {
        let Some(description) = known.get(&id) else {
            continue; // reported by the test above
        };
        if shares_no_words(&what, description) {
            wrong.push(format!(
                "{where_} cites {id}\n    the rule is about: {what}\n    {id} asks:         {}",
                description.chars().take(120).collect::<String>()
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} citation(s) name a requirement they share no words with:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn the_guard_catches_the_mistake_that_was_really_made() {
    // Breaking the guard proves it fails; this proves it fails on the *actual* historical fault
    // rather than on something merely adjacent. V1.2.1 is output encoding; it was cited for SQL.
    let known = requirements();
    let v1_2_1 = known.get("V1.2.1").expect("V1.2.1 is a real requirement");
    assert!(
        shares_no_words(
            "SQL query built by string formatting or concatenation",
            v1_2_1
        ),
        "V1.2.1 cited for SQL has to read as wrong, or this guard proves nothing: {v1_2_1}"
    );
    // And the citation that replaced it has to read as right, or the guard is simply strict.
    let v1_2_4 = known.get("V1.2.4").expect("V1.2.4 is a real requirement");
    assert!(
        !shares_no_words(
            "SQL query built by string formatting or concatenation",
            v1_2_4
        ),
        "V1.2.4 is the right home for it: {v1_2_4}"
    );
}
