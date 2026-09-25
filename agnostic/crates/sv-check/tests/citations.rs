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

/// Every requirement-id-shaped token in the Rust sources, with the file and line it sits on.
fn ids_written_into_the_code() -> Vec<(String, usize, String)> {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut out = Vec::new();
    let mut stack = vec![crates];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            // Only what ships. A test may name an id on purpose *because* it does not exist —
            // `V1.2.9` stands in for a typo in the suite tests — and flagging those would make the
            // guard something people turn off.
            if !path.components().any(|c| c.as_os_str() == "src") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let name = path.display().to_string();
            for (index, line) in text.lines().enumerate() {
                let trimmed = line.trim_start();
                // Prose about a citation is not a citation. `probes.rs` explains in a comment that
                // it once cited `V14.4.1`, "which is not a requirement at all" — the comment is the
                // record of the fix, and reading it as a live citation would report the fix as the
                // bug.
                if trimmed.starts_with("//") || trimmed.starts_with('*') {
                    continue;
                }
                for id in sv_check::suite::requirement_ids_in(line) {
                    // A citation is quoted and names a requirement, not a chapter or a section.
                    // `V6.2` in a doc example is a scope, and scopes are legitimate.
                    if id.matches('.').count() < 2 || !line.contains(&format!("\"{id}\"")) {
                        continue;
                    }
                    out.push((name.clone(), index + 1, id));
                }
            }
        }
    }
    out
}

#[test]
fn every_requirement_id_written_into_the_code_is_one_that_exists() {
    // The data files are guarded above. Citations hard-coded in Rust were not guarded at all, and
    // on 24 September 2026 three of them were found pointing at V1.3.5 — sanitizing user-supplied
    // template and stylesheet content — for the bill of materials, the advisory comparison and the
    // lockfile check. One of those three was attached to a *passing* outcome, so an app with a
    // lockfile earned a green line against template sanitization.
    //
    // This half is cheap and broad: it cannot tell whether a citation is about the right subject,
    // but it does catch the `AC-NN` class, where an id resolves to nothing and the finding lands
    // against a requirement the app is not even assessed on.
    let known = requirements();
    let missing: Vec<String> = ids_written_into_the_code()
        .into_iter()
        .filter(|(_, _, id)| !known.contains_key(id))
        .map(|(file, line, id)| format!("{file}:{line} writes {id}, which resolves to nothing"))
        .collect();
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

#[test]
fn the_checks_that_hard_code_a_citation_are_about_what_they_cite() {
    // The semantic half, for the checks whose citations were wrong. These are built by calling the
    // real code rather than by reading the source, so a citation cannot drift from the finding it
    // travels with.
    use sv_check::sbom::{Component, Sbom, VersionSource};
    let known = requirements();

    let incomplete = Sbom {
        components: vec![Component {
            name: "flask".into(),
            version: "3.0.0".into(),
            ecosystem: "Python".into(),
            source: VersionSource::Declared,
        }],
        unread: vec![("npm".into(), "no lockfile".into())],
    };
    let finding = sv_check::sbom::incompleteness_finding(&incomplete).expect("it is incomplete");
    let complete = Sbom {
        components: vec![Component {
            name: "flask".into(),
            version: "3.0.0".into(),
            ecosystem: "Python".into(),
            source: VersionSource::Locked,
        }],
        unread: vec![],
    };
    let claim = sv_check::sbom::completeness_verified(&complete).expect("it is complete");

    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for id in &finding.requirement_ids {
        pairs.push((
            "sbom.incomplete".into(),
            id.clone(),
            format!("{} {}", finding.title, finding.impact),
        ));
    }
    for id in &claim.requirement_ids {
        pairs.push(("sbom (clean)".into(), id.clone(), claim.scope.clone()));
    }

    // The configuration checks, which is where the third wrong citation lived. Each is run against
    // a folder built to make it fail, because the failing side carries the prose — the passing side
    // records only that the check ran, and both cite the same ids by construction.
    let dir = std::env::temp_dir().join("sv-citations-config");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    // A manifest with no lockfile beside it: `config.versions-pinned` fails.
    std::fs::write(dir.join("requirements.txt"), "flask==3.0.0\n").unwrap();
    let config = sv_check::config::check_dir(&dir);
    assert!(
        config
            .findings
            .iter()
            .any(|f| f.rule_id == "config.versions-pinned"),
        "the fixture has to actually trip the check, or this tests nothing: {:?}",
        config
            .findings
            .iter()
            .map(|f| &f.rule_id)
            .collect::<Vec<_>>()
    );
    for finding in &config.findings {
        for id in &finding.requirement_ids {
            pairs.push((
                finding.rule_id.clone(),
                id.clone(),
                format!(
                    "{} {} {}",
                    finding.title, finding.description, finding.impact
                ),
            ));
        }
    }

    let mut wrong = Vec::new();
    for (what, id, words) in pairs {
        let Some(description) = known.get(&id) else {
            wrong.push(format!("{what} cites {id}, which does not exist"));
            continue;
        };
        if shares_no_words(&words, description) {
            wrong.push(format!(
                "{what} cites {id}\n    it is about: {words}\n    {id} asks:   {}",
                description.chars().take(110).collect::<String>()
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
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
