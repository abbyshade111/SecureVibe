//! `data/README.md` lists the fields a rule in `ast-rules.json` may have (architecture assessment of
//! 8 October 2026, item 12). A list written by hand drifts from the code the day a field is added, so
//! this holds it to the fields `sv` itself accepts: the loader refuses a field it does not know, and
//! its refusal names every field it does, which is the code's own list rather than a copy of it.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data")
}

/// The fields the loader accepts, read from its refusal of a rule with a field it does not know.
fn accepted() -> BTreeSet<String> {
    let dir = std::env::temp_dir().join(format!("sv-ast-rule-schema-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("ast-rules.json");
    std::fs::write(&path, r#"{"rules": [{"notAFieldOfARule": true}]}"#).unwrap();
    let loaded = sv_check::ast::AstRules::load(&path);
    let _ = std::fs::remove_dir_all(&dir);
    let refusal = match loaded {
        Ok(_) => panic!("a rule with a field the loader does not know was loaded"),
        Err(e) => format!("{e:#}"),
    };
    let (_, expected) = refusal
        .split_once("expected one of ")
        .unwrap_or_else(|| panic!("the refusal does not list the fields it accepts: {refusal}"));
    backticked(expected.lines().next().unwrap())
}

/// Every name between backticks in `text`.
fn backticked(text: &str) -> BTreeSet<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The fields the README lists: each item of its section on the fields of a rule names one or more
/// before its first `:` or ` (`.
fn listed(readme: &str) -> BTreeSet<String> {
    let section = readme
        .split_once("## The fields of a rule in `ast-rules.json`")
        .expect("data/README.md has a section on the fields of a rule")
        .1;
    let section = section.split("\n## ").next().unwrap();
    section
        .lines()
        .filter_map(|line| line.strip_prefix("- "))
        .flat_map(|item| {
            let end = [item.find(':'), item.find(" (")]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(item.len());
            backticked(&item[..end])
        })
        .collect()
}

#[test]
fn the_readme_lists_every_field_of_a_rule_and_no_other() {
    let accepted = accepted();
    // The refusal has to name the fields, or an empty list on both sides would pass.
    assert!(
        accepted.len() > 25 && accepted.contains("queries") && accepted.contains("findingsOnly"),
        "the loader's refusal named too few fields: {accepted:?}"
    );
    let readme = std::fs::read_to_string(data_dir().join("README.md")).unwrap();
    let listed = listed(&readme);
    let unlisted: Vec<_> = accepted.difference(&listed).collect();
    assert!(
        unlisted.is_empty(),
        "fields a rule may have that data/README.md does not list; add a line saying what each does: {unlisted:?}"
    );
    let extra: Vec<_> = listed.difference(&accepted).collect();
    assert!(
        extra.is_empty(),
        "data/README.md lists fields a rule may not have: {extra:?}"
    );
}
