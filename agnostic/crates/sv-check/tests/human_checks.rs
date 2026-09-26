//! The how-to-verify catalog, held to the requirements it claims to explain.
//!
//! The same guards as the other two catalogs, plus the one this catalog needs and they do not: a
//! requirement must not appear here *and* in the security notes or the design questions. Two
//! catalogs would give different advice about the same thing, and the reader has no way to tell
//! which is meant — nor which one a later editor updated.

use std::collections::BTreeSet;
use std::path::PathBuf;
use sv_check::design::Questions;
use sv_check::human::HumanChecks;
use sv_check::notes::Catalog;
use sv_check::suite::shares_no_words;
use sv_frameworks::Frameworks;

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(name)
}

fn human() -> HumanChecks {
    HumanChecks::load(&data("human-checks.json")).expect("the human checks load")
}

fn notes() -> Catalog {
    Catalog::load(&data("security-notes.json")).expect("the notes catalog loads")
}

fn design() -> Questions {
    Questions::load(&data("design-questions.json")).expect("the design questions load")
}

fn frameworks() -> Frameworks {
    Frameworks::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/frameworks"))
        .expect("the frameworks load")
}

#[test]
fn every_check_names_a_requirement_that_exists() {
    let f = frameworks();
    let unknown: Vec<String> = human()
        .checks
        .iter()
        .map(|c| c.id.clone())
        .filter(|id| !f.requirements.contains_key(id))
        .collect();
    assert!(unknown.is_empty(), "no such requirement: {unknown:?}");
}

#[test]
fn no_requirement_is_explained_by_two_catalogs() {
    // The guard this catalog needs and the others do not. Two sets of advice about one requirement
    // is worse than one: the reader cannot tell which is meant, and a later editor updates whichever
    // they found first.
    let asked: BTreeSet<String> = notes()
        .sections
        .iter()
        .map(|s| s.id.clone())
        .chain(design().questions.iter().map(|q| q.id.clone()))
        .collect();
    let twice: Vec<String> = human()
        .checks
        .iter()
        .map(|c| c.id.clone())
        .filter(|id| asked.contains(id))
        .collect();
    assert!(
        twice.is_empty(),
        "these are already asked about in the security notes or the design questions, so they must \
         not be here too: {twice:?}"
    );
}

#[test]
fn every_check_shares_words_with_the_requirement_it_explains() {
    let f = frameworks();
    let mut adrift = Vec::new();
    for c in &human().checks {
        let Some(r) = f.requirements.get(&c.id) else {
            continue;
        };
        if shares_no_words(&format!("{} {}", c.title, c.how), &r.description) {
            adrift.push(format!("{}: {}", c.id, c.title));
        }
    }
    assert!(adrift.is_empty(), "these have drifted: {adrift:#?}");
}

#[test]
fn every_check_tells_somebody_what_to_actually_do() {
    // A line that restates the requirement is not an instruction. Each of these has to name an
    // action — open, try, list, compare — or it is the requirement's own wording with extra steps.
    let verbs = [
        "open",
        "try",
        "list",
        "compare",
        "take",
        "sign in",
        "run",
        "do ",
        "go ",
        "search",
        "check",
        "start",
        "write down",
        "look",
    ];
    let mut lazy = Vec::new();
    for c in &human().checks {
        let how = c.how.to_lowercase();
        if !verbs.iter().any(|v| how.contains(v)) {
            lazy.push(format!("{}: {}", c.id, c.how));
        }
    }
    assert!(
        lazy.is_empty(),
        "these restate the requirement rather than saying what to do: {lazy:#?}"
    );
}

#[test]
fn no_check_is_listed_twice() {
    let mut seen = BTreeSet::new();
    let repeated: Vec<String> = human()
        .checks
        .iter()
        .filter(|c| !seen.insert(c.id.clone()))
        .map(|c| c.id.clone())
        .collect();
    assert!(repeated.is_empty(), "listed twice: {repeated:?}");
}

#[test]
fn every_check_is_at_level_one_or_two() {
    let f = frameworks();
    let high: Vec<String> = human()
        .checks
        .iter()
        .filter_map(|c| {
            let r = f.requirements.get(&c.id)?;
            (r.level > 2).then(|| format!("{} is level {}", c.id, r.level))
        })
        .collect();
    assert!(high.is_empty(), "{high:?}");
}

#[test]
fn every_check_is_written_for_somebody_who_is_not_a_programmer() {
    let jargon = ["canonicaliz", "idempoten", "nonce", "deserializ", "mitigat"];
    let mut unreadable = Vec::new();
    for c in &human().checks {
        let text = format!("{} {}", c.title, c.how).to_lowercase();
        for word in jargon {
            if text.contains(word) {
                unreadable.push(format!("{}: {word}", c.id));
            }
        }
    }
    assert!(unreadable.is_empty(), "{unreadable:#?}");
}
