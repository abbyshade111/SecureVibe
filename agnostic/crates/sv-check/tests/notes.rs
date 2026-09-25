//! The security notes catalog, held to the requirements it claims to ask about.
//!
//! `data/security-notes.json` is prose: nineteen questions written in plain words for somebody who
//! is not a programmer. Prose drifts from what it paraphrases, and a question that has drifted is
//! worse than no question, because the owner answers it, the report calls the requirement
//! documented, and what was asked for was something else.
//!
//! So three guards, in the order they would catch a mistake:
//!
//! 1. **Every id exists**, the way every other citation in the data files must.
//! 2. **The question shares words with the requirement** — the same weak overlap test the citations
//!    use, for the same reason: it must catch a question pointing at a different subject, and it
//!    must not be something anyone is tempted to route around.
//! 3. **No documentation requirement is missing by accident.** Every ASVS requirement at level 1 or
//!    2 whose own words say "document" is either a section here or named in `elsewhere` with why.
//!    Without this, adding the nineteenth question and forgetting the twentieth looks exactly like
//!    deciding there are nineteen.

use std::collections::BTreeSet;
use std::path::PathBuf;
use sv_check::notes::Catalog;
use sv_check::suite::shares_no_words;
use sv_frameworks::Frameworks;

fn catalog() -> Catalog {
    Catalog::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/security-notes.json"))
        .expect("the security notes catalog loads")
}

fn frameworks() -> Frameworks {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/frameworks");
    Frameworks::load(&dir).expect("the frameworks load")
}

#[test]
fn every_question_names_a_requirement_that_exists() {
    let frameworks = frameworks();
    let unknown: Vec<&str> = catalog()
        .sections
        .iter()
        .map(|s| s.id.as_str())
        .filter(|id| !frameworks.requirements.contains_key(*id))
        .map(|id| Box::leak(id.to_owned().into_boxed_str()) as &str)
        .collect();
    assert!(unknown.is_empty(), "no such requirement: {unknown:?}");
}

#[test]
fn every_question_shares_words_with_the_requirement_it_asks_about() {
    let frameworks = frameworks();
    let mut adrift = Vec::new();
    for section in &catalog().sections {
        let Some(requirement) = frameworks.requirements.get(&section.id) else {
            continue;
        };
        let asked = format!("{} {}", section.title, section.asks);
        if shares_no_words(&asked, &requirement.description) {
            adrift.push(format!("{}: {}", section.id, section.title));
        }
    }
    assert!(
        adrift.is_empty(),
        "these questions share no vocabulary with the requirement they claim to ask about: {adrift:#?}"
    );
}

/// Words worth comparing: the short ones are shared by any two English sentences.
fn words(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 3)
        .map(|w| w.trim_end_matches('s').to_owned())
        .collect()
}

#[test]
fn every_question_matches_its_own_requirement_better_than_any_other() {
    // The blindness the citation guard admits to and cannot fix: two neighboring requirements share
    // vocabulary, so a question written for one, filed under the other, shares words with both and
    // passes. Here it is fixable, because these nineteen are a small closed set that can be compared
    // against each other. Swapping V11.1.1 (the key policy) with V11.1.2 (the key inventory) passes
    // the overlap test above and fails this one.
    let frameworks = frameworks();
    let catalog = catalog();
    let mut misfiled = Vec::new();
    for section in &catalog.sections {
        let Some(own) = frameworks.requirements.get(&section.id) else {
            continue;
        };
        let asked = words(&format!("{} {}", section.title, section.asks));
        let mine = asked.intersection(&words(&own.description)).count();
        for other in &catalog.sections {
            if other.id == section.id {
                continue;
            }
            let Some(theirs) = frameworks.requirements.get(&other.id) else {
                continue;
            };
            let count = asked.intersection(&words(&theirs.description)).count();
            if count >= mine {
                misfiled.push(format!(
                    "{} shares {mine} word(s) with its own requirement and {count} with {}",
                    section.id, other.id
                ));
            }
        }
    }
    assert!(
        misfiled.is_empty(),
        "these questions fit another requirement at least as well as their own, which is what a \
         swap between two neighbors looks like: {misfiled:#?}"
    );
}

#[test]
fn every_documentation_requirement_is_either_a_section_or_explained() {
    let frameworks = frameworks();
    let catalog = catalog();
    let asked: BTreeSet<&str> = catalog.sections.iter().map(|s| s.id.as_str()).collect();
    let explained: BTreeSet<&str> = catalog.elsewhere.iter().map(|e| e.id.as_str()).collect();

    let mut unaccounted = Vec::new();
    for (id, info) in &frameworks.requirements {
        if !id.starts_with('V') || info.level > 2 {
            continue;
        }
        let text = info.description.to_lowercase();
        if !text.contains("document") {
            continue;
        }
        if !asked.contains(id.as_str()) && !explained.contains(id.as_str()) {
            unaccounted.push(format!(
                "{id}: {}",
                &info.description[..80.min(info.description.len())]
            ));
        }
    }
    assert!(
        unaccounted.is_empty(),
        "these requirements mention documentation and are neither asked about nor explained away \
         in data/security-notes.json: {unaccounted:#?}"
    );
}

#[test]
fn nothing_is_both_asked_about_and_explained_away() {
    let catalog = catalog();
    let asked: BTreeSet<&str> = catalog.sections.iter().map(|s| s.id.as_str()).collect();
    let both: Vec<&str> = catalog
        .elsewhere
        .iter()
        .map(|e| e.id.as_str())
        .filter(|id| asked.contains(id))
        .collect();
    assert!(
        both.is_empty(),
        "asked and explained away at once: {both:?}"
    );
}

#[test]
fn every_question_is_written_for_somebody_who_is_not_a_programmer() {
    // The owner is not a programmer, and a question they cannot read is one they cannot answer.
    // ASVS's own wording is quoted separately, under the question, where it is labeled as such.
    let jargon = [
        "sanitization",
        "canonicaliz",
        "idempoten",
        "deserializ",
        "entropy",
        "nonce",
        "mitigat",
    ];
    let mut unreadable = Vec::new();
    for section in &catalog().sections {
        let text = format!("{} {}", section.title, section.asks).to_lowercase();
        for word in jargon {
            if text.contains(word) {
                unreadable.push(format!("{}: {word}", section.id));
            }
        }
    }
    assert!(
        unreadable.is_empty(),
        "these questions use a word the owner would have to look up: {unreadable:#?}"
    );
}

#[test]
fn the_explanations_say_why_rather_than_only_that() {
    // An `elsewhere` entry with an empty reason is a requirement dropped silently with extra steps.
    let thin: Vec<String> = catalog()
        .elsewhere
        .iter()
        .filter(|e| e.why.split_whitespace().count() < 4)
        .map(|e| format!("{}: {:?}", e.id, e.why))
        .collect();
    assert!(thin.is_empty(), "these say nothing about why: {thin:#?}");
}
