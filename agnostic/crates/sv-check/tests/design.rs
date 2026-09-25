//! The design questions, held to the requirements they claim to ask about.
//!
//! The same guards as the security notes catalog, for the same reason: these are plain-language
//! paraphrases, paraphrases drift, and a question that has drifted gets answered by the owner and
//! credited against something else. Plus one this catalog needs and the notes do not — every
//! question must be about a requirement that really applies to ordinary apps, since a design
//! question nobody is ever asked is a question that cannot be wrong and cannot help.

use std::collections::BTreeSet;
use std::path::PathBuf;
use sv_check::design::Questions;
use sv_check::suite::shares_no_words;
use sv_frameworks::Frameworks;

fn questions() -> Questions {
    Questions::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/design-questions.json"),
    )
    .expect("the design questions load")
}

fn frameworks() -> Frameworks {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../data/frameworks");
    Frameworks::load(&dir).expect("the frameworks load")
}

fn words(text: &str) -> BTreeSet<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() > 3)
        .map(|w| w.trim_end_matches('s').to_owned())
        .collect()
}

#[test]
fn every_question_names_a_requirement_that_exists() {
    let frameworks = frameworks();
    let unknown: Vec<String> = questions()
        .questions
        .iter()
        .map(|q| q.id.clone())
        .filter(|id| !frameworks.requirements.contains_key(id))
        .collect();
    assert!(unknown.is_empty(), "no such requirement: {unknown:?}");
}

#[test]
fn every_question_shares_words_with_the_requirement_it_asks_about() {
    let frameworks = frameworks();
    let mut adrift = Vec::new();
    for q in &questions().questions {
        let Some(requirement) = frameworks.requirements.get(&q.id) else {
            continue;
        };
        let asked = format!("{} {}", q.title, q.asks);
        if shares_no_words(&asked, &requirement.description) {
            adrift.push(format!("{}: {}", q.id, q.title));
        }
    }
    assert!(adrift.is_empty(), "these have drifted: {adrift:#?}");
}

#[test]
fn every_question_matches_its_own_requirement_better_than_any_other() {
    // The neighbor swap, as in the security notes. V13.2.1 (the app's services authenticate to each
    // other) and V13.2.2 (that traffic is encrypted) are the pair this is here for.
    let frameworks = frameworks();
    let catalog = questions();
    let mut misfiled = Vec::new();
    for q in &catalog.questions {
        let Some(own) = frameworks.requirements.get(&q.id) else {
            continue;
        };
        let asked = words(&format!("{} {}", q.title, q.asks));
        let mine = asked.intersection(&words(&own.description)).count();
        for other in &catalog.questions {
            if other.id == q.id {
                continue;
            }
            let Some(theirs) = frameworks.requirements.get(&other.id) else {
                continue;
            };
            let count = asked.intersection(&words(&theirs.description)).count();
            if count >= mine {
                misfiled.push(format!(
                    "{} shares {mine} with its own requirement and {count} with {}",
                    q.id, other.id
                ));
            }
        }
    }
    assert!(misfiled.is_empty(), "{misfiled:#?}");
}

#[test]
fn no_question_is_asked_twice() {
    let catalog = questions();
    let mut seen = BTreeSet::new();
    let repeated: Vec<String> = catalog
        .questions
        .iter()
        .filter(|q| !seen.insert(q.id.clone()))
        .map(|q| q.id.clone())
        .collect();
    assert!(repeated.is_empty(), "asked twice: {repeated:?}");
}

#[test]
fn every_question_is_at_level_one_or_two() {
    // Above level 2 the owner is not being asked about the requirement at all, so a question about
    // it would be answered and then counted against nothing.
    let frameworks = frameworks();
    let too_high: Vec<String> = questions()
        .questions
        .iter()
        .filter_map(|q| {
            let r = frameworks.requirements.get(&q.id)?;
            (r.level > 2).then(|| format!("{} is level {}", q.id, r.level))
        })
        .collect();
    assert!(too_high.is_empty(), "{too_high:?}");
}

#[test]
fn every_question_says_what_where_should_name() {
    // `where` is what turns an assertion into something somebody can go and check, and a stale one
    // into a finding. A question that does not say what to point at gets pointed at anything.
    let vague: Vec<String> = questions()
        .questions
        .iter()
        .filter(|q| q.where_means.split_whitespace().count() < 3)
        .map(|q| format!("{}: {:?}", q.id, q.where_means))
        .collect();
    assert!(vague.is_empty(), "{vague:#?}");
}

#[test]
fn every_question_is_written_for_somebody_who_is_not_a_programmer() {
    let jargon = [
        "canonicaliz",
        "idempoten",
        "entropy",
        "nonce",
        "mitigat",
        "sanitiz",
    ];
    let mut unreadable = Vec::new();
    for q in &questions().questions {
        let text = format!("{} {}", q.title, q.asks).to_lowercase();
        for word in jargon {
            if text.contains(word) {
                unreadable.push(format!("{}: {word}", q.id));
            }
        }
    }
    assert!(unreadable.is_empty(), "{unreadable:#?}");
}

#[test]
fn a_design_question_is_never_also_a_security_note() {
    // The two catalogs credit different tiers, so a requirement in both would be credited twice and
    // at whichever tier happened to win. They answer different kinds of question and must not meet.
    let notes = sv_check::notes::Catalog::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/security-notes.json"),
    )
    .expect("the notes catalog loads");
    let documented: BTreeSet<&str> = notes.sections.iter().map(|s| s.id.as_str()).collect();
    let both: Vec<String> = questions()
        .questions
        .iter()
        .filter(|q| documented.contains(q.id.as_str()))
        .map(|q| q.id.clone())
        .collect();
    assert!(both.is_empty(), "in both catalogs: {both:?}");
}
