//! The one rule for whose word a status rests on (`confirmed_only_by`), held here where the report
//! reads it. Before 9 October 2026 nothing in this crate failed when it was broken: the only witness
//! was `sv explain`'s test (backlog 0226, part 1, item 2).

use super::*;

fn ids(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn the_tools_word_confirmed_through_review_is_labeled_as_the_tools() {
    let none: Vec<String> = Vec::new();
    for (status, attested, by_hand, documented, label) in [
        (
            Status::Attested,
            ids(&["design.stated-by-ai"]),
            none.clone(),
            none.clone(),
            "stated by the AI coding tool, confirmed through sv review",
        ),
        (
            Status::ByHand,
            none.clone(),
            ids(&[sv_check::confirm::HAND_CONFIRMED]),
            none.clone(),
            "checked by the AI coding tool, confirmed through sv review",
        ),
        (
            Status::Documented,
            none.clone(),
            none.clone(),
            ids(&[sv_check::notes::CONFIRMED]),
            "written by the AI coding tool, confirmed through sv review",
        ),
    ] {
        assert!(
            confirmed_only_by(status, &attested, &by_hand, &documented),
            "{status:?}"
        );
        assert_eq!(status.shown(true), label);
    }
}

#[test]
fn the_owners_own_record_is_labeled_as_theirs() {
    let none: Vec<String> = Vec::new();
    assert!(!confirmed_only_by(
        Status::Attested,
        &ids(&["design.attested", "design.stated-by-ai"]),
        &none,
        &none
    ));
    assert!(!confirmed_only_by(
        Status::ByHand,
        &none,
        &ids(&[sv_check::confirm::HAND_CONFIRMED, "hand.recorded"]),
        &none
    ));
    assert!(!confirmed_only_by(
        Status::Documented,
        &none,
        &none,
        &ids(&[sv_check::notes::CONFIRMED, "notes.documented"])
    ));
    // A status that is nobody's word is never read as confirmed.
    for status in [Status::Checked, Status::NeedsAttention, Status::Stated] {
        assert!(
            !confirmed_only_by(status, &none, &none, &none),
            "{status:?}"
        );
        assert_eq!(status.shown(false), status.label());
    }
}
