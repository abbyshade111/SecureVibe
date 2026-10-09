//! `sv review` asking the owner to confirm the two answers that set the level, the audience and
//! the data list, and sealing them (gap analysis of 7 October 2026, finding 17; ADR-024, Later,
//! 9 October 2026).

use super::tests::{Scratch, with_app};
use super::{Waiting, counts};

const APP: &str = "manifest-version = 1\n[app]\nname = \"R\"\naudience = \"just-me\"\n[stack]\nlanguages = [\"python\"]\n[data]\ncategories = [\"contact\"]\n";

fn manifest(s: &Scratch) -> sv_manifest::Manifest {
    sv_manifest::Manifest::load(&s.app().join("stackvet.toml")).unwrap()
}

fn text(s: &Scratch) -> String {
    std::fs::read_to_string(s.app().join("stackvet.toml")).unwrap()
}

/// Whether the answers count as confirmed here, as the report and `sv review` both decide it.
fn confirmed(s: &Scratch) -> bool {
    counts(&manifest(s), &Waiting::Scope, &s.checker())
}

#[test]
fn the_owner_confirms_both_answers_and_the_seal_holds() {
    let s = Scratch::new("scope-owner");
    with_app(&s, APP);
    assert!(!confirmed(&s), "the setup: nothing is confirmed yet");
    let (result, out) = s.run("owner\n");
    result.unwrap();
    assert!(
        out.contains("Last, the answers that set the app's level."),
        "{out}"
    );
    assert!(out.contains("[app] audience = \"just-me\""), "{out}");
    assert!(out.contains("[data] categories = [contact]"), "{out}");
    assert!(out.contains("Confirmed as your answers."), "{out}");
    let entry = manifest(&s).scope_review.expect("[scope-review] written");
    assert_eq!(entry.audience, "just-me");
    assert_eq!(entry.categories, Some(vec!["contact".to_owned()]));
    assert_eq!(entry.by, "owner");
    assert!(confirmed(&s), "{}", text(&s));
}

#[test]
fn enter_leaves_them_unconfirmed_and_writes_nothing() {
    let s = Scratch::new("scope-enter");
    with_app(&s, APP);
    let (result, out) = s.run("\n");
    result.unwrap();
    assert!(out.contains("Left unconfirmed."), "{out}");
    assert_eq!(text(&s), APP);
}

#[test]
fn only_the_owner_confirms_them() {
    let s = Scratch::new("scope-name");
    with_app(&s, APP);
    let (result, out) = s.run("Sam Lee\nAI coding tool\n\n");
    result.unwrap();
    assert_eq!(
        out.matches("Only the app's owner knows who uses it")
            .count(),
        2,
        "{out}"
    );
    assert_eq!(text(&s), APP);
}

#[test]
fn once_confirmed_it_is_not_asked_again() {
    let s = Scratch::new("scope-again");
    with_app(&s, APP);
    s.run("owner\n").0.unwrap();
    let (result, out) = s.run("");
    result.unwrap();
    assert!(!out.contains("Last, the answers"), "{out}");
}

#[test]
fn an_answer_changed_after_it_was_confirmed_is_asked_about_again() {
    for (name, from, to) in [
        (
            "audience",
            "audience = \"just-me\"",
            "audience = \"my-team\"",
        ),
        (
            "category",
            "categories = [\"contact\"]",
            "categories = [\"contact\", \"health\"]",
        ),
        ("emptied", "categories = [\"contact\"]", "categories = []"),
        (
            "unanswered",
            "categories = [\"contact\"]",
            "# categories = ?",
        ),
    ] {
        let s = Scratch::new(&format!("scope-changed-{name}"));
        with_app(&s, APP);
        s.run("owner\n").0.unwrap();
        assert!(confirmed(&s), "the setup: confirmed before the change");
        let changed = text(&s).replacen(from, to, 1);
        assert_ne!(changed, text(&s), "the setup: {from} is in the file");
        std::fs::write(s.app().join("stackvet.toml"), changed).unwrap();
        assert!(!confirmed(&s), "{name}: still counted after the change");
        let (_, out) = s.run("\n");
        assert!(out.contains("Last, the answers"), "{name}: {out}");
    }
}

#[test]
fn the_same_categories_in_another_order_or_case_are_the_same_answer() {
    let s = Scratch::new("scope-order");
    with_app(
        &s,
        &APP.replace(
            "categories = [\"contact\"]",
            "categories = [\"contact\", \"Financial\"]",
        ),
    );
    s.run("owner\n").0.unwrap();
    let rewritten = text(&s).replacen(
        "categories = [\"contact\", \"Financial\"]\n\n[",
        "categories = [\" financial \", \"CONTACT\"]\n\n[",
        1,
    );
    assert_ne!(rewritten, text(&s), "the setup: the list was rewritten");
    std::fs::write(s.app().join("stackvet.toml"), rewritten).unwrap();
    assert!(confirmed(&s), "{}", text(&s));
}

#[test]
fn a_scope_review_written_by_hand_is_not_a_confirmation() {
    let s = Scratch::new("scope-hand");
    with_app(
        &s,
        &format!(
            "{APP}\n[scope-review]\naudience = \"just-me\"\ncategories = [\"contact\"]\nby = \"owner\"\non = \"2026-10-09\"\n"
        ),
    );
    assert!(!confirmed(&s), "an entry with no seal counts");
    let (_, out) = s.run("\n");
    assert!(out.contains("Last, the answers"), "{out}");
    // A seal copied from another entry does not hold for this one.
    let t = Scratch::new("scope-copied");
    with_app(&t, APP);
    t.run("owner\n").0.unwrap();
    let sealed = text(&t);
    let forged = sealed
        .replace(
            "audience = \"just-me\"\n[stack]",
            "audience = \"public\"\n[stack]",
        )
        .replace(
            "[scope-review]\naudience = \"just-me\"",
            "[scope-review]\naudience = \"public\"",
        );
    assert_ne!(forged, sealed, "the setup: both audiences were changed");
    std::fs::write(t.app().join("stackvet.toml"), forged).unwrap();
    assert!(!confirmed(&t), "{}", text(&t));
}

#[test]
fn a_persons_name_is_not_taken_in_place_of_owner() {
    // A teammate may know the audience; only the owner's word sets it, so a name, then Enter,
    // leaves the file as it was.
    let s = Scratch::new("scope-teammate");
    with_app(&s, APP);
    let (result, out) = s.run("Sam Lee\n\n");
    result.unwrap();
    assert!(out.contains("Left unconfirmed."), "{out}");
    assert!(!out.contains("Confirmed as your answers"), "{out}");
    assert_eq!(text(&s), APP);
}

#[test]
fn answering_a_list_confirmed_as_unanswered_is_asked_about_again() {
    // Confirmed while the data list was unanswered; `[]` then says the app holds nothing about
    // people, which lowers the level, so it is a new answer for the owner to confirm.
    let s = Scratch::new("scope-unanswered");
    with_app(&s, &APP.replace("[data]\ncategories = [\"contact\"]\n", ""));
    s.run("owner\n").0.unwrap();
    assert!(confirmed(&s), "the setup: confirmed while unanswered");
    let answered = format!("{}\n[data]\ncategories = []\n", text(&s));
    std::fs::write(s.app().join("stackvet.toml"), answered).unwrap();
    assert!(!confirmed(&s), "{}", text(&s));
}
