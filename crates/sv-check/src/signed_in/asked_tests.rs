//! Every configuration of the signed-in suite names the same requirements: a check that cannot
//! run in one of them says so, and never nothing.
//!
//! A check is `fn(.., out: &mut Outcome)`, and nothing makes it touch `out`: on 8 October 2026
//! three of them returned without a word when there was no private page to confirm against, and
//! their requirements were missing from the report, neither credited, nor found, nor not assessed
//! (the architecture assessment of that day, item 8). This holds the suite as a whole: whatever the
//! app is, and whether or not signing in works, every requirement the correct app's run names is
//! named again, in one of the three buckets. A guard in each check would be the fuller form; this
//! is the cheaper one, and a check that goes silent in a configuration here fails it by name.

use super::fake_app::{Flaws, run_against, users_full};
use super::{NEEDS_A_SESSION, Outcome};
use std::collections::BTreeSet;

/// Every requirement id `out` says anything about: found, credited, or not assessed.
fn named(out: &Outcome) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for f in &out.findings {
        ids.extend(f.requirement_ids.iter().cloned());
    }
    for v in &out.verified {
        ids.extend(v.requirement_ids.iter().cloned());
    }
    for (list, _) in &out.not_assessed {
        ids.extend(list.split(',').map(|id| id.trim().to_owned()));
    }
    ids.retain(|id| !id.is_empty());
    ids
}

#[test]
fn every_configuration_of_the_suite_names_every_requirement_the_correct_app_does() {
    let configurations: Vec<(&str, Flaws)> = vec![
        ("the correct app", Flaws::default()),
        (
            "private pages open and sign-in broken, so no page confirms a session",
            Flaws {
                private_open: true,
                broken_login: true,
                ..Flaws::default()
            },
        ),
        (
            "an app with many flaws",
            Flaws {
                private_open: true,
                admin_open: true,
                idor: true,
                no_csrf_check: true,
                logout_keeps_session: true,
                short_password_ok: true,
                default_admin: true,
                password_in_url: true,
                logout_on_get: true,
                change_without_current: true,
                ..Flaws::default()
            },
        ),
    ];
    let users = users_full();
    // Each run takes about a minute against the fake app; side by side, the test takes one.
    let runs: Vec<(&str, BTreeSet<String>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = configurations
            .iter()
            .map(|(name, flaws)| {
                let users = &users;
                scope.spawn(move || (*name, named(&run_against(*flaws, users))))
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("a run finishes"))
            .collect()
    });
    let correct = &runs[0].1;
    // The setup: the correct app's run names what the suite is for, the session checks included.
    assert!(
        correct.len() >= 40,
        "{} ids named: {correct:?}",
        correct.len()
    );
    for id in NEEDS_A_SESSION.split(", ") {
        assert!(correct.contains(id), "{id} is not named on the correct app");
    }
    for (name, ids) in &runs[1..] {
        let silent: Vec<&String> = correct.difference(ids).collect();
        assert!(
            silent.is_empty(),
            "against {name}, the suite says nothing about {silent:?}: a check returned without a \
             finding, a credit, or a reason it could not run"
        );
    }
}
