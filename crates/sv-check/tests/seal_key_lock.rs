//! Whether the key behind a signed seal has a passphrase, said with the entry (gap analysis of 7
//! October 2026, finding 22(a); ADR-043, Later, 9 October 2026).
//!
//! The fault this pins: a seal made with a key that has no passphrase reads exactly like one made
//! with a key that has one, though without it anything that can run as the owner, the AI coding
//! tool included, could have signed. Where the key is on this computer, the entry says which;
//! where it is not, it says that cannot be told. What counts is unchanged in every case.

use std::path::{Path, PathBuf};
use sv_check::seal::{App, Checker, KeyLock, Sealed, recorded_where};
use sv_check::signed::{SigningKey, Trust, trust_here};

const FIELDS: &[&str] = &["finding-review", "ast.open-redirect", "app.py", "owner"];

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sv-key-lock-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(dir.join("app")).unwrap();
        Scratch(dir)
    }
    fn app(&self) -> App {
        App::of(&self.0.join("app")).unwrap()
    }
    fn folder(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

/// A key made in `folder`, trusted there for the app, and a seal it made.
fn sealed_by(s: &Scratch, folder: &Path, passphrase: Option<&str>) -> (SigningKey, String) {
    let key = SigningKey::make_in(folder, passphrase).unwrap();
    assert!(trust_here(folder, &key, &s.app()).unwrap());
    let seal = key.for_app(&s.app()).seal(FIELDS).unwrap();
    (key, seal)
}

fn lock_of(sealed: Result<Sealed, sv_check::seal::Unrecorded>) -> KeyLock {
    match sealed {
        Ok(Sealed::Signed { lock, .. }) => lock,
        other => panic!("the seal did not count as signed: {other:?}"),
    }
}

#[test]
fn a_key_here_with_no_passphrase_is_said_so() {
    let s = Scratch::new("plain");
    let keys = s.folder("keys");
    let (_, seal) = sealed_by(&s, &keys, None);
    let sealed = Checker::in_folder(Some(&keys), &s.0.join("app")).recorded(Some(&seal), FIELDS);
    assert_eq!(lock_of(sealed.clone()), KeyLock::NoPassphrase);
    let words = recorded_where(&sealed.unwrap());
    assert!(words.contains("no passphrase"), "{words}");
    assert!(words.contains("your AI coding tool included"), "{words}");
}

#[test]
fn a_key_here_with_a_passphrase_is_said_so() {
    let s = Scratch::new("locked");
    let keys = s.folder("keys");
    let (_, seal) = sealed_by(&s, &keys, Some("horse battery staple"));
    // The setup: the key on disk really is locked.
    assert!(matches!(
        SigningKey::load_from(&keys).unwrap(),
        Some(sv_check::signed::Stored::Locked(_))
    ));
    let sealed = Checker::in_folder(Some(&keys), &s.0.join("app")).recorded(Some(&seal), FIELDS);
    assert_eq!(lock_of(sealed.clone()), KeyLock::Passphrase);
    let words = recorded_where(&sealed.unwrap());
    assert!(words.contains("with a passphrase"), "{words}");
    assert!(!words.contains("no passphrase"), "{words}");
}

#[test]
fn a_seal_checked_where_the_key_is_not_cannot_say() {
    // CI: only the list, given in SV_TRUSTED_SEALS, and no key file at all.
    let s = Scratch::new("ci");
    let keys = s.folder("keys");
    let (key, seal) = sealed_by(&s, &keys, None);
    let line = key.trusted_line(&s.app()).unwrap();
    let ci = Checker::no_key().trusting(Trust::load(None, Some(line.into())), Some(s.app()));
    let sealed = ci.recorded(Some(&seal), FIELDS);
    assert_eq!(lock_of(sealed.clone()), KeyLock::NotHere);
    let words = recorded_where(&sealed.unwrap());
    assert!(words.contains("cannot be told here"), "{words}");
}

#[test]
fn another_key_on_this_computer_says_nothing_about_the_one_that_signed() {
    // This computer has its own key, with no passphrase; the seal was made by another, which this
    // computer's list also trusts. The key here is not the one that signed, so it cannot speak
    // for it, either way.
    let s = Scratch::new("other");
    let here = s.folder("here");
    let elsewhere = s.folder("elsewhere");
    SigningKey::make_in(&here, None).unwrap();
    let (other, seal) = sealed_by(&s, &elsewhere, Some("horse battery staple"));
    assert!(trust_here(&here, &other, &s.app()).unwrap());
    let sealed = Checker::in_folder(Some(&here), &s.0.join("app")).recorded(Some(&seal), FIELDS);
    assert_eq!(lock_of(sealed), KeyLock::NotHere);
}

#[test]
fn every_lock_is_worded_differently() {
    let said = [
        KeyLock::Passphrase.said(),
        KeyLock::NoPassphrase.said(),
        KeyLock::NotHere.said(),
    ];
    for (i, a) in said.iter().enumerate() {
        assert!(a.starts_with(" ("), "{a}");
        for b in &said[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn a_locked_key_here_says_nothing_about_a_plain_one_that_signed() {
    // The other way round: the key here has a passphrase, the one that signed has none. Taking
    // the key here for the signer would say "with a passphrase" of a seal anything could have made.
    let s = Scratch::new("other-locked");
    let here = s.folder("here");
    let elsewhere = s.folder("elsewhere");
    SigningKey::make_in(&here, Some("horse battery staple")).unwrap();
    let (other, seal) = sealed_by(&s, &elsewhere, None);
    assert!(trust_here(&here, &other, &s.app()).unwrap());
    let sealed = Checker::in_folder(Some(&here), &s.0.join("app")).recorded(Some(&seal), FIELDS);
    let lock = lock_of(sealed.clone());
    assert_eq!(lock, KeyLock::NotHere);
    let words = recorded_where(&sealed.unwrap());
    assert!(!words.contains("with a passphrase)"), "{words}");
}
