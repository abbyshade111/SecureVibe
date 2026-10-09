//! A passphrase is what `sv review` makes its signing key with unless the person types `none`
//! (gap analysis of 7 October 2026, finding 22(a); ADR-043, Later, 9 October 2026).

use super::*;

/// The key `signing_key` makes in a fresh folder when the person types `typed`, as it is kept.
fn made_with(name: &str, typed: &str) -> (Stored, String) {
    let folder = std::env::temp_dir().join(format!(
        "sv-review-passphrase-{name}-{}",
        std::process::id()
    ));
    std::fs::remove_dir_all(&folder).ok();
    let mut out = Vec::new();
    let key = signing_key(
        &folder,
        &mut std::io::Cursor::new(typed.as_bytes().to_vec()),
        &mut out,
        &mut ask,
    )
    .unwrap();
    assert!(key.is_some(), "a key was made");
    let stored = SigningKey::load_from(&folder).unwrap().expect("a key file");
    std::fs::remove_dir_all(&folder).ok();
    (stored, String::from_utf8(out).unwrap())
}

#[test]
fn pressing_enter_chooses_a_passphrase() {
    let (stored, out) = made_with("enter", "\nhorse battery staple\nhorse battery staple\n");
    assert!(matches!(stored, Stored::Locked(_)), "{out}");
    assert!(out.contains("Press Enter to choose one"), "{out}");
    assert!(!out.contains("horse"), "{out}");
}

#[test]
fn yes_still_chooses_a_passphrase() {
    let (stored, _) = made_with("yes", "yes\nhorse battery staple\nhorse battery staple\n");
    assert!(matches!(stored, Stored::Locked(_)));
}

#[test]
fn none_or_no_makes_a_key_without_one() {
    for (name, typed) in [("none", "none\n"), ("no", "No\n"), ("n", " n \n")] {
        let (stored, out) = made_with(name, typed);
        assert!(matches!(stored, Stored::Ready(_)), "{typed:?}: {out}");
        assert!(
            out.contains("every entry signed with it says so"),
            "the person is told what having none means: {out}"
        );
    }
}

#[test]
fn a_key_made_by_pressing_enter_signs_entries_that_say_it_has_a_passphrase() {
    let folder =
        std::env::temp_dir().join(format!("sv-review-passphrase-signs-{}", std::process::id()));
    std::fs::remove_dir_all(&folder).ok();
    let app_folder = folder.join("app");
    std::fs::create_dir_all(&app_folder).unwrap();
    let keys = folder.join("keys");
    let key = signing_key(
        &keys,
        &mut std::io::Cursor::new(b"\nhorse battery staple\nhorse battery staple\n".to_vec()),
        &mut Vec::new(),
        &mut ask,
    )
    .unwrap()
    .expect("a key was made");
    let app = sv_check::seal::App::of(&app_folder).unwrap();
    assert!(sv_check::signed::trust_here(&keys, &key, &app).unwrap());
    let fields = ["finding-review", "ast.open-redirect", "app.py", "owner"];
    let seal = key.for_app(&app).seal(&fields).unwrap();
    let sealed = Checker::in_folder(Some(&keys), &app_folder).recorded(Some(&seal), &fields);
    std::fs::remove_dir_all(&folder).ok();
    match sealed {
        Ok(Sealed::Signed { lock, .. }) => {
            assert_eq!(lock, sv_check::seal::KeyLock::Passphrase)
        }
        other => panic!("the seal did not count as signed: {other:?}"),
    }
}
