//! Where an app's manifest is (ADR-062): `stackvet.toml`, or `securevibe.toml` while only it
//! exists; both at once refused; neither, none.

use std::path::PathBuf;
use sv_frameworks::names::{MANIFEST, OLD_MANIFEST};
use sv_manifest::{locate, locate_or_bail};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-locate-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_new_name_first_the_old_one_alone_and_both_refused() {
    let dir = scratch("states");
    assert_eq!(locate(&dir).unwrap(), None);
    let none = locate_or_bail(&dir).expect_err("no manifest is an error");
    assert!(
        none.to_string().starts_with(&format!("no {MANIFEST} in ")),
        "{none}"
    );
    std::fs::write(dir.join(OLD_MANIFEST), "").unwrap();
    let old = locate(&dir).unwrap().expect("the old name is read");
    assert_eq!(old.path, dir.join(OLD_MANIFEST));
    assert!(old.old_name);
    let note = old.note().expect("the old name is said");
    assert!(
        note.contains(OLD_MANIFEST) && note.contains(MANIFEST),
        "{note}"
    );
    std::fs::write(dir.join(MANIFEST), "").unwrap();
    let both = locate(&dir).expect_err("two manifests are two answers");
    assert!(
        both.to_string().contains("two manifests are two answers"),
        "{both}"
    );
    std::fs::remove_file(dir.join(OLD_MANIFEST)).unwrap();
    let new = locate(&dir).unwrap().expect("the new name is read");
    assert_eq!(new.path, dir.join(MANIFEST));
    assert!(!new.old_name);
    assert_eq!(new.note(), None);
    std::fs::remove_dir_all(&dir).ok();
}
