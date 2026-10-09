//! A signature's condition is a `Condition`, not a free string (the architecture assessment of
//! 8 October 2026, item 12): a name a data file misspells stops the load and is named, where it used
//! to leave that one signature silently unread, so its condition went unanswered with nothing said.

use sv_scan::Signatures;

fn load(tag: &str, condition: &str) -> Result<Signatures, String> {
    let dir = std::env::temp_dir().join(format!("sv-condition-names-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("signatures.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"signatures": [{{"condition": "{condition}", "note": "a test", "files": ["*.xml"]}}]}}"#
        ),
    )
    .unwrap();
    let loaded = Signatures::load(&path).map_err(|e| format!("{e:#}"));
    std::fs::remove_dir_all(&dir).ok();
    loaded
}

#[test]
fn a_misspelled_condition_stops_the_load_and_is_named() {
    // The control: the same file with a real name loads, and its signature is there.
    let good = load("good", "xml").expect("a known condition loads");
    assert_eq!(good.signatures.len(), 1);
    assert_eq!(good.signatures[0].condition.name(), "xml");

    let refused = load("misspelled", "xmll").expect_err("a misspelled condition is refused");
    assert!(refused.contains("unknown condition `xmll`"), "{refused}");
}
