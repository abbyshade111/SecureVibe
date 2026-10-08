//! `docs/ARCHITECTURE.md` names only files that exist, as `decision_records.rs` holds the records
//! (BACKLOG, "From the architecture assessment of 8 October 2026", item 5): a map whose paths have
//! moved is worse than none, since it is read by whoever is new here.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every span between backticks that names a file or folder in this repository.
fn paths_named(text: &str) -> Vec<String> {
    const PLACES: [&str; 6] = [
        "crates/",
        "data/",
        "docs/",
        "tools/",
        "examples/",
        ".github/",
    ];
    text.split('`')
        .skip(1)
        .step_by(2)
        .filter(|span| !span.contains(' ') && !span.contains('*') && !span.contains('<'))
        .filter(|span| PLACES.iter().any(|p| span.starts_with(p)))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_map_names_only_files_and_folders_that_exist() {
    let text = std::fs::read_to_string(root().join("docs/ARCHITECTURE.md")).unwrap();
    let named = paths_named(&text);
    // The setup: the map really names paths, and one that is there is found.
    assert!(
        named.len() >= 20,
        "only {} paths named: {named:?}",
        named.len()
    );
    assert!(named.iter().any(|p| p == "crates/sv-report/src/lib.rs"));
    let missing: Vec<&String> = named.iter().filter(|p| !root().join(p).exists()).collect();
    assert!(
        missing.is_empty(),
        "named in docs/ARCHITECTURE.md, not here: {missing:?}"
    );
    // And the guard really looks: a path that is not there is caught.
    let planted = paths_named("see `crates/sv-check/src/no-such-file.rs` here");
    assert_eq!(planted, ["crates/sv-check/src/no-such-file.rs"]);
    assert!(!root().join(&planted[0]).exists());
}
