//! `data/README.md` says what each data file is and what reads it. A file added without a line there
//! is one somebody will later edit thinking it does something, or leave alone thinking it does not; a
//! line left for a file that is gone is a claim about nothing.

use std::path::{Path, PathBuf};

fn data_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data")
}

/// Every file under `data/`, as a path relative to it with `/` separators, except the README itself
/// and hidden files.
fn files(dir: &Path, base: &Path, out: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        // Hidden files (`.DS_Store`, which macOS leaves in folders it has shown) are no one's data.
        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.is_dir() {
            files(&path, base, out);
        } else {
            let rel = path.strip_prefix(base).unwrap();
            let rel: Vec<_> = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect();
            let rel = rel.join("/");
            if rel != "README.md" {
                out.push(rel);
            }
        }
    }
}

/// The files the README names, from the first column of its tables.
fn listed(readme: &str) -> Vec<String> {
    readme
        .lines()
        .filter_map(|line| line.strip_prefix("| `"))
        .filter_map(|rest| rest.split_once('`'))
        .map(|(name, _)| name.to_owned())
        .collect()
}

#[test]
fn every_data_file_is_listed_and_every_listed_file_exists() {
    let dir = data_dir();
    let mut found = Vec::new();
    files(&dir, &dir, &mut found);
    found.sort();
    // The walk has to see the files, or an empty folder would pass.
    assert!(
        found.len() > 20 && found.iter().any(|f| f == "frameworks/asvs-5.0.0.json"),
        "the walk of data/ found too little: {found:?}"
    );

    let readme = std::fs::read_to_string(dir.join("README.md")).expect("data/README.md exists");
    let named = listed(&readme);
    assert!(
        named.len() > 20,
        "the README's tables were not read: {named:?}"
    );

    let unlisted: Vec<&String> = found.iter().filter(|f| !named.contains(f)).collect();
    assert!(
        unlisted.is_empty(),
        "in data/ but not in data/README.md; add a line saying what each is and what reads it: {unlisted:?}"
    );
    let missing: Vec<&String> = named.iter().filter(|n| !found.contains(n)).collect();
    assert!(
        missing.is_empty(),
        "named in data/README.md but not in data/: {missing:?}"
    );
}
