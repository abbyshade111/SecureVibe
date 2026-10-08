//! The decision records point at things that exist (BACKLOG, "Decision records written with the change, not after
//! it", 4 October 2026).
//!
//! A record says which tests hold it, which files it governs, and which other records it relates to. Renaming a
//! test, moving a file, or citing a record that was never written would make it quietly wrong; each of those fails
//! here instead. `sv`'s records are ADR-015 onward; v1's, ADR-001 to ADR-014, are on the `v1` branch.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every file in the repository, as a path from its root with `/` separators, leaving out what git ignores here.
fn repository_files() -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if matches!(name.as_str(), ".git" | "target" | "node_modules") {
                continue;
            }
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                walk(&path, base, out);
            } else if kind.is_file() {
                let rel = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push(rel);
            }
        }
    }
    let mut out = Vec::new();
    walk(&root(), &root(), &mut out);
    out
}

/// `sv`'s records: number and text.
fn records() -> Vec<(u32, String)> {
    let mut out: Vec<(u32, String)> = std::fs::read_dir(root().join("docs/adr"))
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            let n: u32 = name
                .strip_prefix("ADR-")?
                .strip_suffix(".md")?
                .parse()
                .ok()?;
            (n >= 15).then(|| (n, std::fs::read_to_string(e.path()).unwrap()))
        })
        .collect();
    out.sort();
    out
}

/// The spans written in backticks.
fn quoted(text: &str) -> Vec<String> {
    text.split('`')
        .enumerate()
        .filter(|(i, _)| i % 2 == 1)
        .map(|(_, s)| s.to_owned())
        .collect()
}

/// The patterns on a record's `**Governs:**` paragraph.
pub fn governs(text: &str) -> Vec<String> {
    let Some(start) = text.find("**Governs:**") else {
        return Vec::new();
    };
    let paragraph = text[start..].split("\n\n").next().unwrap_or("");
    let listed = paragraph
        .split(". A pull request")
        .next()
        .unwrap_or(paragraph);
    quoted(listed)
}

/// A `Governs` pattern as `tools/adr_check.py` reads it: `*` matches any run of characters, `/` included.
fn matches(pattern: &str, path: &str) -> bool {
    fn go(p: &[u8], s: &[u8]) -> bool {
        match p.split_first() {
            None => s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| go(rest, &s[i..])),
            Some((c, rest)) => s.first() == Some(c) && go(rest, &s[1..]),
        }
    }
    go(pattern.as_bytes(), path.as_bytes())
}

/// Every `fn name` in the workspace's Rust code.
fn functions() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for file in repository_files() {
        if !(file.starts_with("crates/") && file.ends_with(".rs")) {
            continue;
        }
        let text = std::fs::read_to_string(root().join(&file)).unwrap_or_default();
        for piece in text.split("fn ").skip(1) {
            let name: String = piece
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    out
}

/// A span that names a test: lower case with at least three underscores, as this repository names them.
fn looks_like_a_test(span: &str) -> bool {
    span.matches('_').count() >= 3
        && span
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// A span that names a file in this repository.
fn looks_like_a_path(span: &str) -> bool {
    const PLACES: [&str; 6] = [
        "crates/",
        "data/",
        "docs/",
        "tools/",
        "examples/",
        ".github/",
    ];
    const KINDS: [&str; 8] = [
        ".rs", ".json", ".md", ".py", ".toml", ".yml", ".html", ".txt",
    ];
    !span.contains(' ')
        && !span.contains('*')
        && PLACES.iter().any(|p| span.starts_with(p))
        && KINDS.iter().any(|k| span.ends_with(k))
}

/// Problems with what a record names. Empty when every reference holds.
fn problems(n: u32, text: &str, files: &[String], functions: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let patterns = governs(text);
    if patterns.is_empty() {
        out.push(format!("ADR-{n:03} has no **Governs:** list"));
    }
    for pattern in &patterns {
        if !files.iter().any(|f| matches(pattern, f)) {
            out.push(format!(
                "ADR-{n:03} governs `{pattern}`, which matches no file"
            ));
        }
    }
    for span in quoted(text) {
        if looks_like_a_test(&span) && !functions.contains(&span) {
            out.push(format!(
                "ADR-{n:03} names `{span}`, and no function has that name"
            ));
        }
        // v1's records live on the `v1` branch, so a path to one of them is not looked for here.
        let v1_record = span
            .strip_prefix("docs/adr/ADR-")
            .and_then(|r| r.get(..3))
            .and_then(|d| d.parse::<u32>().ok())
            .is_some_and(|d| d < 15);
        if looks_like_a_path(&span) && !v1_record && !files.contains(&span) {
            out.push(format!(
                "ADR-{n:03} names `{span}`, and there is no such file"
            ));
        }
    }
    out
}

#[test]
fn every_record_names_only_tests_files_and_records_that_exist() {
    let files = repository_files();
    let functions = functions();
    let records = records();
    // The setup: the records, the files, and the functions were really found.
    assert!(
        records.len() >= 12,
        "only {} records were read",
        records.len()
    );
    assert!(files.iter().any(|f| f == "crates/sv-check/src/seal.rs"));
    assert!(functions.contains("every_record_names_only_tests_files_and_records_that_exist"));
    let mut found = Vec::new();
    for (n, text) in &records {
        found.extend(problems(*n, text, &files, &functions));
    }
    assert!(found.is_empty(), "{}", found.join("\n"));
}

#[test]
fn every_record_number_cited_is_a_record() {
    let numbers: BTreeSet<u32> = records().into_iter().map(|(n, _)| n).collect();
    let mut cited = Vec::new();
    for file in repository_files() {
        let read = file.starts_with("crates/") && file.ends_with(".rs")
            || file.starts_with("docs/") && file.ends_with(".md")
            || matches!(file.as_str(), "CLAUDE.md" | "README.md");
        if !read {
            continue;
        }
        let text = std::fs::read_to_string(root().join(&file)).unwrap_or_default();
        for piece in text.split("ADR-").skip(1) {
            let digits: String = piece.chars().take_while(char::is_ascii_digit).collect();
            if digits.len() != 3 {
                continue;
            }
            let n: u32 = digits.parse().unwrap();
            // v1's are 1 to 14, on the `v1` branch.
            if n >= 15 && !numbers.contains(&n) {
                cited.push(format!("{file} cites ADR-{n:03}, which has no record"));
            }
        }
    }
    assert!(cited.is_empty(), "{}", cited.join("\n"));
}

#[test]
fn the_index_lists_every_record() {
    let index = std::fs::read_to_string(root().join("docs/adr/README.md")).unwrap();
    let missing: Vec<String> = records()
        .into_iter()
        .map(|(n, _)| format!("(ADR-{n:03}.md)"))
        .filter(|link| !index.contains(link.as_str()))
        .collect();
    assert!(missing.is_empty(), "not in docs/adr/README.md: {missing:?}");
    // And as a table a reader can use: one row each, in order, with no blank line breaking it. A row
    // added twice, or a blank line that ends the table early, passed the check above on 7 October 2026.
    let lines: Vec<&str> = index.lines().collect();
    let rows: Vec<(usize, u32)> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| {
            let rest = l.strip_prefix("| [ADR-")?;
            Some((i, rest.get(..3)?.parse().ok()?))
        })
        .collect();
    let numbers: Vec<u32> = rows.iter().map(|(_, n)| *n).collect();
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        numbers, sorted,
        "the index's rows are not one each, in order: {numbers:?}"
    );
    let (first, last) = (rows[0].0, rows[rows.len() - 1].0);
    assert_eq!(
        last - first + 1,
        rows.len(),
        "something other than a row breaks the index's table"
    );
}

#[test]
fn the_checks_catch_what_they_are_for() {
    let files = vec![
        "crates/a/src/one.rs".to_owned(),
        "data/frameworks/x.json".to_owned(),
    ];
    let functions: BTreeSet<String> = ["a_test_that_is_there".to_owned()].into();
    let good = "**Status:** accepted.\n\n**Governs:** `crates/a/src/one.rs`, `data/frameworks/*`. A pull request \
                that changes any of these.\n\n`a_test_that_is_there` in `crates/a/src/one.rs`, and v1's \
                `docs/adr/ADR-012.md`.";
    assert!(problems(99, good, &files, &functions).is_empty());
    for (bad, says) in [
        (
            good.replace("**Governs:**", "Governs"),
            "no **Governs:** list",
        ),
        (
            good.replace("`crates/a/src/one.rs`,", "`crates/a/src/two.rs`,"),
            "matches no file",
        ),
        (
            good.replace("a_test_that_is_there", "a_test_that_is_gone"),
            "no function",
        ),
        (
            good.replace("in `crates/a/src/one.rs`", "in `crates/a/src/gone.rs`"),
            "no such file",
        ),
    ] {
        let found = problems(99, &bad, &files, &functions);
        assert!(found.iter().any(|p| p.contains(says)), "{says}: {found:?}");
    }
    assert!(matches("crates/*/Cargo.toml", "crates/sv-cli/Cargo.toml"));
    assert!(!matches("crates/*/Cargo.toml", "Cargo.toml"));
}
