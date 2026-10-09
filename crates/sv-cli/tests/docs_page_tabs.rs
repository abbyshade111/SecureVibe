//! The two views at the top of every page of the owner's private documentation set: the documents, and
//! the backlog at a glance. The owner asked on 9 October 2026 for the board to sit beside the documents,
//! "so it's all in one place", rather than behind a link on the index alone.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Every page the script wrote, by path.
fn pages(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            pages(&path, out);
        } else if path.extension().is_some_and(|e| e == "html") {
            out.push(path);
        }
    }
}

/// The two tab links of one page, as (text, target, highlighted).
fn tabs(page: &str) -> Vec<(String, String, bool)> {
    let start = page
        .find("<div class=\"tabs\">")
        .expect("the page has the tabs");
    let block = &page[start..start + page[start..].find("</div>").unwrap()];
    block
        .split("<a")
        .skip(1)
        .map(|a| {
            let href = a
                .split("href=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            let text = a.split('>').nth(1).unwrap().split('<').next().unwrap();
            (
                text.to_owned(),
                href.to_owned(),
                a.contains("class=\"here\""),
            )
        })
        .collect()
}

#[test]
fn every_page_offers_the_documents_and_the_backlog_one_click_away() {
    let dir = std::env::temp_dir().join(format!("sv-docs-page-tabs-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let out = Command::new("python3")
        .arg("-I")
        .arg(repo().join("tools/docs_page.py"))
        .args(["--out", dir.to_str().unwrap()])
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut all = Vec::new();
    pages(&dir, &mut all);
    // The setup: the documents were written, the board among them, and some sit in folders, so a
    // link that does not climb back up would be caught.
    let board = dir.join("backlog-board.html");
    assert!(all.len() > 50 && all.contains(&board), "{}", all.len());
    assert!(all.iter().any(|p| p.parent() != Some(dir.as_path())));
    for page in &all {
        let text = std::fs::read_to_string(page).unwrap();
        let found = tabs(&text);
        let names: Vec<&str> = found.iter().map(|(n, _, _)| n.as_str()).collect();
        assert_eq!(
            names,
            ["Documents", "Backlog at a glance"],
            "{}",
            page.display()
        );
        for (name, href, _) in &found {
            let target = page.parent().unwrap().join(href).canonicalize();
            let expected = if name == "Documents" {
                "index.html"
            } else {
                "backlog-board.html"
            };
            assert_eq!(
                target.ok(),
                dir.join(expected).canonicalize().ok(),
                "{}: {name} goes to {href}",
                page.display()
            );
        }
        // Only the board's own page shows the board's tab as the one you are on.
        let on_board = found[1].2;
        assert_eq!(on_board, *page == board, "{}", page.display());
        assert_eq!(found[0].2, *page != board, "{}", page.display());
    }
    std::fs::remove_dir_all(&dir).ok();
}
