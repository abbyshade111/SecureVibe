//! `tools/docs_page.py`, the owner's private set of pages holding `sv`'s documentation (ADR-058).
//!
//! The script is Python, as the other tools are; these tests run it, because a page that is wrong, or a
//! folder written over, would be found only by the owner otherwise.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn script(args: &[&str]) -> Output {
    Command::new("python3")
        .arg("-I")
        .arg(repo().join("tools/docs_page.py"))
        .args(args)
        .output()
        .expect("python3 runs")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-docs-page-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    dir
}

#[test]
fn its_markdown_reader_passes_its_own_checks() {
    let out = script(&["--self-test"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(said(&out).contains("checks passed"), "{}", said(&out));
}

#[test]
fn the_pages_hold_the_documents_and_leave_out_the_paper() {
    let dir = scratch("pages");
    let out = script(&["--out", dir.to_str().unwrap()]);
    let read = |p: &str| std::fs::read_to_string(dir.join(p)).unwrap_or_default();
    let index = read("index.html");
    let adr = read("docs/adr/ADR-058.html");
    let guide = read("docs/GETTING-STARTED.html");
    let paper = dir.join("docs/paper").exists();
    let marked = dir.join(".securevibe-docs").is_file();
    std::fs::remove_dir_all(&dir).ok();

    assert!(out.status.success(), "{}", said(&out));
    assert!(marked, "the folder is marked as the tool's own");
    assert!(index.contains("StackVet's documentation"), "{index}");
    assert!(
        index.contains("href=\"docs/adr/ADR-058.html\""),
        "the index lists the records"
    );
    assert!(adr.contains("<h1"), "a record is a page of its own");
    assert!(
        guide.contains("On this page"),
        "a long document has its table of contents"
    );
    assert!(
        !paper,
        "the paper's drafts are left out, as the owner chose"
    );
    // Nor linked: the documents may name the folder, but no page points into it.
    assert!(!index.contains("href=\"docs/paper/"), "nor listed");
    // Fetches nothing: no script or style from anywhere, and the search index holds no `<` that
    // could end its own element.
    for page in [&index, &adr, &guide] {
        assert!(!page.contains("<script src"), "a script fetched");
        assert!(!page.contains("<link"), "a style fetched");
    }
    let data = index
        .split("id=\"index\">")
        .nth(1)
        .and_then(|rest| rest.split("</script>").next())
        .expect("the search index is in the page");
    assert!(data.len() > 1000, "the search index holds the documents");
    assert!(!data.contains('<'), "a `<` in the search index");
}

#[test]
fn it_writes_only_into_its_own_folder() {
    // A folder that is not the tool's own, with something in it, is left alone.
    let theirs = scratch("theirs");
    std::fs::create_dir_all(&theirs).unwrap();
    std::fs::write(theirs.join("notes.txt"), "the owner's").unwrap();
    let refused = script(&["--out", theirs.to_str().unwrap()]);
    let left = std::fs::read_dir(&theirs).unwrap().count();
    std::fs::remove_dir_all(&theirs).ok();
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(
        said(&refused).contains("was not made by this tool"),
        "{}",
        said(&refused)
    );
    assert_eq!(left, 1, "something was written into it");

    // Not inside the repository, where it could be committed.
    let inside = repo()
        .join("target")
        .join(format!("docs-page-test-{}", std::process::id()));
    let refused = script(&["--out", inside.to_str().unwrap()]);
    let made = inside.exists();
    std::fs::remove_dir_all(&inside).ok();
    assert!(!refused.status.success(), "{}", said(&refused));
    assert!(!made, "a folder was made inside the repository");

    // Its own folder is brought up to date: a page for a document that is gone goes, and only pages.
    let ours = scratch("ours");
    assert!(script(&["--out", ours.to_str().unwrap()]).status.success());
    std::fs::write(ours.join("docs/GONE.html"), "old").unwrap();
    std::fs::write(ours.join("docs/kept.txt"), "not a page").unwrap();
    let again = script(&["--out", ours.to_str().unwrap()]);
    let gone = !ours.join("docs/GONE.html").exists();
    let kept = ours.join("docs/kept.txt").exists();
    std::fs::remove_dir_all(&ours).ok();
    assert!(again.status.success(), "{}", said(&again));
    assert!(gone && kept);
}
