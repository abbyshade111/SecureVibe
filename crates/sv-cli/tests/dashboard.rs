//! `sv dashboard`, end to end through the binary: one page from the reports already in each app's
//! folder, written only where it is told, and never over anything it did not make (ADR-057).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const SV: &str = env!("CARGO_BIN_EXE_sv");

fn sv(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(SV).args(args).output().unwrap();
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-dashboard-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A copy of one of the example apps, with a fresh report of its own.
fn reported(root: &Path, example: &str) -> PathBuf {
    let from = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(example);
    let to = root.join(example);
    copy(&from, &to);
    std::fs::remove_dir_all(to.join("securevibe-report")).ok();
    let (code, said) = sv(&["report", s(&to)]);
    assert!(
        to.join("securevibe-report/report.json").is_file(),
        "the setup: sv report wrote a report ({code:?}): {said}"
    );
    to
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

#[test]
fn the_page_shows_each_app_as_its_report_left_it() {
    let root = scratch("page");
    let notes = reported(&root, "notes-with-users");
    let clinic = reported(&root, "flask-booking");
    let empty = root.join("no-report-yet");
    std::fs::create_dir_all(&empty).unwrap();
    let out = root.join("dashboard.html");
    let (code, said) = sv(&[
        "dashboard",
        s(&notes),
        s(&empty),
        s(&clinic),
        "--out",
        s(&out),
    ]);
    let page = std::fs::read_to_string(&out).unwrap_or_default();
    let reports: Vec<Value> = [&clinic, &notes]
        .iter()
        .map(|a| {
            serde_json::from_str(
                &std::fs::read_to_string(a.join("securevibe-report/report.json")).unwrap(),
            )
            .unwrap()
        })
        .collect();
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(code, Some(0), "{said}");
    assert!(said.contains("no-report-yet: no report to show"), "{said}");
    // Alphabetical, whatever order the folders were given in.
    let at = |text: &str| {
        page.find(text)
            .unwrap_or_else(|| panic!("{text} is not on the page"))
    };
    assert!(at(">Clinic booking<") < at(">no-report-yet<"));
    assert!(at(">no-report-yet<") < at(">Notes with users<"));
    // Every count on the page is one its report states.
    for report in &reports {
        let c = &report["counts"];
        for key in ["applicable", "not_applicable", "not_verified", "checked"] {
            let n = c[key].as_u64().unwrap();
            if n > 0 {
                assert!(page.contains(&format!("<strong>{n}</strong>")), "{key} {n}");
            }
        }
        assert!(page.contains(&format!("The {} requirements that apply", c["applicable"])));
    }
    assert!(page.contains("no report.json in its securevibe-report folder yet"));
    assert!(page.contains("Open the full report"));
    // Fetches nothing: no script, and no address but the reports' own files.
    assert!(!page.contains("<script"), "a script on the page");
    assert!(!page.contains("http://") && !page.contains("https://"));
    for word in ["pass", "passed", "secure", "compliant", "safe", "score"] {
        let words: Vec<&str> = page
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .collect();
        assert!(!words.contains(&word), "{word} on the page");
    }
}

#[test]
fn it_writes_only_where_it_is_told_and_never_over_what_it_did_not_make() {
    let root = scratch("writes");
    let app = reported(&root, "tested-notes");
    let (no_out, no_out_said) = sv(&["dashboard", s(&app)]);
    let inside = app.join("dashboard.html");
    let (in_app, in_app_said) = sv(&["dashboard", s(&app), "--out", s(&inside)]);
    let theirs = root.join("theirs.html");
    std::fs::write(&theirs, "the owner's own page").unwrap();
    let (over, over_said) = sv(&["dashboard", s(&app), "--out", s(&theirs)]);
    let folder = root.join("a-folder.html");
    std::fs::create_dir_all(&folder).unwrap();
    let (into_folder, _) = sv(&["dashboard", s(&app), "--out", s(&folder)]);
    let ours = root.join("ours.html");
    let (first, _) = sv(&["dashboard", s(&app), "--out", s(&ours)]);
    let (again, again_said) = sv(&["dashboard", s(&app), "--out", s(&ours)]);
    #[cfg(unix)]
    let link = {
        let link = root.join("link.html");
        std::os::unix::fs::symlink(&theirs, &link).unwrap();
        sv(&["dashboard", s(&app), "--out", s(&link)])
    };
    let (none, _) = sv(&["dashboard", "--out", s(&root.join("x.html"))]);
    let theirs_after = std::fs::read_to_string(&theirs).unwrap();
    let inside_written = inside.exists();
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(no_out, Some(3), "{no_out_said}");
    assert!(no_out_said.contains("add --out FILE.html"), "{no_out_said}");
    assert_eq!(in_app, Some(3), "{in_app_said}");
    assert!(
        in_app_said.contains("inside the app folder"),
        "{in_app_said}"
    );
    assert!(!inside_written, "a page was written into the app");
    assert_eq!(over, Some(3), "{over_said}");
    assert!(
        over_said.contains("was not written by sv dashboard"),
        "{over_said}"
    );
    assert_eq!(into_folder, Some(3));
    assert_eq!(
        (first, again),
        (Some(0), Some(0)),
        "its own page is replaced: {again_said}"
    );
    #[cfg(unix)]
    assert_eq!(link.0, Some(3), "{}", link.1);
    assert_eq!(theirs_after, "the owner's own page");
    assert_eq!(none, Some(3), "no app folders given");
}

#[test]
fn what_a_report_says_reaches_the_page_as_text_and_never_as_markup() {
    // The app's name comes from securevibe.toml, which the AI coding tool writes.
    let root = scratch("escape");
    let app = root.join("odd");
    std::fs::create_dir_all(app.join("securevibe-report")).unwrap();
    std::fs::write(
        app.join("securevibe-report/report.json"),
        r#"{"app_name":"<img src=x onerror=alert(1)>","target_level":1,
            "counts":{"applicable":1,"not_verified":1},
            "findings":[{"severity":"high","title":"<script>alert(2)</script>"}],
            "gaps":[{"what":"<b>bold</b>"}]}"#,
    )
    .unwrap();
    let out = root.join("page.html");
    let (code, said) = sv(&["dashboard", s(&app), "--out", s(&out)]);
    let page = std::fs::read_to_string(&out).unwrap_or_default();
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(code, Some(0), "{said}");
    assert!(
        page.contains("&lt;img src=x onerror=alert(1)&gt;"),
        "{page}"
    );
    assert!(page.contains("&lt;script&gt;alert(2)&lt;/script&gt;"));
    assert!(page.contains("&lt;b&gt;bold&lt;/b&gt;"));
    assert!(!page.contains("<img") && !page.contains("<script") && !page.contains("<b>"));
}
