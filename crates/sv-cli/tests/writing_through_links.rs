//! The files `sv` writes from the command line are never written through a link, and a report never
//! lands on top of the app's own files (deep review S3 to S5). Each test plants the fault the review
//! reproduced, shows the plant is real, and then that the file it points at is left alone.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sv(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs")
}

fn said(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// A scratch folder with a copy of the Flask example in `app/` and a precious file beside it.
fn scratch(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-writes-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    for entry in std::fs::read_dir(&example).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            std::fs::copy(entry.path(), app.join(entry.file_name())).unwrap();
        }
    }
    let precious = root.join("precious.txt");
    std::fs::write(&precious, "keep me\n").unwrap();
    (root, app, precious)
}

/// Plants a link at `at` to `precious`, and shows it is real: reading through it reads the file.
fn plant(precious: &Path, at: &Path) {
    std::os::unix::fs::symlink(precious, at).unwrap();
    assert_eq!(std::fs::read_to_string(at).unwrap(), "keep me\n");
}

fn assert_refused_and_left_alone(out: &Output, precious: &Path, link: &Path) {
    assert!(!out.status.success(), "it went through: {}", said(out));
    assert!(said(out).contains("is a link"), "{}", said(out));
    assert_eq!(
        std::fs::read_to_string(precious).unwrap(),
        "keep me\n",
        "the file the link points at was written over"
    );
    assert!(
        std::fs::symlink_metadata(link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link was removed rather than refused"
    );
}

#[test]
fn sv_rules_does_not_write_through_a_link_at_agents_md() {
    let (root, app, precious) = scratch("rules");
    let link = app.join("AGENTS.md");
    plant(&precious, &link);
    let out = sv(&["rules", app.to_str().unwrap()]);
    assert_refused_and_left_alone(&out, &precious, &link);
    // And without the link, it writes as it always did, leaving no staging file behind.
    std::fs::remove_file(&link).unwrap();
    let out = sv(&["rules", app.to_str().unwrap()]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        std::fs::read_to_string(&link)
            .unwrap()
            .contains("Appendix C")
    );
    assert_no_staging_left(&app);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn sv_notes_does_not_write_through_a_link_at_the_notes_file() {
    let (root, app, precious) = scratch("notes");
    let link = app.join("security-notes.md");
    plant(&precious, &link);
    let out = sv(&["notes", app.to_str().unwrap()]);
    assert_refused_and_left_alone(&out, &precious, &link);
    std::fs::remove_file(&link).unwrap();
    let out = sv(&["notes", app.to_str().unwrap()]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(
        std::fs::read_to_string(&link)
            .unwrap()
            .contains("Written by")
    );
    assert_no_staging_left(&app);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn sv_bundle_does_not_write_through_a_link_where_its_zip_goes() {
    let (root, app, precious) = scratch("bundle");
    let link = root.join("app-securevibe-bundle.zip");
    plant(&precious, &link);
    let out = sv(&["bundle", app.to_str().unwrap()]);
    assert_refused_and_left_alone(&out, &precious, &link);
    std::fs::remove_file(&link).unwrap();
    let out = sv(&["bundle", app.to_str().unwrap()]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(std::fs::read(&link).unwrap().starts_with(b"PK"));
    assert_no_staging_left(&root);
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_report_is_not_written_over_the_apps_own_files() {
    let (root, app, _) = scratch("report-here");
    std::fs::write(app.join("SECURITY.md"), "Our security policy.\n").unwrap();
    let before: Vec<_> = listing(&app);
    // `--out` at the app itself, as `out: "."` did over MCP.
    let out = sv(&[
        "report",
        app.to_str().unwrap(),
        "--out",
        app.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "it went through: {}", said(&out));
    assert!(
        said(&out).contains("so sv does not write its report there"),
        "{}",
        said(&out)
    );
    assert_eq!(listing(&app), before, "something was written into the app");
    assert_eq!(
        std::fs::read_to_string(app.join("SECURITY.md")).unwrap(),
        "Our security policy.\n"
    );
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_report_is_not_written_into_a_folder_of_someone_elses() {
    // The app folder without the case clash: refused because it holds files sv did not write.
    let (root, app, _) = scratch("report-theirs");
    // A README.md too: a marker matched loosely, by case or by kind of file, would take it for sv's.
    std::fs::write(app.join("README.md"), "Our app.\n").unwrap();
    let before = listing(&app);
    let out = sv(&[
        "report",
        app.to_str().unwrap(),
        "--out",
        app.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "it went through: {}", said(&out));
    assert!(
        said(&out).contains("files sv did not write"),
        "{}",
        said(&out)
    );
    assert_eq!(listing(&app), before, "something was written into the app");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_report_folder_holding_a_name_like_one_of_svs_but_for_capitals_is_refused_even_when_marked() {
    // The marker can be planted, and on a disk that does not tell capitals apart `security.md` is
    // `SECURITY.md`. Built on whatever disk this runs on, so the name is checked, not the disk.
    let (root, app, _) = scratch("report-case");
    let out_dir = root.join("report");
    std::fs::create_dir(&out_dir).unwrap();
    std::fs::write(out_dir.join(".securevibe-report"), "planted\n").unwrap();
    std::fs::write(out_dir.join("SECURITY.md"), "Theirs.\n").unwrap();
    let out = sv(&[
        "report",
        app.to_str().unwrap(),
        "--out",
        out_dir.to_str().unwrap(),
    ]);
    assert!(!out.status.success(), "it went through: {}", said(&out));
    assert!(said(&out).contains("`SECURITY.md`"), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(out_dir.join("SECURITY.md")).unwrap(),
        "Theirs.\n"
    );
    assert!(!out_dir.join("report.json").exists());
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_report_is_written_into_a_new_an_empty_or_its_own_folder() {
    let (root, app, _) = scratch("report-ok");
    let app_s = app.to_str().unwrap();
    // A folder that does not exist yet, then the same folder again: marked by the first report.
    let fresh = root.join("fresh");
    for _ in 0..2 {
        let out = sv(&["report", app_s, "--out", fresh.to_str().unwrap()]);
        assert!(out.status.success(), "{}", said(&out));
    }
    assert!(fresh.join(".securevibe-report").exists() && fresh.join("report.json").exists());
    // A folder sv marked, with a file the owner put there since: still sv's, and the file is kept.
    std::fs::write(fresh.join("notes-to-self.txt"), "mine\n").unwrap();
    let out = sv(&["report", app_s, "--out", fresh.to_str().unwrap()]);
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(
        std::fs::read_to_string(fresh.join("notes-to-self.txt")).unwrap(),
        "mine\n"
    );
    // An empty folder.
    let empty = root.join("empty");
    std::fs::create_dir(&empty).unwrap();
    let out = sv(&["report", app_s, "--out", empty.to_str().unwrap()]);
    assert!(out.status.success(), "{}", said(&out));
    // A folder from before the marker: only names sv writes.
    let old = root.join("old");
    std::fs::create_dir(&old).unwrap();
    for name in ["report.json", "security.md", "compliance.md"] {
        std::fs::write(old.join(name), "old\n").unwrap();
    }
    let out = sv(&["report", app_s, "--out", old.to_str().unwrap()]);
    assert!(out.status.success(), "{}", said(&out));
    assert_ne!(
        std::fs::read_to_string(old.join("report.json")).unwrap(),
        "old\n"
    );
    // The default folder inside the app, which every `sv report` uses.
    let out = sv(&["report", app_s]);
    assert!(out.status.success(), "{}", said(&out));
    std::fs::remove_dir_all(&root).ok();
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn assert_no_staging_left(dir: &Path) {
    let staging: Vec<String> = listing(dir)
        .into_iter()
        .filter(|n| n.contains(".sv-"))
        .collect();
    assert!(staging.is_empty(), "staging files left: {staging:?}");
}
