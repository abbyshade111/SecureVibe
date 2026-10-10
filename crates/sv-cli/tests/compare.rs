//! `sv compare` on two real reports of one app, through the real `sv`, with a home of its own (the
//! report seal's key is kept there): it lists what changed, writes nothing, and says when it cannot
//! show a report is `sv`'s.

use std::path::{Path, PathBuf};
use std::process::Command;

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

/// Every file under `dir`, with its content, to see that nothing changed.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(snapshot(&path));
        } else {
            out.push((path.clone(), std::fs::read(&path).unwrap()));
        }
    }
    out.sort();
    out
}

#[test]
fn two_reports_are_compared_and_nothing_is_written() {
    let root = std::env::temp_dir().join(format!("sv-compare-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let app = root.join("app");
    copy(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking"),
        &app,
    );
    std::fs::remove_dir_all(app.join(sv_scan::ecosystems::DEFAULT_REPORT_DIR)).ok();
    let sv = |args: &[&str], dir: &Path| {
        Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(args)
            .current_dir(dir)
            .env("HOME", &home)
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("XDG_DATA_HOME")
            .output()
            .unwrap()
    };
    let (older, newer) = (root.join("older"), root.join("newer"));
    let made = sv(
        &[
            "report",
            app.to_str().unwrap(),
            "--out",
            older.to_str().unwrap(),
        ],
        &root,
    );
    assert!(
        matches!(made.status.code(), Some(0..=2)),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    // The setup: the older report has the finding the change below takes away.
    let gone = "There is no way to report a security problem";
    assert!(
        std::fs::read_to_string(older.join("report.json"))
            .unwrap()
            .contains(gone)
    );
    std::fs::write(
        app.join("SECURITY.md"),
        "Write to security@example.com; we answer within a week.\n",
    )
    .unwrap();
    let made = sv(
        &[
            "report",
            app.to_str().unwrap(),
            "--out",
            newer.to_str().unwrap(),
        ],
        &root,
    );
    assert!(
        matches!(made.status.code(), Some(0..=2)),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    assert!(
        !std::fs::read_to_string(newer.join("report.json"))
            .unwrap()
            .contains(gone)
    );

    let before = snapshot(&root);
    let out = sv(
        &["compare", older.to_str().unwrap(), newer.to_str().unwrap()],
        &root,
    );
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{said}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        snapshot(&root),
        before,
        "sv compare wrote or changed a file"
    );
    assert!(
        said.contains(&format!("No longer found (low): {gone}")),
        "{said}"
    );
    // Both are sealed, by this home's key, and alike: nothing to warn of.
    assert!(!said.contains("cannot show"), "{said}");
    assert!(!said.contains("not alike"), "{said}");

    // A report changed after `sv` wrote it is still compared, and said not to be shown as `sv`'s.
    let report = older.join("report.json");
    let mut text = std::fs::read_to_string(&report).unwrap();
    text.push(' ');
    std::fs::write(&report, text).unwrap();
    let out = sv(
        &["compare", older.to_str().unwrap(), newer.to_str().unwrap()],
        &root,
    );
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("sv cannot show it wrote the older report"),
        "{said}"
    );
    assert!(
        !said.contains("sv cannot show it wrote the newer report"),
        "{said}"
    );

    // Given one folder, the newer is this folder's own report.
    let made = sv(&["report", "."], &app);
    assert!(matches!(made.status.code(), Some(0..=2)));
    let out = sv(&["compare", newer.to_str().unwrap()], &app);
    let said = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{said}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        said.contains("app/stackvet-report") || said.contains("stackvet-report"),
        "{said}"
    );
    assert!(said.contains("No requirement's status changed."), "{said}");

    // A folder with no report is refused, and says what to give.
    let out = sv(
        &["compare", home.to_str().unwrap(), newer.to_str().unwrap()],
        &root,
    );
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("holds no report.json"));
    std::fs::remove_dir_all(&root).ok();
}
