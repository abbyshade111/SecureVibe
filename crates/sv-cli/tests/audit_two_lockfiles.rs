//! `sv audit` on an app with two lockfiles of one kind, end to end through the binary.
//!
//! `package-lock.json` is read and compared; a `yarn.lock` beside it is not, and may be the one the
//! app is installed from. Nothing matching in the file that was compared is then not a clean result,
//! so the exit status must not be 0, and the owner is told which file was not read.

use std::path::PathBuf;
use std::process::Command;

fn app(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("sv-audit-two-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(root.join("osv")).unwrap();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("package-lock.json"),
        r#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo"},
           "node_modules/lodash":{"version":"4.17.21"}}}"#,
    )
    .unwrap();
    // A record about lodash that 4.17.21 is past, so the comparison has something to compare
    // against and finds nothing.
    std::fs::write(
        root.join("osv/GHSA-lodash.json"),
        r#"{"id":"GHSA-lodash","summary":"A vulnerability.","published":"2020-07-15T00:00:00Z",
            "affected":[{"package":{"ecosystem":"npm","name":"lodash"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"4.17.19"}]}]}]}"#,
    )
    .unwrap();
    root
}

fn audit(dir: &std::path::Path) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "audit",
            dir.to_str().unwrap(),
            "--advisories",
            dir.join("osv").to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn a_second_lockfile_nothing_read_is_not_a_clean_audit() {
    let dir = app("clean");
    let (one_code, one) = audit(&dir);
    std::fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    let (two_code, two) = audit(&dir);
    std::fs::remove_dir_all(&dir).ok();

    // The control: with one lockfile, everything was compared and nothing matched.
    assert_eq!(one_code, Some(0), "{one}");
    assert!(!one.contains("yarn.lock"), "{one}");

    assert_eq!(two_code, Some(2), "not assessed, never clean:\n{two}");
    assert!(
        two.contains("`package-lock.json` was read; `yarn.lock` is there too and was not read"),
        "{two}"
    );
}
