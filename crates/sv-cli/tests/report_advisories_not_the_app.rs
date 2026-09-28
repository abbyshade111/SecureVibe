//! `sv report --advisories` and the folders securevibe.toml says are not the app. `sv audit` counts
//! only what the app ships; the report used to build its own list of packages from the whole folder,
//! so an example app's vulnerable package counted against V15.2.1 there and not in `sv audit`.

use std::path::{Path, PathBuf};
use std::process::Command;

const HIGH: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";

fn lockfile(dir: &Path, packages: &[(&str, &str)]) {
    std::fs::create_dir_all(dir).unwrap();
    let deps: Vec<String> = packages
        .iter()
        .map(|(n, v)| format!("\"{n}\":\"{v}\""))
        .collect();
    let locked: Vec<String> = packages
        .iter()
        .map(|(n, v)| format!("\"node_modules/{n}\":{{\"version\":\"{v}\"}}"))
        .collect();
    std::fs::write(
        dir.join("package.json"),
        format!(
            r#"{{"name":"demo","version":"1.0.0","dependencies":{{{}}}}}"#,
            deps.join(",")
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        format!(
            r#"{{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"name":"demo","version":"1.0.0"}},{}}}}}"#,
            locked.join(",")
        ),
    )
    .unwrap();
}

/// An npm app using qs, a demo app beside it using lodash, and a database with one advisory each.
fn setup(name: &str, repository: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-report-nta-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let (dir, osv) = (root.join("app"), root.join("osv"));
    lockfile(&dir, &[("qs", "6.5.0")]);
    lockfile(&dir.join("demo/shop"), &[("lodash", "4.17.15")]);
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Shop\"\n[stack]\nlanguages = [\"javascript\"]\n{repository}"
        ),
    )
    .unwrap();
    std::fs::create_dir_all(&osv).unwrap();
    for (id, package) in [("GHSA-in-the-app", "qs"), ("GHSA-in-the-demo", "lodash")] {
        std::fs::write(
            osv.join(format!("{id}.json")),
            format!(
                r#"{{"id":"{id}","summary":"A vulnerability.","published":"2020-07-15T00:00:00Z",
                    "severity":[{{"type":"CVSS_V3","score":"{HIGH}"}}],
                    "affected":[{{"package":{{"ecosystem":"npm","name":"{package}"}},
                    "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"99"}}]}}]}}]}}"#
            ),
        )
        .unwrap();
    }
    (dir, osv)
}

/// The report's findings as JSON text, and its compliance page.
fn report(dir: &Path, osv: &Path) -> (String, String) {
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(dir)
        .arg("--advisories")
        .arg(osv)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    (
        json["findings"].to_string(),
        std::fs::read_to_string(out.join("compliance.md")).unwrap(),
    )
}

#[test]
fn a_vulnerable_package_in_a_folder_that_is_not_the_app_is_listed_and_not_counted() {
    // The control: without the list, the demo is part of the app, and both are findings.
    let (dir, osv) = setup("whole", "");
    let (findings, _) = report(&dir, &osv);
    assert!(findings.contains("GHSA-in-the-app"), "{findings}");
    assert!(
        findings.contains("GHSA-in-the-demo"),
        "the demo's is really found: {findings}"
    );

    let (dir, osv) = setup("named", "[repository]\nnot-the-app = [\"demo\"]\n");
    let (findings, compliance) = report(&dir, &osv);
    assert!(
        findings.contains("GHSA-in-the-app"),
        "the app's own still counts: {findings}"
    );
    assert!(
        !findings.contains("GHSA-in-the-demo"),
        "not counted: {findings}"
    );
    assert!(
        compliance
            .contains("1 known vulnerability in folders securevibe.toml says are not the app"),
        "{compliance}"
    );
    assert!(
        compliance.contains("GHSA-in-the-demo"),
        "and named: {compliance}"
    );
    assert!(
        compliance.contains("not counted against the app"),
        "{compliance}"
    );
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();
}
