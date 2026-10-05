//! `sv audit` and the folders securevibe.toml says are not the app, and what its exit status says,
//! end to end through the binary. What is in those folders is listed apart and still counted, since
//! the AI coding tool writes securevibe.toml. A weekly job in CI holds `sv` itself to V15.2.1 with
//! this, so the status is the check: 0 only when everything was compared and nothing matched.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const HIGH: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
const NOT_THE_APP: &str = "manifest-version = 1\n[app]\nname = \"Audited\"\n[stack]\nlanguages = [\"javascript\"]\n[repository]\nnot-the-app = [\"examples\"]\n";
const PLAIN: &str =
    "manifest-version = 1\n[app]\nname = \"Audited\"\n[stack]\nlanguages = [\"javascript\"]\n";

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

/// An npm app whose own packages are `app_packages`, with an example app beside it using lodash
/// 4.17.15, and an advisory database about npm with a record for lodash and one for qs.
fn setup(name: &str, manifest: &str, app_packages: &[(&str, &str)]) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-audit-nta-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let (dir, osv) = (root.join("app"), root.join("osv"));
    lockfile(&dir, app_packages);
    lockfile(&dir.join("examples/demo"), &[("lodash", "4.17.15")]);
    std::fs::write(dir.join("securevibe.toml"), manifest).unwrap();
    std::fs::create_dir_all(&osv).unwrap();
    for (id, package) in [("GHSA-app", "qs"), ("GHSA-example", "lodash")] {
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

fn audit(dir: &Path, osv: Option<&Path>) -> (Option<i32>, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sv"));
    command.args(["audit", dir.to_str().unwrap()]);
    if let Some(osv) = osv {
        command.args(["--advisories", osv.to_str().unwrap()]);
    }
    let out: Output = command.output().expect("sv runs");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A lockfile `sv` cannot read, in `folder` under the app.
fn unreadable_lockfile(dir: &Path, folder: &str) {
    std::fs::create_dir_all(dir.join(folder)).unwrap();
    std::fs::write(dir.join(folder).join("package.json"), r#"{"name":"x"}"#).unwrap();
    std::fs::write(
        dir.join(folder).join("package-lock.json"),
        "this is not a lockfile",
    )
    .unwrap();
}

#[test]
fn an_example_apps_vulnerability_is_listed_apart_and_still_counted() {
    let (dir, osv) = setup("apart", NOT_THE_APP, &[("qs", "6.5.0")]);
    let (code, text) = audit(&dir, Some(&osv));
    // The control: with nothing said about examples, both are the app's own.
    std::fs::write(dir.join("securevibe.toml"), PLAIN).unwrap();
    let (plain_code, plain) = audit(&dir, Some(&osv));
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();

    assert_eq!(code, Some(1), "{text}");
    let (app_part, apart) = text
        .split_once("not the app")
        .unwrap_or_else(|| panic!("no section for what is not the app:\n{text}"));
    assert!(
        app_part.contains("\n1 known vulnerability:")
            && app_part.contains("qs 6.5.0")
            && !app_part.contains("lodash"),
        "{text}"
    );
    assert!(
        apart.contains("counted all the same") && apart.contains("lodash 4.17.15"),
        "{text}"
    );

    assert_eq!(plain_code, Some(1), "{plain}");
    assert!(plain.contains("\n2 known vulnerabilities:"), "{plain}");
}

#[test]
fn naming_a_folder_never_hides_its_vulnerability() {
    // The app itself is clean; the only vulnerable package is in a folder securevibe.toml sets apart.
    // A line the AI coding tool writes must not be able to turn that into a clean result.
    let (dir, osv) = setup("hidden", NOT_THE_APP, &[("express", "4.21.2")]);
    let (code, text) = audit(&dir, Some(&osv));
    // The control: the same example without the vulnerable package is clean, status 0.
    lockfile(&dir.join("examples/demo"), &[("express", "4.21.2")]);
    let (clean, clean_text) = audit(&dir, Some(&osv));
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();

    assert!(text.contains("lodash 4.17.15"), "{text}");
    assert_eq!(code, Some(1), "{text}");
    assert_eq!(clean, Some(0), "{clean_text}");
}

#[test]
fn a_comparison_that_did_not_cover_the_app_is_status_2_never_0() {
    let (dir, osv) = setup("partial", NOT_THE_APP, &[("express", "4.21.2")]);
    // The example is clean here, so what the status says is about the app alone.
    lockfile(&dir.join("examples/demo"), &[("express", "4.21.2")]);
    // No database at all.
    let (none, text) = audit(&dir, None);
    assert_eq!(none, Some(2), "{text}");
    // An empty one.
    let empty = dir.parent().unwrap().join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (blank, text) = audit(&dir, Some(&empty));
    assert_eq!(blank, Some(2), "{text}");
    // An ecosystem the database holds nothing about: a Python lockfile in the app itself.
    std::fs::write(dir.join("requirements.txt"), "flask==3.0.0\n").unwrap();
    let (uncovered, text) = audit(&dir, Some(&osv));
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    assert!(text.contains("Not assessed"), "{text}");
    assert_eq!(uncovered, Some(2), "{text}");
}

#[test]
fn an_incomplete_list_is_status_2_in_the_app_or_in_a_folder_set_apart() {
    for folder in ["web", "examples/broken"] {
        let (dir, osv) = setup("incomplete", NOT_THE_APP, &[("express", "4.21.2")]);
        // The control: the example's vulnerable package out of the way, the setup is clean.
        lockfile(&dir.join("examples/demo"), &[("express", "4.21.2")]);
        let (before, text) = audit(&dir, Some(&osv));
        assert_eq!(before, Some(0), "clean before the lockfile breaks: {text}");
        unreadable_lockfile(&dir, folder);
        let (code, text) = audit(&dir, Some(&osv));
        std::fs::remove_dir_all(dir.parent().unwrap()).ok();
        assert!(text.contains("incomplete"), "{folder}: {text}");
        if folder.starts_with("examples") {
            // "None matches" beside "incomplete" would read as clean for that folder.
            let (_, apart) = text.split_once("not the app").unwrap();
            assert!(!apart.contains("none matches a record"), "{folder}: {text}");
        }
        assert_eq!(code, Some(2), "{folder}: {text}");
    }
}

#[test]
fn a_database_that_only_mentions_an_ecosystem_in_passing_does_not_cover_it() {
    // The app's own Python packages, and a database about npm whose one other record also names a
    // PyPI package, as OSV's per-ecosystem exports do for packages published to both.
    let (dir, osv) = setup("passing", NOT_THE_APP, &[("express", "4.21.2")]);
    // The example is clean here, so what the status says is about the app alone.
    lockfile(&dir.join("examples/demo"), &[("express", "4.21.2")]);
    std::fs::write(dir.join("requirements.txt"), "flask==3.0.0\n").unwrap();
    std::fs::write(
        osv.join("GHSA-both.json"),
        r#"{"id":"GHSA-both","affected":[
            {"package":{"ecosystem":"npm","name":"left-pad"},
             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.1"}]}]},
            {"package":{"ecosystem":"PyPI","name":"left-pad"},
             "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0.1"}]}]}]}"#,
    )
    .unwrap();
    let (code, text) = audit(&dir, Some(&osv));
    // The control: a record about PyPI alone covers it, and the same app is then clean.
    std::fs::write(
        osv.join("PYSEC-only.json"),
        r#"{"id":"PYSEC-only","affected":[{"package":{"ecosystem":"PyPI","name":"django"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0"}]}]}]}"#,
    )
    .unwrap();
    let (covered, covered_text) = audit(&dir, Some(&osv));
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();
    assert!(text.contains("holds nothing about Python"), "{text}");
    assert_eq!(code, Some(2), "{text}");
    // Still 2 then, for another reason the output gives: a requirements.txt is not a lockfile, so
    // the list is incomplete. What changes is that Python counts as compared.
    assert!(
        !covered_text.contains("holds nothing about Python"),
        "{covered_text}"
    );
    assert_eq!(covered, Some(2), "{covered_text}");
}

#[test]
fn a_folder_set_apart_by_a_pattern_still_counts_both_ways() {
    // `fixtures/*` in securevibe.toml, as `sv`'s own manifest writes `crates/*/tests`.
    let manifest = "manifest-version = 1\n[app]\nname = \"Audited\"\n[stack]\nlanguages = [\"javascript\"]\n[repository]\nnot-the-app = [\"examples\", \"fixtures/*\"]\n";
    let (dir, osv) = setup("pattern", manifest, &[("express", "4.21.2")]);
    lockfile(&dir.join("examples/demo"), &[("express", "4.21.2")]);
    let (clean, clean_text) = audit(&dir, Some(&osv));
    assert_eq!(clean, Some(0), "the setup is clean: {clean_text}");

    // A vulnerable package in a fixture: listed apart, and status 1.
    lockfile(&dir.join("fixtures/one"), &[("qs", "6.5.0")]);
    let (found, found_text) = audit(&dir, Some(&osv));
    // A fixture whose lockfile cannot be read, the vulnerable one gone: status 2.
    std::fs::remove_dir_all(dir.join("fixtures/one")).unwrap();
    unreadable_lockfile(&dir, "fixtures/two");
    let (partial, partial_text) = audit(&dir, Some(&osv));
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();

    let (_, apart) = found_text
        .split_once("not the app")
        .unwrap_or_else(|| panic!("{found_text}"));
    assert!(apart.contains("qs 6.5.0"), "{found_text}");
    assert_eq!(found, Some(1), "{found_text}");
    assert_eq!(partial, Some(2), "{partial_text}");
    let (_, apart) = partial_text.split_once("not the app").unwrap();
    assert!(!apart.contains("none matches a record"), "{partial_text}");
}

#[test]
fn a_list_that_would_set_apart_all_the_app_s_code_is_not_used_by_audit_either() {
    // Deep review R12: the only code is under `examples`, so naming it would leave nothing that is
    // the app's. `sv audit` reads the list as every other command does (ADR-031).
    let (dir, osv) = setup("all-apart", NOT_THE_APP, &[("qs", "6.5.0")]);
    std::fs::write(dir.join("examples/demo/index.js"), "console.log('hi')\n").unwrap();
    let (code, text) = audit(&dir, Some(&osv));
    std::fs::remove_dir_all(dir.parent().unwrap()).ok();

    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains(
            "`[repository] not-the-app` is not used: together they would set apart all 1"
        ),
        "{text}"
    );
    assert!(text.contains("\n2 known vulnerabilities:"), "{text}");
    assert!(!text.contains("counted all the same"), "{text}");
}
