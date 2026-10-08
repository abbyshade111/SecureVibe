//! Pipenv apps, and Python dependency files `sv` does not read, end to end through the binary
//! (deep review H9).
//!
//! Before: an app whose Python half had only `Pipfile` and `Pipfile.lock` had no Python at all as
//! far as `sv` could tell. Django 2.2.0 in the lockfile was never compared with its advisory, and the
//! comparison of the rest of the app was credited as V15.2.1, "checked". A `setup.py` or a
//! `requirements-dev.txt` went the same way. Each test here starts from a locked npm app whose
//! comparison is clean and credited (the control), adds one Python file, and checks what changes.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A locked npm app, lodash past its fix, and a database holding one record about lodash and one
/// about Django below 2.2.1, so both ecosystems are covered.
fn app(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-pipenv-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("osv")).unwrap();
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes/stackvet.toml"),
        dir.join("stackvet.toml"),
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo"},
           "node_modules/lodash":{"version":"4.17.21"}}}"#,
    )
    .unwrap();
    for (id, ecosystem, package, fixed) in [
        ("GHSA-lodash", "npm", "lodash", "4.17.19"),
        ("PYSEC-django", "PyPI", "django", "2.2.1"),
    ] {
        std::fs::write(
            dir.join("osv").join(format!("{id}.json")),
            format!(
                r#"{{"id":"{id}","summary":"A vulnerability.","published":"2019-01-01T00:00:00Z",
                    "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{package}"}},
                    "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"{fixed}"}}]}}]}}]}}"#
            ),
        )
        .unwrap();
    }
    dir
}

fn write(dir: &Path, path: &str, text: &str) {
    let path = dir.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

const PIPFILE: &str = "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\n\
                       name = \"pypi\"\n\n[packages]\ndjango = \"*\"\n\n[dev-packages]\n\
                       pytest = \"*\"\n\n[requires]\npython_version = \"3.11\"\n";

/// A `Pipfile.lock` holding this Django, and pytest among the development packages.
fn pipfile_lock(django: &str) -> String {
    format!(
        r#"{{"_meta": {{"hash": {{"sha256": "0"}}, "pipfile-spec": 6, "requires": {{"python_version": "3.11"}},
             "sources": [{{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}}]}},
            "default": {{"django": {{"hashes": ["sha256:0"], "index": "pypi", "version": "=={django}"}}}},
            "develop": {{"pytest": {{"hashes": ["sha256:0"], "index": "pypi", "version": "==8.0.0"}}}}}}"#
    )
}

fn audit(dir: &Path) -> (Option<i32>, String) {
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

fn report(dir: &Path) -> Value {
    let out = dir.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--advisories",
            dir.join("osv").to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "sv report failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let json = std::fs::read_to_string(out.join("report.json")).unwrap();
    // Gone before the next run, so it is never read back as part of the app.
    std::fs::remove_dir_all(&out).ok();
    serde_json::from_str(&json).unwrap()
}

/// The status the report gives a requirement.
fn status(report: &Value, id: &str) -> String {
    fn walk<'a>(v: &'a Value, id: &str) -> Option<&'a str> {
        match v {
            Value::Object(m) => {
                if m.get("id").and_then(Value::as_str) == Some(id)
                    && let Some(s) = m.get("status").and_then(Value::as_str)
                {
                    return Some(s);
                }
                m.values().find_map(|x| walk(x, id))
            }
            Value::Array(a) => a.iter().find_map(|x| walk(x, id)),
            _ => None,
        }
    }
    walk(report, id)
        .unwrap_or_else(|| panic!("{id} is not in the report"))
        .to_owned()
}

fn gaps(report: &Value) -> Vec<(String, String)> {
    report["gaps"]
        .as_array()
        .expect("the report has gaps")
        .iter()
        .map(|g| {
            (
                g["what"].as_str().unwrap_or_default().to_owned(),
                g["why"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect()
}

fn advisory_findings(report: &Value) -> Vec<String> {
    report["findings"]
        .as_array()
        .expect("the report lists its findings")
        .iter()
        .filter_map(|f| f["rule_id"].as_str())
        .filter(|id| id.starts_with("advisory."))
        .map(str::to_owned)
        .collect()
}

#[test]
fn django_in_a_pipfile_lock_is_compared_and_found() {
    let dir = app("vulnerable");
    // The control: the npm half alone is clean and credited.
    let (code, said) = audit(&dir);
    assert_eq!(code, Some(0), "the control:\n{said}");
    assert_eq!(status(&report(&dir), "V15.2.1"), "checked", "the control");

    write(&dir, "api/Pipfile", PIPFILE);
    write(&dir, "api/Pipfile.lock", &pipfile_lock("2.2.0"));
    let (code, said) = audit(&dir);
    let r = report(&dir);
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        said.contains("Compared 3 packages"),
        "Django and pytest are in the list beside lodash:\n{said}"
    );
    assert!(said.contains("PYSEC-django"), "{said}");
    assert_ne!(
        code,
        Some(0),
        "a known vulnerability is not a clean audit:\n{said}"
    );
    assert_eq!(advisory_findings(&r), ["advisory.PYSEC-django"]);
    assert_ne!(status(&r, "V15.2.1"), "checked");
}

#[test]
fn django_in_a_pipfile_lock_with_no_pipfile_is_compared_and_found() {
    // `pipenv sync` installs from `Pipfile.lock` alone, and an app can be shipped with only that.
    // Before, with no `Pipfile` beside it, nothing found it: Django 2.2.0 was never compared, and
    // the npm half's clean comparison was credited as covering the app.
    let dir = app("lock-alone");
    let (code, said) = audit(&dir);
    assert_eq!(code, Some(0), "the control:\n{said}");
    assert_eq!(status(&report(&dir), "V15.2.1"), "checked", "the control");

    write(&dir, "api/Pipfile.lock", &pipfile_lock("2.2.0"));
    let (code, said) = audit(&dir);
    let r = report(&dir);
    std::fs::remove_dir_all(&dir).ok();

    assert!(
        said.contains("Compared 3 packages"),
        "Django and pytest are in the list beside lodash:\n{said}"
    );
    assert!(said.contains("PYSEC-django"), "{said}");
    assert_ne!(
        code,
        Some(0),
        "a known vulnerability is not a clean audit:\n{said}"
    );
    assert_eq!(advisory_findings(&r), ["advisory.PYSEC-django"]);
    assert_ne!(status(&r, "V15.2.1"), "checked");
}

#[test]
fn a_pipenv_app_past_the_fix_is_credited() {
    // The guard against over-reaching: a Pipenv app read whole, with nothing affected, is a clean
    // comparison like any other, and a reader that blocked every Pipfile would fail here.
    let dir = app("clean");
    write(&dir, "api/Pipfile", PIPFILE);
    write(&dir, "api/Pipfile.lock", &pipfile_lock("4.2.11"));
    let (code, said) = audit(&dir);
    let r = report(&dir);
    std::fs::remove_dir_all(&dir).ok();

    assert!(said.contains("Compared 3 packages"), "{said}");
    assert_eq!(code, Some(0), "{said}");
    assert_eq!(status(&r, "V15.2.1"), "checked");
}

/// Files to add to the app, each as (path, contents).
type Files<'a> = &'a [(&'a str, &'a str)];

#[test]
fn python_files_sv_cannot_read_stop_the_credit_and_say_why() {
    // Each beside the clean, credited app above: the comparison of what was read finds nothing,
    // and still is not a clean result, because the list leaves these out.
    let cases: &[(&str, Files, &str)] = &[
        (
            "setup",
            &[(
                "worker/setup.py",
                "from setuptools import setup\nsetup(name='worker', install_requires=['django'])\n",
            )],
            "`worker/setup.py` names Python packages",
        ),
        (
            "setup-cfg",
            &[(
                "worker/setup.cfg",
                "[metadata]\nname = worker\n\n[options]\ninstall_requires =\n    django\n",
            )],
            "`worker/setup.cfg` names Python packages",
        ),
        (
            "requirements-dev",
            &[("requirements-dev.txt", "pytest==8.0.0\n")],
            "`requirements-dev.txt` lists Python packages",
        ),
        (
            "pipfile-alone",
            &[("api/Pipfile", PIPFILE)],
            "`api/Pipfile` has no `Pipfile.lock` beside it, and 2 of its packages ask for a range \
             or any version",
        ),
        (
            "pipfile-lock-git",
            &[
                ("api/Pipfile", PIPFILE),
                (
                    "api/Pipfile.lock",
                    r#"{"_meta": {}, "default": {
                        "django": {"version": "==4.2.11"},
                        "toolkit": {"git": "https://example.com/toolkit.git", "ref": "0123abc"}},
                        "develop": {}}"#,
                ),
            ],
            "1 package(s) in `api/Pipfile.lock` give no version",
        ),
    ];
    for (name, files, said) in cases {
        let dir = app(name);
        for (path, text) in *files {
            write(&dir, path, text);
        }
        let (code, out) = audit(&dir);
        let r = report(&dir);
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(code, Some(2), "{name}: not assessed, never clean:\n{out}");
        assert!(
            out.contains(&format!("Not assessed — Python: {said}")),
            "{name}: the audit says which file and why:\n{out}"
        );
        assert_eq!(status(&r, "V15.2.1"), "not-verified", "{name}");
        // Django is listed from the lockfile that has the repository package beside it, so that
        // list is not empty and must not be called empty; in the other cases nothing from Python
        // is listed at all.
        let what = if *name == "pipfile-lock-git" {
            "part of what Python installs"
        } else {
            "everything Python installs"
        };
        let gaps = gaps(&r);
        assert!(
            gaps.iter().any(|(w, why)| w == what && why.contains(said)),
            "{name}: the report says why, under `{what}`: {gaps:?}"
        );
    }
}
