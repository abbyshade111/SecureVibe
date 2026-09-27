//! Known vulnerabilities in `sv report`, end to end through the binary.
//!
//! Until 26 September 2026 the report never ran the advisory comparison, and said nothing about
//! it: a report silent about known vulnerabilities reads as one that found none. These pin both
//! halves — what the report says with a database, and that it says so when there is none.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

const HIGH: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";

/// An npm app shipping lodash 4.17.15, with a 30-day time frame for high-rated vulnerabilities.
fn app(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-report-adv-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("osv")).unwrap();
    let manifest = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/tested-notes/securevibe.toml"),
    )
    .unwrap();
    assert!(
        !manifest.contains("[policy]"),
        "the example grew a policy; merge rather than append"
    );
    std::fs::write(
        dir.join("securevibe.toml"),
        format!("{manifest}\n[policy]\nfix-within-days = {{ high = 30 }}\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo"},
           "node_modules/lodash":{"version":"4.17.15"}}}"#,
    )
    .unwrap();
    dir
}

/// One advisory record in the app's `osv` folder.
fn advisory(dir: &Path, id: &str, ecosystem: &str, package: &str, published: &str) {
    std::fs::write(
        dir.join("osv").join(format!("{id}.json")),
        format!(
            r#"{{"id":"{id}","summary":"A vulnerability.","published":"{published}",
                "severity":[{{"type":"CVSS_V3","score":"{HIGH}"}}],
                "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{package}"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"99"}}]}}]}}]}}"#
        ),
    )
    .unwrap();
}

fn report(dir: &Path, with_database: bool) -> Value {
    let out = dir.join("report");
    let mut args = vec![
        "report".to_owned(),
        dir.to_str().unwrap().to_owned(),
        "--out".to_owned(),
        out.to_str().unwrap().to_owned(),
    ];
    if with_database {
        args.push("--advisories".to_owned());
        args.push(dir.join("osv").to_str().unwrap().to_owned());
    }
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(&args)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "sv report failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap()
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

fn advisory_findings(report: &Value) -> Vec<(String, Vec<String>)> {
    report["findings"]
        .as_array()
        .expect("the report lists its findings")
        .iter()
        .filter(|f| {
            f["rule_id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("advisory.")
        })
        .map(|f| {
            (
                f["rule_id"].as_str().unwrap().to_owned(),
                f["requirement_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|r| r.as_str().unwrap().to_owned())
                    .collect(),
            )
        })
        .collect()
}

fn gap_about_vulnerabilities(report: &Value) -> Option<String> {
    report["gaps"].as_array()?.iter().find_map(|g| {
        let what = g["what"].as_str()?;
        what.contains("known vulnerabilit").then(|| what.to_owned())
    })
}

#[test]
fn with_no_database_the_report_says_it_compared_nothing() {
    let dir = app("none");
    advisory(&dir, "GHSA-late", "npm", "lodash", "2020-01-01T00:00:00Z");
    let r = report(&dir, false);
    assert!(gap_about_vulnerabilities(&r).is_some(), "silent about it");
    assert!(advisory_findings(&r).is_empty());
    assert_eq!(status(&r, "V15.2.1"), "not-verified");
}

#[test]
fn a_late_vulnerability_needs_attention_and_one_inside_its_time_frame_is_still_listed() {
    let dir = app("late");
    advisory(&dir, "GHSA-late", "npm", "lodash", "2020-01-01T00:00:00Z");
    advisory(&dir, "GHSA-inside", "npm", "lodash", "2099-01-01T00:00:00Z");
    let r = report(&dir, true);
    let mut found = advisory_findings(&r);
    found.sort();
    assert_eq!(
        found,
        [
            ("advisory.GHSA-inside".to_owned(), vec![]),
            ("advisory.GHSA-late".to_owned(), vec!["V15.2.1".to_owned()]),
        ]
    );
    assert_eq!(status(&r, "V15.2.1"), "needs-attention");
}

#[test]
fn a_vulnerability_inside_its_time_frame_is_not_a_clean_result_in_the_report_either() {
    // The advisory check holds this already. The report is a second place it could go wrong: a
    // finding that cites nothing leaves nothing marking V15.2.1, and it must not come out checked.
    let dir = app("inside");
    advisory(&dir, "GHSA-inside", "npm", "lodash", "2099-01-01T00:00:00Z");
    let r = report(&dir, true);
    assert_eq!(
        advisory_findings(&r).len(),
        1,
        "the setup: one vulnerability, inside its time frame"
    );
    assert_eq!(status(&r, "V15.2.1"), "not-verified");
}

#[test]
fn a_clean_comparison_checks_v15_2_1() {
    let dir = app("clean");
    advisory(
        &dir,
        "GHSA-other",
        "npm",
        "left-pad",
        "2020-01-01T00:00:00Z",
    );
    let r = report(&dir, true);
    assert!(advisory_findings(&r).is_empty());
    assert!(
        gap_about_vulnerabilities(&r).is_none(),
        "{:?}",
        gap_about_vulnerabilities(&r)
    );
    assert_eq!(status(&r, "V15.2.1"), "checked");
}

#[test]
fn a_database_about_another_ecosystem_is_a_gap_and_not_a_clean_result() {
    let dir = app("elsewhere");
    advisory(&dir, "PYSEC-other", "PyPI", "flask", "2020-01-01T00:00:00Z");
    let r = report(&dir, true);
    let gap =
        gap_about_vulnerabilities(&r).expect("npm was never compared, and it does not say so");
    assert!(gap.contains("npm"), "{gap}");
    assert_eq!(status(&r, "V15.2.1"), "not-verified");
}
