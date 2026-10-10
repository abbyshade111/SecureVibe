//! The census of findings beside the census of credits (backlog item 32, step 1): `finding::found`
//! writes each finding a check makes to `SV_CREDIT_LOG` + `.withheld`, and `tools/coverage.py
//! --withheld` lists the checks the suite saw credit and never saw withhold. This test is a binary of
//! its own, so the one variable it sets is read by nothing else.

use std::path::{Path, PathBuf};
use std::process::Command;
use sv_check::{Confidence, Finding, Location, Severity};

fn a_finding(rule: &str) -> Finding {
    Finding {
        evidence: Vec::new(),
        rule_id: rule.into(),
        title: String::new(),
        severity: Severity::Low,
        confidence: Confidence::Medium,
        location: Location {
            file: "app.py".into(),
            line: 1,
        },
        secret: None,
        requirement_ids: Vec::new(),
        cwe: Vec::new(),
        description: String::new(),
        impact: String::new(),
        fix: String::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
    }
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// `tools/coverage.py --withheld` over `credits` and, beside it, `withheld`.
fn report(dir: &Path, credits: &str, withheld: &str) -> String {
    let log = dir.join("census.log");
    std::fs::write(&log, credits).unwrap();
    std::fs::write(dir.join("census.log.withheld"), withheld).unwrap();
    let out = Command::new("python3")
        .arg("-I")
        .arg(repo().join("tools/coverage.py"))
        .arg("--withheld")
        .arg(&log)
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Python on Windows ends each line it prints with "\r\n" (backlog 0120).
    String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n")
}

#[test]
fn a_finding_is_written_down_with_the_place_that_made_it_and_only_the_checks_own_count() {
    let dir = std::env::temp_dir().join(format!("sv-withheld-log-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mine = dir.join("credits.log");
    let ci = std::env::var_os("SV_CREDIT_LOG");
    // SAFETY: the only test in this binary, and no thread of its own has started.
    unsafe { std::env::set_var("SV_CREDIT_LOG", &mine) };
    let line = line!() + 1;
    let f = sv_check::finding::found(a_finding("probe.security-headers"));
    assert_eq!(f.rule_id, "probe.security-headers", "handed back unchanged");
    let written = std::fs::read_to_string(dir.join("credits.log.withheld")).unwrap();
    assert_eq!(
        written,
        format!("probe.security-headers\t{}:{line}\n", file!())
    );
    // A check that withholds without a finding: written down when it gave no credit, and not when it did.
    let none_line = line!() + 1;
    sv_check::verified::unless_credited("probe.clear-site-data", &[]);
    let credited = [sv_check::Verified::new(
        "probe.clear-site-data",
        &["V14.3.1"],
        "a test's own".to_owned(),
    )];
    sv_check::verified::unless_credited("probe.clear-site-data", &credited);
    let written = std::fs::read_to_string(dir.join("credits.log.withheld")).unwrap();
    assert_eq!(
        written,
        format!(
            "probe.security-headers\t{f}:{line}\nprobe.clear-site-data\t{f}:{none_line}\n",
            f = file!()
        ),
        "withheld once, when not credited"
    );
    // And into the suite's own log, when there is one, for the census to leave out: made here, by a test.
    if let Some(ci) = ci {
        unsafe { std::env::set_var("SV_CREDIT_LOG", ci) };
        sv_check::finding::found(a_finding("probe.security-headers"));
    }

    // The report: a credit made by the check, in the code that ships.
    let credit = "probe.security-headers\tV3.4.3\tcrates/sv-check/src/probes.rs:400\n";
    // A finding a test made counts for nothing: the check is still never seen withholding.
    let by_a_test = format!("probe.security-headers\t{}:{line}\n", file!());
    let said = report(&dir, credit, &by_a_test);
    assert!(
        said.contains("1 checks were seen giving credit; 0 of them were also seen withholding it")
            && said.contains("\n  probe.security-headers\n"),
        "{said}"
    );
    // One the check made, in the code that ships, does.
    let by_the_check =
        format!("{by_a_test}probe.security-headers\tcrates/sv-check/src/probes.rs:400\n");
    let said = report(&dir, credit, &by_the_check);
    assert!(
        said.contains("1 of them were also seen withholding it, and 0 never were"),
        "{said}"
    );
    // The gate (ADR-059): `--credits` fails on a check that credited and was never seen withholding.
    let gate = |withheld: &str| {
        std::fs::write(dir.join("census.log"), credit).unwrap();
        std::fs::write(dir.join("census.log.withheld"), withheld).unwrap();
        let out = Command::new("python3")
            .arg("-I")
            .arg(repo().join("tools/coverage.py"))
            .arg("--credits")
            .arg(dir.join("census.log"))
            .output()
            .expect("python3 runs");
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let never = "probe.security-headers gives credit and was never seen withholding it";
    let failed = gate(&by_a_test);
    assert!(failed.contains(never), "{failed}");
    // The control: with the check's own finding, the same gate says nothing of it.
    let passed = gate(&by_the_check);
    assert!(
        !passed.contains(never) && passed.contains("disagree"),
        "the gate still fails, on the other checks this small log never credited: {passed}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
