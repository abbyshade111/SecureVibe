//! `sv plan`, end to end: a plan before any code, that writes nothing, credits nothing, and agrees
//! with the report about what applies (ADR-030).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn sv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs")
}

/// A folder holding only a brief: the `tested-notes` example's securevibe.toml.
fn brief_only(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-plan-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    std::fs::copy(manifest, dir.join("securevibe.toml")).unwrap();
    dir
}

/// Every file under `dir`, with its contents.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push((path.clone(), std::fs::read(&path).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// The requirement ids a section of the plan lists, as its `- ID (level N): …` lines give them.
fn ids_in_section(plan: &str, heading: &str) -> BTreeSet<String> {
    let start = plan
        .find(heading)
        .unwrap_or_else(|| panic!("no {heading:?} in the plan"));
    let rest = &plan[start + heading.len()..];
    let section = &rest[..rest.find("\n## ").unwrap_or(rest.len())];
    section
        .lines()
        .filter_map(|l| l.strip_prefix("- "))
        .filter(|l| l.contains(" (level "))
        .filter_map(|l| l.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn a_plan_needs_no_code_writes_nothing_and_credits_nothing() {
    let dir = brief_only("nothing");
    let before = snapshot(&dir);
    let out = sv(&["plan", dir.to_str().unwrap()]);
    let plan = String::from_utf8_lossy(&out.stdout).into_owned();
    let after = snapshot(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(
        out.status.code(),
        Some(0),
        "a plan is not a failed check: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(before, after, "the plan wrote into the app's folder");
    for part in [
        "## 1. The requirements that will apply",
        "## 2. Decide before you build",
        "## 3. The tests worth writing",
        "## 4. What the app must give `sv run`",
        "## 5. The threats the brief raises",
    ] {
        assert!(plan.contains(part), "{part} missing:\n{plan}");
    }
    assert!(plan.contains("It credits nothing"), "{plan}");
    // A plan never says a requirement passed. Its list items quote the requirements', questions',
    // and threats' own wording, which may use the word for other things; `sv`'s own words are every
    // other line, and the lines saying what `sv run` needs.
    let own_words = plan
        .lines()
        .filter(|l| !l.starts_with("- ") || l.starts_with("- [stack."));
    for line in own_words {
        assert!(
            !line.to_lowercase().contains("passed"),
            "a plan never says passed: {line}"
        );
    }
    // The parts have something in them: this brief brings requirements, prompts, and tests.
    assert!(ids_in_section(&plan, "## 1.").len() > 10, "{plan}");
    assert!(ids_in_section(&plan, "## 3.").len() > 10, "{plan}");
    assert!(plan.contains("`design-limits`, shown to work"), "{plan}");
}

#[test]
fn the_plan_and_the_report_agree_about_what_applies_and_the_tests_to_write() {
    let dir = brief_only("agree");
    let plan = String::from_utf8_lossy(&sv(&["plan", dir.to_str().unwrap()]).stdout).into_owned();
    let out = dir.join("report");
    sv(&[
        "report",
        dir.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let report: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    let ids = |key: &str| -> BTreeSet<String> {
        report[key]
            .as_array()
            .unwrap_or_else(|| panic!("no {key} in report.json"))
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect()
    };
    let applies = ids("requirements");
    assert!(
        !applies.is_empty(),
        "the setup: the report lists requirements"
    );
    assert_eq!(ids_in_section(&plan, "## 1."), applies);
    assert_eq!(ids_in_section(&plan, "## 3."), ids("tests_to_write"));
}

#[test]
fn a_folder_with_no_brief_is_told_to_write_one() {
    let dir = std::env::temp_dir().join(format!("sv-plan-none-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let out = sv(&["plan", dir.to_str().unwrap()]);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(
        said.contains("no securevibe.toml") && said.contains("sv init"),
        "{said}"
    );
}
