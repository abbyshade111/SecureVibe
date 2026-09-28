//! The report's shape, as the owner decided it on 28 September 2026, through the binary.
//!
//! `report.json` holds each requirement's text once, in `requirement_text`; `compliance.md` counts
//! the requirements chapter by chapter, what applies beside what does not, with the text in an
//! appendix. What these tests hold is that nothing was lost in either: every id can still be looked
//! up, every requirement that applies is still listed, and the chapter counts add up to the report's
//! own totals, so a smaller page never means a smaller truth.

use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

struct Written {
    json: Value,
    compliance: String,
}

fn report_on_the_flask_example(tag: &str) -> Written {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let out = std::env::temp_dir().join(format!("sv-shape-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&out).ok();
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "report",
            app.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let written = Written {
        json: serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap())
            .unwrap(),
        compliance: std::fs::read_to_string(out.join("compliance.md")).unwrap(),
    };
    std::fs::remove_dir_all(&out).ok();
    written
}

/// The rows of every list that used to carry a requirement's text.
fn rows_of<'a>(json: &'a Value, path: &[&str]) -> &'a Vec<Value> {
    let mut at = json;
    for name in path {
        at = &at[*name];
    }
    at.as_array()
        .unwrap_or_else(|| panic!("{path:?} is not a list"))
}

#[test]
fn report_json_holds_each_text_once_and_every_id_can_be_looked_up() {
    let w = report_on_the_flask_example("json");
    let text = w.json["requirement_text"]
        .as_object()
        .expect("requirement_text is in report.json");
    let mut rows_seen = 0;
    for path in sv_report::json::LISTS_WITH_TEXT {
        for row in rows_of(&w.json, path) {
            rows_seen += 1;
            let id = row["id"].as_str().expect("every row keeps its id");
            let filed = text
                .get(id)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{id} in {path:?} has no text to look up"));
            assert!(!filed.trim().is_empty(), "{id} was filed with no words");
            assert!(
                row.get("description").is_none(),
                "{id} in {path:?} still carries its text"
            );
        }
    }
    // Setup, asserted: the lists this test is about are not empty on this app, so the loop above
    // examined something. Each of these carried text before the change.
    for path in [
        &["requirements"][..],
        &["tests_to_write"],
        &["excluded"],
        &["undecided"],
        &["ai_process", "lines"],
    ] {
        assert!(
            !rows_of(&w.json, path).is_empty(),
            "{path:?} is empty on the example"
        );
    }
    // And the table holds exactly the ids the lists name: nothing orphaned, nothing missing.
    let named: std::collections::BTreeSet<&str> = sv_report::json::LISTS_WITH_TEXT
        .iter()
        .flat_map(|p| rows_of(&w.json, p).iter())
        .map(|r| r["id"].as_str().unwrap())
        .collect();
    let filed: std::collections::BTreeSet<&str> = text.keys().map(String::as_str).collect();
    assert_eq!(named, filed);
    assert!(
        rows_seen > filed.len(),
        "some id is named in more than one list"
    );
}

/// The chapter table in compliance.md, as column name to the column's values.
fn chapter_table(compliance: &str) -> BTreeMap<String, Vec<String>> {
    let start = compliance
        .find("| chapter | apply |")
        .expect("the chapter table is in compliance.md");
    let mut lines = compliance[start..].lines();
    let header: Vec<String> = cells(lines.next().unwrap());
    lines.next(); // the |---| row
    let mut columns: BTreeMap<String, Vec<String>> =
        header.iter().map(|h| (h.clone(), Vec::new())).collect();
    for line in lines.take_while(|l| l.starts_with('|')) {
        for (h, v) in header.iter().zip(cells(line)) {
            columns.get_mut(h).unwrap().push(v);
        }
    }
    columns
}

fn cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split(" | ")
        .map(|c| c.trim().trim_matches('*').to_owned())
        .collect()
}

#[test]
fn the_chapter_counts_add_up_to_the_reports_own_totals() {
    let w = report_on_the_flask_example("chapters");
    let table = chapter_table(&w.compliance);
    let sum = |column: &str| -> u64 {
        table
            .get(column)
            .unwrap_or_else(|| panic!("no column {column:?}; the columns are {:?}", table.keys()))
            .iter()
            .map(|v| {
                v.parse::<u64>()
                    .unwrap_or_else(|_| panic!("{column}: {v:?}"))
            })
            .sum()
    };
    let counts = &w.json["counts"];
    let total = |name: &str| counts[name].as_u64().unwrap();
    // Setup, asserted: this app has requirements in every column that matters here, so a column
    // that summed to nothing could not match by accident.
    for name in [
        "applicable",
        "checked",
        "not_verified",
        "not_applicable",
        "not_assessed",
    ] {
        assert!(total(name) > 0, "the example has no {name} requirements");
    }
    assert_eq!(sum("apply"), total("applicable"));
    assert_eq!(sum("a problem found"), total("needs_attention"));
    assert_eq!(sum("checked"), total("checked"));
    assert_eq!(sum("not verified"), total("not_verified"));
    assert_eq!(sum("does not apply"), total("not_applicable"));
    assert_eq!(sum("not placed yet"), total("not_assessed"));
    // Appendix C is one row, named for the appendix rather than for its first section.
    let chapters = &table["chapter"];
    assert!(
        chapters
            .iter()
            .any(|c| c == "AISVS Appendix C: how the app is built with AI"),
        "{chapters:?}"
    );
    assert!(
        !chapters.iter().any(|c| c.starts_with("AC ")),
        "an Appendix C row is titled by one of its sections: {chapters:?}"
    );
    // Each chapter appears once.
    let mut unique = chapters.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        chapters.len(),
        "a chapter is listed twice: {chapters:?}"
    );
}

#[test]
fn every_requirement_that_applies_is_listed_once_by_chapter_and_once_in_the_appendix() {
    let w = report_on_the_flask_example("appendix");
    let section = |from: &str| -> &str {
        let start = w
            .compliance
            .find(from)
            .unwrap_or_else(|| panic!("no {from:?} in compliance.md"));
        let rest = &w.compliance[start + from.len()..];
        &rest[..rest.find("\n## ").unwrap_or(rest.len())]
    };
    let by_chapter = section("## Requirements that apply\n");
    let appendix = section("## Appendix: what each requirement asks for\n");
    let text = w.json["requirement_text"].as_object().unwrap();
    let applies = w.json["requirements"].as_array().unwrap();
    assert!(
        !applies.is_empty(),
        "the example has requirements that apply"
    );
    for r in applies {
        let id = r["id"].as_str().unwrap();
        let row = format!("| {id} |");
        assert_eq!(
            by_chapter.matches(&row).count(),
            1,
            "{id} under the chapters"
        );
        assert_eq!(appendix.matches(&row).count(), 1, "{id} in the appendix");
        // The appendix row carries the requirement's own words: the start of its text, cut before
        // anything the table would have escaped.
        let words: String = text[id]
            .as_str()
            .unwrap()
            .chars()
            .take_while(|c| *c != '|' && *c != '\\')
            .take(40)
            .collect();
        let at = appendix.find(&row).unwrap();
        let line = appendix[at..].lines().next().unwrap();
        assert!(
            line.contains(&words),
            "{id}'s appendix row lacks its text: {line}"
        );
    }
    // And the chapter lists no longer carry the text; the appendix is where it is.
    let sample = text[applies[0]["id"].as_str().unwrap()].as_str().unwrap();
    let words: String = sample.chars().take(40).collect();
    assert!(
        !by_chapter.contains(&words),
        "a requirement's text is still in the chapter lists"
    );
}
