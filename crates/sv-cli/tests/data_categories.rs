//! A data category `sv` does not know, end to end: the report names it and holds the app to
//! level 2 (the documentation review of 6 October 2026, item 7; ADR-024, Later).

use std::process::Command;

#[test]
fn a_misspelled_data_category_is_named_in_the_report() {
    let app = std::env::temp_dir().join(format!("sv-data-categories-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), "def home():\n    return 'hello'\n").unwrap();
    let report = |categories: &str| -> (String, serde_json::Value) {
        std::fs::write(
            app.join("securevibe.toml"),
            format!(
                "manifest-version = 1\n[app]\nname = \"Notes\"\naudience = \"just-me\"\n\
                 [stack]\nlanguages = [\"python\"]\n[data]\ncategories = {categories}\n"
            ),
        )
        .unwrap();
        let out = app.join("report");
        std::fs::remove_dir_all(&out).ok();
        let run = Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(["report"])
            .arg(&app)
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
            serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap())
                .unwrap();
        (
            std::fs::read_to_string(out.join("compliance.md")).unwrap(),
            json,
        )
    };
    let (misspelled, json) = report("[\"contact\", \"helth\"]");
    let (spelled, right) = report("[\"contact\"]");
    std::fs::remove_dir_all(&app).ok();
    assert!(misspelled.contains("`helth`"), "{misspelled}");
    assert_eq!(json["target_level"], 2, "{}", json["target_level"]);
    // The control: the same list spelled as listed is level 1, and nothing is said.
    assert!(!spelled.contains("not among the names"), "{spelled}");
    assert_eq!(right["target_level"], 1, "{}", right["target_level"]);
}
