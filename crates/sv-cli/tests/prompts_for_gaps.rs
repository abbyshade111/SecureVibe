//! `sv prompts --app`, end to end: a real `sv report` on a small app, then the prompts for what
//! that report shows unproven. A test with a hand-written report would not show the real report's
//! shape is the one read.

use std::process::Command;

#[test]
fn the_prompts_offered_are_for_requirements_the_real_report_shows_unproven() {
    let app = std::env::temp_dir().join(format!("sv-prompts-gaps-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), "def hello():\n    return 'hello'\n").unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Gaps\"\naudience = \"customers\"\n\
         deployment = \"internet\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    let sv = env!("CARGO_BIN_EXE_sv");
    let before = Command::new(sv)
        .args(["prompts", "--app"])
        .arg(&app)
        .output()
        .expect("sv runs");
    let report = Command::new(sv)
        .arg("report")
        .arg(&app)
        .output()
        .expect("sv runs");
    let after = Command::new(sv)
        .args(["prompts", "--app"])
        .arg(&app)
        .output()
        .expect("sv runs");
    let both = Command::new(sv)
        .args(["prompts", "--requirement", "V3.4.3", "--app"])
        .arg(&app)
        .output()
        .expect("sv runs");
    let json: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(app.join("securevibe-report/report.json")).unwrap_or_default(),
    )
    .unwrap_or_default();
    std::fs::remove_dir_all(&app).ok();

    // Before any report, it says to make one rather than offering anything.
    assert!(!before.status.success());
    let said = String::from_utf8_lossy(&before.stderr);
    assert!(said.contains("Make one first"), "{said}");

    assert!(
        report.status.code().is_some_and(|c| c == 0 || c == 2),
        "{}",
        String::from_utf8_lossy(&report.stderr)
    );
    // A single requirement and an app at once is refused, not quietly answered with one of them.
    assert!(!both.status.success());
    let said = String::from_utf8_lossy(&both.stderr);
    assert!(said.contains("not both"), "{said}");

    let text = String::from_utf8_lossy(&after.stdout);
    assert!(
        after.status.success(),
        "{}",
        String::from_utf8_lossy(&after.stderr)
    );
    assert!(
        text.starts_with("## Prompts for what the app has not yet shown"),
        "{text}"
    );
    // An app on the internet that was never run has the security headers unproven, and the prompt
    // for them is offered, saying which requirement it is for and what the report said of it.
    let status_of = |id: &str| {
        json["requirements"]
            .as_array()
            .and_then(|all| all.iter().find(|r| r["id"] == id))
            .and_then(|r| r["status"].as_str())
            .map(str::to_owned)
    };
    assert_eq!(
        status_of("V3.4.3").as_deref(),
        Some("not-verified"),
        "{json}"
    );
    assert!(
        text.contains("### Send the security headers on every page"),
        "{text}"
    );
    assert!(text.contains("V3.4.3 (nothing shown yet)"), "{text}");
    // Every requirement a prompt is offered for really is unproven in that report.
    for line in text.lines().filter(|l| l.starts_with("For: ")) {
        for id in line
            .trim_start_matches("For: ")
            .trim_end_matches('.')
            .split(", ")
            .map(|part| part.split(' ').next().unwrap())
        {
            let status = status_of(id).unwrap_or_default();
            assert!(
                ["needs-attention", "not-verified", "attested", "stated"]
                    .contains(&status.as_str()),
                "{id} is {status} in the report, and a prompt was offered for it"
            );
        }
    }
}
