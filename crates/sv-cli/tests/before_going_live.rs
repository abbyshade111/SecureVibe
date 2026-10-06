//! The report's "Before going live" list, end to end: `sv report` on an app securevibe.toml says
//! will be on the internet lists what only its live site can answer, and the same app kept on one
//! computer does not (the `sv probe` item's leftover, 6 October 2026).

use std::path::PathBuf;
use std::process::Command;

fn compliance(deployment: &str) -> String {
    let app =
        std::env::temp_dir().join(format!("sv-live-list-{deployment}-{}", std::process::id()));
    std::fs::remove_dir_all(&app).ok();
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("app.py"), "def hello():\n    return 'hello'\n").unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Live\"\naudience = \"customers\"\n\
             deployment = \"{deployment}\"\n[stack]\nlanguages = [\"python\"]\n"
        ),
    )
    .unwrap();
    let out: PathBuf = app.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    let text = std::fs::read_to_string(out.join("compliance.md")).unwrap_or_default();
    std::fs::remove_dir_all(&app).ok();
    assert!(
        run.status.code().is_some_and(|c| c == 0 || c == 2),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(
        text.contains("## Requirements that apply"),
        "the report was written: {text}"
    );
    text
}

#[test]
fn an_app_on_the_internet_has_a_before_going_live_list_and_one_kept_local_does_not() {
    let internet = compliance("internet");
    assert!(internet.contains("## Before going live"), "{internet}");
    assert!(
        internet.contains("`sv probe https://your-address` asks this."),
        "{internet}"
    );
    let local = compliance("local-only");
    assert!(!local.contains("Before going live"), "{local}");
}
