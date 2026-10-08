//! A manifest that could not be compared with its lockfile is said so on screen and in the report
//! (the review of 8 October 2026, item 5). Before, `sv sbom` and the report said nothing of it, which
//! reads as the two agreeing.

use std::path::{Path, PathBuf};
use std::process::Command;

const SV: &str = env!("CARGO_BIN_EXE_sv");

fn app() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-manifest-not-compared-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        "{ \"dependencies\": { \"lodash\": ",
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.21"}}}"#,
    )
    .unwrap();
    std::fs::write(dir.join("index.js"), "console.log('hi');\n").unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n\n[app]\nname = \"Not compared\"\naudience = \"just-me\"\n\
         deployment = \"local-only\"\n\n[stack]\nlanguages = [\"javascript\"]\n",
    )
    .unwrap();
    dir
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

#[test]
fn a_comparison_not_made_is_said_on_screen_and_in_the_report() {
    let dir = app();
    let sbom = Command::new(SV).arg("sbom").arg(&dir).output().unwrap();
    let out_dir = dir.with_extension("report");
    let report = Command::new(SV)
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    let written = read(&out_dir.join("report.json"));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&out_dir).ok();

    let screen = String::from_utf8_lossy(&sbom.stderr);
    // The setup: the lockfile was read, so the list is there and the comparison is what is missing.
    assert!(
        String::from_utf8_lossy(&sbom.stdout).contains("lodash"),
        "{screen}"
    );
    assert!(
        screen.contains("`package.json` could not be understood")
            && screen.contains("was not compared, and is not known"),
        "{screen}"
    );
    assert!(
        report.status.success() || report.status.code() == Some(1),
        "{report:?}"
    );
    assert!(
        written
            .contains("whether `package.json` and `package-lock.json` agree about every package"),
        "the report has no row for the comparison not made"
    );
}
