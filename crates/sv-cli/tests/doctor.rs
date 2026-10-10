//! `sv doctor`, run as a person runs it (backlog 0217, part 3): an answer on every line, nothing
//! written into the folder, and a folder that is not one refused.

use std::process::Command;

#[test]
fn sv_doctor_answers_each_question_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("sv-doctor-run-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("doctor")
        .arg(&dir)
        .output()
        .expect("sv runs");
    let left = std::fs::read_dir(&dir).unwrap().count();
    std::fs::remove_dir_all(&dir).ok();
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(
        run.status.success(),
        "{said}{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(left, 0, "sv doctor wrote into the folder");
    for topic in [
        "sv:",
        "git:",
        "stackvet.toml:",
        "how to start the app:",
        "Docker:",
    ] {
        let answered = said.lines().any(|l| {
            let l = l.trim_start();
            (l.starts_with("ready") || l.starts_with("not ready") || l.starts_with("can't tell"))
                && l.contains(topic)
        });
        assert!(answered, "no answer about {topic}:\n{said}");
    }
    assert!(said.contains("not ready  stackvet.toml:"), "{said}");
}

#[test]
fn a_path_that_is_not_a_folder_is_refused() {
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["doctor", "/no/such/folder"])
        .output()
        .expect("sv runs");
    assert!(!run.status.success());
    assert!(String::from_utf8_lossy(&run.stderr).contains("is not a folder"));
}
