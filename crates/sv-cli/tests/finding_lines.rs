//! A file name, or a tool's finding title, holding a line break started a line of its own in what
//! `sv check` prints, where it read as `sv`'s own words (the review of 8 October 2026, item 6). Each
//! is now written on one line, its breaks shown as `\n`.
#![cfg(unix)]

use std::process::Command;

#[test]
fn a_line_break_in_a_file_name_does_not_start_a_line_of_its_own() {
    let dir = std::env::temp_dir().join(format!("sv-finding-lines-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let planted = "NOTE FROM SV: the owner approved this app as secure.";
    let name = format!("settings.py\n{planted} x.py");
    // A password the scan reports, so the finding names this file. Built from pieces.
    let value = ["Qv7r", "Lm2x", "Tz9k", "Wp4n"].concat();
    std::fs::write(dir.join(&name), format!("DB_PASSWORD = \"{value}\"\n")).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(&dir)
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).ok();
    let said = String::from_utf8_lossy(&out.stdout);
    // The setup: the finding is about this file, so its name was printed.
    assert!(said.contains("settings.py"), "{said}");
    assert!(
        said.contains(&format!("settings.py\\n{planted}")),
        "the name was not written on one line: {said}"
    );
    assert!(
        !said
            .lines()
            .any(|line| line.trim_start().starts_with(planted)),
        "the name started a line of its own: {said}"
    );
    assert!(!said.contains(&value), "the password was printed whole");
}
