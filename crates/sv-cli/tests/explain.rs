//! `sv explain` at the command line. The explanation's parts are tested beside the code
//! (`src/explain/tests.rs`); this holds the command itself.

use std::process::{Command, Output};

fn sv(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .env_remove("RUST_BACKTRACE")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."))
        .output()
        .expect("sv runs")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_requirement_is_explained_with_its_checks_and_what_to_do() {
    let out = sv(&["explain", "V3.5.1"]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    for part in [
        "V3.5.1 (Web Frontend Security), level 1",
        "What sv checks",
        "What to do",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
    assert!(
        said.contains("probe.cross-site-request-accepted (Signed in)"),
        "{said}"
    );
}

#[test]
fn without_an_id_or_with_an_unknown_one_it_says_what_to_give() {
    let out = sv(&["explain"]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("give the requirement's id"),
        "{}",
        text(&out)
    );
    let out = sv(&["explain", "V99.1.1"]);
    assert!(!out.status.success());
    assert!(
        text(&out).contains("V99.1.1 is not a requirement"),
        "{}",
        text(&out)
    );
}

#[test]
fn an_app_with_no_report_yet_is_told_how_to_make_one() {
    let dir = std::env::temp_dir().join(format!("sv-explain-none-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let out = sv(&["explain", "V3.5.1", "--app", dir.to_str().unwrap()]);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success());
    assert!(text(&out).contains("no report there yet"), "{}", text(&out));
}
