//! A panic in `sv` ends as a failure of `sv`, with 3 and words a person can act on, not Rust's own
//! line and 101 (backlog 226, part 1, item 5). The panic is asked for with a switch only a debug
//! build has.

use std::process::Command;

#[test]
fn a_panic_exits_3_and_says_it_is_sv_s_fault_and_nothing_was_assessed() {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("--version")
        .env("SV_PANIC_FOR_TEST", "1")
        .env_remove("RUST_BACKTRACE")
        .output()
        .unwrap();
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{said}");
    assert!(
        said.contains("sv itself failed: a fault in sv, not in your app"),
        "{said}"
    );
    assert!(said.contains("Nothing was assessed"), "{said}");
    assert!(
        said.contains("src/main.rs:"),
        "where it failed is not said: {said}"
    );
    assert!(
        !said.contains("thread 'main' panicked"),
        "Rust's own line too: {said}"
    );
}
