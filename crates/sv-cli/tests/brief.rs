//! `sv brief`: one feature's brief, before it is built, at the command line. The brief's parts are
//! tested beside the code (`brief.rs`) and through the MCP server; this holds the command itself.

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
fn with_no_feature_named_it_lists_the_features() {
    let out = sv(&["brief", "examples/flask-booking"]);
    assert!(out.status.success(), "{}", text(&out));
    let said = text(&out);
    for feature in [
        "sign-in", "admin", "uploads", "payments", "email", "ai", "fetch",
    ] {
        assert!(said.contains(&format!("  {feature} ")), "{feature}: {said}");
    }
}

#[test]
fn a_brief_has_its_five_parts_and_credits_nothing() {
    let out = sv(&["brief", "examples/flask-booking", "--feature", "sign-in"]);
    assert!(out.status.success(), "{}", text(&out));
    let said = text(&out);
    for part in [
        "## 1. The requirements it brings",
        "## 2. Decide first",
        "## 3. Rules to code by",
        "## 4. Tests to write",
        "## 5. What `sv run` needs in `securevibe.toml`",
    ] {
        assert!(said.contains(part), "{part}: {said}");
    }
    assert!(said.contains("A brief credits nothing"), "{said}");
    // A sign-in requirement, the sign-in prompt in full, and the login setting from the spec.
    assert!(said.contains("**V6.2.1**"), "{said}");
    assert!(said.contains("(`design-sign-in`"), "{said}");
    assert!(said.contains("# login  = { path = \"/login\""), "{said}");
}

#[test]
fn a_feature_with_no_brief_is_refused_naming_those_with_one() {
    let out = sv(&["brief", "examples/flask-booking", "--feature", "bookings"]);
    assert!(!out.status.success());
    let said = text(&out);
    assert!(said.contains("no brief for `bookings`"), "{said}");
    assert!(said.contains("payments"), "{said}");
}
