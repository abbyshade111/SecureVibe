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
    // Gap analysis 4.4: the tests are asked for with the lesson of the first build, that a test names
    // a requirement only where it proves it. The setup: there are tests to write.
    assert!(said.contains("A test naming **"), "{said}");
    assert!(
        said.contains("Name a requirement in a test only where the test proves it"),
        "{said}"
    );
}

#[test]
fn a_feature_with_no_brief_is_refused_naming_those_with_one() {
    let out = sv(&["brief", "examples/flask-booking", "--feature", "bookings"]);
    assert!(!out.status.success());
    let said = text(&out);
    assert!(said.contains("no brief for `bookings`"), "{said}");
    assert!(said.contains("payments"), "{said}");
}

#[test]
fn a_brief_before_securevibe_toml_says_what_waits_for_it_and_gives_the_rest() {
    // A builder asks for the brief before writing the settings file (the delivery test of 6
    // October 2026). An empty folder: no securevibe.toml, no code.
    let dir = std::env::temp_dir().join(format!("sv-brief-none-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let out = sv(&["brief", dir.to_str().unwrap(), "--feature", "ai"]);
    std::fs::remove_dir_all(&dir).ok();
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("(no securevibe.toml yet)"), "{said}");
    assert!(said.contains("Waiting for securevibe.toml"), "{said}");
    // What does not wait: a requirement it can bring, the prompt shown to work, and a setting.
    assert!(said.contains("**C2.1.3**"), "{said}");
    assert!(said.contains("(`ai-feature-guard`)"), "{said}");
    assert!(
        said.contains("## 5. What `sv run` needs in `securevibe.toml`"),
        "{said}"
    );
}
