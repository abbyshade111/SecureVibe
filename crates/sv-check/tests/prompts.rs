//! The prompt library: that it loads, that a prompt said to be tried says what happened, and that
//! the ones shown to work come first. Whether each prompt's requirements are the ones its check's
//! rules cite is held by `tools/coverage.py` (run by `coverage_doc.rs`).

use std::path::PathBuf;
use sv_check::prompts::{Prompts, Status};

fn library() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/prompts.json")
}

/// The library as JSON, changed by `edit`, written to a file of its own.
fn changed(name: &str, edit: impl FnOnce(&mut serde_json::Value)) -> PathBuf {
    let mut data: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(library()).unwrap()).unwrap();
    edit(&mut data);
    let path = std::env::temp_dir().join(format!("sv-prompts-{name}-{}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_string(&data).unwrap()).unwrap();
    path
}

#[test]
fn the_library_loads_with_the_shown_prompts_first() {
    let prompts = Prompts::load(&library()).expect("the library loads");
    let chosen = prompts.select(None);
    assert_eq!(chosen.len(), prompts.prompts.len());
    let first_other = chosen.iter().position(|p| p.status != Status::Shown);
    // The control: there are prompts on both sides of the line.
    assert!(matches!(first_other, Some(i) if i > 0), "{first_other:?}");
    assert!(
        chosen[first_other.unwrap()..]
            .iter()
            .all(|p| p.status != Status::Shown)
    );
}

#[test]
fn the_shown_prompts_come_first_wherever_the_file_puts_them() {
    // The library happens to list them first already, so the order is tested with them moved last.
    let path = changed("shown-last", |d| {
        let list = d["prompts"].as_array_mut().unwrap();
        list.sort_by_key(|p| p["status"] == "shown");
    });
    let loaded = Prompts::load(&path);
    std::fs::remove_file(&path).ok();
    let prompts = loaded.expect("the reordered library loads");
    assert_ne!(prompts.prompts[0].status, Status::Shown, "the setup moved nothing");
    assert_eq!(prompts.select(None)[0].status, Status::Shown);
}

#[test]
fn a_prompt_said_to_be_tried_has_to_say_what_happened() {
    let path = changed("no-result", |d| {
        let tried = d["prompts"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|p| p["status"] == "not-shown")
            .expect("a prompt that was tried");
        tried["tested"] = serde_json::Value::Null;
    });
    let refused = Prompts::load(&path);
    std::fs::remove_file(&path).ok();
    let why = format!("{:#}", refused.expect_err("refused"));
    assert!(why.contains("does not say what happened"), "{why}");
}

#[test]
fn a_prompt_not_tried_cannot_carry_a_result() {
    let path = changed("untested-result", |d| {
        d["prompts"][0]["status"] = "untested".into();
    });
    let refused = Prompts::load(&path);
    std::fs::remove_file(&path).ok();
    let why = format!("{:#}", refused.expect_err("refused"));
    assert!(why.contains("is untested and says"), "{why}");
}

#[test]
fn an_id_used_twice_is_refused() {
    let path = changed("twice", |d| {
        let first = d["prompts"][0].clone();
        d["prompts"].as_array_mut().unwrap().push(first);
    });
    let refused = Prompts::load(&path);
    std::fs::remove_file(&path).ok();
    let why = format!("{:#}", refused.expect_err("refused"));
    assert!(why.contains("used twice"), "{why}");
}
