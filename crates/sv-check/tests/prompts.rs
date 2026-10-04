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
    assert_ne!(
        prompts.prompts[0].status,
        Status::Shown,
        "the setup moved nothing"
    );
    assert_eq!(prompts.select(None)[0].status, Status::Shown);
}

#[test]
fn every_prompt_is_marked_above_its_text_as_shown_or_not_tested() {
    // The library has no prompt left untried, so one is made untried here, to have all three kinds.
    let path = changed("each-kind", |d| {
        let last = d["prompts"].as_array_mut().unwrap().last_mut().unwrap();
        last["status"] = "untested".into();
        last["tested"] = serde_json::Value::Null;
    });
    let loaded = Prompts::load(&path);
    std::fs::remove_file(&path).ok();
    let prompts = loaded.expect("the changed library loads");
    for status in [Status::Shown, Status::NotShown, Status::Untested] {
        assert!(
            prompts.prompts.iter().any(|p| p.status == status),
            "no {status:?} prompt to test"
        );
    }
    let text = prompts.markdown(&prompts.select(None));
    for p in &prompts.prompts {
        let after = text
            .split(&format!("### {}\n\n", p.title))
            .nth(1)
            .unwrap_or_else(|| panic!("{} is not in the text", p.title));
        let mark = match p.status {
            Status::Shown => "**Shown to work.**",
            Status::NotShown => "**Not tested:** tried, and not shown to work.",
            Status::Untested => "**Not tested:** not tried yet.",
        };
        assert!(
            after.starts_with(mark),
            "{} is not marked {mark}:\n{after}",
            p.title
        );
    }
    assert!(text.trim_end().ends_with(prompts.credit.as_str()), "{text}");
}

fn design_library() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/design-prompts.json")
}

#[test]
fn the_design_time_prompts_join_the_library_with_their_own_credit() {
    let one = Prompts::load(&library()).unwrap();
    let both = Prompts::load_all(&[&library(), &design_library()]).expect("both files load");
    assert!(both.prompts.len() > one.prompts.len());
    assert!(
        both.credit.contains("Cloud Security Alliance"),
        "{}",
        both.credit
    );
    assert!(both.credit.contains("Secure by Design"), "{}", both.credit);
    let found: Vec<&str> = both
        .select(Some("SBD-AC-03"))
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(found, ["design-who-may-do-what"]);
    let text = both.markdown(&both.select(Some("SBD-AC-03")));
    assert!(
        text.contains("helps you answer (you still answer each): SBD-AC-03."),
        "{text}"
    );
}

#[test]
fn an_id_in_both_files_is_refused() {
    let path = changed("across", |d| {
        d["prompts"][0]["id"] = "design-limits".into();
    });
    let refused = Prompts::load_all(&[&path, &design_library()]);
    std::fs::remove_file(&path).ok();
    let why = format!("{:#}", refused.expect_err("refused"));
    assert!(why.contains("already used by another file"), "{why}");
}

#[test]
fn a_file_that_does_not_say_where_its_prompts_came_from_is_refused() {
    let path = changed("no-credit", |d| {
        d.as_object_mut().unwrap().remove("credit");
    });
    let refused = Prompts::load_all(&[&path, &design_library()]);
    std::fs::remove_file(&path).ok();
    let why = format!("{:#}", refused.expect_err("refused"));
    assert!(
        why.contains("does not say where its prompts came from"),
        "{why}"
    );
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
