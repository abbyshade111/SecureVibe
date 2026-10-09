//! Two tools folded into others, as the owner decided on 9 October 2026 (backlog 0187, part 10):
//! `stackvet_questions` into `stackvet_check`'s section "questions", and `stackvet_notes_file` into
//! `stackvet_record_answer` called with no id and no answer. The old names still answer, unlisted, and
//! say which tool to call instead.

use super::tests::{call, scratch_app, text};
use super::*;
use std::collections::BTreeSet;

fn ids(questions: &Value) -> BTreeSet<String> {
    questions
        .as_array()
        .expect("a list of questions")
        .iter()
        .map(|q| q["id"].as_str().unwrap().to_owned())
        .collect()
}

/// The check's section "questions", every page of it: its text, and its questions as structured items.
fn questions_section(server: &Server, app: &str) -> (String, Value) {
    let (mut words, mut questions, mut page) = (String::new(), Vec::new(), 1);
    loop {
        let result = call(
            server,
            "stackvet_check",
            json!({ "path": app, "section": "questions", "page": page }),
        );
        assert_eq!(result["isError"], false, "{}", text(&result));
        words.push_str(text(&result));
        let data = &result["structuredContent"];
        questions.extend(data["questions"].as_array().into_iter().flatten().cloned());
        let shown = data["part"]["shown"]
            .as_array()
            .expect("an answer in parts");
        let last = shown.last().unwrap();
        assert_eq!(last["section"], "questions");
        let (at, of) = (
            last["page"].as_u64().unwrap(),
            last["pages"].as_u64().unwrap(),
        );
        if at == of {
            return (words, json!(questions));
        }
        page = at + 1;
    }
}

#[test]
fn the_old_names_give_what_the_tools_they_were_folded_into_give_and_say_so() {
    let root = scratch_app("fold-old-names", "flask-booking");
    let server = Server::new(&root).unwrap();
    let app = json!({ "path": "app" });

    let old = call(&server, "stackvet_questions", app.clone());
    // Every page of the check's section, read through as an AI coding tool would.
    let new = questions_section(&server, "app");
    assert_eq!(old["isError"], false, "{}", text(&old));
    // The setup: the app has questions to ask, so the comparison below compares something.
    let asked = ids(&old["structuredContent"]["questions"]);
    assert!(asked.len() > 10, "{asked:?}");
    // The same questions, every one of them with its own words in the new answer's text.
    assert_eq!(ids(&new.1), asked);
    for id in &asked {
        assert!(
            new.0.contains(&format!(" - {id}: ")),
            "{id} is not asked: {}",
            new.0
        );
    }
    assert!(new.0.contains(sv_report::interview::HOW_TO_ASK));
    assert!(
        text(&old)
            .ends_with("call stackvet_check, with section \"questions\", which gives the same."),
        "{}",
        text(&old)
    );
    assert!(!new.0.contains("going away"), "{}", new.0);

    let old = call(&server, "stackvet_notes_file", app.clone());
    let new = call(&server, "stackvet_record_answer", app.clone());
    assert_eq!(old["isError"], false, "{}", text(&old));
    assert_eq!(new["isError"], false, "{}", text(&new));
    assert!(root.join("app/security-notes.md").is_file());
    assert_eq!(old["structuredContent"], new["structuredContent"]);
    assert!(new["structuredContent"]["asked"].as_u64().unwrap() > 0);
    assert!(
        text(&old).ends_with(
            "call stackvet_record_answer, with no id and no answer, which gives the same."
        ),
        "{}",
        text(&old)
    );
    assert!(!text(&new).contains("going away"), "{}", text(&new));

    // Neither old name is listed.
    let list = server
        .handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"stackvet_check") && names.contains(&"stackvet_record_answer"));
    for gone in ["stackvet_questions", "stackvet_notes_file"] {
        assert!(!names.contains(&gone), "{gone} is still listed: {names:?}");
    }
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn an_answer_with_no_id_or_an_id_with_no_answer_is_refused_and_nothing_is_written() {
    let root = scratch_app("fold-half-answer", "flask-booking");
    let server = Server::new(&root).unwrap();
    let notes = root.join("app/security-notes.md");
    // The setup: no notes file yet, so a write would be seen.
    assert!(!notes.exists());
    for (args, needed) in [
        (json!({ "path": "app", "id": "V6.1.1" }), "answer is needed"),
        (
            json!({ "path": "app", "answer": "The tool's answer, long enough to count as one." }),
            "id is needed",
        ),
    ] {
        let result = call(&server, "stackvet_record_answer", args.clone());
        assert_eq!(result["isError"], true, "{args}: {}", text(&result));
        assert!(text(&result).contains(needed), "{args}: {}", text(&result));
        assert!(!notes.exists(), "{args}: the notes file was written");
    }
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn a_check_too_long_with_its_questions_comes_whole_with_them_counted() {
    // flask-booking's check is about 19,000 characters with its questions counted and about 57,000
    // with all 70 in full: over the budget, so asked for with no section it comes whole, as it did
    // before the fold, rather than in parts. Asked for as a whole, it has them all.
    let examples = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let server = Server::new(&examples).unwrap();
    let first = call(
        &server,
        "stackvet_check",
        json!({ "path": "flask-booking" }),
    );
    let all = call(
        &server,
        "stackvet_check",
        json!({ "path": "flask-booking", "section": "all" }),
    );
    assert!(
        first["structuredContent"].get("part").is_none(),
        "{}",
        text(&first)
    );
    assert!(text(&first).len() <= crate::parts::ANSWER_BUDGET);
    assert!(text(&all).len() > crate::parts::ANSWER_BUDGET, "the setup");
    // Counted, with the way to ask for them, and not given.
    assert!(
        text(&first).contains("stackvet_check again with section \"questions\""),
        "{}",
        text(&first)
    );
    assert!(!text(&first).contains(sv_report::interview::HOW_TO_ASK));
    assert!(first["structuredContent"].get("questions").is_none());
    // All of them in the whole.
    assert!(text(&all).contains(sv_report::interview::HOW_TO_ASK));
    let questions = all["structuredContent"]["questions"].as_array().unwrap();
    assert!(questions.len() > 10, "{}", questions.len());
    for question in questions {
        let id = question["id"].as_str().unwrap();
        assert!(text(&all).contains(&format!(" - {id}: ")), "{id}");
    }
}
