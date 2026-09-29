//! `report.json`, with each requirement's text written once.
//!
//! The report names a requirement in several lists: the ones that apply, the tests worth writing,
//! the ones that do not apply, the ones nobody has placed, and the ones about how the app is built
//! with an AI coding tool. Written out as it is held, every list carried the requirement's full
//! sentence again, and the tests worth writing repeated 153 sentences the list above them already
//! had. The owner's decision (28 September 2026): the text once, in `requirement_text`, keyed by
//! id, and every list points to it by the id it already carries.
//!
//! Nothing is dropped. Every id in a list that carried a text is a key in `requirement_text`, and
//! a row whose text differs from the one already filed under its id keeps its own. No two lists
//! build their text differently today; the second rule is there so that if one ever does, the
//! difference is kept rather than silently replaced by the first.
//!
//! The same holds for the checks only a person can make. `only_you_can_check` was, entry for entry,
//! a subset of `questions_for_you`: fifty of sixty-two on the Flask example, 27 KB written twice.
//! The owner's decision, the same day: drop the duplicate. `report.json` keeps which questions they
//! are, as `only_you_can_check_ids`, in the list's own order; the entries themselves are in
//! `questions_for_you`. If an entry ever differs from the question of the same id, or has no
//! question, the full list is kept as it was, for the same reason a differing text is.
//!
//! The pages for people (`compliance.md`, `report.html`) are written from the `Report` itself and
//! are not affected. The MCP server's answers are not affected either.

use crate::Report;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The lists whose rows carry an `id` and a `description` that is the requirement's own text,
/// as paths from the top of the report. A path of two names reaches a list inside an object.
pub const LISTS_WITH_TEXT: &[&[&str]] = &[
    &["requirements"],
    &["tests_to_write"],
    &["excluded"],
    &["undecided"],
    &["checklist_above_level"],
    &["ai_process", "lines"],
];

/// The report as `report.json` holds it.
pub fn to_value(report: &Report) -> Value {
    let mut value = serde_json::to_value(report).expect("a report serializes");
    file_text(&mut value);
    only_you_by_id(&mut value);
    value
}

/// Replaces `only_you_can_check` with the ids of its entries, when every entry is the question of
/// the same id in `questions_for_you`, word for word.
fn only_you_by_id(value: &mut Value) {
    let Value::Object(top) = value else {
        return;
    };
    let (Some(Value::Array(only)), Some(Value::Array(questions))) =
        (top.get("only_you_can_check"), top.get("questions_for_you"))
    else {
        return;
    };
    let mut ids = Vec::new();
    for entry in only {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            return;
        };
        if !questions.iter().any(|q| q == entry) {
            return;
        }
        ids.push(Value::String(id.to_owned()));
    }
    top.remove("only_you_can_check");
    top.insert("only_you_can_check_ids".to_owned(), Value::Array(ids));
}

/// Moves each row's `description` into `requirement_text`, under its id, once.
fn file_text(value: &mut Value) {
    let mut text: BTreeMap<String, String> = BTreeMap::new();
    for path in LISTS_WITH_TEXT {
        let Some(rows) = reach(value, path) else {
            continue;
        };
        for row in rows.iter_mut() {
            let Some(row) = row.as_object_mut() else {
                continue;
            };
            let (Some(id), Some(Value::String(description))) = (
                row.get("id").and_then(Value::as_str).map(str::to_owned),
                row.get("description").cloned(),
            ) else {
                continue;
            };
            match text.get(&id) {
                // A different text under the same id: kept on the row, never replaced.
                Some(filed) if *filed != description => {}
                Some(_) => {
                    row.remove("description");
                }
                None => {
                    text.insert(id, description);
                    row.remove("description");
                }
            }
        }
    }
    if let Value::Object(top) = value {
        top.insert(
            "requirement_text".to_owned(),
            Value::Object(
                text.into_iter()
                    .map(|(id, t)| (id, Value::String(t)))
                    .collect::<Map<_, _>>(),
            ),
        );
    }
}

/// `report.json`'s bytes: pretty-printed, and ending in a newline.
pub fn to_string(report: &Report) -> String {
    serde_json::to_string_pretty(&to_value(report)).expect("a JSON value serializes") + "\n"
}

fn reach<'a>(value: &'a mut Value, path: &[&str]) -> Option<&'a mut Vec<Value>> {
    let mut at = value;
    for name in path {
        at = at.get_mut(*name)?;
    }
    at.as_array_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_text_is_filed_once_and_every_row_keeps_its_id() {
        let mut v = json!({
            "requirements": [{"id": "V1.1.1", "description": "one", "status": "not-verified"}],
            "tests_to_write": [{"id": "V1.1.1", "description": "one", "level": 1}],
            "excluded": [{"id": "V2.1.1", "description": "two", "reason": "no forms"}],
            "ai_process": {"lines": [{"id": "AC.1.1", "description": "three"}]},
        });
        file_text(&mut v);
        assert_eq!(
            v["requirement_text"],
            json!({"AC.1.1": "three", "V1.1.1": "one", "V2.1.1": "two"})
        );
        for row in [
            &v["requirements"][0],
            &v["tests_to_write"][0],
            &v["excluded"][0],
            &v["ai_process"]["lines"][0],
        ] {
            assert!(row.get("description").is_none(), "{row}");
            assert!(row["id"].is_string(), "{row}");
        }
        // What the rows carried besides their text is untouched.
        assert_eq!(v["excluded"][0]["reason"], "no forms");
        assert_eq!(v["tests_to_write"][0]["level"], 1);
    }

    #[test]
    fn the_checks_only_you_can_make_are_kept_by_id_when_each_is_a_question() {
        let q = |id: &str, how: &str| json!({"id": id, "title": "t", "how": how});
        let mut v = json!({
            "questions_for_you": [q("V1.1.1", "look"), q("V2.2.2", "ask"), q("V3.3.3", "read")],
            "only_you_can_check": [q("V3.3.3", "read"), q("V1.1.1", "look")],
        });
        only_you_by_id(&mut v);
        assert!(v.get("only_you_can_check").is_none(), "{v}");
        // In the list's own order, which is not the questions' order.
        assert_eq!(v["only_you_can_check_ids"], json!(["V3.3.3", "V1.1.1"]));
        assert_eq!(v["questions_for_you"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn a_check_that_is_not_word_for_word_a_question_keeps_the_whole_list() {
        // An entry that differs, or has no question at all: dropping it would lose what it says.
        for only in [
            json!([{"id": "V1.1.1", "title": "t", "how": "look closer"}]),
            json!([{"id": "V2.2.2", "title": "t", "how": "look"}]),
        ] {
            let mut v = json!({
                "questions_for_you": [{"id": "V1.1.1", "title": "t", "how": "look"}],
                "only_you_can_check": only.clone(),
            });
            only_you_by_id(&mut v);
            assert_eq!(v["only_you_can_check"], only);
            assert!(v.get("only_you_can_check_ids").is_none(), "{v}");
        }
    }

    #[test]
    fn a_row_whose_text_differs_from_the_filed_one_keeps_its_own() {
        // No two lists build their text differently today. If one ever does, the difference must
        // survive: replacing it with the first list's text would say something the row never said.
        let mut v = json!({
            "requirements": [{"id": "V1.1.1", "description": "one"}],
            "undecided": [{"id": "V1.1.1", "description": "one, said differently"}],
        });
        file_text(&mut v);
        assert_eq!(v["requirement_text"]["V1.1.1"], "one");
        assert_eq!(v["undecided"][0]["description"], "one, said differently");
        assert!(v["requirements"][0].get("description").is_none());
    }
}
