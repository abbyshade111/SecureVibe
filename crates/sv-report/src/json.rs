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
    value
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
