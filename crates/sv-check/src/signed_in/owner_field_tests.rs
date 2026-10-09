//! A record's owner taken from the request that creates it (the gap analysis of 7 October 2026,
//! finding 13(a)): found when the first user is shown the second user's record as theirs, and only
//! then, and said to be unasked when the record names no owner or the first user sees the second
//! user's records anyway.

use super::fake_app::*;
use super::*;

fn naming_owner(flaws: Flaws) -> Flaws {
    Flaws {
        record_names_owner: true,
        ..flaws
    }
}

fn unasked(o: &Outcome) -> Vec<&str> {
    o.not_assessed
        .iter()
        .filter(|(id, _)| id == "V15.3.3")
        .map(|(_, why)| why.as_str())
        .collect()
}

#[test]
fn an_owner_taken_from_the_request_is_found() {
    let o = run_against(
        naming_owner(Flaws {
            owner_from_request: true,
            ..Default::default()
        }),
        &users(),
    );
    let f = o
        .findings
        .iter()
        .find(|f| f.rule_id == OWNER_FIELD.rule_id)
        .unwrap_or_else(|| panic!("{:?}", o.steps));
    assert_eq!(f.title, "A record can be put into another user's account");
    assert_eq!(f.requirement_ids, ["V15.3.3", "V8.2.3", "V8.2.2"]);
    assert!(f.description.contains("`user_id`"), "{}", f.description);
    assert!(unasked(&o).is_empty(), "{:?}", unasked(&o));
    // The other user's-data checks are not set off by it: the first user's own record stayed theirs.
    assert!(
        !rule_ids(&o).contains(&OTHER_USERS_DATA.rule_id),
        "{:?}",
        rule_ids(&o)
    );
}

#[test]
fn an_owner_set_on_the_server_is_not_reported_and_credits_nothing() {
    let o = run_against(naming_owner(Flaws::default()), &users());
    assert!(!rule_ids(&o).contains(&OWNER_FIELD.rule_id));
    assert!(!verified_ids(&o).contains(&OWNER_FIELD.rule_id));
    assert!(unasked(&o).is_empty(), "{:?}", unasked(&o));
    // The setup: both records were made, the one with the field accepted like the plain one, so
    // the field reached an app that ignored it.
    assert!(
        o.steps.iter().any(|s| s
            == "B created a record with `user_id` set to the value A's own record names as its \
                owner, and one without it (303, 303)"),
        "{:?}",
        o.steps
    );
}

#[test]
fn a_record_that_names_no_owner_leaves_it_unasked() {
    // The flaw is there, and nothing names a value to send it.
    let o = run_against(
        Flaws {
            owner_from_request: true,
            ..Default::default()
        },
        &users(),
    );
    assert!(!rule_ids(&o).contains(&OWNER_FIELD.rule_id));
    let why = unasked(&o);
    assert_eq!(why.len(), 1, "{why:?}");
    assert!(why[0].contains("names no owner"), "{}", why[0]);
    assert!(
        !o.steps
            .iter()
            .any(|s| s.starts_with("B created a record with"))
    );
}

#[test]
fn a_first_user_shown_the_second_users_records_anyway_proves_nothing() {
    // Any signed-in user reads any record, so the first user is shown the second user's plain record
    // too, and being shown the one with the field says nothing about the field.
    let o = run_against(
        naming_owner(Flaws {
            owner_from_request: true,
            idor: true,
            ..Default::default()
        }),
        &users(),
    );
    assert!(!rule_ids(&o).contains(&OWNER_FIELD.rule_id));
    let why = unasked(&o);
    assert_eq!(why.len(), 1, "{why:?}");
    assert!(why[0].contains("without an owner field too"), "{}", why[0]);
    // The control is what stopped it: the reading flaw itself is still found.
    assert!(rule_ids(&o).contains(&OTHER_USERS_DATA.rule_id));
}

#[test]
fn the_owner_a_record_names_is_read_as_json_wherever_it_is() {
    assert_eq!(
        named_owner(r#"{"id":3,"user_id":7,"text":"x"}"#),
        Some(("user_id", serde_json::json!(7)))
    );
    assert_eq!(
        named_owner(r#"<script>const n={"ownerId" : "u-41"}</script>"#),
        Some(("ownerId", serde_json::json!("u-41")))
    );
    // An empty value is no owner, and the next field is looked for.
    assert_eq!(
        named_owner(r#"{"user_id":"","created_by":"ann"}"#),
        Some(("created_by", serde_json::json!("ann")))
    );
    // Only the whole name: `owner_name` is not `owner`, and a field that is an object is not read.
    assert_eq!(
        named_owner(r#"{"owner_name":"Ann","owner":{"id":1}}"#),
        None
    );
    assert_eq!(named_owner("<p>Owner: Ann</p>"), None);
}

fn sent(content_type: &str, body: &str) -> ProbeRequest {
    ProbeRequest {
        id: "t".into(),
        method: "POST".into(),
        path: "/notes".into(),
        headers: vec![("Content-Type".into(), content_type.into())],
        body: Some(body.as_bytes().to_vec()),
    }
}

fn body(r: &ProbeRequest) -> String {
    String::from_utf8(r.body.clone().unwrap()).unwrap()
}

#[test]
fn the_field_goes_into_the_body_the_request_already_has() {
    let json = with_field(
        sent("application/json", r#"{"text":"hi"}"#),
        "user_id",
        &serde_json::json!(7),
    )
    .unwrap();
    // A number stays a number, so an app that checks the type still takes it.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body(&json)).unwrap(),
        serde_json::json!({"text": "hi", "user_id": 7})
    );
    let form = with_field(
        sent("application/x-www-form-urlencoded", "text=hi"),
        "owner",
        &serde_json::json!("a b@x"),
    )
    .unwrap();
    assert_eq!(body(&form), "text=hi&owner=a+b%40x");
    assert!(
        with_field(
            sent("multipart/form-data; boundary=x", ""),
            "user_id",
            &serde_json::json!(7)
        )
        .is_none()
    );
}
