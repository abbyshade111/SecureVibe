//! What the app answered reaches `seen.json` with no credential in it (ADR-082, backlog 0229, part 1).

use super::*;
use sv_report::seen::KEPT_CHARS;

fn rules() -> SecretRules {
    SecretRules::load(&crate::secret_rules_path()).expect("sv's secret rules load")
}

/// A key the secrets scan knows, and a session id no rule could know from any other letters,
/// built from pieces so this file holds neither.
fn planted() -> (String, String) {
    let key = ["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb9Xm2Qc"].join("-");
    let session = ["s%3A", "qZ8vT2", "nLw5Rk", "9pXe1H"].concat();
    (key, session)
}

fn request(id: &str, path: &str) -> ProbeRequest {
    ProbeRequest {
        id: id.to_owned(),
        method: "GET".to_owned(),
        path: path.to_owned(),
        headers: Vec::new(),
        body: None,
    }
}

fn response(id: &str, headers: Vec<(&str, String)>, body: String) -> ProbeResponse {
    ProbeResponse {
        id: id.to_owned(),
        status: 500,
        headers: headers
            .into_iter()
            .map(|(n, v)| (n.to_owned(), v))
            .collect(),
        body,
    }
}

/// Every place an answer can carry a credential, each carrying one.
fn answers(key: &str, session: &str) -> (Vec<ProbeRequest>, Vec<ProbeResponse>) {
    let asked = vec![
        request("in-body", "/a"),
        request("in-header", "/b"),
        request("in-cookie", "/c"),
        request("in-authorization", "/d"),
        request("named-in-body", "/e"),
    ];
    let answered = vec![
        response(
            "in-body",
            Vec::new(),
            format!("Traceback (most recent call last):\n  client = Client({key})\nKeyError"),
        ),
        response(
            "in-header",
            vec![("x-debug-key", key.to_owned())],
            String::new(),
        ),
        response(
            "in-cookie",
            vec![(
                "set-cookie",
                format!("sid={session}; Path=/; HttpOnly; SameSite=Lax"),
            )],
            String::new(),
        ),
        response(
            "in-authorization",
            vec![("www-authenticate", format!("Bearer {session}"))],
            String::new(),
        ),
        response(
            "named-in-body",
            Vec::new(),
            format!("{{\"error\": \"bad\", \"session_secret\": \"{session}\"}}"),
        ),
    ];
    (asked, answered)
}

#[test]
fn no_credential_the_app_answered_with_reaches_the_record() {
    let rules = rules();
    let (key, session) = planted();
    // The setup: the scan really knows the key, and the answers really carry both, so their absence
    // below is the record's doing.
    assert!(
        redact_text(&rules, &key).1 >= 1,
        "the planted key is not one the scan knows"
    );
    let (asked, answered) = answers(&key, &session);
    let raw = format!("{answered:?}");
    assert!(raw.contains(&key) && raw.contains(&session), "{raw}");

    let seen = record(&rules, &asked, &answered, &[]);
    assert_eq!(seen.exchanges.len(), asked.len(), "{seen:#?}");
    let kept = serde_json::to_string(&seen).unwrap();
    assert!(!kept.contains(&key), "a key reached the record: {kept}");
    assert!(
        !kept.contains(&session),
        "a session id reached the record: {kept}"
    );
    // Each answer is still there to follow: what went wrong, and what the checks read.
    assert!(kept.contains("KeyError"), "{kept}");
    assert!(
        kept.contains("HttpOnly") && kept.contains("SameSite=Lax"),
        "{kept}"
    );
    assert!(kept.contains("sid=[removed,"), "{kept}");
    assert!(kept.contains("Bearer [removed,"), "{kept}");
    assert!(seen.credentials_removed >= 3, "{seen:#?}");
}

#[test]
fn a_question_with_no_answer_is_said_and_the_record_stops_at_its_most() {
    let rules = rules();
    let mut asked: Vec<ProbeRequest> = (0..MOST_EXCHANGES + 3)
        .map(|i| request(&format!("q{i}"), "/"))
        .collect();
    let mut answered: Vec<ProbeResponse> = asked
        .iter()
        .map(|r| response(&r.id, Vec::new(), "ok".to_owned()))
        .collect();
    asked.push(request("silent", "/s"));
    asked.push(request("limited", "/l"));
    answered.push(response("unasked", Vec::new(), String::new()));
    let seen = record(&rules, &asked, &answered, &["limited (429)".to_owned()]);
    assert_eq!(seen.exchanges.len(), MOST_EXCHANGES);
    assert_eq!(seen.left_out, 3);
    assert_eq!(
        seen.not_answered,
        [
            "silent (no answer)",
            "limited (answered by the app's rate limiter in its place)"
        ]
    );
    // The order asked is the order kept, and an answer to nothing asked is not kept.
    assert_eq!(seen.exchanges[0].id, "q0");
    assert!(seen.exchanges.iter().all(|e| e.id != "unasked"));
}

#[test]
fn a_rate_limited_id_is_matched_whole() {
    let rules = rules();
    let asked = vec![request("home", "/")];
    let seen = record(&rules, &asked, &[], &["home-page (429)".to_owned()]);
    assert_eq!(seen.not_answered, ["home (no answer)"]);
}

#[test]
fn no_credential_a_stand_in_received_reaches_the_record() {
    let rules = rules();
    let (key, _) = planted();
    let received = sv_run::stand_ins::StandIns {
        model: Some(serde_json::json!({
            "seen": [{
                "tag": "ab12",
                "system": format!("You are a helper. Use the key {key} for the search API."),
                "tool_result": format!("{{\"api_key\": \"{key}\"}}"),
                "tools_offered": [format!("search_{key}")],
            }],
            "fetched": [],
        })),
        provider: Some(serde_json::json!({
            "requests": [{"method": "GET", "path": "/authorize", "query": ["state", "code_challenge"]}],
            "left_out": 0,
        })),
        mail: Some(vec![sv_run::stand_ins::Mail {
            to: vec!["sv-a-0a1b2c@example.test".to_owned()],
            subject: format!("Your key is {key}"),
            at: "2026-10-10T03:00:01Z".to_owned(),
        }]),
        unread: vec!["the test sign-in provider"],
    };
    // The setup: the key is in every kind of record.
    assert!(format!("{received:?}").matches(key.as_str()).count() >= 4);
    let mut seen = Seen::default();
    stand_ins(&rules, &received, &mut seen);
    let kept = serde_json::to_string(&seen).unwrap();
    assert!(!kept.contains(&key), "a key reached the record: {kept}");
    assert!(seen.credentials_removed >= 4, "{seen:#?}");
    // What arrived is still there to read.
    for still in [
        "You are a helper.",
        "/authorize",
        "code_challenge",
        "sv-a-0a1b2c@example.test",
        "Your key is",
    ] {
        assert!(kept.contains(still), "{still} is gone: {kept}");
    }
    assert_eq!(seen.stand_ins.not_read, ["the test sign-in provider"]);
}

#[test]
fn a_stand_in_record_is_bounded_and_says_what_was_cut() {
    let rules = rules();
    let long = "a".repeat(KEPT_CHARS + 10);
    let many: Vec<serde_json::Value> = (0..MOST_EXCHANGES + 5)
        .map(|i| serde_json::json!(i))
        .collect();
    let received = sv_run::stand_ins::StandIns {
        model: Some(serde_json::json!({"seen": [{"system": long}], "fetched": many})),
        ..Default::default()
    };
    let mut seen = Seen::default();
    stand_ins(&rules, &received, &mut seen);
    let model = seen.stand_ins.model.as_ref().unwrap();
    let system = model["seen"][0]["system"].as_str().unwrap();
    assert!(
        system.ends_with("… (10 more characters)"),
        "{}",
        &system[system.len() - 40..]
    );
    assert_eq!(model["fetched"].as_array().unwrap().len(), MOST_EXCHANGES);
    // One string cut, and five entries.
    assert_eq!(seen.stand_ins.cut, 6);
}

#[test]
fn no_credential_the_app_logged_reaches_the_record() {
    let rules = rules();
    let (key, _) = planted();
    let asked = sv_check::signed_in::Outcome {
        log_lines: vec![sv_check::logs::KeptLine {
            read_for: "the failed sign-in (V16.3.1, V16.2.1, V16.2.2, V16.2.4)".to_owned(),
            line: format!("2026-10-10T03:00:01Z WARN sign-in failed, upstream key {key}"),
        }],
        log_tail: vec![
            format!("boot with ANTHROPIC_API_KEY={key}"),
            "x".repeat(KEPT_CHARS + 3),
        ],
        ..Default::default()
    };
    // The setup: the key is in both kinds of kept line.
    assert_eq!(format!("{asked:?}").matches(key.as_str()).count(), 2);
    let mut seen = Seen::default();
    app_log(&rules, Some(&asked), &mut seen);
    let kept = serde_json::to_string(&seen).unwrap();
    assert!(!kept.contains(&key), "a key reached the record: {kept}");
    assert!(seen.credentials_removed >= 2, "{seen:#?}");
    assert!(kept.contains("sign-in failed, upstream key"), "{kept}");
    assert_eq!(
        seen.app_log.lines_read[0].read_for,
        asked.log_lines[0].read_for
    );
    assert!(seen.app_log.last_lines[1].ends_with("… (3 more characters)"));
    assert_eq!(seen.app_log.cut, 1);
    // No suite that read the log, nothing kept.
    let mut none = Seen::default();
    app_log(&rules, None, &mut none);
    assert!(none.app_log.is_empty());
}
