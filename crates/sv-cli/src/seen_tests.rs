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

fn examined_with(output: Option<String>) -> sv_report::Examined {
    sv_report::Examined::not_run("semgrep.", "a test").with_tool(Some(
        sv_check::adapters::ToolRun {
            program: "Semgrep".to_owned(),
            output,
            ..Default::default()
        },
    ))
}

#[test]
fn no_credential_a_tool_quoted_reaches_the_kept_tool_output() {
    let rules = rules();
    let (key, _) = planted();
    let sarif = format!(
        r#"{{"runs":[{{"results":[{{"message":{{"text":"hard-coded key"}},"snippet":"client = Client(\"{key}\")"}}]}}]}}"#
    );
    // The setup: the key is in what the tool wrote.
    assert!(sarif.contains(&key));
    let examined = vec![
        examined_with(Some(sarif)),
        // A tool that wrote nothing, and one of sv's own checks: neither has a report to keep.
        examined_with(None),
        sv_report::Examined::not_run("config.", "a test"),
    ];
    let mut seen = Seen::default();
    tool_output(&rules, &examined, &mut seen);
    assert_eq!(seen.tool_output.len(), 1, "{seen:#?}");
    let kept = &seen.tool_output[0];
    assert!(
        !kept.report.contains(&key),
        "a key reached the record: {}",
        kept.report
    );
    assert!(kept.report.contains("hard-coded key"), "{}", kept.report);
    assert_eq!(
        (kept.program.as_str(), kept.rules.as_str()),
        ("Semgrep", "semgrep.")
    );
    assert_eq!(kept.cut_chars, 0);
    assert!(seen.credentials_removed >= 1);
}

#[test]
fn a_tool_report_past_its_most_is_cut_and_says_by_how_much() {
    let rules = rules();
    let long = "a".repeat(sv_report::seen::MOST_TOOL_CHARS + 7);
    let mut seen = Seen::default();
    tool_output(&rules, &[examined_with(Some(long))], &mut seen);
    assert_eq!(seen.tool_output[0].cut_chars, 7);
    assert_eq!(
        seen.tool_output[0].report.chars().count(),
        sv_report::seen::MOST_TOOL_CHARS
    );
}

#[test]
fn no_credential_a_signed_in_answer_carries_reaches_the_record() {
    let rules = rules();
    let (key, session) = planted();
    let asked = sv_check::signed_in::Outcome {
        exchanges: vec![
            sv_check::signed_in::recording::Recorded {
                method: "GET".to_owned(),
                path: "/account".to_owned(),
                status: Some(200),
                headers: vec![
                    (
                        "set-cookie".to_owned(),
                        format!("sid={session}; Path=/; HttpOnly"),
                    ),
                    ("x-debug-key".to_owned(), key.clone()),
                ],
                body: format!("<p>your key is {key}</p>"),
            },
            // A question no answer came to: counted, not kept.
            sv_check::signed_in::recording::Recorded {
                method: "GET".to_owned(),
                path: "/silent".to_owned(),
                status: None,
                headers: Vec::new(),
                body: String::new(),
            },
        ],
        ..Default::default()
    };
    // The setup: the key and the session are in what the signed-in suite was answered with.
    assert!(format!("{asked:?}").matches(key.as_str()).count() >= 2);
    let mut seen = Seen::default();
    signed_in(&rules, Some(&asked), &mut seen);
    let kept = serde_json::to_string(&seen).unwrap();
    assert!(!kept.contains(&key), "a key reached the record: {kept}");
    assert!(
        !kept.contains(&session),
        "a session reached the record: {kept}"
    );
    assert_eq!(seen.signed_in.len(), 1, "{seen:#?}");
    assert_eq!(seen.signed_in[0].id, "signed-in-1");
    assert_eq!(seen.signed_in[0].status, 200);
    assert!(
        kept.contains("trace=") || kept.contains("sid=[removed,"),
        "{kept}"
    );
    assert_eq!(seen.signed_in_unanswered, 1);
    assert!(seen.credentials_removed >= 2, "{seen:#?}");
    // No signed-in suite ran, nothing kept.
    let mut none = Seen::default();
    signed_in(&rules, None, &mut none);
    assert!(none.signed_in.is_empty());
}

#[test]
fn a_test_secret_marker_in_an_address_is_left_whole_not_cut_as_a_password() {
    let rules = rules();
    // What sv-run leaves where a test password was in the address: the marker after `password=`.
    let address = format!("/login?email=sv-a%40example.test&password={TEST_SECRET}&next=/account");
    let (out, _) = redact_around_markers(&rules, &address);
    assert_eq!(out, address, "the marker was cut: {out}");
    // A real password in the same place is still cut.
    let (key, _) = planted();
    let (out, n) = redact_around_markers(&rules, &format!("/login?password={key}"));
    assert!(!out.contains(&key) && n >= 1, "{out}");
}
