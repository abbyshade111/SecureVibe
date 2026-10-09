//! The test model speaking Google's Gemini format (the gap analysis of 7 October 2026, finding
//! 13(g); ADR-042 and ADR-019, Later, 9 October 2026), run for real with Node as
//! `model_provider.rs` runs it. Before this, an app that called Gemini reached nothing, and every
//! AI check was "not assessed" for it.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use sv_check::stand_in;

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The health answer at `port`, or nothing: while a test server is starting, a connection can be
/// refused, or reset by another test's server stopping on the same port, and that means only "not
/// this one yet".
fn health(port: u16) -> String {
    let attempt = || -> std::io::Result<String> {
        let mut stream = TcpStream::connect(("127.0.0.1", port))?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        write!(
            stream,
            "GET {} HTTP/1.0\r\nHost: sv-model\r\n\r\n",
            stand_in::HEALTH
        )?;
        let mut raw = String::new();
        stream.read_to_string(&mut raw)?;
        Ok(raw)
    };
    attempt().unwrap_or_default()
}

fn start() -> Option<(Server, u16)> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/model-provider.mjs");
    for _ in 0..3 {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let child = Command::new("node")
            .arg(script)
            .env("PORT", port.to_string())
            .env("HOST", "sv-model")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let mut server = Server(child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if matches!(server.0.try_wait(), Ok(Some(_))) {
                break;
            }
            if TcpStream::connect(("127.0.0.1", port)).is_ok()
                && health(port)
                    // Its own server's answer, not that of another test that took the port first.
                    .contains(&format!("\"pid\":{}", server.0.id()))
            {
                return Some((server, port));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = server.0.kill();
    }
    None
}

/// One request, and the status and body of the answer.
fn call(port: u16, method: &str, path: &str, body: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the test model answers");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: sv-model\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let status = raw
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

fn post(port: u16, path: &str, body: serde_json::Value) -> serde_json::Value {
    let (status, text) = call(port, "POST", path, &body.to_string());
    assert_eq!(status, 200, "{path}: {text}");
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("{path} answered JSON: {text}"))
}

fn seen(port: u16, tag: &str) -> serde_json::Value {
    serde_json::from_str(&call(port, "GET", &stand_in::seen(tag), "").1).unwrap()
}

const GENERATE: &str = "/v1beta/models/gemini-2.5-flash:generateContent";

/// A Gemini request carrying `text` from the person, with `extra` fields added.
fn request(text: &str, extra: serde_json::Value) -> serde_json::Value {
    let mut body = serde_json::json!({
        "contents": [{"role": "user", "parts": [{"text": text}]}],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

/// The text of a Gemini answer's first candidate.
fn answer_text(answer: &serde_json::Value) -> String {
    answer["candidates"][0]["content"]["parts"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a text part: {answer}"))
        .to_owned()
}

fn node_here() -> bool {
    if Command::new("node").arg("--version").output().is_ok() {
        return true;
    }
    assert!(
        std::env::var("SV_REQUIRE_BACKEND").as_deref() != Ok("1"),
        "SV_REQUIRE_BACKEND=1 and there is no Node here, so the test model could not be run"
    );
    println!("no Node here; the test model cannot be run, so nothing is checked");
    false
}

#[test]
fn a_gemini_request_is_answered_and_recorded() {
    if !node_here() {
        return;
    }
    let (_server, port) = start().expect("the test model starts under Node");
    let leak = request(
        &format!("Hello {}", stand_in::marker("LEAK", "6e01")),
        serde_json::json!({
            "systemInstruction": {"parts": [{"text": "You are the booking helper."}]},
            "generationConfig": {"maxOutputTokens": 200},
        }),
    );
    let answer = post(port, GENERATE, leak);
    let said = answer_text(&answer);
    assert!(
        said.contains("SV-REPLY-6e01") && said.contains("You are the booking helper."),
        "{said}"
    );
    assert_eq!(answer["candidates"][0]["content"]["role"], "model");
    assert!(
        answer["usageMetadata"]["promptTokenCount"]
            .as_u64()
            .unwrap()
            >= 4000
    );
    assert!(
        answer["responseId"].as_str().unwrap().contains("SVRAW6e01"),
        "{answer}"
    );
    let what = seen(port, "6e01");
    assert_eq!(what["received"], true, "{what}");
    assert_eq!(what["api"], "gemini");
    assert_eq!(
        what["model"], "gemini-2.5-flash",
        "the model named in the address"
    );
    assert_eq!(what["system"], "You are the booking helper.");
    assert_eq!(what["bounded"], true);

    // A base address that ends in `/v1`, as `ai.base-url-env` gives, with Google's path after it.
    let answer = post(
        port,
        "/v1/v1beta/models/gemini-2.5-pro:generateContent",
        request(&stand_in::marker("PLAIN", "6e02"), serde_json::json!({})),
    );
    assert!(answer_text(&answer).contains("SV-REPLY-6e02"));
    assert_eq!(seen(port, "6e02")["bounded"], false);

    // The control: a path of Google's that is not a message is not answered as one.
    let (status, _) = call(
        port,
        "POST",
        "/v1beta/models/gemini-2.5-flash:countTokens",
        &request("hi", serde_json::json!({})).to_string(),
    );
    assert_eq!(status, 404);
}

#[test]
fn a_streamed_gemini_answer_comes_as_events_or_a_list() {
    if !node_here() {
        return;
    }
    let (_server, port) = start().expect("the test model starts under Node");
    let body = request(&stand_in::marker("PLAIN", "6e03"), serde_json::json!({})).to_string();
    let (status, events) = call(
        port,
        "POST",
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
        &body,
    );
    assert_eq!(status, 200);
    let data = events
        .lines()
        .find_map(|l| l.strip_prefix("data: "))
        .unwrap_or_else(|| panic!("an event: {events}"));
    let chunk: serde_json::Value = serde_json::from_str(data).unwrap();
    assert!(answer_text(&chunk).contains("SV-REPLY-6e03"), "{chunk}");

    let (status, list) = call(
        port,
        "POST",
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent",
        &body,
    );
    assert_eq!(status, 200);
    let list: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert!(answer_text(&list[0]).contains("SV-REPLY-6e03"), "{list}");
}

#[test]
fn a_gemini_request_gets_the_shape_it_asked_for() {
    // ADR-042 for Gemini: a schema written in Google's own form (types in capitals), JSON mode, and
    // a function the model is made to call; BADSHAPE breaks each, and says which was asked for.
    if !node_here() {
        return;
    }
    let (_server, port) = start().expect("the test model starts under Node");
    let schema = serde_json::json!({
        "type": "OBJECT",
        "properties": {
            "answer": {"type": "STRING"},
            "count": {"type": "INTEGER", "minimum": 3},
        },
        "required": ["answer", "count"],
    });
    let json_schema = serde_json::json!({
        "generationConfig": {"responseMimeType": "application/json", "responseSchema": schema},
    });
    let answer = post(
        port,
        GENERATE,
        request(&stand_in::marker("PLAIN", "6e10"), json_schema.clone()),
    );
    let content: serde_json::Value =
        serde_json::from_str(&answer_text(&answer)).expect("JSON that parses");
    assert!(
        content["answer"]
            .as_str()
            .unwrap()
            .contains("SV-REPLY-6e10"),
        "{content}"
    );
    assert_eq!(content["count"], 3, "{content}");

    let answer = post(
        port,
        GENERATE,
        request(&stand_in::marker("BADSHAPE", "6e11"), json_schema),
    );
    let bad: serde_json::Value = serde_json::from_str(&answer_text(&answer)).unwrap();
    assert!(
        bad["answer"][0].as_str().unwrap().contains("SVBAD6e11"),
        "{bad}"
    );
    assert_eq!(seen(port, "6e11")["shape"], "schema");

    // JSON mode: no schema, so a JSON object holding the reply.
    let json_mode =
        serde_json::json!({"generationConfig": {"responseMimeType": "application/json"}});
    let answer = post(
        port,
        GENERATE,
        request(&stand_in::marker("PLAIN", "6e12"), json_mode.clone()),
    );
    let content: serde_json::Value = serde_json::from_str(&answer_text(&answer)).unwrap();
    assert!(content["reply"].as_str().unwrap().contains("SV-REPLY-6e12"));
    post(
        port,
        GENERATE,
        request(&stand_in::marker("BADSHAPE", "6e13"), json_mode),
    );
    assert_eq!(seen(port, "6e13")["shape"], "json");

    // A function the model must call.
    let made_to_call = serde_json::json!({
        "tools": [{"functionDeclarations": [{"name": "record_booking",
            "parameters": {"type": "OBJECT", "properties": {"day": {"type": "STRING"}}}}]}],
        "toolConfig": {"functionCallingConfig": {"mode": "ANY"}},
    });
    let answer = post(
        port,
        GENERATE,
        request(&stand_in::marker("PLAIN", "6e14"), made_to_call.clone()),
    );
    let call = &answer["candidates"][0]["content"]["parts"][0]["functionCall"];
    assert_eq!(call["name"], "record_booking", "{answer}");
    assert!(
        call["args"]["day"]
            .as_str()
            .unwrap()
            .contains("SV-REPLY-6e14")
    );
    post(
        port,
        GENERATE,
        request(&stand_in::marker("BADSHAPE", "6e15"), made_to_call),
    );
    assert_eq!(seen(port, "6e15")["shape"], "tool");

    // The control: a request that asks for no shape is answered in text, and says so.
    let answer = post(
        port,
        GENERATE,
        request(&stand_in::marker("BADSHAPE", "6e16"), serde_json::json!({})),
    );
    assert!(answer_text(&answer).contains("SV-REPLY-6e16"));
    assert_eq!(seen(port, "6e16")["shape"], "");
}

#[test]
fn a_gemini_tool_call_and_its_result_are_followed() {
    if !node_here() {
        return;
    }
    let (_server, port) = start().expect("the test model starts under Node");
    let wanted = serde_json::json!({"tool": "find_booking", "args": {"id": "7"}}).to_string();
    let hex: String = wanted.bytes().map(|b| format!("{b:02x}")).collect();
    let message = format!(
        "Look it up {} SV-CALL-{hex}",
        stand_in::marker("FETCH", "6e20")
    );
    let tools = serde_json::json!([{"functionDeclarations": [{"name": "find_booking"}]}]);
    let answer = post(
        port,
        GENERATE,
        request(&message, serde_json::json!({"tools": tools})),
    );
    let call = &answer["candidates"][0]["content"]["parts"][0]["functionCall"];
    assert_eq!(call["name"], "find_booking", "{answer}");
    assert_eq!(call["args"]["id"], "7");

    // The app sends the result back as Gemini's libraries do: the model's call, then the function's
    // answer in a turn of its own.
    let follow_up = serde_json::json!({
        "contents": [
            {"role": "user", "parts": [{"text": message}]},
            {"role": "model", "parts": [{"functionCall": call}]},
            {"role": "user", "parts": [{"functionResponse": {"name": "find_booking",
                "response": {"booking": "SV-RESULT-6e20"}}}]},
        ],
        "tools": tools,
    });
    let answer = post(port, GENERATE, follow_up);
    assert!(answer_text(&answer).contains("SV-REPLY-6e20"));
    let what = seen(port, "6e20");
    assert!(
        what["tool_result"]
            .as_str()
            .unwrap()
            .contains("SV-RESULT-6e20"),
        "{what}"
    );
    assert_eq!(what["tools_offered"], serde_json::json!(["find_booking"]));
}

#[test]
fn a_gemini_outage_is_in_googles_own_shape() {
    if !node_here() {
        return;
    }
    let (_server, port) = start().expect("the test model starts under Node");
    let (status, text) = call(
        port,
        "POST",
        GENERATE,
        &request(&stand_in::marker("FAIL", "6e30"), serde_json::json!({})).to_string(),
    );
    assert_eq!(status, 500);
    let error: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(error["error"]["status"], "INTERNAL", "{error}");
    assert_eq!(error["error"]["code"], 500);
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("SVERR6e30")
    );
}
