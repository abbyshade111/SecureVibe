//! The test model (`assets/model-provider.mjs`) run for real with Node, and asked what the AI checks
//! rely on it for: that a reply's own id carries its tag (C11.3.2), that a HIDDEN reply hides what it
//! says it hides (C7.3.4), that both ends of a long message are recorded (C2.1.4), and that its
//! moderation endpoint flags a HARM reply and nothing else (C7.3.1).
//!
//! The judgment is tested in `sv_check::ai` against a fake written in Rust; this is the one place
//! the real script is run, so a change to it that the fake does not copy is caught here. Without
//! Node it says so, since there is nothing to run.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Starts the test model on a port the system says is free, and waits until the test model
/// itself answers there: a connection alone could be to something else that took the port first.
/// Tried on three ports before giving up.
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
                && call(port, "GET", "/_sv/health", "").contains("\"ok\":true")
            {
                return Some((server, port));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = server.0.kill();
    }
    None
}

/// One request, and the body of the answer.
fn call(port: u16, method: &str, path: &str, body: &str) -> String {
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
    raw.split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default()
}

fn chat(port: u16, message: &str) -> serde_json::Value {
    let body = serde_json::json!({
        "model": "gpt-test",
        "messages": [{"role": "user", "content": message}],
    });
    serde_json::from_str(&call(
        port,
        "POST",
        "/v1/chat/completions",
        &body.to_string(),
    ))
    .expect("a chat completion")
}

fn seen(port: u16, tag: &str) -> serde_json::Value {
    serde_json::from_str(&call(port, "GET", &format!("/_sv/seen/{tag}"), "")).unwrap()
}

fn moderate(port: u16, input: &str) -> bool {
    let body = serde_json::json!({ "input": input, "model": "omni-moderation-latest" });
    let answer: serde_json::Value =
        serde_json::from_str(&call(port, "POST", "/v1/moderations", &body.to_string())).unwrap();
    answer["results"][0]["flagged"]
        .as_bool()
        .expect("a verdict")
}

#[test]
fn the_test_model_does_what_the_ai_checks_rely_on() {
    if Command::new("node").arg("--version").output().is_err() {
        println!("no Node here; the test model cannot be run, so nothing is checked");
        return;
    }
    let (_server, port) = start().expect("the test model starts under Node");

    // C11.3.2: a plain reply's id carries its tag, and the control, a reply to another tag, does not.
    let plain = chat(port, "Hello SV-PROBE-PLAIN-a1b2");
    let content = plain["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(content.contains("SV-REPLY-a1b2"), "{plain}");
    assert_eq!(plain["id"], "chatcmpl-SVRAWa1b2", "{plain}");
    assert!(
        !chat(port, "Hi SV-PROBE-PLAIN-c3d4")["id"]
            .as_str()
            .unwrap()
            .contains("a1b2")
    );

    // C7.3.4: a HIDDEN reply carries all four things; the plain one carries none.
    let hidden = chat(port, "A note SV-PROBE-HIDDEN-e5f6");
    let text = hidden["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(text.contains("SV-REPLY-e5f6"));
    assert!(
        text.chars()
            .any(|c| ('\u{E0000}'..='\u{E007F}').contains(&c)),
        "{text:?}"
    );
    assert!(
        text.contains('\u{200B}') && text.contains('\u{202E}'),
        "{text:?}"
    );
    assert!(
        text.contains("[https://example.test/a](http://sv-model:") && text.contains("/_sv/x/e5f6")
    );
    assert!(!content.chars().any(|c| c as u32 >= 0x2000), "{content:?}");

    // C2.1.4: both ends of a long message recorded, and only one when only one arrived.
    chat(
        port,
        &format!(
            "SV-PROBE-LONG-0a0b {} SV-PROBE-LONGEND-0a0b",
            "x ".repeat(20_000)
        ),
    );
    assert_eq!(
        seen(port, "0a0b")["kinds"],
        serde_json::json!(["LONG", "LONGEND"])
    );
    chat(port, "SV-PROBE-LONG-0c0d xxxx");
    assert_eq!(seen(port, "0c0d")["kinds"], serde_json::json!(["LONG"]));

    // C7.3.1: the moderation endpoint flags a HARM reply, records that it was asked, and flags
    // nothing else: a plain reply, or the HARM message's own words.
    chat(port, "A story SV-PROBE-HARM-1e1f");
    assert!(!moderate(port, "SV-REPLY-a1b2 Hello from the test model."));
    assert!(!moderate(port, "A story SV-PROBE-HARM-1e1f"));
    assert_ne!(seen(port, "1e1f")["reply_screened"], true);
    assert!(moderate(port, "SV-REPLY-1e1f Hello from the test model."));
    assert_eq!(seen(port, "1e1f")["reply_screened"], true);

    // C9.5.3: a FETCH message has the model call the app's own tool it names, with its arguments,
    // and what the app sends back as that tool's result is recorded.
    let call = serde_json::json!({"tool": "get_note", "args": {"id": "7"}}).to_string();
    let hex: String = call.bytes().map(|b| format!("{b:02x}")).collect();
    let message = format!("Look it up. SV-PROBE-FETCH-2a2b SV-CALL-{hex}");
    let tools = serde_json::json!([{"type": "function", "function": {"name": "get_note"}}]);
    let asked: serde_json::Value = serde_json::from_str(&call_json(
        port,
        serde_json::json!({"model": "m", "tools": tools, "messages": [{"role": "user", "content": message}]}),
    ))
    .unwrap();
    let requested = &asked["choices"][0]["message"]["tool_calls"][0]["function"];
    assert_eq!(requested["name"], "get_note", "{asked}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(requested["arguments"].as_str().unwrap())
            .unwrap(),
        serde_json::json!({"id": "7"})
    );
    call_json(
        port,
        serde_json::json!({"model": "m", "tools": tools, "messages": [
            {"role": "user", "content": message},
            {"role": "tool", "tool_call_id": "call_sv", "content": "SV-OWN-5c5d the note"}
        ]}),
    );
    let fetched = seen(port, "2a2b");
    assert_eq!(fetched["tool_requested"], true);
    assert!(
        fetched["tool_result"]
            .as_str()
            .unwrap()
            .contains("SV-OWN-5c5d"),
        "{fetched}"
    );
    // The control: with no such tool offered, nothing is asked for.
    chat(port, "Look it up. SV-PROBE-FETCH-3a3b SV-CALL-7b7d");
    assert_ne!(seen(port, "3a3b")["tool_requested"], true);
}

fn call_json(port: u16, body: serde_json::Value) -> String {
    call(port, "POST", "/v1/chat/completions", &body.to_string())
}
