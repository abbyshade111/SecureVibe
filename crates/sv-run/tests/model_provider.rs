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

fn start(port: u16) -> Option<Server> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/model-provider.mjs");
    let child = Command::new("node")
        .arg(script)
        .env("PORT", port.to_string())
        .env("HOST", "sv-model")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let server = Server(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(server);
        }
        std::thread::sleep(Duration::from_millis(100));
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
    let port = 39000 + (std::process::id() % 1000) as u16;
    let _server = start(port).expect("the test model starts under Node");

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
}
