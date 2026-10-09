//! The test sign-in provider (`assets/oidc-provider.mjs`) run for real with Node, and held to the
//! protocol `sv` speaks to it (`sv_check::stand_in`): its health address, the mode names, and what
//! each mode does to the next ID token. The judgment in `sv_check::oidc` is tested against a fake in
//! Rust that copies the script; until 9 October 2026 nothing ran the script itself, so a change to
//! it the fake did not copy went unseen (the architecture assessment of 8 October 2026, item 9).
//! Without Node it says so, since there is nothing to run.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use sv_check::stand_in::{self, oidc};

const CLIENT_ID: &str = "sv-client";
const CLIENT_SECRET: &str = "sv-client-secret";
const BACK: &str = "http://app.test/callback";

struct Server(Child);

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// One answer: status, the `location` header when there is one, and the body.
struct Answer {
    status: u16,
    location: Option<String>,
    body: String,
}

fn call(port: u16, method: &str, path: &str, headers: &[(&str, String)], body: &str) -> Answer {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the provider answers");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head = format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    write!(stream, "{head}Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap_or((raw.as_str(), ""));
    Answer {
        status: head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        location: head.lines().find_map(|l| {
            l.split_once(':')
                .filter(|(k, _)| k.eq_ignore_ascii_case("location"))
                .map(|(_, v)| v.trim().to_owned())
        }),
        body: body.to_owned(),
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

/// Starts the provider on a free port and waits for its health address to answer.
fn start() -> Option<(Server, u16)> {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/assets/oidc-provider.mjs");
    for _ in 0..3 {
        let port = std::net::TcpListener::bind(("127.0.0.1", 0))
            .ok()?
            .local_addr()
            .ok()?
            .port();
        let child = Command::new("node")
            .arg(script)
            .env("PORT", port.to_string())
            .env("ISSUER", format!("http://127.0.0.1:{port}"))
            .env("CLIENT_ID", CLIENT_ID)
            .env("CLIENT_SECRET", CLIENT_SECRET)
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

fn set_mode(port: u16, mode: &str) -> Answer {
    call(
        port,
        "POST",
        oidc::MODE,
        &[(
            "Content-Type",
            "application/x-www-form-urlencoded".to_owned(),
        )],
        &format!("mode={mode}"),
    )
}

/// A query parameter of an address, undecoded (the values here need no decoding).
fn param(address: &str, name: &str) -> Option<String> {
    address
        .split_once('?')?
        .1
        .split('&')
        .find_map(|pair| pair.strip_prefix(&format!("{name}=")).map(str::to_owned))
}

fn unbase64url(text: &str) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut held = 0;
    let mut out = Vec::new();
    for c in text.bytes() {
        let Some(v) = ALPHABET.iter().position(|&a| a == c) else {
            continue;
        };
        bits = (bits << 6) | v as u32;
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
        }
    }
    out
}

/// What one sign-in gave: the `iss` on the way back, and the ID token's header, claims, and the
/// token itself.
struct SignIn {
    iss_back: Option<String>,
    header: serde_json::Value,
    claims: serde_json::Value,
    token: String,
}

/// A whole sign-in, as an app makes it: to `/authorize`, then the code to `/token`.
fn sign_in(port: u16) -> SignIn {
    let to = call(
        port,
        "GET",
        &format!("/authorize?client_id={CLIENT_ID}&redirect_uri={BACK}&state=s1&nonce=n1"),
        &[],
        "",
    );
    assert_eq!(to.status, 302, "{}", to.body);
    let back = to.location.expect("sent back to the app");
    assert!(back.starts_with(BACK), "{back}");
    let code = param(&back, "code").expect("a code");
    let iss_back = param(&back, "iss").map(|s| s.replace("%3A", ":").replace("%2F", "/"));
    let token = call(
        port,
        "POST",
        "/token",
        &[(
            "Content-Type",
            "application/x-www-form-urlencoded".to_owned(),
        )],
        &format!(
            "grant_type=authorization_code&code={code}&redirect_uri={BACK}\
             &client_id={CLIENT_ID}&client_secret={CLIENT_SECRET}"
        ),
    );
    assert_eq!(token.status, 200, "{}", token.body);
    let answer: serde_json::Value = serde_json::from_str(&token.body).unwrap();
    let id = answer["id_token"].as_str().expect("an ID token").to_owned();
    let mut parts = id.split('.');
    let header = serde_json::from_slice(&unbase64url(parts.next().unwrap())).unwrap();
    let claims = serde_json::from_slice(&unbase64url(parts.next().unwrap())).unwrap();
    SignIn {
        iss_back,
        header,
        claims,
        token: id,
    }
}

/// Whether the token's signature checks against the keys the provider publishes, asked of Node's
/// own crypto, so the test needs no library of its own for RSA.
fn signed_by_published_key(port: u16, token: &str) -> bool {
    let jwks = call(port, "GET", "/jwks", &[], "").body;
    let check = "const [t, k] = process.argv.slice(1);\
                 const c = require('node:crypto');\
                 const [h, p, s] = t.split('.');\
                 const key = c.createPublicKey({ key: JSON.parse(k).keys[0], format: 'jwk' });\
                 const ok = s !== '' && c.verify('sha256', Buffer.from(h + '.' + p), key, Buffer.from(s, 'base64url'));\
                 process.stdout.write(ok ? 'yes' : 'no');";
    let out = Command::new("node")
        .args(["-e", check, token, &jwks])
        .output()
        .expect("node");
    String::from_utf8_lossy(&out.stdout) == "yes"
}

#[test]
fn the_provider_does_to_each_token_what_sv_assumes_each_mode_does() {
    if Command::new("node").arg("--version").output().is_err() {
        println!("no Node on this computer, so the provider script cannot be run");
        return;
    }
    let (_server, port) = start().expect("the provider started and answered its health address");
    let issuer = format!("http://127.0.0.1:{port}");

    // Every mode `sv` sends is taken, and one it does not know is refused.
    for mode in oidc::MODES {
        let taken = set_mode(port, mode);
        assert_eq!(taken.status, 200, "{mode}: {}", taken.body);
    }
    assert_eq!(set_mode(port, "no-such-mode").status, 400);

    // Setup: an ordinary sign-in is as it should be, signed with the published key.
    set_mode(port, oidc::NORMAL);
    let normal = sign_in(port);
    assert_eq!(normal.claims["nonce"], "n1");
    assert_eq!(normal.claims["aud"], CLIENT_ID);
    assert_eq!(normal.claims["iss"], issuer.as_str());
    assert_eq!(normal.iss_back.as_deref(), Some(issuer.as_str()));
    assert_eq!(normal.header["alg"], "RS256");
    assert!(signed_by_published_key(port, &normal.token));

    let after = |mode: &str| {
        let set = set_mode(port, mode);
        assert_eq!(set.status, 200, "{mode}");
        let made = sign_in(port);
        // A mode is used once: the sign-in after it is ordinary again.
        let next = sign_in(port);
        assert_eq!(next.claims["nonce"], "n1", "{mode} lasted");
        assert_eq!(next.claims["aud"], CLIENT_ID, "{mode} lasted");
        assert_eq!(next.claims["sub"], normal.claims["sub"], "{mode} lasted");
        assert!(signed_by_published_key(port, &next.token), "{mode} lasted");
        made
    };

    let wrong_nonce = after(oidc::WRONG_NONCE);
    assert_ne!(wrong_nonce.claims["nonce"], "n1");

    let wrong_aud = after(oidc::WRONG_AUD);
    assert_ne!(wrong_aud.claims["aud"], CLIENT_ID);

    let unsigned = after(oidc::UNSIGNED);
    assert_eq!(unsigned.header["alg"], "none");
    assert!(unsigned.token.ends_with('.'), "{}", unsigned.token);

    let wrong_key = after(oidc::WRONG_KEY);
    assert_eq!(wrong_key.header["alg"], "RS256");
    assert!(!signed_by_published_key(port, &wrong_key.token));

    let wrong_iss = after(oidc::WRONG_ISS);
    assert_ne!(wrong_iss.iss_back.as_deref(), Some(issuer.as_str()));
    assert_eq!(wrong_iss.claims["iss"], issuer.as_str());

    let wrong_token_iss = after(oidc::WRONG_TOKEN_ISS);
    assert_ne!(wrong_token_iss.claims["iss"], issuer.as_str());
    assert_eq!(wrong_token_iss.iss_back.as_deref(), Some(issuer.as_str()));

    let other = after(oidc::OTHER_PERSON);
    assert_ne!(other.claims["sub"], normal.claims["sub"]);
    assert_eq!(other.claims["email"], normal.claims["email"]);

    let moved = after(oidc::NEW_EMAIL);
    assert_eq!(moved.claims["sub"], normal.claims["sub"]);
    assert_ne!(moved.claims["email"], normal.claims["email"]);
}
