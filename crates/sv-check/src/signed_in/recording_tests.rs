//! The signed-in suite's exchanges with the app are kept as the app answered them, and nothing the
//! suite sent in a request is kept (ADR-082, backlog 0229, part 1).

use super::*;
use crate::probes::{ProbeRequest, ProbeResponse};
use crate::signed_in::Http;

/// Answers every request with a 200 and a body that names its path; an answer to `/none` is missing.
struct Canned;

impl Http for Canned {
    fn send(&mut self, request: &ProbeRequest) -> Option<ProbeResponse> {
        (request.path != "/none").then(|| ProbeResponse {
            id: request.id.clone(),
            status: 200,
            headers: vec![("content-type".to_owned(), "text/html".to_owned())],
            body: format!("page {}", request.path),
        })
    }
}

fn request(method: &str, path: &str, body: Option<&str>) -> ProbeRequest {
    ProbeRequest {
        id: "q".to_owned(),
        method: method.to_owned(),
        path: path.to_owned(),
        headers: vec![("cookie".to_owned(), "sid=Rk7Pz2Lw9".to_owned())],
        body: body.map(|b| b.as_bytes().to_vec()),
    }
}

#[test]
fn each_answer_is_kept_with_its_status_headers_and_body_in_the_order_asked() {
    let mut http = Recording::new(Box::new(Canned));
    let _ = http.send(&request("GET", "/account", None));
    let _ = http.send(&request("POST", "/login", None));
    let kept = http.finish();
    assert_eq!(kept.len(), 2, "{kept:#?}");
    assert_eq!(
        (kept[0].method.as_str(), kept[0].path.as_str()),
        ("GET", "/account")
    );
    assert_eq!(kept[0].status, Some(200));
    assert_eq!(kept[0].body, "page /account");
    assert_eq!(
        kept[0].headers,
        [("content-type".to_owned(), "text/html".to_owned())]
    );
    assert_eq!(kept[1].path, "/login");
}

#[test]
fn a_request_with_no_answer_is_kept_with_none_for_its_status() {
    let mut http = Recording::new(Box::new(Canned));
    assert!(http.send(&request("GET", "/none", None)).is_none());
    let kept = http.finish();
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].status, None);
    assert!(kept[0].headers.is_empty() && kept[0].body.is_empty());
}

#[test]
fn a_request_body_and_its_headers_are_never_kept() {
    // The setup: the password and the session cookie are in what the suite sent.
    let sent = request(
        "POST",
        "/login",
        Some("email=a@example.test&password=Sv-4f1c9a0b2e7d-aZ9!"),
    );
    assert!(sent.body_text().contains("Sv-4f1c9a0b2e7d-aZ9!"));
    let mut http = Recording::new(Box::new(Canned));
    let _ = http.send(&sent);
    let kept = format!("{:?}", http.finish());
    assert!(!kept.contains("Sv-4f1c9a0b2e7d-aZ9!"), "{kept}");
    assert!(!kept.contains("Rk7Pz2Lw9"), "{kept}");
}

#[test]
fn the_other_methods_are_passed_through_and_not_kept() {
    // The model and the provider are stand-ins, not the app: their answers are not kept here.
    struct Stand;
    impl Http for Stand {
        fn send(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
            None
        }

        fn model(&mut self, _request: &ProbeRequest) -> Option<ProbeResponse> {
            Some(ProbeResponse {
                id: "m".to_owned(),
                status: 200,
                headers: Vec::new(),
                body: "from the model".to_owned(),
            })
        }
    }
    let mut http = Recording::new(Box::new(Stand));
    assert_eq!(
        http.model(&request("POST", "/v1/messages", None))
            .unwrap()
            .body,
        "from the model"
    );
    assert!(http.finish().is_empty());
}
