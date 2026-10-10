//! The tests of `production.rs` that were `mod tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct FakeSite {
    /// url -> answer
    answers: BTreeMap<String, Answer>,
    /// Every (url, verify) pair asked for, in order. A stapling question counts as a request.
    asked: Vec<(String, bool)>,
    /// What asking for the stapled status gets; `None` is a fetcher that cannot ask.
    stapling: Option<Stapling>,
    /// What a handshake offering only TLS 1.0 and 1.1 gets; `None` is a fetcher that cannot.
    pub old_tls: Option<OldTls>,
    /// How many times that was asked. It is also in `asked`, as a request to the HTTPS address.
    pub old_tls_asked: usize,
}

impl Fetch for FakeSite {
    fn get_as_program(&mut self, url: &str) -> Answer {
        self.get(&format!("as a program: {url}"), true)
    }

    fn old_tls(&mut self, url: &str) -> OldTls {
        self.asked.push((url.to_owned(), true));
        self.old_tls_asked += 1;
        self.old_tls
            .clone()
            .unwrap_or_else(|| OldTls::CannotTell("the fake was given no answer".to_owned()))
    }

    fn stapled(&mut self, url: &str) -> Stapling {
        self.asked.push((url.to_owned(), true));
        self.stapling
            .clone()
            .unwrap_or_else(|| Stapling::CannotAsk("the fake was given no answer".to_owned()))
    }

    fn get(&mut self, url: &str, verify: bool) -> Answer {
        self.asked.push((url.to_owned(), verify));
        self.answers.get(url).cloned().unwrap_or(Answer {
            revocation: None,
            status: 0,
            headers: Vec::new(),
            failure: Some("no such host".to_owned()),
        })
    }
}

pub fn ok(headers: &[(&str, &str)]) -> Answer {
    Answer {
        revocation: None,
        status: 200,
        headers: headers
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect(),
        failure: None,
    }
}

pub fn redirect(status: u16, to: &str) -> Answer {
    Answer {
        revocation: None,
        status,
        headers: vec![("location".to_owned(), to.to_owned())],
        failure: None,
    }
}

pub fn site(pairs: &[(&str, Answer)]) -> FakeSite {
    FakeSite {
        answers: pairs
            .iter()
            .map(|(u, a)| ((*u).to_owned(), a.clone()))
            .collect(),
        asked: Vec::new(),
        stapling: None,
        old_tls: None,
        old_tls_asked: 0,
    }
}

pub fn target() -> Target {
    read_target("https://example.test").expect("a good address")
}

fn rules(out: &Outcome) -> Vec<&str> {
    out.findings.iter().map(|f| f.rule_id.as_str()).collect()
}

#[test]
fn a_well_set_up_site_is_credited_for_each_thing_it_got_right() {
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[
                (
                    "strict-transport-security",
                    "max-age=31536000; includeSubDomains",
                ),
                ("set-cookie", "__Host-session=abc; Secure; Path=/"),
            ]),
        ),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    assert!(out.findings.is_empty(), "{:?}", rules(&out));
    let checked: Vec<&str> = out.verified.iter().map(|v| v.check_id.as_str()).collect();
    for want in [
        UNTRUSTED_CERTIFICATE.rule_id,
        NO_HSTS.rule_id,
        COOKIE_WITHOUT_HOST_PREFIX.rule_id,
        PLAIN_HTTP_SERVED.rule_id,
    ] {
        assert!(
            checked.contains(&want),
            "{want} was not credited: {checked:?}"
        );
    }
    // The front page's one answer and its cookies, in part; the transport, in full (ADR-053, Later).
    for v in &out.verified {
        let one_answer = [NO_HSTS.rule_id, COOKIE_WITHOUT_HOST_PREFIX.rule_id];
        assert_eq!(v.in_part, one_answer.contains(&v.check_id.as_str()), "{v:?}");
    }
}

#[test]
fn a_site_that_gets_each_thing_wrong_is_reported() {
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("set-cookie", "session=abc")]),
        ),
        ("http://example.test/", ok(&[])),
    ]);
    let out = run(&mut s, &target());
    let found = rules(&out);
    for want in [
        NO_HSTS.rule_id,
        COOKIE_WITHOUT_HOST_PREFIX.rule_id,
        PLAIN_HTTP_SERVED.rule_id,
    ] {
        assert!(found.contains(&want), "{want} was not reported: {found:?}");
    }
}

#[test]
fn a_certificate_nothing_trusts_is_a_finding_and_never_a_pass() {
    // The one place verification is turned off, and only to tell an untrusted certificate from
    // a host that is not there. The result is a finding either way.
    let mut s = FakeSite::default();
    s.answers.insert(
        "https://example.test/".to_owned(),
        Answer {
            revocation: None,
            status: 0,
            headers: Vec::new(),
            failure: Some("self-signed certificate".to_owned()),
        },
    );
    // Without verification the same address answers.
    struct Untrusted(FakeSite);
    impl Fetch for Untrusted {
        fn get(&mut self, url: &str, verify: bool) -> Answer {
            if verify {
                self.0.get(url, true)
            } else {
                self.0.asked.push((url.to_owned(), false));
                ok(&[])
            }
        }
    }
    let mut u = Untrusted(s);
    let out = run(&mut u, &target());
    assert!(
        rules(&out).contains(&UNTRUSTED_CERTIFICATE.rule_id),
        "{:?}",
        rules(&out)
    );
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == UNTRUSTED_CERTIFICATE.rule_id),
        "an untrusted certificate must never be credited"
    );
    // Nor is anything said about its revocation status: the certificate is not one this
    // machine trusts, so whether its status is stapled is not a question worth an answer.
    assert!(
        !out.not_assessed.iter().any(|(ids, _)| ids == "V12.1.4"),
        "{:?}",
        out.not_assessed
    );
}

#[test]
fn a_host_that_is_not_there_settles_nothing() {
    let mut s = FakeSite::default();
    let out = run(&mut s, &target());
    assert!(out.findings.is_empty(), "{:?}", rules(&out));
    assert!(out.verified.is_empty());
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, _)| ids.contains("V12.2.2")),
        "{:?}",
        out.not_assessed
    );
}

/// A fetcher whose first verified request to one address fails with `why`, and every later one
/// gets the site's answer.
struct FailsOnce {
    site: FakeSite,
    url: &'static str,
    why: &'static str,
    failed: bool,
}

impl Fetch for FailsOnce {
    fn get(&mut self, url: &str, verify: bool) -> Answer {
        if url == self.url && verify && !self.failed {
            self.failed = true;
            self.site.asked.push((url.to_owned(), verify));
            return Answer {
                revocation: None,
                status: 0,
                headers: Vec::new(),
                failure: Some(self.why.to_owned()),
            };
        }
        self.site.get(url, verify)
    }
}

fn failure(why: &str) -> Answer {
    Answer {
        revocation: None,
        status: 0,
        headers: Vec::new(),
        failure: Some(why.to_owned()),
    }
}

#[test]
fn a_first_request_that_timed_out_is_not_called_a_certificate_problem() {
    // The review of 1 to 4 October, item 1: a host waking from sleep misses the time limit
    // once and answers the retry, and that was reported as an untrusted certificate.
    let pages = [
        ("https://example.test/", ok(&[])),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ];
    let mut slow = FailsOnce {
        site: site(&pages),
        url: "https://example.test/",
        why: "Operation timed out after 15001 milliseconds with 0 bytes received",
        failed: false,
    };
    let out = run(&mut slow, &target());
    assert!(slow.failed, "the setup: the first request failed");
    assert!(
        !rules(&out).contains(&UNTRUSTED_CERTIFICATE.rule_id),
        "{:?}",
        out.findings
    );
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == UNTRUSTED_CERTIFICATE.rule_id)
    );
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, why)| ids.contains("V12.2.2") && why.contains("timed out")),
        "{:?}",
        out.not_assessed
    );
    // The control: a failure that names the certificate is still the finding.
    let mut bad = FailsOnce {
        site: site(&pages),
        url: "https://example.test/",
        why: "SSL certificate problem: self-signed certificate",
        failed: false,
    };
    let out = run(&mut bad, &target());
    assert!(
        rules(&out).contains(&UNTRUSTED_CERTIFICATE.rule_id),
        "{:?}",
        out.findings
    );
}

#[test]
fn plain_http_is_credited_only_for_a_connection_refused_and_asked_on_port_80() {
    // The review of 1 to 4 October, item 2.
    let credited = |plain: Answer| {
        let mut s = site(&[
            ("https://example.test/", ok(&[])),
            ("http://example.test/", plain),
        ]);
        run(&mut s, &target())
            .verified
            .iter()
            .any(|v| v.check_id == PLAIN_HTTP_SERVED.rule_id)
    };
    assert!(credited(failure(
        "Failed to connect to example.test port 80 after 3 ms: Connection refused"
    )));
    assert!(credited(failure(
        "Failed to connect to example.test port 80 after 3 ms: Couldn't connect to server"
    )));
    for why in [
        "Empty reply from server",
        "Connection timed out after 15000 milliseconds",
        "Operation timed out after 15001 milliseconds with 0 bytes received",
    ] {
        assert!(!credited(failure(why)), "{why} was credited");
    }
    // The plain question goes to port 80, whatever port the HTTPS address names, and is held
    // to the checked address there too.
    for (typed, http) in [
        ("https://app.example.test:443/", "http://app.example.test/"),
        (
            "https://app.example.test:8443/x",
            "http://app.example.test/",
        ),
        // A public address: `2001:db8::/32` is kept for documentation, and refused.
        (
            "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]:8443/",
            "http://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/",
        ),
    ] {
        assert_eq!(read_target(typed).unwrap().http, http, "{typed}");
    }
    let t = read_target("https://app.example.test:8443/").unwrap();
    let held = resolve_args(&t, &["203.0.113.7".parse().unwrap()]);
    assert!(
        held.iter().any(|a| a == "app.example.test:80:203.0.113.7"),
        "{held:?}"
    );
    assert!(
        held.iter()
            .any(|a| a == "app.example.test:8443:203.0.113.7"),
        "{held:?}"
    );
}

fn api_site(api_answer: Option<Answer>) -> FakeSite {
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("strict-transport-security", "max-age=63072000")]),
        ),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    if let Some(a) = api_answer {
        s.answers
            .insert("as a program: http://example.test/api/health".to_owned(), a);
    }
    s
}

fn api_target() -> Target {
    target().with_api("/api/health").expect("a good path")
}

fn api_why(out: &Outcome) -> Vec<&str> {
    out.not_assessed
        .iter()
        .filter(|(ids, _)| ids == "V4.1.2")
        .map(|(_, why)| why.as_str())
        .collect()
}

#[test]
fn an_api_redirected_to_https_over_plain_http_is_found() {
    let mut s = api_site(Some(redirect(301, "https://example.test/api/health")));
    let out = run(&mut s, &api_target());
    let found = out
        .findings
        .iter()
        .find(|f| f.rule_id == API_REDIRECTED.rule_id)
        .unwrap_or_else(|| panic!("{:?}", out.findings));
    assert_eq!(found.requirement_ids, ["V4.1.2"]);
    assert!(
        found.description.contains("answered 301"),
        "{}",
        found.description
    );
    // Asked on port 80 of the same host, once, as a program; the browser's plain-HTTP
    // question is still asked too, and the run stays within its cap.
    assert!(
        s.asked
            .iter()
            .any(|(u, _)| u == "as a program: http://example.test/api/health")
    );
    assert!(s.asked.iter().any(|(u, _)| u == "http://example.test/"));
    assert!(s.asked.len() <= MOST_REQUESTS_WITH_API, "{:?}", s.asked);
    assert!(
        out.requested
            .contains(&"http://example.test/api/health".to_owned())
    );
    assert!(
        !out.verified
            .iter()
            .any(|v| v.requirement_ids.contains(&"V4.1.2".to_owned()))
    );
}

#[test]
fn an_api_that_refuses_plain_http_or_cannot_be_asked_credits_nothing() {
    for (answer, says) in [
        (
            Answer {
                revocation: None,
                status: 403,
                headers: Vec::new(),
                failure: None,
            },
            "answered 403 with no redirect",
        ),
        (
            redirect(301, "https://elsewhere.test/api/health"),
            "another host",
        ),
        (
            redirect(302, "http://example.test/api/v2/health"),
            "with no redirect",
        ),
        (
            Answer {
                revocation: None,
                status: 0,
                headers: Vec::new(),
                failure: Some("Connection refused".to_owned()),
            },
            "could not be asked",
        ),
    ] {
        let mut s = api_site(Some(answer));
        let out = run(&mut s, &api_target());
        assert!(
            !out.findings
                .iter()
                .any(|f| f.rule_id == API_REDIRECTED.rule_id),
            "{says}: {:?}",
            out.findings
        );
        assert!(
            !out.verified
                .iter()
                .any(|v| v.requirement_ids.contains(&"V4.1.2".to_owned()))
        );
        assert!(
            api_why(&out)
                .iter()
                .any(|w| w.contains(says) && w.contains("credits nothing")),
            "{says}: {:?}",
            out.not_assessed
        );
    }
}

#[test]
fn without_an_api_path_nothing_more_is_asked_and_it_says_how() {
    let mut s = api_site(None);
    let out = run(&mut s, &target());
    assert!(
        !s.asked.iter().any(|(u, _)| u.starts_with("as a program")),
        "{:?}",
        s.asked
    );
    assert!(s.asked.len() <= MOST_REQUESTS);
    assert!(
        api_why(&out).iter().any(|w| w.contains("--api")),
        "{:?}",
        out.not_assessed
    );
    // The cap a fetcher keeps follows the same rule.
    let ip = ["203.0.113.7".parse().unwrap()];
    assert_eq!(Curl::held_to(&target(), &ip).most, MOST_REQUESTS);
    assert_eq!(
        Curl::held_to(&api_target(), &ip).most,
        MOST_REQUESTS_WITH_API
    );
}

#[test]
fn an_api_path_is_a_path_on_the_same_host_and_nothing_else() {
    let good = target().with_api("/api/v1/items?limit=1").unwrap();
    assert_eq!(
        good.api.as_deref(),
        Some("http://example.test/api/v1/items?limit=1")
    );
    // On port 80, whatever port the HTTPS address names.
    let other_port = read_target("https://example.test:8443")
        .unwrap()
        .with_api("/api")
        .unwrap();
    assert_eq!(other_port.api.as_deref(), Some("http://example.test/api"));
    for bad in [
        "api/health",
        "//elsewhere.test/api",
        "http://elsewhere.test/api",
        "/api/../admin",
        "/api health",
        "/api#x",
        "/api/{a,b}",
        "/api\\x",
    ] {
        assert!(target().with_api(bad).is_err(), "{bad}");
    }
    assert!(target().with_api(&format!("/{}", "a".repeat(300))).is_err());
}

#[test]
fn curl_is_told_to_use_no_proxy() {
    // The review of 1 to 4 October, item 3: a proxy from this computer's settings looks the
    // name up itself, so the request was not held to the checked address.
    let curl = Curl::held_to(&target(), &["203.0.113.7".parse().unwrap()]);
    let args = curl.args(&[]);
    let at = args
        .iter()
        .position(|a| *a == "--noproxy")
        .expect("--noproxy is passed");
    assert_eq!(args[at + 1], "*");
}

#[test]
fn a_redirect_to_another_host_is_refused_rather_than_followed() {
    // The safety rule with teeth. Following it would let the address the owner named hand this
    // to somewhere they did not, which is both a way to make `sv` fetch a stranger and a way to
    // report a wrong answer about the owner's own site.
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("strict-transport-security", "max-age=1")]),
        ),
        (
            "http://example.test/",
            redirect(301, "https://somewhere-else.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == PLAIN_HTTP_SERVED.rule_id),
        "a redirect away from the host proves nothing about it"
    );
    assert!(
        out.not_assessed
            .iter()
            .any(|(_, why)| why.contains("somewhere-else.test")),
        "{:?}",
        out.not_assessed
    );
    let hosts: Vec<&String> = s.asked.iter().map(|(u, _)| u).collect();
    assert!(
        !hosts.iter().any(|u| u.contains("somewhere-else")),
        "it fetched the other host: {hosts:?}"
    );
}

#[test]
fn it_never_asks_for_more_than_the_cap() {
    let mut s = site(&[
        ("https://example.test/", ok(&[("set-cookie", "a=b")])),
        ("http://example.test/", ok(&[])),
    ]);
    let out = run(&mut s, &target());
    assert!(
        s.asked.len() <= MOST_REQUESTS,
        "made {} requests: {:?}",
        s.asked.len(),
        s.asked
    );
    assert_eq!(
        out.requested.len(),
        s.asked.len(),
        "every request must be reported to the owner"
    );
}

#[test]
fn it_only_ever_asks_for_the_host_it_was_given() {
    // No path guessing: that is the line between a look and a scan.
    let mut s = site(&[
        ("https://example.test/", ok(&[])),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    run(&mut s, &target());
    for (url, _) in &s.asked {
        assert!(
            url == "https://example.test/" || url == "http://example.test/",
            "asked for something other than the address given: {url}"
        );
    }
}

#[test]
fn the_address_has_to_be_an_https_url_for_a_public_host() {
    for (bad, why) in [
        ("http://example.test", "plain"),
        ("example.test", "no scheme"),
        ("https://localhost:3000", "this machine"),
        ("https://127.0.0.1", "this machine"),
        ("https://intranet", "no dot"),
        ("https://user@example.test", "credentials"),
        ("https://", "no host"),
    ] {
        assert!(read_target(bad).is_err(), "{bad} should be refused ({why})");
    }
    let good = read_target("https://app.example.test/some/page").expect("accepted");
    assert_eq!(good.host, "app.example.test");
    assert_eq!(good.https, "https://app.example.test/");
    assert_eq!(good.http, "http://app.example.test/");
}

#[test]
fn a_temporary_redirect_is_not_as_good_as_a_permanent_one() {
    let mut s = site(&[
        (
            "https://example.test/",
            ok(&[("strict-transport-security", "max-age=1")]),
        ),
        (
            "http://example.test/",
            redirect(302, "https://example.test/"),
        ),
    ]);
    let out = run(&mut s, &target());
    assert!(
        rules(&out).contains(&PLAIN_HTTP_SERVED.rule_id),
        "{:?}",
        rules(&out)
    );
}

/// The site at `target()`, with this HSTS value on its HTTPS answer (`None` sends none) and a
/// permanent redirect from plain HTTP.
fn hsts_site(hsts: Option<&str>, status: u16) -> FakeSite {
    let mut secure = ok(&hsts
        .map(|v| vec![("strict-transport-security", v)])
        .unwrap_or_default());
    secure.status = status;
    site(&[
        ("https://example.test/", secure),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ])
}

fn hsts_credited(out: &Outcome) -> bool {
    out.verified.iter().any(|v| v.check_id == NO_HSTS.rule_id)
}

fn hsts_found(out: &Outcome) -> bool {
    rules(out).contains(&NO_HSTS.rule_id)
}

#[test]
fn hsts_is_credited_only_for_a_year_or_more_across_subdomains() {
    // The control: what V3.4.1 asks for at every level is credited, however it is spelled.
    for good in [
        "max-age=31536000; includeSubDomains",
        "includesubdomains; max-age=63072000; preload",
        "MAX-AGE=\"31536000\" ; INCLUDESUBDOMAINS",
        "max-age=99999999999999999999999; includeSubDomains",
    ] {
        let out = run(&mut hsts_site(Some(good), 200), &target());
        assert!(hsts_credited(&out), "{good}: {:?}", out.verified);
        assert!(!hsts_found(&out), "{good}: {:?}", rules(&out));
    }
    // Too short, told to forget, or a header browsers ignore: a finding, never credit.
    for (weak, says) in [
        ("max-age=0", "forget"),
        ("max-age=0; includeSubDomains", "forget"),
        ("max-age=31535999; includeSubDomains", "31535999 seconds"),
        ("max-age=1", "1 seconds"),
        ("includeSubDomains", "no max-age"),
        ("max-age=; includeSubDomains", "no max-age"),
        ("max-age=1y; includeSubDomains", "no max-age"),
        ("max-age=-1; includeSubDomains", "no max-age"),
        (
            "max-age=31536000; max-age=31536000; includeSubDomains",
            "no max-age",
        ),
    ] {
        let out = run(&mut hsts_site(Some(weak), 200), &target());
        assert!(
            !hsts_credited(&out),
            "{weak} was credited: {:?}",
            out.verified
        );
        let found = out
            .findings
            .iter()
            .find(|f| f.rule_id == NO_HSTS.rule_id)
            .unwrap_or_else(|| panic!("{weak} was not found: {:?}", rules(&out)));
        assert!(
            found.description.contains(says),
            "{weak}: {}",
            found.description
        );
    }
}

#[test]
fn a_year_without_subdomains_is_left_to_the_owners_level() {
    // Enough at level 1, not at level 2 and up, and `sv probe` is not told which applies.
    let out = run(&mut hsts_site(Some("max-age=31536000"), 200), &target());
    assert!(!hsts_credited(&out), "{:?}", out.verified);
    assert!(!hsts_found(&out), "{:?}", rules(&out));
    assert!(
        out.not_assessed
            .iter()
            .any(|(id, why)| id == "V3.4.1" && why.contains("includeSubDomains")),
        "{:?}",
        out.not_assessed
    );
}

#[test]
fn hsts_on_an_error_answer_is_neither_credited_nor_found() {
    // The control: the same header on an ordinary answer is credited.
    let good = "max-age=31536000; includeSubDomains";
    assert!(hsts_credited(&run(
        &mut hsts_site(Some(good), 200),
        &target()
    )));
    for status in [400, 404, 500, 503] {
        for header in [Some(good), Some("max-age=0"), None] {
            let out = run(&mut hsts_site(header, status), &target());
            assert!(
                !hsts_credited(&out),
                "{status} {header:?}: {:?}",
                out.verified
            );
            assert!(!hsts_found(&out), "{status} {header:?}: {:?}", rules(&out));
        }
    }
}

#[test]
fn only_a_redirect_to_https_on_this_host_is_credited() {
    // The control.
    let credited = |to: &str, status: u16| {
        let mut s = site(&[
            ("https://example.test/", ok(&[])),
            ("http://example.test/", redirect(status, to)),
        ]);
        let out = run(&mut s, &target());
        let credited = out
            .verified
            .iter()
            .any(|v| v.check_id == PLAIN_HTTP_SERVED.rule_id);
        let found = rules(&out).contains(&PLAIN_HTTP_SERVED.rule_id);
        let open = out.not_assessed.iter().any(|(id, _)| id == "V12.2.1");
        (credited, found, open)
    };
    for good in [
        "https://example.test/",
        "https://EXAMPLE.test/login",
        "HTTPS://example.test",
        " https://example.test/?next=/ ",
    ] {
        assert_eq!(credited(good, 301), (true, false, false), "{good}");
        assert_eq!(credited(good, 308), (true, false, false), "{good}");
        // Temporary, to HTTPS: still the finding it always was.
        assert_eq!(credited(good, 302), (false, true, false), "{good}");
    }
    // Each leaves the browser on plain HTTP, permanent or not: neither credit nor a finding,
    // since where it ends up would take following it.
    for plain in [
        "http://example.test/",
        "http://example.test/home",
        "/login",
        "login",
        "//example.test/",
        "?next=/",
        "",
    ] {
        for status in [301, 302, 307, 308] {
            assert_eq!(
                credited(plain, status),
                (false, false, true),
                "{status} to {plain:?}"
            );
        }
    }
}

/// A well-set-up HTTPS answer whose certificate says this about revocation.
fn secure_with(revocation: Option<Revocation>) -> Answer {
    let mut a = ok(&[("strict-transport-security", "max-age=31536000")]);
    a.revocation = revocation;
    a
}

fn stapling_site(revocation: Option<Revocation>, stapling: Option<Stapling>) -> FakeSite {
    let mut s = site(&[
        ("https://example.test/", secure_with(revocation)),
        (
            "http://example.test/",
            redirect(301, "https://example.test/"),
        ),
    ]);
    s.stapling = stapling;
    s
}

fn stapling_asked(s: &FakeSite) -> usize {
    // The stapling question is the only request made twice to the HTTPS address with
    // verification on; the first is the ordinary look.
    s.asked
        .iter()
        .filter(|(u, v)| u == "https://example.test/" && *v)
        .count()
        .saturating_sub(1 + s.old_tls_asked)
}

fn ocsp() -> Option<Revocation> {
    Some(Revocation::Ocsp("http://ocsp.example.test".into()))
}

#[test]
fn a_site_that_staples_is_credited_and_one_that_does_not_is_found() {
    let mut stapled = stapling_site(ocsp(), Some(Stapling::Stapled));
    let out = run(&mut stapled, &target());
    assert_eq!(stapling_asked(&stapled), 1, "asked once");
    assert!(
        out.verified
            .iter()
            .any(|v| v.check_id == OCSP_NOT_STAPLED.rule_id
                && v.scope.contains("http://ocsp.example.test")),
        "{:?}",
        out.verified
    );
    assert!(!rules(&out).contains(&OCSP_NOT_STAPLED.rule_id));

    let mut not = stapling_site(ocsp(), Some(Stapling::NotStapled));
    let out = run(&mut not, &target());
    assert!(
        rules(&out).contains(&OCSP_NOT_STAPLED.rule_id),
        "{:?}",
        rules(&out)
    );
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == OCSP_NOT_STAPLED.rule_id)
    );
}

#[test]
fn asking_about_stapling_and_old_tls_keeps_a_run_to_four_requests_all_reported() {
    // The unverified retry happens only when the certificate failed, and the stapling and old
    // TLS questions only when it passed, so a run never makes all three: HTTPS, the stapling
    // question, the old TLS handshake, plain HTTP.
    for stapling in [Stapling::Stapled, Stapling::NotStapled] {
        let mut s = stapling_site(ocsp(), Some(stapling));
        let out = run(&mut s, &target());
        assert_eq!(s.asked.len(), 4, "{:?}", s.asked);
        assert_eq!(s.old_tls_asked, 1);
        assert_eq!(
            out.requested.len(),
            s.asked.len(),
            "every request, the stapling and old TLS questions included, is reported"
        );
        assert_eq!(
            s.asked.len(),
            MOST_REQUESTS,
            "the cap is reached and not passed"
        );
    }
}

fn old_tls_site(answer: Option<OldTls>) -> FakeSite {
    let mut s = stapling_site(Some(Revocation::NoOcsp), None);
    s.old_tls = answer;
    s
}

fn old_tls_credited(out: &Outcome) -> bool {
    out.verified
        .iter()
        .any(|v| v.requirement_ids.iter().any(|r| r == "V12.1.1"))
}

#[test]
fn a_site_that_accepts_old_tls_is_found_and_one_that_refuses_is_not_credited() {
    let mut accepts = old_tls_site(Some(OldTls::Accepted));
    let out = run(&mut accepts, &target());
    assert_eq!(accepts.old_tls_asked, 1);
    assert!(
        rules(&out).contains(&OLD_TLS_ACCEPTED.rule_id),
        "{:?}",
        rules(&out)
    );
    assert!(!old_tls_credited(&out));
    assert!(
        out.requested
            .iter()
            .any(|r| r.contains("offering only TLS 1.0 and 1.1")),
        "{:?}",
        out.requested
    );

    let mut refuses = old_tls_site(Some(OldTls::Refused("tlsv1 alert protocol version".into())));
    let out = run(&mut refuses, &target());
    assert_eq!(refuses.old_tls_asked, 1);
    assert!(!rules(&out).contains(&OLD_TLS_ACCEPTED.rule_id));
    assert!(!old_tls_credited(&out), "half of V12.1.1 is not all of it");
    assert!(
        out.not_assessed.iter().any(|(ids, why)| ids == "V12.1.1"
            && why.contains("alert protocol version")
            && why.contains("not credited")),
        "{:?}",
        out.not_assessed
    );
}

#[test]
fn an_old_tls_question_that_went_nowhere_settles_nothing() {
    for answer in [
        None,
        Some(OldTls::CannotTell(
            "legacy sigalg disallowed or unsupported".into(),
        )),
    ] {
        let mut s = old_tls_site(answer);
        let out = run(&mut s, &target());
        assert_eq!(s.old_tls_asked, 1);
        assert!(!rules(&out).contains(&OLD_TLS_ACCEPTED.rule_id));
        assert!(!old_tls_credited(&out));
        assert!(
            out.not_assessed
                .iter()
                .any(|(ids, why)| ids == "V12.1.1" && why.contains("could not be told")),
            "{:?}",
            out.not_assessed
        );
    }
}

#[test]
fn a_host_that_is_not_there_names_old_tls_among_what_it_could_not_settle() {
    let mut s = site(&[]);
    s.old_tls = Some(OldTls::Accepted);
    let out = run(&mut s, &target());
    assert_eq!(s.old_tls_asked, 0);
    assert!(!rules(&out).contains(&OLD_TLS_ACCEPTED.rule_id));
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, _)| ids.contains("V12.1.1")),
        "{:?}",
        out.not_assessed
    );
}

#[test]
fn a_certificate_naming_no_responder_is_not_asked_about_and_not_judged() {
    // Every Let's Encrypt certificate since 2025. There is nothing to staple, and that says
    // nothing about revocation being handled badly.
    let mut s = stapling_site(Some(Revocation::NoOcsp), Some(Stapling::NotStapled));
    let out = run(&mut s, &target());
    assert_eq!(
        stapling_asked(&s),
        0,
        "no request for a status that cannot exist"
    );
    assert!(!rules(&out).contains(&OCSP_NOT_STAPLED.rule_id));
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == OCSP_NOT_STAPLED.rule_id)
    );
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, why)| ids == "V12.1.4" && why.contains("names no OCSP responder")),
        "{:?}",
        out.not_assessed
    );
}

#[test]
fn unknown_certificate_details_and_a_question_that_failed_settle_nothing() {
    let mut unknown = stapling_site(None, Some(Stapling::Stapled));
    let out = run(&mut unknown, &target());
    assert_eq!(stapling_asked(&unknown), 0);
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, why)| ids == "V12.1.4" && why.contains("did not report")),
        "{:?}",
        out.not_assessed
    );
    let mut failed = stapling_site(ocsp(), Some(Stapling::CannotAsk("timed out".into())));
    let out = run(&mut failed, &target());
    assert!(!rules(&out).contains(&OCSP_NOT_STAPLED.rule_id));
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == OCSP_NOT_STAPLED.rule_id)
    );
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, why)| ids == "V12.1.4" && why.contains("timed out")),
        "{:?}",
        out.not_assessed
    );
}

#[test]
fn a_certificate_nothing_trusts_is_never_asked_about_stapling() {
    // The certificate fails verification but the site answers without it, so the run goes on
    // past the handshake. It names a responder; nothing about stapling may be asked or said,
    // since the certificate is not one this machine trusts.
    struct Untrusted(FakeSite);
    impl Fetch for Untrusted {
        fn get(&mut self, url: &str, verify: bool) -> Answer {
            self.0.asked.push((url.to_owned(), verify));
            if verify && url.starts_with("https") {
                Answer {
                    revocation: ocsp(),
                    status: 0,
                    headers: Vec::new(),
                    failure: Some("self-signed certificate".to_owned()),
                }
            } else {
                let mut a = ok(&[]);
                a.revocation = ocsp();
                a
            }
        }
        fn stapled(&mut self, url: &str) -> Stapling {
            self.0.stapled(url)
        }
        fn old_tls(&mut self, url: &str) -> OldTls {
            self.0.old_tls(url)
        }
    }
    let mut u = Untrusted(stapling_site(ocsp(), Some(Stapling::Stapled)));
    u.0.old_tls = Some(OldTls::Accepted);
    let out = run(&mut u, &target());
    assert!(
        rules(&out).contains(&UNTRUSTED_CERTIFICATE.rule_id),
        "the setup: the certificate was not trusted and the site answered"
    );
    assert!(
        !out.requested.iter().any(|r| r.contains("stapled status")),
        "{:?}",
        out.requested
    );
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == OCSP_NOT_STAPLED.rule_id)
    );
    assert!(!out.not_assessed.iter().any(|(ids, _)| ids == "V12.1.4"));
    // Nor about old TLS: a handshake refused for the certificate is not a refusal of TLS 1.0.
    assert_eq!(u.0.old_tls_asked, 0, "{:?}", u.0.asked);
    assert!(!rules(&out).contains(&OLD_TLS_ACCEPTED.rule_id));
    assert!(
        out.not_assessed
            .iter()
            .any(|(ids, why)| ids == "V12.1.1" && why.contains("only of a certificate")),
        "{:?}",
        out.not_assessed
    );
    assert!(out.requested.len() <= MOST_REQUESTS);
}

/// curl 8.12.1's `%{certs}` for a certificate that names a responder, cut to the lines that
/// matter and with no key material: the site's certificate, then its issuer's.
const CERTS_WITH_OCSP: &str = "Subject:CN = www.example.test\nIssuer:C = US, O = DigiCert Inc, CN = DigiCert EV RSA CA G2\nX509v3 CRL Distribution Points:Full Name:\nAuthority Information Access:OCSP - URI:http://ocsp.digicert.com\nCA Issuers - URI:http://cacerts.digicert.com/DigiCertEVRSACAG2.crt\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\nSubject:C = US, O = DigiCert Inc, CN = DigiCert EV RSA CA G2\nAuthority Information Access:OCSP - URI:http://ocsp.digicert.com\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";

/// The same for letsencrypt.org, whose certificate names only where its issuer is published.
/// Its issuer names a responder of its own, which is not the site's certificate.
const CERTS_WITHOUT_OCSP: &str = "Subject:CN = letsencrypt.org\nIssuer:C = US, O = Let's Encrypt, CN = YE2\nAuthority Information Access:CA Issuers - URI:http://ye2.i.lencr.org/\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\nSubject:C = US, O = Let's Encrypt, CN = YE2\nAuthority Information Access:OCSP - URI:http://x1.o.lencr.org\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n";

#[test]
fn the_responder_is_read_from_the_sites_own_certificate_only() {
    assert_eq!(
        parse_revocation(CERTS_WITH_OCSP),
        Some(Revocation::Ocsp("http://ocsp.digicert.com".into()))
    );
    assert_eq!(
        parse_revocation(CERTS_WITHOUT_OCSP),
        Some(Revocation::NoOcsp)
    );
    assert_eq!(
        parse_revocation(""),
        None,
        "no details is not the same as no responder"
    );
    let head = "HTTP/2 200\r\nstrict-transport-security: max-age=1\r\n\r\n";
    let mark = certs_mark();
    let a = read_curl_output(&format!("{head}{mark}{CERTS_WITH_OCSP}"), &mark);
    assert_eq!(a.status, 200);
    assert_eq!(a.header("strict-transport-security"), Some("max-age=1"));
    assert_eq!(
        a.revocation,
        Some(Revocation::Ocsp("http://ocsp.digicert.com".into()))
    );
    assert_eq!(
        read_curl_output(head, &mark).revocation,
        None,
        "not asked for, not known"
    );
}

#[test]
fn a_site_cannot_write_the_certificate_s_details_into_its_own_headers() {
    // The deep review's improvement 5: with the marker fixed, a header line that was the marker,
    // and a responder of the site's own after it, was read as the certificate's details.
    let mark = certs_mark();
    assert_ne!(
        mark,
        certs_mark(),
        "a marker is made fresh for each request"
    );
    let forged = format!("HTTP/1.1 200 OK\nx: 1\n@@sv-probe-certs@@\n{CERTS_WITH_OCSP}\r\n\r\n");
    let answer = read_curl_output(&format!("{forged}{mark}{CERTS_WITHOUT_OCSP}"), &mark);
    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.revocation,
        parse_revocation(CERTS_WITHOUT_OCSP),
        "the details are the certificate's, not the headers'"
    );
    assert_ne!(answer.revocation, parse_revocation(CERTS_WITH_OCSP));
}

#[test]
fn curls_own_output_carries_through_to_what_the_probe_says() {
    // End to end from what curl prints: the headers and `%{certs}` for the first request, and
    // curl's exit and message for the stapling question, read the way `Curl` reads them.
    struct CurlShaped {
        certs: &'static str,
        staple: (Option<i32>, &'static str),
        asked: usize,
    }
    impl Fetch for CurlShaped {
        fn get(&mut self, url: &str, _verify: bool) -> Answer {
            self.asked += 1;
            if url.starts_with("https") {
                let head = "HTTP/2 200\r\nstrict-transport-security: max-age=63072000\r\n\r\n";
                let mark = certs_mark();
                read_curl_output(&format!("{head}{mark}{}", self.certs), &mark)
            } else {
                read_curl_output(
                    "HTTP/1.1 301 Moved\r\nlocation: https://example.test/\r\n\r\n",
                    &certs_mark(),
                )
            }
        }
        fn stapled(&mut self, _url: &str) -> Stapling {
            self.asked += 1;
            stapling_from(self.staple.0, self.staple.1)
        }
        fn old_tls(&mut self, _url: &str) -> OldTls {
            // What curl 8.12.1 on OpenSSL 3.0.17 printed for github.com on 3 October 2026.
            self.asked += 1;
            old_tls_from(
                Some(35),
                "curl: (35) TLS connect error: error:0A00042E:SSL routines::tlsv1 alert protocol version",
            )
        }
    }
    let probe = |certs, staple| {
        let mut f = CurlShaped {
            certs,
            staple,
            asked: 0,
        };
        let out = run(&mut f, &target());
        (out, f.asked)
    };
    let v1214 = |out: &Outcome| {
        out.not_assessed
            .iter()
            .filter(|(ids, _)| ids == "V12.1.4")
            .map(|(_, why)| why.clone())
            .collect::<Vec<_>>()
    };

    // Names a responder, none stapled: a finding, and the question is reported as asked.
    let (out, asked) = probe(
        CERTS_WITH_OCSP,
        (Some(91), "curl: (91) No OCSP response received"),
    );
    assert!(
        rules(&out).contains(&OCSP_NOT_STAPLED.rule_id),
        "{:?}",
        rules(&out)
    );
    assert!(
        !out.verified
            .iter()
            .any(|v| v.check_id == OCSP_NOT_STAPLED.rule_id)
    );
    assert!(out.requested.iter().any(|r| r.contains("stapled status")));
    assert_eq!((asked, out.requested.len()), (4, 4));
    // The old TLS handshake, refused in the site's words: said, and V12.1.1 not credited.
    assert!(
        out.not_assessed.iter().any(|(ids, why)| ids == "V12.1.1"
            && why.contains("tlsv1 alert protocol version")
            && !why.contains("curl: ")),
        "{:?}",
        out.not_assessed
    );
    assert!(!rules(&out).contains(&OLD_TLS_ACCEPTED.rule_id));

    // A stapled status that says the certificate was revoked is not "none stapled".
    let (out, _) = probe(
        CERTS_WITH_OCSP,
        (
            Some(91),
            "curl: (91) SSL certificate revocation reason: keyCompromise",
        ),
    );
    assert!(!rules(&out).contains(&OCSP_NOT_STAPLED.rule_id));
    assert!(
        v1214(&out).iter().any(|w| w.contains("keyCompromise")),
        "{:?}",
        v1214(&out)
    );

    // Only the issuer names a responder: the site's certificate names none, and nothing is asked.
    let (out, asked) = probe(CERTS_WITHOUT_OCSP, (Some(0), ""));
    assert_eq!(asked, 3, "HTTPS, the old TLS handshake, plain HTTP");
    assert!(
        v1214(&out)
            .iter()
            .any(|w| w.contains("names no OCSP responder"))
    );

    // curl printed no certificate details: not known, and not "no responder".
    let (out, asked) = probe("", (Some(0), ""));
    assert_eq!(asked, 3, "HTTPS, the old TLS handshake, plain HTTP");
    assert!(
        v1214(&out).iter().any(|w| w.contains("did not report")),
        "{:?}",
        v1214(&out)
    );
}

#[test]
fn curls_answer_to_the_stapling_question_is_read_for_what_it_says() {
    assert_eq!(stapling_from(Some(0), ""), Stapling::Stapled);
    assert_eq!(
        stapling_from(Some(91), "curl: (91) No OCSP response received"),
        Stapling::NotStapled
    );
    // A status that came back and said something else is not "none stapled".
    assert!(matches!(
        stapling_from(Some(91), "curl: (91) SSL certificate revocation reason: keyCompromise"),
        Stapling::CannotAsk(why) if why.contains("keyCompromise")
    ));
    assert!(matches!(
        stapling_from(Some(4), "curl: option --cert-status: the installed libcurl version does not support this"),
        Stapling::CannotAsk(why) if why.contains("does not support")
    ));
    assert!(matches!(stapling_from(None, ""), Stapling::CannotAsk(_)));
}
