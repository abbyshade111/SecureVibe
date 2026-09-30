//! `sv probe https://…` — the questions only the live site can answer.
//!
//! Some requirements are about deployment rather than code, and reading a repository will never
//! settle them: whether the certificate is one browsers trust, whether plain HTTP still works,
//! whether HSTS is set. They are the requirements `sv` has always had to report as *not verified*
//! with a note saying "check the production settings", which is advice rather than an answer.
//!
//! # What it is allowed to do, and why that is most of the design
//!
//! This is the first thing in `sv` that reaches outside the machine it runs on. Everything else
//! reads files, or talks to an app inside a fence that cannot route anywhere. A tool that fetches
//! an address somebody supplies is a tool that can be pointed at a stranger, so the limits are
//! narrow and each one is a test:
//!
//! - **The address comes from the command line and nowhere else.** Not from securevibe.toml. A file
//!   can be committed and then run by CI against a host its author never meant; an argument was
//!   typed by a person who is looking at the terminal. That is the consent, and it is the only one
//!   available, because nothing here can prove who owns a domain.
//! - **Read-only.** GET and HEAD, no body, no cookies, no `Authorization`. It cannot sign in,
//!   cannot post a form, and cannot change anything.
//! - **A hard cap of [`MOST_REQUESTS`].** Three or four requests to one address is a look; a
//!   hundred is a scan, and no amount of good intent makes the second one acceptable from somebody
//!   else's laptop.
//! - **One host.** A redirect to a different host is reported and not followed. Otherwise the
//!   owner's own address could hand the probe to somewhere they never named, which is both a way to
//!   make `sv` fetch a stranger and a way to get a wrong answer about the owner's own site.
//! - **No path guessing.** It asks for the address it was given. It does not go looking for
//!   `/admin` or `/.git`, which is what distinguishes this from a scanner.
//!
//! # TLS verification is the check, not a setting
//!
//! `curl` is run without `-k`, so the handshake fails when the certificate is self-signed, expired,
//! or for the wrong name. Refusing to disable verification is what makes V12.2.2 answerable at all:
//! a tool that skips verification to "get a result" has thrown the result away.

use crate::{Confidence, Finding, Location, Severity, Verified};

/// The most requests one run may make. A run makes at most three: HTTPS; then either the same
/// address without verification, only when the certificate failed, or the question about its
/// stapled status (V12.1.4), only when it passed and names an OCSP responder, never both; then plain
/// HTTP. The fourth is slack.
pub const MOST_REQUESTS: usize = 4;

/// What a request to the live site came back with, or why it could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    /// Absent when the request itself failed: a refused TLS handshake, no such host, a timeout.
    pub failure: Option<String>,
    /// What the site's certificate says about checking whether it was revoked, from this same
    /// request's handshake. `None` when nothing reported the certificate's details.
    pub revocation: Option<Revocation>,
}

/// Whether the certificate names an OCSP responder, the address a browser would ask whether it was
/// revoked. Let's Encrypt's have named none since 2025, and then there is nothing to staple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Revocation {
    Ocsp(String),
    NoOcsp,
}

/// What asking for the certificate's stapled status came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stapling {
    /// The site sent a status for its certificate in the handshake, and it said the certificate is
    /// good.
    Stapled,
    /// The handshake carried no status for the certificate.
    NotStapled,
    /// The question could not be asked or answered, and why.
    CannotAsk(String),
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn reached(&self) -> bool {
        self.failure.is_none()
    }
}

/// Something that can fetch one address, read-only. Separated so the judgment is testable without a
/// network, the same split the signed-in probes use.
pub trait Fetch {
    /// A GET with no body, no cookies, and no credentials. `verify` false is only ever used to tell
    /// "the certificate is not trusted" apart from "the host is not there", and never to get a
    /// result that is then reported as if verification had passed.
    fn get(&mut self, url: &str, verify: bool) -> Answer;

    /// A HEAD to `url` that asks for the certificate's stapled status (V12.1.4), with verification
    /// on. One more request, counted against the same cap.
    fn stapled(&mut self, _url: &str) -> Stapling {
        Stapling::CannotAsk("this fetcher cannot ask for a stapled status".to_owned())
    }
}

/// The address to probe, once it has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    /// Always https. The plain-HTTP request is derived from it.
    pub https: String,
    pub http: String,
}

/// Reads the address the owner typed, and refuses anything this must not be pointed at.
///
/// Deliberately strict. A vague address is a request to guess, and guessing is how a tool ends up
/// fetching something nobody meant.
pub fn read_target(raw: &str) -> Result<Target, String> {
    let raw = raw.trim();
    let rest = match raw.strip_prefix("https://") {
        Some(rest) => rest,
        None if raw.starts_with("http://") => {
            return Err(
                "give the https address: this checks whether plain HTTP still works, and \
                        starting from it would make that answer meaningless"
                    .to_owned(),
            );
        }
        None => {
            return Err("give the full address, starting with https://".to_owned());
        }
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() {
        return Err("there is no host in that address".to_owned());
    }
    if host.contains('@') {
        return Err(
            "take the username out of the address: this never sends credentials".to_owned(),
        );
    }
    // A bare name with no dot is a machine on the local network, and `localhost` and friends are
    // this machine. Neither is a production address, and a typo that resolves to something on an
    // internal network is exactly the request nobody meant to make.
    let name = host.split(':').next().unwrap_or_default();
    if name.eq_ignore_ascii_case("localhost") || name.starts_with("127.") || name == "::1" {
        return Err(
            "that is this machine. `sv report --run` checks the app locally; this is for \
                    the address your app is served from"
                .to_owned(),
        );
    }
    if !name.contains('.') {
        return Err(
            "that is not a public address: give the host your app is served from".to_owned(),
        );
    }
    Ok(Target {
        host: host.to_owned(),
        https: format!("https://{host}/"),
        http: format!("http://{host}/"),
    })
}

/// A redirect's destination, when it names one.
fn redirect_host(answer: &Answer) -> Option<String> {
    let location = answer.header("location")?;
    let rest = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))?;
    Some(
        rest.split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub verified: Vec<Verified>,
    /// What could not be asked, and why.
    pub not_assessed: Vec<(String, String)>,
    /// Every address that was fetched, in order, so the owner can see exactly what was sent.
    pub requested: Vec<String>,
}

/// What one rule is about, kept together so a finding and the claim it makes cannot drift apart.
/// The same shape as `signed_in::Rule`.
struct Rule {
    rule_id: &'static str,
    requirement_ids: &'static [&'static str],
    title: &'static str,
    severity: Severity,
    impact: &'static str,
    fix: &'static str,
}

const UNTRUSTED_CERTIFICATE: Rule = Rule {
    rule_id: "probe.certificate-not-trusted",
    requirement_ids: &["V12.2.2"],
    title: "The certificate is not one browsers trust",
    severity: Severity::High,
    impact: "Every visitor gets a browser warning, and the ones who click through cannot tell your \
             site from somebody impersonating it.",
    fix: "Get a certificate from a public authority — Let's Encrypt issues them free — and make \
          sure the name on it matches the address and it has not expired.",
};

const PLAIN_HTTP_SERVED: Rule = Rule {
    rule_id: "probe.plain-http-served",
    requirement_ids: &["V12.2.1"],
    title: "The site is served over plain HTTP",
    severity: Severity::High,
    impact: "Anything sent over that connection — a password, a session cookie, the contents of a \
             page — can be read or altered by anybody on the network in between.",
    fix: "Serve nothing over plain HTTP but a permanent redirect to the HTTPS address.",
};

const TEMPORARY_REDIRECT: Rule = Rule {
    rule_id: "probe.plain-http-served",
    requirement_ids: &["V12.2.1"],
    title: "Plain HTTP redirects, but only temporarily",
    severity: Severity::Low,
    impact: "The first request of every visit still goes out unencrypted, where it can be read or \
             changed before the redirect arrives.",
    fix: "Answer 301 or 308 instead, and send Strict-Transport-Security so browsers stop trying \
          plain HTTP at all.",
};

const OCSP_NOT_STAPLED: Rule = Rule {
    rule_id: "probe.ocsp-not-stapled",
    requirement_ids: &["V12.1.4"],
    title: "The site does not staple its certificate's revocation status",
    severity: Severity::Low,
    impact: "A browser that wants to know whether the certificate was revoked has to ask the \
             certificate authority itself, which tells the authority which site is being visited, or \
             skip the check, as most do.",
    fix: "Turn on OCSP stapling where TLS ends: nginx `ssl_stapling on;` with `ssl_stapling_verify \
          on;`, Apache `SSLUseStapling On`. Most hosting and CDN services staple when it is switched on \
          in their TLS settings.",
};

const NO_HSTS: Rule = Rule {
    rule_id: "probe.no-hsts",
    requirement_ids: &["V3.4.1"],
    title: "The site does not tell browsers to always use HTTPS",
    severity: Severity::Medium,
    impact: "Somebody's first visit, or a link they typed without https, can be intercepted before \
             the redirect happens.",
    fix: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS answers, \
          once you are sure every subdomain is served over HTTPS.",
};

const COOKIE_WITHOUT_HOST_PREFIX: Rule = Rule {
    rule_id: "probe.cookie-without-host-prefix",
    requirement_ids: &["V3.3.3"],
    title: "A cookie does not carry the `__Host-` prefix",
    severity: Severity::Low,
    impact: "A cookie without that prefix can be set by a subdomain, so something running on \
             another subdomain can overwrite the session cookie.",
    fix: "Rename the cookie to start with `__Host-`, and send it with Secure, Path=/ and no Domain \
          attribute, which is what the prefix requires.",
};

fn finding(rule: &Rule, description: String, host: &str) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        marked_test_code: false,
        rule_id: rule.rule_id.to_owned(),
        title: rule.title.to_owned(),
        severity: rule.severity,
        confidence: Confidence::High,
        location: Location {
            file: host.to_owned(),
            line: 1,
        },
        secret: None,
        requirement_ids: rule
            .requirement_ids
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        cwe: Vec::new(),
        description,
        impact: rule.impact.to_owned(),
        fix: rule.fix.to_owned(),
    }
}

/// Asks the live site the handful of questions only it can answer.
pub fn run(http: &mut dyn Fetch, target: &Target) -> Outcome {
    let mut out = Outcome::default();

    // 1. HTTPS, with verification on. The handshake is the check.
    out.requested.push(target.https.clone());
    let secure = http.get(&target.https, true);
    if let Some(why) = &secure.failure {
        // Was it the certificate, or is the host simply not there? Asked without verification only
        // to tell those apart, and the answer is a finding either way — never a pass.
        out.requested
            .push(format!("{} (without verification)", target.https));
        let unverified = http.get(&target.https, false);
        if unverified.reached() {
            out.findings.push(finding(
                &UNTRUSTED_CERTIFICATE,
                format!(
                    "{} answered, but only with certificate checking turned off. With it on: {why}",
                    target.https
                ),
                &target.host,
            ));
        } else {
            out.not_assessed.push((
                "V12.2.1, V12.2.2, V3.4.1, V3.3.3".to_owned(),
                format!("{} could not be reached at all: {why}", target.https),
            ));
            return out;
        }
    } else {
        out.verified.push(Verified::new(
            UNTRUSTED_CERTIFICATE.rule_id,
            UNTRUSTED_CERTIFICATE.requirement_ids,
            format!(
                "{} completed a TLS handshake with certificate checking on, so the certificate is \
                 one this machine's trust store accepts, matches the name, and has not expired",
                target.https
            ),
        ));
    }

    // 1b. The certificate's revocation status, stapled into the handshake (V12.1.4). Only for a
    //     certificate this machine trusts, and only when it names an OCSP responder: without one
    //     there is nothing to staple, which is so for every Let's Encrypt certificate since 2025,
    //     and says nothing about how revocation is handled instead. Made only where the unverified
    //     retry above was not, so a run still makes at most three requests.
    if secure.failure.is_none() {
        match &secure.revocation {
            None => out.not_assessed.push((
                "V12.1.4".to_owned(),
                "Whether the site staples its certificate's revocation status: curl on this \
                 machine did not report the certificate's details, so whether it names an OCSP \
                 responder is not known."
                    .to_owned(),
            )),
            Some(Revocation::NoOcsp) => out.not_assessed.push((
                "V12.1.4".to_owned(),
                format!(
                    "The certificate {} presented names no OCSP responder, so there is no status \
                     to staple (Let's Encrypt's have named none since 2025). Whether revocation is \
                     handled another way, such as short-lived certificates, is not something this \
                     asks.",
                    target.https
                ),
            )),
            Some(Revocation::Ocsp(responder)) => {
                out.requested.push(format!(
                    "{} (asking for the certificate's stapled status)",
                    target.https
                ));
                match http.stapled(&target.https) {
                    Stapling::Stapled => out.verified.push(Verified::new(
                        OCSP_NOT_STAPLED.rule_id,
                        OCSP_NOT_STAPLED.requirement_ids,
                        format!(
                            "{} stapled a good status for its certificate into the handshake \
                             (its responder is {responder})",
                            target.https
                        ),
                    )),
                    Stapling::NotStapled => out.findings.push(finding(
                        &OCSP_NOT_STAPLED,
                        format!(
                            "{}'s certificate names an OCSP responder ({responder}), but the \
                             handshake carried no stapled status for it.",
                            target.https
                        ),
                        &target.host,
                    )),
                    Stapling::CannotAsk(why) => out.not_assessed.push((
                        "V12.1.4".to_owned(),
                        format!(
                            "Whether {} staples its certificate's status could not be asked: {why}",
                            target.https
                        ),
                    )),
                }
            }
        }
    }

    // The handshake succeeding is what V12.2.2 asks about, and it is answered above whatever comes
    // back. Everything below reads the *headers* of that answer, and an error page's headers are
    // not what the site sends normally: an edge that answers 400 to an unusual request, or a proxy
    // in the way, sends none of the site's own. Judging HSTS from one reported a missing header on
    // a site that certainly sends it, which is how this was found.
    let ordinary = secure.reached() && secure.status > 0 && secure.status < 400;
    if secure.reached() && !ordinary {
        out.not_assessed.push((
            "V3.4.1, V3.3.3".to_owned(),
            format!(
                "{} answered {}, which is not an ordinary answer, so its headers are not the ones \
                 the site sends to a visitor and nothing here can be read from them.",
                target.https, secure.status
            ),
        ));
    }

    // 2. Strict-Transport-Security, on the answer that came back over HTTPS.
    match secure.header("strict-transport-security") {
        Some(value) => out.verified.push(Verified::new(
            NO_HSTS.rule_id,
            NO_HSTS.requirement_ids,
            format!("{} sent Strict-Transport-Security: {value}", target.https),
        )),
        None if ordinary => out.findings.push(finding(
            &NO_HSTS,
            format!("{} sent no Strict-Transport-Security header.", target.https),
            &target.host,
        )),
        None => {}
    }

    // 3. Cookies set over HTTPS, and whether they carry the `__Host-` prefix.
    let cookies: Vec<&str> = if ordinary {
        secure.headers.as_slice()
    } else {
        &[]
    }
    .iter()
    .filter(|(n, _)| n == "set-cookie")
    .map(|(_, v)| v.as_str())
    .collect();
    if !ordinary {
        // Already said above; saying it twice would read as two separate gaps.
    } else if cookies.is_empty() {
        out.not_assessed.push((
            "V3.3.3".to_owned(),
            format!(
                "{} set no cookies on its front page, so nothing here saw one to look at. A \
                 signed-in page would, and this never signs in.",
                target.https
            ),
        ));
    } else {
        let plain: Vec<&str> = cookies
            .iter()
            .filter(|c| !c.trim_start().starts_with("__Host-"))
            .map(|c| c.split('=').next().unwrap_or("").trim())
            .collect();
        if plain.is_empty() {
            out.verified.push(Verified::new(
                COOKIE_WITHOUT_HOST_PREFIX.rule_id,
                COOKIE_WITHOUT_HOST_PREFIX.requirement_ids,
                format!(
                    "every cookie {} set carries the `__Host-` prefix",
                    target.https
                ),
            ));
        } else {
            out.findings.push(finding(
                &COOKIE_WITHOUT_HOST_PREFIX,
                format!("{} set: {}.", target.https, plain.join(", ")),
                &target.host,
            ));
        }
    }

    // 4. Plain HTTP: is it still served, or does it send the browser to HTTPS?
    out.requested.push(target.http.clone());
    let plain = http.get(&target.http, true);
    if !plain.reached() {
        out.verified.push(Verified::new(
            PLAIN_HTTP_SERVED.rule_id,
            PLAIN_HTTP_SERVED.requirement_ids,
            format!(
                "{} refused the connection, so there is no plain-HTTP way in",
                target.http
            ),
        ));
        return out;
    }
    let to = redirect_host(&plain);
    match (plain.status, to.as_deref()) {
        // A redirect away from the host the owner named is not followed. See the module note.
        (_, Some(elsewhere)) if elsewhere != target.host => {
            out.not_assessed.push((
                "V12.2.1".to_owned(),
                format!(
                    "{} redirects to {elsewhere}, which is a different host from the one you gave. \
                     Nothing here follows that: this only ever asks the address you named.",
                    target.http
                ),
            ));
        }
        (301 | 308, _) => out.verified.push(Verified::new(
            PLAIN_HTTP_SERVED.rule_id,
            PLAIN_HTTP_SERVED.requirement_ids,
            format!(
                "{} answered {} and sent the browser to HTTPS permanently",
                target.http, plain.status
            ),
        )),
        (302 | 303 | 307, _) => out.findings.push(finding(
            &TEMPORARY_REDIRECT,
            format!(
                "{} answered {}, which is a temporary redirect. Browsers do not remember it, so \
                 every visit starts over plain HTTP.",
                target.http, plain.status
            ),
            &target.host,
        )),
        (status, _) if (200..300).contains(&status) => out.findings.push(finding(
            &PLAIN_HTTP_SERVED,
            format!("{} answered {status} and served a page.", target.http),
            &target.host,
        )),
        (status, _) => out.not_assessed.push((
            "V12.2.1".to_owned(),
            format!(
                "{} answered {status}, which is neither a page nor a redirect to HTTPS, so nothing \
                 here can say what a browser arriving over plain HTTP would get.",
                target.http
            ),
        )),
    }

    out
}

#[cfg(test)]
pub(crate) mod tests_support {
    pub use super::tests::{ok, redirect, site, target};
}

#[cfg(test)]
mod tests {
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
    }

    impl Fetch for FakeSite {
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
                    ("strict-transport-security", "max-age=31536000"),
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
            .saturating_sub(1)
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
    fn asking_about_stapling_keeps_a_run_to_three_requests_all_reported() {
        // The unverified retry happens only when the certificate failed, and the stapling question
        // only when it passed, so a run never makes both: HTTPS, one of the two, plain HTTP.
        for stapling in [Stapling::Stapled, Stapling::NotStapled] {
            let mut s = stapling_site(ocsp(), Some(stapling));
            let out = run(&mut s, &target());
            assert_eq!(s.asked.len(), 3, "{:?}", s.asked);
            assert_eq!(
                out.requested.len(),
                s.asked.len(),
                "every request, the stapling question included, is reported to the owner"
            );
            assert!(s.asked.len() < MOST_REQUESTS);
        }
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
        }
        let mut u = Untrusted(stapling_site(ocsp(), Some(Stapling::Stapled)));
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
        let a = read_curl_output(&format!("{head}{CERTS_MARK}{CERTS_WITH_OCSP}"));
        assert_eq!(a.status, 200);
        assert_eq!(a.header("strict-transport-security"), Some("max-age=1"));
        assert_eq!(
            a.revocation,
            Some(Revocation::Ocsp("http://ocsp.digicert.com".into()))
        );
        assert_eq!(
            read_curl_output(head).revocation,
            None,
            "not asked for, not known"
        );
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
                    read_curl_output(&format!("{head}{CERTS_MARK}{}", self.certs))
                } else {
                    read_curl_output(
                        "HTTP/1.1 301 Moved\r\nlocation: https://example.test/\r\n\r\n",
                    )
                }
            }
            fn stapled(&mut self, _url: &str) -> Stapling {
                self.asked += 1;
                stapling_from(self.staple.0, self.staple.1)
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
        assert_eq!((asked, out.requested.len()), (3, 3));

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
        assert_eq!(asked, 2);
        assert!(
            v1214(&out)
                .iter()
                .any(|w| w.contains("names no OCSP responder"))
        );

        // curl printed no certificate details: not known, and not "no responder".
        let (out, asked) = probe("", (Some(0), ""));
        assert_eq!(asked, 2);
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
}

/// The real fetcher: `curl`, with the flags that make the limits above true rather than intended.
///
/// `curl` rather than a Rust HTTP client for the reason the tool adapters are external programs: it
/// is everywhere, it has the platform's trust store, and its TLS is maintained by people who do
/// nothing else. Absent, the check says so and settles nothing, exactly as a missing scanner does.
pub struct Curl {
    /// Counted here rather than trusted to the caller, so the cap is a property of the fetcher.
    made: usize,
}

impl Default for Curl {
    fn default() -> Self {
        Self::new()
    }
}

impl Curl {
    pub fn new() -> Self {
        Curl { made: 0 }
    }

    /// Whether `curl` is on this machine at all.
    pub fn available() -> bool {
        std::process::Command::new("curl")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

impl Fetch for Curl {
    fn get(&mut self, url: &str, verify: bool) -> Answer {
        // The cap, enforced where the requests are actually made. A caller that loops cannot get
        // past it, which is the point of putting it here rather than in `run`.
        if self.made >= MOST_REQUESTS {
            return Answer {
                revocation: None,
                status: 0,
                headers: Vec::new(),
                failure: Some(format!(
                    "this check makes at most {MOST_REQUESTS} requests, and that is all of them"
                )),
            };
        }
        self.made += 1;

        let mut args: Vec<&str> = vec![
            // Headers only: no body is downloaded, so nothing large is fetched and nothing is
            // written anywhere.
            "--head",
            "--silent",
            "--show-error",
            // Redirects are this module's decision, not curl's, because the destination has to be
            // checked against the host the owner named before anything follows it.
            "--max-redirs",
            "0",
            "--max-time",
            "15",
            "--user-agent",
            "sv-probe (OWASP ASVS check, read-only)",
            // Written out rather than left to a default, so a change to curl's defaults cannot
            // quietly start sending something.
            "--no-alpn",
            "--disable",
        ];
        if verify {
            // The certificate's details, after the headers and marked off from them, so whether it
            // names an OCSP responder is read from this same handshake rather than asked again.
            args.push("--write-out");
            args.push(CERTS_WRITE_OUT);
        } else {
            args.push("--insecure");
        }
        args.push(url);

        let out = match std::process::Command::new("curl").args(&args).output() {
            Ok(out) => out,
            Err(e) => {
                return Answer {
                    revocation: None,
                    status: 0,
                    headers: Vec::new(),
                    failure: Some(format!("curl could not be run: {e}")),
                };
            }
        };
        if !out.status.success() {
            return Answer {
                revocation: None,
                status: 0,
                headers: Vec::new(),
                failure: Some(
                    String::from_utf8_lossy(&out.stderr)
                        .trim()
                        .trim_start_matches("curl: ")
                        .to_owned(),
                ),
            };
        }
        read_curl_output(&String::from_utf8_lossy(&out.stdout))
    }

    fn stapled(&mut self, url: &str) -> Stapling {
        if self.made >= MOST_REQUESTS {
            return Stapling::CannotAsk(format!(
                "this check makes at most {MOST_REQUESTS} requests, and that is all of them"
            ));
        }
        self.made += 1;
        let out = match std::process::Command::new("curl")
            .args([
                // curl refuses the handshake when no stapled status comes back, with its own exit
                // code, 91; any other failure is not an answer to this question.
                "--cert-status",
                "--head",
                "--silent",
                "--show-error",
                "--max-redirs",
                "0",
                "--max-time",
                "15",
                "--user-agent",
                "sv-probe (OWASP ASVS check, read-only)",
                "--no-alpn",
                "--disable",
                "--output",
                "/dev/null",
                url,
            ])
            .output()
        {
            Ok(out) => out,
            Err(e) => return Stapling::CannotAsk(format!("curl could not be run: {e}")),
        };
        stapling_from(out.status.code(), &String::from_utf8_lossy(&out.stderr))
    }
}

/// Curl's output for a request: the headers, then, when asked for, the certificate's details after
/// [`CERTS_MARK`].
pub fn read_curl_output(text: &str) -> Answer {
    let (head, certs) = match text.split_once(CERTS_MARK) {
        Some((head, certs)) => (head, Some(certs)),
        None => (text, None),
    };
    let mut answer = parse_head(head);
    answer.revocation = certs.and_then(parse_revocation);
    answer
}

/// How `Curl::get` marks where the headers end and the certificate's details begin.
const CERTS_MARK: &str = "\n@@sv-probe-certs@@\n";
const CERTS_WRITE_OUT: &str = "\n@@sv-probe-certs@@\n%{certs}";

/// Reads curl's `%{certs}`: the certificate chain, the site's own first, each with its extensions
/// as text. The site's certificate names an OCSP responder on a line such as `Authority Information
/// Access:OCSP - URI:http://ocsp.digicert.com`. `None` when curl reported no certificate details at
/// all, which a curl built without them, or too old for `%{certs}`, does.
pub fn parse_revocation(certs: &str) -> Option<Revocation> {
    let leaf = certs
        .split("-----END CERTIFICATE-----")
        .next()
        .unwrap_or_default();
    if !leaf.lines().any(|l| l.starts_with("Subject:")) {
        return None;
    }
    let responder = leaf
        .lines()
        .filter_map(|l| l.split_once("OCSP - URI:").map(|(_, rest)| rest))
        .map(|rest| {
            rest.split(|c: char| c.is_whitespace() || c == ',')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .find(|uri| !uri.is_empty());
    Some(responder.map_or(Revocation::NoOcsp, Revocation::Ocsp))
}

/// What curl's exit says about the stapled status. 0 is a good status stapled. 91 with "No OCSP
/// response received" is none stapled. Any other 91 means a status came back and said something else
/// (revoked, expired, not verifiable), which is not "none stapled" and is passed on in curl's own
/// words; anything else did not get as far as the question.
pub fn stapling_from(code: Option<i32>, stderr: &str) -> Stapling {
    let said: String = stderr
        .trim()
        .trim_start_matches("curl: ")
        .chars()
        .take(200)
        .collect();
    match code {
        Some(0) => Stapling::Stapled,
        Some(91) if said.contains("No OCSP response received") => Stapling::NotStapled,
        _ if said.is_empty() => Stapling::CannotAsk("curl did not say why".to_owned()),
        _ => Stapling::CannotAsk(said),
    }
}

/// Reads curl's `--head` output: a status line, then headers.
fn parse_head(text: &str) -> Answer {
    let mut status = 0;
    let mut headers = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if let Some(rest) = line.strip_prefix("HTTP/") {
            // A proxy answers CONNECT with its own status line before the site says anything. It is
            // not a response from the site, and counting it would make the site's own headers
            // vanish when they arrive before it — found by running this behind one.
            if line.to_ascii_lowercase().contains("connection established") {
                continue;
            }
            // A new status line means a new response; the last one is the one that answered.
            if let Some(code) = rest.split_whitespace().nth(1)
                && let Ok(n) = code.parse::<u16>()
            {
                status = n;
                headers.clear();
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_lowercase(), value.trim().to_owned()));
        }
    }
    Answer {
        revocation: None,
        status,
        headers,
        failure: None,
    }
}

#[cfg(test)]
mod curl_tests {
    use super::*;

    #[test]
    fn the_cap_is_a_property_of_the_fetcher_not_of_the_caller() {
        // A caller that loops must not be able to turn this into a scan, so the count lives with
        // the thing that makes the requests.
        let mut c = Curl::new();
        c.made = MOST_REQUESTS;
        let answer = c.get("https://example.test/", true);
        assert!(!answer.reached());
        assert!(
            answer.failure.unwrap().contains("at most"),
            "and it says why rather than looking like a network error"
        );
    }

    #[test]
    fn curls_headers_are_read_and_the_last_response_is_the_one_kept() {
        // curl prints every response when it follows anything, and the first one's headers are not
        // the answer. Keeping them would read a redirect's Location as the final page's.
        let answer = parse_head(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://example.test/\r\n\r\n\
             HTTP/2 200 \r\nStrict-Transport-Security: max-age=1\r\nSet-Cookie: a=b\r\n\r\n",
        );
        assert_eq!(answer.status, 200);
        assert_eq!(
            answer.header("strict-transport-security"),
            Some("max-age=1")
        );
        assert_eq!(
            answer.header("location"),
            None,
            "the redirect's header must not survive"
        );
    }

    #[test]
    fn header_names_are_read_whatever_case_they_arrive_in() {
        let answer = parse_head("HTTP/2 200 \r\nSTRICT-Transport-Security: max-age=1\r\n");
        assert_eq!(
            answer.header("strict-transport-security"),
            Some("max-age=1")
        );
    }
}

#[cfg(test)]
mod error_answer_tests {
    use super::tests_support::*;
    use super::*;

    #[test]
    fn an_error_answer_settles_nothing_about_the_headers_it_did_not_send() {
        // Found by running this against a real site through a proxy that answered 400. The site
        // certainly sends HSTS; the 400 did not, and the check reported the site as missing it.
        // An error page's headers are not the ones a visitor gets.
        let mut s = site(&[
            (
                "https://example.test/",
                Answer {
                    revocation: None,
                    status: 400,
                    headers: Vec::new(),
                    failure: None,
                },
            ),
            (
                "http://example.test/",
                redirect(301, "https://example.test/"),
            ),
        ]);
        let out = run(&mut s, &target());
        let found: Vec<&str> = out.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert!(
            !found.contains(&"probe.no-hsts"),
            "a 400 that sent no HSTS is not the site failing to send it: {found:?}"
        );
        assert!(
            out.not_assessed
                .iter()
                .any(|(ids, why)| ids.contains("V3.4.1") && why.contains("400")),
            "and it says why: {:?}",
            out.not_assessed
        );
        // The handshake still answers V12.2.2, because that is about the certificate and not the
        // page, and it still reads plain HTTP, because that is a different request.
        assert!(
            out.verified
                .iter()
                .any(|v| v.check_id == "probe.certificate-not-trusted"),
            "the certificate question is answered by the handshake whatever the status"
        );
    }

    #[test]
    fn an_ordinary_answer_is_still_judged() {
        // The other half: without this, making errors settle nothing would be indistinguishable
        // from the check never running.
        let mut s = site(&[
            ("https://example.test/", ok(&[])),
            (
                "http://example.test/",
                redirect(301, "https://example.test/"),
            ),
        ]);
        let out = run(&mut s, &target());
        assert!(
            out.findings.iter().any(|f| f.rule_id == "probe.no-hsts"),
            "a 200 with no HSTS is the site failing to send it"
        );
    }

    #[test]
    fn a_proxys_connect_line_is_not_read_as_the_sites_answer() {
        // A proxy answers CONNECT with its own status line first. Counting it would clear the
        // site's headers when they arrive after, or take its 200 for the site's.
        let answer = parse_head(
            "HTTP/1.1 200 Connection Established\r\n\r\n\
             HTTP/2 200 \r\nStrict-Transport-Security: max-age=1\r\n\r\n",
        );
        assert_eq!(answer.status, 200);
        assert_eq!(
            answer.header("strict-transport-security"),
            Some("max-age=1"),
            "the site's headers must survive the tunnel's own status line"
        );
    }
}
