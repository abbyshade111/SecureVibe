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

/// The most requests one run may make. Three is the plan; the fourth is slack for one redirect.
pub const MOST_REQUESTS: usize = 4;

/// What a request to the live site came back with, or why it could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    /// Absent when the request itself failed: a refused TLS handshake, no such host, a timeout.
    pub failure: Option<String>,
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
        /// Every (url, verify) pair asked for, in order.
        asked: Vec<(String, bool)>,
    }

    impl Fetch for FakeSite {
        fn get(&mut self, url: &str, verify: bool) -> Answer {
            self.asked.push((url.to_owned(), verify));
            self.answers.get(url).cloned().unwrap_or(Answer {
                status: 0,
                headers: Vec::new(),
                failure: Some("no such host".to_owned()),
            })
        }
    }

    pub fn ok(headers: &[(&str, &str)]) -> Answer {
        Answer {
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
        if !verify {
            args.push("--insecure");
        }
        args.push(url);

        let out = match std::process::Command::new("curl").args(&args).output() {
            Ok(out) => out,
            Err(e) => {
                return Answer {
                    status: 0,
                    headers: Vec::new(),
                    failure: Some(format!("curl could not be run: {e}")),
                };
            }
        };
        if !out.status.success() {
            return Answer {
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
        parse_head(&String::from_utf8_lossy(&out.stdout))
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
