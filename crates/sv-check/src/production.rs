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
//! - **The address comes from the command line and nowhere else.** Not from stackvet.toml. A file
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
//! - **Public addresses only, and only the one checked.** An address on this computer, a private
//!   network, or a link-local range is refused, whether it is typed or a name looks it up there
//!   (the deep review of 4 October 2026, S13): pointed at `10.0.0.1` or at a name that resolves to
//!   it, `sv` would be a way to reach the owner's own network. The name is looked up once, here,
//!   and curl is held to the addresses that were checked (`--resolve`), so a second lookup cannot
//!   give it a different one. Curl's own globbing is off, so one address is one request.
//! - **No path guessing.** It asks for the address it was given. It does not go looking for
//!   `/admin` or `/.git`, which is what distinguishes this from a scanner.
//!
//! # TLS verification is the check, not a setting
//!
//! `curl` is run without `-k`, so the handshake fails when the certificate is self-signed, expired,
//! or for the wrong name. Refusing to disable verification is what makes V12.2.2 answerable at all:
//! a tool that skips verification to "get a result" has thrown the result away.

use crate::{Confidence, Finding, Location, Severity, Verified};

/// The most requests one run may make, and a run can make all four: HTTPS; then either the same
/// address without verification, only when the certificate failed, or, only when it passed, the
/// question about its stapled status (V12.1.4) when it names an OCSP responder and one handshake
/// offering only TLS 1.0 and 1.1 (V12.1.1); then plain HTTP. There is no slack left.
pub const MOST_REQUESTS: usize = 4;

/// The most with `--api`: one more, the address of the app's API the owner named, asked over plain
/// HTTP the way a program asks (V4.1.2). Never without it (ADR-027, Later, 6 October 2026).
pub const MOST_REQUESTS_WITH_API: usize = MOST_REQUESTS + 1;

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

/// What one handshake offering only TLS 1.0 and 1.1 came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OldTls {
    /// The site completed the handshake: it still accepts one of them.
    Accepted,
    /// The site refused, in words that can only have come from its side of the handshake, quoted.
    Refused(String),
    /// Anything else, and why: this machine's TLS library would not offer the old versions, the
    /// connection was dropped, a timeout. Not an answer either way.
    CannotTell(String),
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

    /// A HEAD to `url` whose handshake offers only TLS 1.0 and 1.1 (V12.1.1), with verification on.
    /// One more request, counted against the same cap.
    fn old_tls(&mut self, _url: &str) -> OldTls {
        OldTls::CannotTell("this fetcher cannot offer old TLS versions".to_owned())
    }

    /// A HEAD to `url`, the API address the owner named, shaped the way a program asks rather than
    /// a browser: it accepts JSON, and carries nothing a browser sends (V4.1.2). One more request,
    /// counted against the same cap.
    fn get_as_program(&mut self, _url: &str) -> Answer {
        Answer {
            revocation: None,
            status: 0,
            headers: Vec::new(),
            failure: Some("this fetcher cannot ask as a program".to_owned()),
        }
    }
}

/// The address to probe, once it has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    /// Always https. The plain-HTTP request is derived from it.
    pub https: String,
    pub http: String,
    /// The plain-HTTP address of the app's API, when the owner named its path (`--api`).
    pub api: Option<String>,
}

impl Target {
    /// The same target, with the path of the app's API the owner typed after `--api`, to be asked
    /// over plain HTTP on this host. A path, never an address: the host stays the one checked.
    pub fn with_api(mut self, path: &str) -> Result<Target, String> {
        let path = path.trim();
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(
                "give --api a path on the same site, starting with /, such as /api/health"
                    .to_owned(),
            );
        }
        if path.len() > 300
            || path.contains("..")
            || path
                .chars()
                .any(|c| !c.is_ascii_graphic() || matches!(c, '{' | '}' | '\\' | '#'))
        {
            return Err("that --api path has characters an address path does not have".to_owned());
        }
        self.api = Some(format!("{}{path}", self.http.trim_end_matches('/')));
        Ok(self)
    }
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
    // Curl reads `{a,b}` and `[1-9]` in an address as a list of addresses; it is told not to
    // (`--globoff`), and an address holding them is refused here as well, since no host has them.
    if host.contains(['{', '}', '\\', ' ']) {
        return Err("that address has characters no host name has".to_owned());
    }
    // A name with letters outside ASCII (`bücher.example`) is looked up, and connected to, by its
    // `xn--` form. Taken as typed, the one lookup `sv` makes and the address curl is held to by
    // `--resolve` would be for a name curl never asks for, and the hold would not hold (the review
    // of 8 October 2026, item 6).
    if !host.is_ascii() {
        return Err(
            "that host name has letters outside plain ASCII: give its xn-- form, which is the \
             name your browser actually connects to (copying the address from its address bar \
             gives it)"
                .to_owned(),
        );
    }
    // An IPv6 address is written in brackets, and its colons are not a port.
    let name = match host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => host.split(':').next().unwrap_or_default(),
    };
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        if let Some(what) = not_public(ip) {
            return Err(refused_address(name, ip, what));
        }
    } else if host.contains(['[', ']']) {
        return Err("that address has characters no host name has".to_owned());
    }
    // A bare name with no dot is a machine on the local network, and `localhost` and friends are
    // this machine. Neither is a production address, and a typo that resolves to something on an
    // internal network is exactly the request nobody meant to make.
    let name = name.trim_end_matches('.');
    if name.eq_ignore_ascii_case("localhost")
        || name.to_ascii_lowercase().ends_with(".localhost")
        || name.starts_with("127.")
        || name == "::1"
    {
        return Err(
            "that is this machine. `sv report --run` checks the app locally; this is for \
                    the address your app is served from"
                .to_owned(),
        );
    }
    if !name.contains('.') && name.parse::<std::net::IpAddr>().is_err() {
        return Err(
            "that is not a public address: give the host your app is served from".to_owned(),
        );
    }
    // Plain HTTP is asked on its own port, 80, whatever port the HTTPS address names: asked on the
    // HTTPS port it is a TLS port refusing plain text, which says nothing about whether plain HTTP
    // is served (the review of 1 to 4 October, item 2).
    let plain_host = match host.strip_prefix('[') {
        Some(rest) => format!("[{}]", rest.split(']').next().unwrap_or_default()),
        None => host.split(':').next().unwrap_or_default().to_owned(),
    };
    Ok(Target {
        host: host.to_owned(),
        https: format!("https://{host}/"),
        http: format!("http://{plain_host}/"),
        api: None,
    })
}

/// Why `ip` is not an address on the public internet, or `None` when it is.
///
/// What is refused is what would turn `sv probe` into a way to reach the owner's own computer or
/// network: this computer, private and shared networks, link-local addresses (where cloud machines
/// keep their credentials), and the ranges nothing on the internet is reached at. An IPv6 address
/// that carries an IPv4 one is judged by the IPv4 one inside it.
pub fn not_public(ip: std::net::IpAddr) -> Option<&'static str> {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if v4.is_loopback() {
                Some("this computer")
            } else if v4.is_unspecified() || a == 0 {
                Some("an address that means no particular computer")
            } else if v4.is_private() {
                Some("a private network")
            } else if a == 100 && (64..128).contains(&b) {
                Some("a network shared behind a provider's address translation")
            } else if v4.is_link_local() {
                Some("a link-local address, which only reaches this computer's own network")
            } else if v4.is_multicast() || v4.is_broadcast() || a >= 240 {
                Some("an address that does not reach one computer on the internet")
            } else if a == 192 && b == 0 && v4.octets()[2] == 0 {
                Some("an address kept for the network's own use")
            } else if a == 198 && (b == 18 || b == 19) {
                Some("an address kept for testing networks")
            } else if matches!(
                (a, b, v4.octets()[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            ) {
                Some("an address kept for documentation and examples, which reaches no computer")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return not_public(IpAddr::V4(v4));
            }
            let segments = v6.segments();
            let v4_in = |hi: u16, lo: u16| {
                IpAddr::V4(std::net::Ipv4Addr::new(
                    (hi >> 8) as u8,
                    hi as u8,
                    (lo >> 8) as u8,
                    lo as u8,
                ))
            };
            // Forms that carry an IPv4 address and are routed to it, judged by it (the second weekly
            // review of the decision records, ADR-027): 6to4 (`2002::/16`), with the address in its
            // second and third groups; NAT64's well-known prefix (`64:ff9b::/96`), with it in the
            // last two; and Teredo (`2001::/32`), whose client's address is in the last two, each
            // bit inverted.
            match segments {
                [0x2002, hi, lo, ..] => return not_public(v4_in(hi, lo)),
                [0x64, 0xff9b, 0, 0, 0, 0, hi, lo] => return not_public(v4_in(hi, lo)),
                [0x2001, 0, .., hi, lo] => return not_public(v4_in(!hi, !lo)),
                _ => {}
            }
            let first = segments[0];
            if segments[..3] == [0x64, 0xff9b, 1] {
                // NAT64's prefix for a network's own translator (RFC 8215), where the IPv4 address
                // sits wherever that network put it.
                Some("an address for a network's own translator, which only reaches inside it")
            } else if segments[..2] == [0x2001, 0xdb8] {
                Some("an address kept for documentation and examples, which reaches no computer")
            } else if v6.is_loopback() {
                Some("this computer")
            } else if v6.is_unspecified() {
                Some("an address that means no particular computer")
            } else if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfec0 {
                // Unique local addresses, and the site-local ones they replaced.
                Some("a private network")
            } else if first & 0xffc0 == 0xfe80 {
                Some("a link-local address, which only reaches this computer's own network")
            } else if v6.is_multicast() {
                Some("an address that does not reach one computer on the internet")
            } else if v6.segments()[..6] == [0; 6] {
                // `::a.b.c.d`, the old way of writing an IPv4 address in IPv6.
                let [_, _, _, _, _, _, hi, lo] = v6.segments();
                let v4 =
                    std::net::Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8);
                not_public(IpAddr::V4(v4))
            } else {
                None
            }
        }
    }
}

fn refused_address(name: &str, ip: std::net::IpAddr, what: &str) -> String {
    let via = if name == ip.to_string() {
        String::new()
    } else {
        format!(" ({name} looks up to {ip})")
    };
    format!(
        "that is {what}{via}, not an address on the public internet. `sv probe` asks only the \
         address your app is served from to the public, so it cannot be used to reach this computer \
         or the network it is on. To check the app locally, use `sv report --run`."
    )
}

/// Looks a name up. Separate so the check of what comes back can be tested without a network.
pub trait Resolve {
    /// Every address `host` looks up to, or why it could not be looked up.
    fn addresses(&mut self, host: &str) -> Result<Vec<std::net::IpAddr>, String>;
}

/// This computer's own resolver, as every other program on it asks.
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn addresses(&mut self, host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        use std::net::ToSocketAddrs;
        let found = (host, 443)
            .to_socket_addrs()
            .map_err(|e| format!("{host} could not be looked up ({e})"))?;
        let mut out: Vec<std::net::IpAddr> = Vec::new();
        for a in found {
            if !out.contains(&a.ip()) {
                out.push(a.ip());
            }
        }
        Ok(out)
    }
}

/// The addresses the probe may connect to for `target`: what its name looks up to, once, when every
/// one of them is public. A name that looks up to any address that is not is refused outright, since
/// which one curl would have used is not this check's to guess.
pub fn addresses(
    target: &Target,
    resolve: &mut dyn Resolve,
) -> Result<Vec<std::net::IpAddr>, String> {
    let name = target_name(target);
    if let Ok(ip) = name.parse::<std::net::IpAddr>() {
        // `read_target` refused it already if it was not public; asked again so this function
        // holds by itself.
        if let Some(what) = not_public(ip) {
            return Err(refused_address(name, ip, what));
        }
        return Ok(vec![ip]);
    }
    let found = resolve.addresses(name)?;
    if found.is_empty() {
        return Err(format!("{name} looks up to no address"));
    }
    for ip in &found {
        if let Some(what) = not_public(*ip) {
            return Err(refused_address(name, *ip, what));
        }
    }
    Ok(found)
}

/// The host's name, without a port or an IPv6 address's brackets.
fn target_name(target: &Target) -> &str {
    match target.host.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => target.host.split(':').next().unwrap_or_default(),
    }
}

/// The port written in the address, if one was.
fn target_port(target: &Target) -> Option<&str> {
    let after = match target.host.strip_prefix('[') {
        Some(rest) => rest.split_once(']').map(|(_, after)| after)?,
        None => &target.host[target_name(target).len()..],
    };
    after.strip_prefix(':').filter(|p| !p.is_empty())
}

/// What holds curl to the checked addresses: `--resolve` for each port the probe may use. Without it
/// curl would look the name up again, and a name can answer differently the second time.
fn resolve_args(target: &Target, addresses: &[std::net::IpAddr]) -> Vec<String> {
    let name = target_name(target);
    // An address typed as numbers is not looked up by curl at all.
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Vec::new();
    }
    let list: Vec<String> = addresses
        .iter()
        .map(|ip| match ip {
            std::net::IpAddr::V6(v6) => format!("[{v6}]"),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        })
        .collect();
    // The HTTPS port, as typed or 443, and 80 for the plain-HTTP question.
    let ports: Vec<&str> = match target_port(target) {
        Some(port) if port != "80" => vec![port, "80"],
        Some(port) => vec![port],
        None => vec!["443", "80"],
    };
    let mut out = Vec::new();
    for port in ports {
        out.push("--resolve".to_owned());
        out.push(format!("{name}:{port}:{}", list.join(",")));
    }
    out
}

/// Whether curl's failure says the site refused the connection, rather than not answering in time,
/// closing it without a word, or something on this computer's side.
fn refused_connection(why: &str) -> bool {
    let why = why.to_ascii_lowercase();
    why.contains("connection refused") || why.contains("couldn't connect to server")
}

/// A redirect's destination, when it names one.
fn redirect_host(answer: &Answer) -> Option<String> {
    let (_, rest) = redirect_parts(answer)?;
    Some(
        rest.split(['/', '?', '#'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    )
}

/// An absolute `Location`, split into whether it is HTTPS and what follows the scheme. A relative
/// one (`/login`, `//host/`) is `None`: it keeps the scheme of the request, which was plain HTTP.
fn redirect_parts(answer: &Answer) -> Option<(bool, &str)> {
    let location = answer.header("location")?.trim();
    let scheme_end = location.find("://")?;
    let scheme = &location[..scheme_end];
    let rest = &location[scheme_end + 3..];
    if scheme.eq_ignore_ascii_case("https") {
        Some((true, rest))
    } else if scheme.eq_ignore_ascii_case("http") {
        Some((false, rest))
    } else {
        None
    }
}

/// Whether a redirect sends the browser to HTTPS on the host the owner named. Only an absolute
/// `https://` address does: a relative one, or one to `http://`, leaves the browser on plain HTTP.
fn redirects_to_https(answer: &Answer, host: &str) -> bool {
    matches!(redirect_parts(answer), Some((true, _)))
        && redirect_host(answer).is_some_and(|to| to.eq_ignore_ascii_case(host))
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

const API_REDIRECTED: Rule = Rule {
    rule_id: "probe.api-redirected-to-https",
    requirement_ids: &["V4.1.2"],
    title: "The app's API sends a program over plain HTTP on to HTTPS without a word",
    severity: Severity::Low,
    impact: "A program, or a mobile app, written with an `http://` address by mistake sends its \
             request, sign-in token and all, unencrypted before the redirect arrives, and then \
             works anyway, so nobody ever finds out that it leaks.",
    fix: "Redirect from HTTP to HTTPS only the pages people open in a browser. For the API, refuse \
          plain HTTP outright (close port 80 for it, or answer 403 or 400 with no redirect), so a \
          client that uses `http://` fails where its author will see it.",
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

const OLD_TLS_ACCEPTED: Rule = Rule {
    rule_id: "probe.old-tls-accepted",
    requirement_ids: &["V12.1.1"],
    title: "The site still accepts TLS 1.0 or 1.1",
    severity: Severity::Medium,
    impact: "TLS 1.0 and 1.1 have known weaknesses and were retired in 2021. A site that still \
             accepts them lets an old or misconfigured browser, or somebody in the middle forcing \
             the connection down, use the weaker protection.",
    fix: "Allow only TLS 1.2 and 1.3 where TLS ends: nginx `ssl_protocols TLSv1.2 TLSv1.3;`, Apache \
          `SSLProtocol -all +TLSv1.2 +TLSv1.3`. Most hosting and CDN services have a \"minimum TLS \
          version\" setting; set it to 1.2.",
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

const WEAK_HSTS: Rule = Rule {
    rule_id: "probe.no-hsts",
    requirement_ids: &["V3.4.1"],
    title: "The site tells browsers to use HTTPS, but not for long enough",
    severity: Severity::Medium,
    impact: "Browsers forget the instruction soon, or at once, so a later visit, or a link typed \
             without https, can be intercepted before the redirect happens.",
    fix: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS answers, \
          once you are sure every subdomain is served over HTTPS.",
};

/// A year in seconds: the shortest max-age V3.4.1 accepts.
const HSTS_YEAR: u64 = 31_536_000;

/// What a Strict-Transport-Security value says, read the way a browser reads it (RFC 6797, 6.1).
#[derive(Debug, PartialEq, Eq)]
struct Hsts {
    max_age: u64,
    include_subdomains: bool,
}

/// `None` when a browser would ignore the header: no max-age, one that is not a number, or a
/// directive given twice.
fn read_hsts(value: &str) -> Option<Hsts> {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut seen = std::collections::BTreeSet::new();
    for directive in value.split(';').map(str::trim).filter(|d| !d.is_empty()) {
        let (name, arg) = match directive.split_once('=') {
            Some((n, a)) => (n.trim(), Some(a.trim())),
            None => (directive, None),
        };
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return None;
        }
        match name.as_str() {
            "max-age" => {
                let digits = arg?
                    .strip_prefix('"')
                    .and_then(|a| a.strip_suffix('"'))
                    .unwrap_or(arg?);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                // A number too long for u64 is still a very long time.
                max_age = Some(digits.parse().unwrap_or(u64::MAX));
            }
            "includesubdomains" => include_subdomains = true,
            _ => {}
        }
    }
    Some(Hsts {
        max_age: max_age?,
        include_subdomains,
    })
}

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

#[track_caller]
fn finding(rule: &Rule, description: String, host: &str) -> Finding {
    crate::finding::found(Finding {
        evidence: Vec::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
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
    })
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
        // A certificate problem only when curl said it was one. A timeout, or a host waking from
        // sleep, fails the first request and answers the second a moment later, and that says
        // nothing about the certificate (the review of 1 to 4 October, item 1).
        let about_certificate = why.to_ascii_lowercase().contains("certificate");
        if unverified.reached() && !about_certificate {
            out.not_assessed.push((
                "V12.2.2, V12.1.1, V12.1.4, V3.4.1, V3.3.3".to_owned(),
                format!(
                    "{} did not answer the first request ({why}), and answered the next one a \
                     moment later. That is not a certificate problem, and with only {MOST_REQUESTS} \
                     requests to make, the certificate and the site's headers were not asked again. \
                     Run `sv probe` again.",
                    target.https
                ),
            ));
            return out;
        }
        if unverified.reached() {
            out.not_assessed.push((
                "V12.1.4, V3.4.1, V3.3.3".to_owned(),
                format!(
                    "{} answered only with certificate checking turned off, so its stapled status \
                     and its headers were not read: an answer like that is not the one a visitor \
                     gets.",
                    target.https
                ),
            ));
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
                "V12.2.1, V12.2.2, V12.1.1, V3.4.1, V3.3.3".to_owned(),
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
    //     retry above was not, so a run still makes at most four requests.
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

    // 1c. Old TLS versions (V12.1.1): one handshake offering only TLS 1.0 and 1.1. Only for a
    //     certificate this machine trusts, so a certificate problem cannot be read as a refusal, and
    //     made in the run where the unverified retry was not, so a run still makes at most four
    //     requests. Only ever a finding: V12.1.1 also asks that the newest version be the one
    //     preferred, and curl reports no negotiated version that can be relied on, so a refusal is
    //     said and not credited.
    if secure.failure.is_none() {
        out.requested
            .push(format!("{} (offering only TLS 1.0 and 1.1)", target.https));
        match http.old_tls(&target.https) {
            OldTls::Accepted => out.findings.push(finding(
                &OLD_TLS_ACCEPTED,
                format!(
                    "{} completed a handshake when offered nothing newer than TLS 1.1.",
                    target.https
                ),
                &target.host,
            )),
            OldTls::Refused(said) => out.not_assessed.push((
                "V12.1.1".to_owned(),
                format!(
                    "{} refused a handshake offering only TLS 1.0 and 1.1 ({said}), so the old \
                     versions are off. V12.1.1 also asks that the newest version be the one \
                     preferred, which this does not ask, so it is not credited.",
                    target.https
                ),
            )),
            OldTls::CannotTell(why) => out.not_assessed.push((
                "V12.1.1".to_owned(),
                format!(
                    "Whether {} still accepts TLS 1.0 or 1.1 could not be told: {why}",
                    target.https
                ),
            )),
        }
    } else {
        out.not_assessed.push((
            "V12.1.1".to_owned(),
            format!(
                "Whether {} still accepts TLS 1.0 or 1.1 is asked only of a certificate this \
                 machine trusts, so that a certificate problem is never read as a refusal.",
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

    // 2. Strict-Transport-Security, on the answer that came back over HTTPS. V3.4.1 asks for a
    // max-age of at least a year, and from level 2 for the policy to cover every subdomain. The
    // header being there is not enough: `max-age=0` tells a browser to forget the site's policy.
    // An error answer's headers were already set aside above, and are not read here either way.
    match (ordinary, secure.header("strict-transport-security")) {
        (false, _) => {}
        (true, None) => out.findings.push(finding(
            &NO_HSTS,
            format!("{} sent no Strict-Transport-Security header.", target.https),
            &target.host,
        )),
        (true, Some(raw)) => {
            // Quoted on one line and cut short; read whole.
            let value = crate::finding::quoted(raw);
            match read_hsts(raw) {
                None => out.findings.push(finding(
                    &WEAK_HSTS,
                    format!(
                        "{} sent Strict-Transport-Security: {value}, which has no max-age a browser \
                         can read, so browsers ignore it.",
                        target.https
                    ),
                    &target.host,
                )),
                Some(hsts) if hsts.max_age < HSTS_YEAR => out.findings.push(finding(
                    &WEAK_HSTS,
                    format!(
                        "{} sent Strict-Transport-Security: {value}. {}",
                        target.https,
                        if hsts.max_age == 0 {
                            "A max-age of 0 tells browsers to forget the site's HTTPS-only policy."
                                .to_owned()
                        } else {
                            format!(
                                "A max-age of {} seconds is less than the year (31536000 seconds) \
                                 V3.4.1 asks for.",
                                hsts.max_age
                            )
                        }
                    ),
                    &target.host,
                )),
                Some(hsts) if !hsts.include_subdomains => out.not_assessed.push((
                    "V3.4.1".to_owned(),
                    format!(
                        "{} sent Strict-Transport-Security: {value}. That is a year or more, which is \
                         what level 1 asks; from level 2, V3.4.1 also asks for includeSubDomains, which \
                         it does not carry. Which level applies is yours to say, so it is not credited.",
                        target.https
                    ),
                )),
                Some(_) => out.verified.push(Verified::new(
                    NO_HSTS.rule_id,
                    NO_HSTS.requirement_ids,
                    format!("{} sent Strict-Transport-Security: {value}", target.https),
                )),
            }
        }
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

    // 3b. The app's API, over plain HTTP, asked as a program would (V4.1.2): a redirect to HTTPS
    // is a finding. Only ever a finding: one address the owner named is not every endpoint.
    match &target.api {
        None => out.not_assessed.push((
            "V4.1.2".to_owned(),
            "Whether only the pages people open in a browser redirect plain HTTP to HTTPS, and \
             the API does not: name an address of the app's API with `--api /path` to have it \
             asked over plain HTTP the way a program asks."
                .to_owned(),
        )),
        Some(api) => {
            out.requested.push(api.clone());
            let answer = http.get_as_program(api);
            let said = match (&answer.failure, redirect_host(&answer)) {
                (Some(why), _) => format!("could not be asked ({why})"),
                (None, Some(elsewhere)) if !elsewhere.eq_ignore_ascii_case(&target.host) => {
                    format!(
                        "answered {} and sent the request to {elsewhere}, another host, which is \
                         not followed",
                        answer.status
                    )
                }
                (None, _) if redirects_to_https(&answer, &target.host) => {
                    out.findings.push(finding(
                        &API_REDIRECTED,
                        format!(
                            "{api}, asked over plain HTTP as a program asks (accepting JSON, \
                             with no browser's headers), answered {} and sent it on to {}.",
                            answer.status,
                            crate::finding::quoted(answer.header("location").map_or("", str::trim))
                        ),
                        &target.host,
                    ));
                    String::new()
                }
                (None, _) => format!("answered {} with no redirect to HTTPS", answer.status),
            };
            if !said.is_empty() {
                out.not_assessed.push((
                    "V4.1.2".to_owned(),
                    format!(
                        "{api}, asked over plain HTTP as a program asks, {said}. One address is \
                         not every endpoint of the API, so this credits nothing."
                    ),
                ));
            }
        }
    }

    // 4. Plain HTTP: is it still served, or does it send the browser to HTTPS?
    out.requested.push(target.http.clone());
    let plain = http.get(&target.http, true);
    // Credited only for a connection refused: a timeout, an empty reply, or port 80 blocked on this
    // computer's side is no answer about the site (the review of 1 to 4 October, item 2).
    if let Some(why) = plain
        .failure
        .as_deref()
        .filter(|why| !refused_connection(why))
    {
        out.not_assessed.push((
            "V12.2.1".to_owned(),
            format!(
                "{} could not be asked ({why}), which is not the site refusing plain HTTP, so \
                 whether it is served was not settled.",
                target.http
            ),
        ));
        return out;
    }
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
    let to_https = redirects_to_https(&plain, &target.host);
    match (plain.status, to.as_deref()) {
        // A redirect away from the host the owner named is not followed. See the module note.
        (_, Some(elsewhere)) if !elsewhere.eq_ignore_ascii_case(&target.host) => {
            out.not_assessed.push((
                "V12.2.1".to_owned(),
                format!(
                    "{} redirects to {}, which is a different host from the one you gave. \
                     Nothing here follows that: this only ever asks the address you named.",
                    target.http,
                    crate::finding::quoted(elsewhere)
                ),
            ));
        }
        // A redirect that does not name `https://` on this host leaves the browser on plain HTTP:
        // `/login`, or `http://` again. Where it ends up would take following it, which this does
        // not do, so it is neither credited nor a finding.
        (300..=399, _) if !to_https => out.not_assessed.push((
            "V12.2.1".to_owned(),
            format!(
                "{} answered {} and sent the browser to {}, which is not an HTTPS address on {}. \
                 Where a browser ends up from there would take following it, which this does not \
                 do.",
                target.http,
                plain.status,
                plain.header("location").map_or_else(
                    || "no address at all".to_owned(),
                    |l| crate::finding::quoted(l.trim())
                ),
                target.host
            ),
        )),
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
mod tests;

/// The real fetcher: `curl`, with the flags that make the limits above true rather than intended.
///
/// `curl` rather than a Rust HTTP client for the reason the tool adapters are external programs: it
/// is everywhere, it has the platform's trust store, and its TLS is maintained by people who do
/// nothing else. Absent, the check says so and settles nothing, exactly as a missing scanner does.
pub struct Curl {
    /// Counted here rather than trusted to the caller, so the cap is a property of the fetcher.
    made: usize,
    /// The cap: [`MOST_REQUESTS`], or [`MOST_REQUESTS_WITH_API`] when the owner named an API path.
    most: usize,
    /// What holds every request to the addresses that were checked (`resolve_args`).
    held: Vec<String>,
}

impl Curl {
    /// A fetcher for `target` that connects only to `addresses`, which `addresses` checked.
    pub fn held_to(target: &Target, addresses: &[std::net::IpAddr]) -> Self {
        Curl {
            made: 0,
            most: if target.api.is_some() {
                MOST_REQUESTS_WITH_API
            } else {
                MOST_REQUESTS
            },
            held: resolve_args(target, addresses),
        }
    }

    /// Every curl this fetcher runs: `--disable` first, the only place curl reads it, so no
    /// `.curlrc` on this computer can add anything to the request; globbing off, so one address is
    /// one request; plain web addresses only; and held to the addresses that were checked. Then the
    /// request's own flags.
    fn args<'a>(&'a self, own: &[&'a str]) -> Vec<&'a str> {
        // No proxy, whatever this computer's settings say: a proxy looks the name up itself, so the
        // request would not be held to the address that was checked (the review of 1 to 4
        // October, item 3).
        let mut args = vec![
            "--disable",
            "--globoff",
            "--noproxy",
            "*",
            "--proto",
            "=http,https",
        ];
        args.extend(self.held.iter().map(String::as_str));
        args.extend(own.iter().copied());
        args
    }

    /// One read-only request, with the cap enforced here: `get`, and `get_as_program` with its
    /// `extra` header.
    fn fetch(&mut self, url: &str, verify: bool, extra: &[&str]) -> Answer {
        // The cap, enforced where the requests are actually made. A caller that loops cannot get
        // past it, which is the point of putting it here rather than in `run`.
        if self.made >= self.most {
            return Answer {
                revocation: None,
                status: 0,
                headers: Vec::new(),
                failure: Some(format!(
                    "this check makes at most {} requests, and that is all of them",
                    self.most
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
        ];
        let mark = certs_mark();
        let write_out = format!("{mark}%{{certs}}");
        if verify {
            // The certificate's details, after the headers and marked off from them, so whether it
            // names an OCSP responder is read from this same handshake rather than asked again.
            args.push("--write-out");
            args.push(&write_out);
        } else {
            args.push("--insecure");
        }
        args.extend(extra.iter().copied());
        args.push(url);

        let out = match std::process::Command::new("curl")
            .args(self.args(&args))
            .output()
        {
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
        read_curl_output(&String::from_utf8_lossy(&out.stdout), &mark)
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
        self.fetch(url, verify, &[])
    }

    fn get_as_program(&mut self, url: &str) -> Answer {
        // Verified like the others; over plain HTTP there is nothing to verify, and the user agent
        // is already this probe's own rather than a browser's.
        self.fetch(url, true, &["--header", "Accept: application/json"])
    }

    fn stapled(&mut self, url: &str) -> Stapling {
        if self.made >= self.most {
            return Stapling::CannotAsk(format!(
                "this check makes at most {} requests, and that is all of them",
                self.most
            ));
        }
        self.made += 1;
        let out = match std::process::Command::new("curl")
            .args(self.args(&[
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
                "--output",
                "/dev/null",
                url,
            ]))
            .output()
        {
            Ok(out) => out,
            Err(e) => return Stapling::CannotAsk(format!("curl could not be run: {e}")),
        };
        stapling_from(out.status.code(), &String::from_utf8_lossy(&out.stderr))
    }

    fn old_tls(&mut self, url: &str) -> OldTls {
        if self.made >= self.most {
            return OldTls::CannotTell(format!(
                "this check makes at most {} requests, and that is all of them",
                self.most
            ));
        }
        // Asked of curl itself, on this machine, before the request: which TLS library it uses.
        let library = std::process::Command::new("curl")
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        self.made += 1;
        let mut args: Vec<&str> = vec![
            "--tlsv1.0",
            "--tls-max",
            "1.1",
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
            "--output",
            "/dev/null",
        ];
        args.extend(old_tls_library_args(&library));
        args.push(url);
        match std::process::Command::new("curl")
            .args(self.args(&args))
            .output()
        {
            Ok(out) => old_tls_from(out.status.code(), &String::from_utf8_lossy(&out.stderr)),
            Err(e) => OldTls::CannotTell(format!("curl could not be run: {e}")),
        }
    }
}

/// What curl needs, for the TLS library it was built with, to offer TLS 1.0 and 1.1 at all.
///
/// OpenSSL 3 will not offer them at its default security level: measured on 3 October 2026, curl
/// 8.12.1 on OpenSSL 3.0.17 and Debian trixie's curl failed against servers that speak
/// only TLS 1.0 or 1.1 with errors of their own ("legacy sigalg disallowed", "no protocols
/// available"), and completed the handshake with `--ciphers DEFAULT@SECLEVEL=0`. macOS's curl, on
/// LibreSSL 3.3.6, offers them as it is and refuses that cipher list. Any other library gets nothing
/// added; if it will not offer them, the request fails in its own words and is not read as the
/// site refusing.
fn old_tls_library_args(curl_version: &str) -> Vec<&'static str> {
    let first = curl_version.lines().next().unwrap_or("");
    if first.contains("OpenSSL/") {
        vec!["--ciphers", "DEFAULT@SECLEVEL=0"]
    } else {
        Vec::new()
    }
}

/// Reads curl's answer to a handshake offering only TLS 1.0 and 1.1.
///
/// Only two messages are read as the site refusing, each seen from a real server on 3 October 2026:
/// `alert protocol version`, the alert a server sends when it will not speak any version offered
/// (github.com and www.digicert.com, through LibreSSL and OpenSSL alike), and LibreSSL's `wrong ssl
/// version`, when the server answers with a version that was not offered. Everything else, including
/// a connection reset and every error the library raises on its own side, is not an answer.
fn old_tls_from(code: Option<i32>, stderr: &str) -> OldTls {
    let said = stderr.trim().trim_start_matches("curl: ").to_owned();
    match code {
        Some(0) => OldTls::Accepted,
        _ if said.contains("alert protocol version") || said.contains("wrong ssl version") => {
            OldTls::Refused(said)
        }
        _ if said.is_empty() => {
            OldTls::CannotTell(format!("curl exited with {code:?} and said nothing"))
        }
        _ => OldTls::CannotTell(said),
    }
}

/// Curl's output for a request: the headers, then, when asked for, the certificate's details after
/// `mark` (`certs_mark`).
pub fn read_curl_output(text: &str, mark: &str) -> Answer {
    let (head, certs) = match text.split_once(mark) {
        Some((head, certs)) => (head, Some(certs)),
        None => (text, None),
    };
    let mut answer = parse_head(head);
    answer.revocation = certs.and_then(parse_revocation);
    answer
}

/// How `Curl::get` marks where the headers end and the certificate's details begin: this, a part made
/// fresh for each request, and `@@`, on a line of its own. With the marker fixed, a site sending a
/// header line that was the marker itself could have its own text read as the certificate's details,
/// and say a responder it does not have (the deep review's improvement 5). A site cannot know a marker
/// made for the request it is answering.
const CERTS_MARK: &str = "@@sv-probe-certs-";

/// A marker for one request, as `CERTS_MARK` describes.
fn certs_mark() -> String {
    use std::hash::{BuildHasher, Hasher};
    // The standard library keys each of these at random, from the system, per process and per use.
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("\n{CERTS_MARK}{random:016x}@@\n")
}

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
mod curl_tests;

#[cfg(test)]
mod error_answer_tests;

#[cfg(test)]
mod quoted_tests;
