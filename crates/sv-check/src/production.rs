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
    // Curl reads `{a,b}` and `[1-9]` in an address as a list of addresses; it is told not to
    // (`--globoff`), and an address holding them is refused here as well, since no host has them.
    if host.contains(['{', '}', '\\', ' ']) {
        return Err("that address has characters no host name has".to_owned());
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

fn finding(rule: &Rule, description: String, host: &str) -> Finding {
    Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
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
        (true, Some(value)) => match read_hsts(value) {
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
        },
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
                    "{} redirects to {elsewhere}, which is a different host from the one you gave. \
                     Nothing here follows that: this only ever asks the address you named.",
                    target.http
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
                plain
                    .header("location")
                    .map_or("no address at all", str::trim),
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
        /// What a handshake offering only TLS 1.0 and 1.1 gets; `None` is a fetcher that cannot.
        pub old_tls: Option<OldTls>,
        /// How many times that was asked. It is also in `asked`, as a request to the HTTPS address.
        pub old_tls_asked: usize,
    }

    impl Fetch for FakeSite {
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

        let mut refuses =
            old_tls_site(Some(OldTls::Refused("tlsv1 alert protocol version".into())));
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
        let forged =
            format!("HTTP/1.1 200 OK\nx: 1\n@@sv-probe-certs@@\n{CERTS_WITH_OCSP}\r\n\r\n");
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
}

/// The real fetcher: `curl`, with the flags that make the limits above true rather than intended.
///
/// `curl` rather than a Rust HTTP client for the reason the tool adapters are external programs: it
/// is everywhere, it has the platform's trust store, and its TLS is maintained by people who do
/// nothing else. Absent, the check says so and settles nothing, exactly as a missing scanner does.
pub struct Curl {
    /// Counted here rather than trusted to the caller, so the cap is a property of the fetcher.
    made: usize,
    /// What holds every request to the addresses that were checked (`resolve_args`).
    held: Vec<String>,
}

impl Curl {
    /// A fetcher for `target` that connects only to `addresses`, which `addresses` checked.
    pub fn held_to(target: &Target, addresses: &[std::net::IpAddr]) -> Self {
        Curl {
            made: 0,
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

    fn stapled(&mut self, url: &str) -> Stapling {
        if self.made >= MOST_REQUESTS {
            return Stapling::CannotAsk(format!(
                "this check makes at most {MOST_REQUESTS} requests, and that is all of them"
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
        if self.made >= MOST_REQUESTS {
            return OldTls::CannotTell(format!(
                "this check makes at most {MOST_REQUESTS} requests, and that is all of them"
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
mod curl_tests {
    use super::*;
    use std::net::IpAddr;

    struct Answers(Vec<&'static str>, usize);

    impl Resolve for Answers {
        fn addresses(&mut self, _host: &str) -> Result<Vec<IpAddr>, String> {
            self.1 += 1;
            Ok(self.0.iter().map(|a| a.parse().unwrap()).collect())
        }
    }

    #[test]
    fn an_address_on_this_computer_or_its_network_is_refused_however_it_is_written() {
        for (typed, says) in [
            ("https://10.0.0.1", "private network"),
            ("https://172.16.5.4:8443/x", "private network"),
            ("https://192.168.1.1", "private network"),
            ("https://169.254.169.254/latest/meta-data", "link-local"),
            ("https://100.64.0.1", "address translation"),
            ("https://0.0.0.0", "no particular computer"),
            ("https://127.0.0.2", "this computer"),
            ("https://[::1]", "this computer"),
            ("https://[::]", "no particular computer"),
            ("https://[fd00::1]", "private network"),
            ("https://[fe80::1]:443", "link-local"),
            ("https://[::ffff:10.1.2.3]", "private network"),
            ("https://[::ffff:127.0.0.1]", "this computer"),
            ("https://224.0.0.1", "does not reach one computer"),
            ("https://255.255.255.255", "does not reach one computer"),
            ("https://app.localhost", "this machine"),
            ("https://localhost.", "this machine"),
            // IPv6 forms that carry an IPv4 address, judged by it (ADR-027, "Later").
            ("https://[2002:a00:1::]", "private network"),
            ("https://[2002:7f00:1::1]", "this computer"),
            ("https://[2002:a9fe:a9fe::]", "link-local"),
            ("https://[64:ff9b::10.0.0.1]", "private network"),
            ("https://[64:ff9b::a9fe:a9fe]", "link-local"),
            (
                "https://[2001:0:4136:e378:8000:63bf:f5ff:fffe]",
                "private network",
            ),
            ("https://[64:ff9b:1::5db8:d70e]", "translator"),
            // The ranges kept for documentation, and IPv6's old site-local one.
            ("https://192.0.2.10", "documentation"),
            ("https://198.51.100.7", "documentation"),
            ("https://203.0.113.9", "documentation"),
            ("https://[2001:db8::1]", "documentation"),
            ("https://[fec0::1]", "private network"),
        ] {
            let refused = read_target(typed).expect_err(typed);
            assert!(refused.contains(says), "{typed}: {refused}");
        }
        // The control: public addresses, typed as numbers, are still accepted, and so are the
        // forms above when the IPv4 address they carry is public.
        for typed in [
            "https://93.184.215.14",
            "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]:8443",
            "https://[2002:5db8:d70e::1]",
            "https://[64:ff9b::5db8:d70e]",
            "https://[2001:0:4136:e378:8000:63bf:a247:28f1]",
        ] {
            let target = read_target(typed).expect(typed);
            assert!(
                addresses(&target, &mut Answers(vec![], 0)).is_ok(),
                "{typed}"
            );
        }
        // Globs and brackets that are not an address are refused rather than handed to curl.
        for typed in [
            "https://app{1,2}.example.test",
            "https://a[1-9].example.test",
            "https://a.example.test]",
        ] {
            assert!(read_target(typed).is_err(), "{typed}");
        }
    }

    #[test]
    fn a_name_that_looks_up_to_an_internal_address_is_refused_and_curl_is_held_to_what_was_checked()
    {
        let target = read_target("https://app.example.test").unwrap();
        // Any internal address among the answers refuses the whole name, and says which.
        for answers in [
            vec!["10.0.0.7"],
            vec!["93.184.215.14", "127.0.0.1"],
            vec!["::ffff:192.168.0.9"],
        ] {
            let mut dns = Answers(answers.clone(), 0);
            let refused = addresses(&target, &mut dns).expect_err("refused");
            assert!(
                refused.contains("app.example.test looks up to"),
                "{refused}"
            );
            assert_eq!(dns.1, 1, "looked up once");
        }
        let mut dns = Answers(vec![], 0);
        assert!(
            addresses(&target, &mut dns)
                .unwrap_err()
                .contains("no address")
        );
        // Public answers are kept, and curl is told to use exactly those, on both ports it uses.
        let mut dns = Answers(
            vec!["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
            0,
        );
        let found = addresses(&target, &mut dns).unwrap();
        assert_eq!(found.len(), 2);
        let curl = Curl::held_to(&target, &found);
        let args = curl.args(&["--head", "https://app.example.test/"]);
        let held = "app.example.test:443:93.184.215.14,[2606:2800:21f:cb07:6820:80da:af6b:8b2c]";
        assert!(
            args.windows(2).any(|w| w == ["--resolve", held]),
            "{args:?}"
        );
        assert!(
            args.iter().any(|a| a.starts_with("app.example.test:80:")),
            "{args:?}"
        );
        // A port in the address is the one held.
        let with_port = read_target("https://app.example.test:8443/").unwrap();
        let curl = Curl::held_to(&with_port, &found);
        let args = curl.args(&[]);
        assert!(
            args.iter().any(|a| a.starts_with("app.example.test:8443:")),
            "{args:?}"
        );
        assert!(
            !args.iter().any(|a| a.starts_with("app.example.test:443:")),
            "{args:?}"
        );
    }

    #[test]
    fn every_curl_reads_no_config_globs_nothing_and_speaks_only_http() {
        let target = read_target("https://app.example.test").unwrap();
        let curl = Curl::held_to(&target, &["93.184.215.14".parse().unwrap()]);
        let args = curl.args(&["--head", "https://app.example.test/"]);
        // `--disable` counts only as curl's very first argument.
        assert_eq!(args[0], "--disable");
        assert!(args.contains(&"--globoff"), "{args:?}");
        assert!(
            args.windows(2).any(|w| w == ["--proto", "=http,https"]),
            "{args:?}"
        );
        assert_eq!(args.iter().filter(|a| **a == "--disable").count(), 1);
        assert_eq!(args.last(), Some(&"https://app.example.test/"));
    }

    #[test]
    fn the_cap_is_a_property_of_the_fetcher_not_of_the_caller() {
        // A caller that loops must not be able to turn this into a scan, so the count lives with
        // the thing that makes the requests.
        let mut c = Curl::held_to(&tests_support::target(), &[]);
        c.made = MOST_REQUESTS;
        let answer = c.get("https://example.test/", true);
        assert!(!answer.reached());
        assert!(
            answer.failure.unwrap().contains("at most"),
            "and it says why rather than looking like a network error"
        );
        assert!(
            matches!(c.old_tls("https://example.test/"), OldTls::CannotTell(why) if why.contains("at most")),
            "the old TLS handshake counts against the same cap"
        );
    }

    #[test]
    fn curls_answer_to_old_tls_is_read_for_what_it_says() {
        // The messages are the ones curl printed on 3 October 2026.
        assert_eq!(old_tls_from(Some(0), ""), OldTls::Accepted);
        for refused in [
            "curl: (35) LibreSSL/3.3.6: error:1404B42E:SSL routines:ST_CONNECT:tlsv1 alert protocol version",
            "curl: (35) TLS connect error: error:0A00042E:SSL routines::tlsv1 alert protocol version",
            "curl: (35) LibreSSL/3.3.6: error:1400410A:SSL routines:CONNECT_CR_SRVR_HELLO:wrong ssl version",
        ] {
            assert!(
                matches!(old_tls_from(Some(35), refused), OldTls::Refused(ref s) if !s.starts_with("curl: ")),
                "{refused}"
            );
        }
        // This machine's own library declining, and a dropped connection, are not the site's answer.
        for not_an_answer in [
            "curl: (35) TLS connect error: error:0A00014D:SSL routines::legacy sigalg disallowed or unsupported",
            "curl: (35) TLS connect error: error:0A0000BF:SSL routines::no protocols available",
            "curl: (35) Recv failure: Connection reset by peer",
            "curl: (59) failed setting cipher list: DEFAULT@SECLEVEL=0",
            // Written for this test rather than seen: a timeout.
            "curl: (28) Operation timed out after 15001 milliseconds",
        ] {
            assert!(
                matches!(old_tls_from(Some(35), not_an_answer), OldTls::CannotTell(_)),
                "{not_an_answer}"
            );
        }
        assert!(
            matches!(old_tls_from(Some(35), ""), OldTls::CannotTell(why) if why.contains("said nothing"))
        );
        assert!(
            matches!(old_tls_from(None, ""), OldTls::CannotTell(_)),
            "killed by a signal"
        );
    }

    #[test]
    fn openssl_is_asked_to_offer_old_tls_and_libressl_is_not() {
        let lowered = vec!["--ciphers", "DEFAULT@SECLEVEL=0"];
        // `curl --version`'s first line, as each printed it on 3 October 2026.
        assert_eq!(
            old_tls_library_args(
                "curl 8.12.1 (Darwin) libcurl/8.12.1 OpenSSL/3.0.17 (SecureTransport) zlib/1.2.13\nRelease-Date: x"
            ),
            lowered
        );
        assert!(
            old_tls_library_args(
                "curl 8.7.1 (x86_64-apple-darwin23.0) libcurl/8.7.1 (SecureTransport) LibreSSL/3.3.6 zlib/1.2.12"
            )
            .is_empty()
        );
        assert!(
            old_tls_library_args("").is_empty(),
            "curl that did not answer"
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
