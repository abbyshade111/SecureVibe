//! Three more questions only the live site can answer, beside `production.rs`: whether its TLS
//! handshake staples an OCSP response (V12.1.4), whether its DNS offers Encrypted Client Hello
//! (V12.1.5), and whether its name is on the HSTS preload list (V3.7.4).
//!
//! The limits `sv probe` keeps are kept here, and one is added. The handshake is one more
//! connection to the same host, and nothing is sent in it. The DNS question goes to this computer's
//! own resolver, as any browser's would, and never to the site. The preload list is never fetched:
//! it is a file the owner downloaded on purpose, exactly as the advisory database is, because
//! looking a name up in somebody else's service tells that service which site is being checked.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;

/// What one TLS handshake showed about revocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Handshake {
    /// Absent when the handshake happened; otherwise why it did not.
    pub failure: Option<String>,
    /// Whether the server sent an OCSP response in the handshake, and whether it said "good".
    pub stapled: bool,
    pub stapled_good: bool,
    /// Whether the site's certificate names an OCSP responder at all. `None` when it could not be
    /// read.
    pub names_responder: Option<bool>,
}

pub trait Tls {
    fn handshake(&mut self, host: &str) -> Handshake;
}

/// One HTTPS resource record (RFC 9460): its priority (0 is an alias), and the keys of the
/// parameters it carries. Key 5 is `ech`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRecord {
    pub priority: u16,
    pub keys: Vec<u16>,
}

pub trait Dns {
    /// The HTTPS records for this name, following whatever the resolver followed. An error when
    /// the question could not be asked or the answer could not be read — never an empty list.
    fn https_records(&mut self, host: &str) -> Result<Vec<ServiceRecord>, String>;
}

const ECH_KEY: u16 = 5;

#[derive(Debug, Default)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub verified: Vec<Verified>,
    pub not_assessed: Vec<(String, String)>,
    /// What was asked, for the owner to see: the handshake, the DNS question, the list lookup.
    pub asked: Vec<String>,
}

struct Rule {
    rule_id: &'static str,
    requirement_ids: &'static [&'static str],
    cwe: &'static [&'static str],
    title: &'static str,
    impact: &'static str,
    fix: &'static str,
}

const NOT_STAPLED: Rule = Rule {
    rule_id: "live.ocsp-not-stapled",
    requirement_ids: &["V12.1.4"],
    cwe: &["CWE-299"],
    title: "The site's certificate names an OCSP responder, and the handshake staples no answer",
    impact: "A browser that wants to know the certificate has not been revoked has to ask the \
             certificate authority itself, which tells the authority who is visiting the site, or \
             skip the question, which is what most browsers do.",
    fix: "Turn on OCSP stapling in the web server or load balancer that ends TLS (`ssl_stapling on` \
          in nginx, `SSLUseStapling on` in Apache; most hosted load balancers do it already).",
};

const NO_ECH: Rule = Rule {
    rule_id: "live.ech-not-offered",
    requirement_ids: &["V12.1.5"],
    cwe: &["CWE-200"],
    title: "The site does not offer Encrypted Client Hello",
    impact: "The name of the site a visitor connects to travels in plain text at the start of every \
             connection, visible to anybody on the network path.",
    fix: "Turn on Encrypted Client Hello where TLS ends. It is published in the site's DNS as an \
          `ech` parameter in an HTTPS record; hosts such as Cloudflare offer it as a setting.",
};

const NOT_PRELOADED: Rule = Rule {
    rule_id: "live.hsts-not-preloaded",
    requirement_ids: &["V3.7.4"],
    cwe: &["CWE-319"],
    title: "The site is not on the HSTS preload list",
    impact: "A visitor's first request to the site can still go over plain HTTP, before any \
             Strict-Transport-Security header has been seen, and be intercepted there.",
    fix: "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` from the \
          site's top-level domain and submit it at hstspreload.org.",
};

fn finding(rule: &Rule, host: &str, description: String) -> Finding {
    Finding {
        rule_id: rule.rule_id.to_owned(),
        title: rule.title.to_owned(),
        severity: Severity::Low,
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
        cwe: rule.cwe.iter().map(|s| (*s).to_owned()).collect(),
        description,
        impact: rule.impact.to_owned(),
        fix: rule.fix.to_owned(),
    }
}

/// Asks the three questions. `preload` is the text of Chromium's list, when the owner gave one.
pub fn run(tls: &mut dyn Tls, dns: &mut dyn Dns, host: &str, preload: Option<&str>) -> Outcome {
    let mut out = Outcome::default();
    // The name without a port: DNS and the preload list know nothing of ports.
    let name = host.split(':').next().unwrap_or(host).to_lowercase();

    // V12.1.4: one handshake.
    out.asked.push(format!("one TLS handshake with {host}, asking for a stapled OCSP answer"));
    let shake = tls.handshake(host);
    match (&shake.failure, shake.stapled, shake.names_responder) {
        (Some(why), _, _) => out.not_assessed.push((
            "V12.1.4".to_owned(),
            format!("Whether the handshake staples an OCSP answer: the handshake did not complete ({why})."),
        )),
        (None, true, _) if shake.stapled_good => out.verified.push(Verified::new(
            NOT_STAPLED.rule_id,
            NOT_STAPLED.requirement_ids,
            format!("the TLS handshake with {host} stapled an OCSP answer saying the certificate is good"),
        )),
        (None, true, _) => out.findings.push(Finding {
            title: "The stapled OCSP answer does not say the certificate is good".to_owned(),
            severity: Severity::High,
            ..finding(
                &NOT_STAPLED,
                &name,
                format!(
                    "The TLS handshake with {host} stapled an OCSP answer, and it did not say \
                     `good`: the certificate may have been revoked, or the answer is stale."
                ),
            )
        }),
        (None, false, Some(true)) => out.findings.push(finding(
            &NOT_STAPLED,
            &name,
            format!(
                "The certificate {host} presents names an OCSP responder, and the handshake sent \
                 no OCSP answer with it."
            ),
        )),
        (None, false, Some(false)) => out.not_assessed.push((
            "V12.1.4".to_owned(),
            format!(
                "The certificate {host} presents names no OCSP responder, so there is nothing to \
                 staple; some authorities, Let's Encrypt among them, now publish revocation only \
                 in lists. Whether that meets what your security notes decided about revocation \
                 is a question for them."
            ),
        )),
        (None, false, None) => out.not_assessed.push((
            "V12.1.4".to_owned(),
            format!(
                "The handshake with {host} stapled no OCSP answer, and whether its certificate \
                 names a responder could not be read, so it cannot be said whether one was owed."
            ),
        )),
    }

    // V12.1.5: the site's HTTPS records, from this computer's resolver.
    out.asked.push(format!(
        "this computer's DNS resolver, for the HTTPS records of {name}"
    ));
    match dns.https_records(&name) {
        Err(why) => out.not_assessed.push((
            "V12.1.5".to_owned(),
            format!("Whether the site offers Encrypted Client Hello: its DNS could not be asked ({why})."),
        )),
        Ok(records) => {
            let service: Vec<&ServiceRecord> = records.iter().filter(|r| r.priority > 0).collect();
            if service.iter().any(|r| r.keys.contains(&ECH_KEY)) {
                out.verified.push(Verified::new(
                    NO_ECH.rule_id,
                    NO_ECH.requirement_ids,
                    format!("an Encrypted Client Hello configuration in the HTTPS record for {name}"),
                ));
            } else if service.is_empty() && !records.is_empty() {
                out.not_assessed.push((
                    "V12.1.5".to_owned(),
                    format!(
                        "The HTTPS record for {name} only points at another name, which this does \
                         not follow, so whether that one offers Encrypted Client Hello was not asked."
                    ),
                ));
            } else {
                out.findings.push(finding(
                    &NO_ECH,
                    &name,
                    if records.is_empty() {
                        format!(
                            "{name} has no HTTPS record in DNS, which is where a browser learns \
                             that Encrypted Client Hello is offered."
                        )
                    } else {
                        format!("The HTTPS record for {name} carries no `ech` parameter.")
                    },
                ));
            }
        }
    }

    // V3.7.4: the list the owner gave, if any.
    match preload {
        None => out.not_assessed.push((
            "V3.7.4".to_owned(),
            "Whether the site is on the HSTS preload list: `sv` never looks a name up in somebody \
             else's service. Download Chromium's list (net/http/transport_security_state_static.json \
             in the Chromium source) and pass it with --hsts-preload FILE."
                .to_owned(),
        )),
        Some(text) => match preload_entry(text, &name) {
            Err(why) => out.not_assessed.push((
                "V3.7.4".to_owned(),
                format!("The HSTS preload list given could not be read: {why}."),
            )),
            Ok(found) => {
                out.asked.push("the HSTS preload list you gave, read here".to_owned());
                match found {
                    Some(entry) => out.verified.push(Verified::new(
                        NOT_PRELOADED.rule_id,
                        NOT_PRELOADED.requirement_ids,
                        if entry == name {
                            format!("{name} on the HSTS preload list you gave")
                        } else {
                            format!(
                                "{name} covered on the HSTS preload list you gave, by the entry \
                                 for {entry} and its subdomains"
                            )
                        },
                    )),
                    None => out.findings.push(finding(
                        &NOT_PRELOADED,
                        &name,
                        format!(
                            "Neither {name} nor any name above it is on the HSTS preload list you \
                             gave with its subdomains."
                        ),
                    )),
                }
            }
        },
    }
    out
}

/// The preload entry covering this name: the name itself, or a name above it whose entry covers
/// its subdomains. `Ok(None)` when none does; an error when the text is not the list.
///
/// The file is Chromium's `transport_security_state_static.json`: JSON once its `//` comment lines
/// are taken out, with every entry `force-https` today. An entry of another mode is not counted.
pub fn preload_entry(text: &str, name: &str) -> Result<Option<String>, String> {
    let json: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let value: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| format!("it is not the list's JSON ({e})"))?;
    let entries = value["entries"]
        .as_array()
        .ok_or("it has no `entries`")?;
    if entries.is_empty() {
        return Err("it has no entries".to_owned());
    }
    let name = name.trim_end_matches('.').to_lowercase();
    let labels: Vec<&str> = name.split('.').collect();
    for start in 0..labels.len() {
        let candidate = labels[start..].join(".");
        let exact = start == 0;
        let found = entries.iter().any(|e| {
            e["name"].as_str() == Some(candidate.as_str())
                && e["mode"].as_str() == Some("force-https")
                && (exact || e["include_subdomains"].as_bool() == Some(true))
        });
        if found {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

// ------------------------------------------------------------------------------------------------
// DNS, spoken directly: one question over UDP to the resolver this computer is set up with.

/// A question for the HTTPS records (type 65) of a name.
pub fn https_query(id: u16, name: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    // Recursion desired; one question.
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&[0, 65, 0, 1]);
    Some(out)
}

/// Reads the answer to [`https_query`]: the HTTPS records in it, or why it cannot be read.
pub fn https_answer(id: u16, data: &[u8]) -> Result<Vec<ServiceRecord>, String> {
    let u16_at = |i: usize| -> Result<u16, String> {
        data.get(i..i + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or_else(|| "the answer is cut short".to_owned())
    };
    if u16_at(0)? != id {
        return Err("the answer is not to the question asked".to_owned());
    }
    let flags = u16_at(2)?;
    if flags & 0x0200 != 0 {
        return Err("the answer was too long for one UDP message".to_owned());
    }
    match flags & 0x000f {
        0 | 3 => {} // no error, or no such name: both mean "no records", which is an answer.
        code => return Err(format!("the resolver answered with error code {code}")),
    }
    let questions = u16_at(4)?;
    let answers = u16_at(6)?;
    // A name anywhere in the message, possibly compressed; returns where it ends.
    let skip_name = |mut i: usize| -> Result<usize, String> {
        loop {
            let len = *data.get(i).ok_or("the answer is cut short")?;
            match len {
                0 => return Ok(i + 1),
                l if l & 0xc0 == 0xc0 => return Ok(i + 2),
                l => i += 1 + l as usize,
            }
        }
    };
    let mut i = 12;
    for _ in 0..questions {
        i = skip_name(i)? + 4;
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        i = skip_name(i)?;
        let kind = u16_at(i)?;
        let length = u16_at(i + 8)? as usize;
        let start = i + 10;
        let end = start + length;
        if end > data.len() {
            return Err("the answer is cut short".to_owned());
        }
        if kind == 65 {
            let priority = u16_at(start)?;
            // The target name in the record is never compressed (RFC 9460).
            let mut j = skip_name(start + 2)?;
            let mut keys = Vec::new();
            while j + 4 <= end {
                keys.push(u16_at(j)?);
                j += 4 + u16_at(j + 2)? as usize;
            }
            records.push(ServiceRecord { priority, keys });
        }
        i = end;
    }
    Ok(records)
}

/// Asks the first resolver named in `/etc/resolv.conf`.
pub struct SystemDns;

impl Dns for SystemDns {
    fn https_records(&mut self, host: &str) -> Result<Vec<ServiceRecord>, String> {
        let conf = std::fs::read_to_string("/etc/resolv.conf")
            .map_err(|_| "there is no /etc/resolv.conf to find a resolver in".to_owned())?;
        let server: std::net::IpAddr = conf
            .lines()
            .filter_map(|l| l.trim().strip_prefix("nameserver"))
            .find_map(|rest| rest.trim().split('%').next()?.parse().ok())
            .ok_or("/etc/resolv.conf names no resolver")?;
        let id = std::process::id() as u16 ^ 0x5ab1;
        let query = https_query(id, host).ok_or("the name cannot be asked about")?;
        let bind = if server.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = std::net::UdpSocket::bind(bind).map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .map_err(|e| e.to_string())?;
        socket
            .send_to(&query, (server, 53))
            .map_err(|e| format!("the resolver at {server} could not be reached ({e})"))?;
        let mut buf = [0u8; 4096];
        let (n, _) = socket
            .recv_from(&mut buf)
            .map_err(|_| format!("the resolver at {server} did not answer"))?;
        https_answer(id, &buf[..n])
    }
}

// ------------------------------------------------------------------------------------------------
// The handshake, through the `openssl` command, as `production.rs` goes through `curl`.

/// Reads what `openssl s_client -status` printed about a stapled OCSP answer.
pub fn read_stapling(printed: &str) -> (bool, bool) {
    if printed.contains("OCSP response: no response sent") {
        return (false, false);
    }
    let stapled = printed.contains("OCSP Response Status: successful");
    let good = stapled && printed.contains("Cert Status: good");
    (stapled, good)
}

/// The first certificate `openssl s_client` printed, as PEM.
pub fn first_certificate(printed: &str) -> Option<String> {
    let start = printed.find("-----BEGIN CERTIFICATE-----")?;
    let end_marker = "-----END CERTIFICATE-----";
    let end = printed[start..].find(end_marker)? + start + end_marker.len();
    Some(format!("{}\n", &printed[start..end]))
}

pub struct Openssl;

impl Openssl {
    pub fn available() -> bool {
        std::process::Command::new("openssl")
            .arg("version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    /// Runs openssl with this input, giving up after `seconds`.
    fn run(args: &[&str], input: &[u8], seconds: u64) -> Result<String, String> {
        use std::io::{Read, Write};
        let mut child = std::process::Command::new("openssl")
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| format!("openssl could not be started: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(input);
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("no answer within {seconds} seconds"));
                }
            }
        }
        let mut out = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_string(&mut out);
        }
        Ok(out)
    }
}

impl Tls for Openssl {
    fn handshake(&mut self, host: &str) -> Handshake {
        let name = host.split(':').next().unwrap_or(host);
        let address = if host.contains(':') {
            host.to_owned()
        } else {
            format!("{host}:443")
        };
        // Nothing is sent after the handshake: stdin is closed at once.
        let printed = match Self::run(
            &["s_client", "-connect", &address, "-servername", name, "-status"],
            b"",
            20,
        ) {
            Ok(printed) => printed,
            Err(why) => {
                return Handshake {
                    failure: Some(why),
                    ..Default::default()
                };
            }
        };
        let Some(certificate) = first_certificate(&printed) else {
            return Handshake {
                failure: Some("no certificate came back".to_owned()),
                ..Default::default()
            };
        };
        let (stapled, stapled_good) = read_stapling(&printed);
        let names_responder = Self::run(&["x509", "-noout", "-ocsp_uri"], certificate.as_bytes(), 10)
            .ok()
            .map(|uri| uri.lines().any(|l| l.trim().starts_with("http")));
        Handshake {
            failure: None,
            stapled,
            stapled_good,
            names_responder,
        }
    }
}
