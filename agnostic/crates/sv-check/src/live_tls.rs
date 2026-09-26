//! Two more questions about the live site, beside `production.rs`: whether its DNS offers Encrypted
//! Client Hello (V12.1.5), and whether its name is on the HSTS preload list (V3.7.4).
//!
//! Neither sends the site anything. The DNS question goes to this computer's own resolver, as any
//! browser's would. The preload list is never fetched: it is a file the owner downloaded on
//! purpose, exactly as the advisory database is, because looking a name up in somebody else's
//! service tells that service which site is being checked.

use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;

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
    /// What was asked, for the owner to see: the DNS question and the list lookup.
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

/// Asks the two questions. `preload` is the text of Chromium's list, when the owner gave one.
pub fn run(dns: &mut dyn Dns, host: &str, preload: Option<&str>) -> Outcome {
    let mut out = Outcome::default();
    // The name without a port: DNS and the preload list know nothing of ports.
    let name = host.split(':').next().unwrap_or(host).to_lowercase();

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
    let entries = value["entries"].as_array().ok_or("it has no `entries`")?;
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
        let bind = if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Real answers from a public resolver on 26 September 2026, to the question `https_query`
    /// asks with id 0x1234: crypto.cloudflare.com, which offers ECH; cloudflare.com, which has an
    /// HTTPS record without it; and github.com, which has none.
    const WITH_ECH: &[u8] = include_bytes!("../tests/fixtures/live/https-with-ech.bin");
    const WITHOUT_ECH: &[u8] = include_bytes!("../tests/fixtures/live/https-without-ech.bin");
    const NO_RECORD: &[u8] = include_bytes!("../tests/fixtures/live/https-none.bin");
    /// Real lines of Chromium's list: its header, `app` and `dev` (whole top-level domains),
    /// `accounts.google.com` and `github.com` with their subdomains, and `g.co` without.
    const PRELOAD: &str = include_str!("../tests/fixtures/live/preload-sample.json");

    struct FakeDns(Result<Vec<ServiceRecord>, String>);

    impl Dns for FakeDns {
        fn https_records(&mut self, _host: &str) -> Result<Vec<ServiceRecord>, String> {
            self.0.clone()
        }
    }

    fn ech() -> FakeDns {
        FakeDns(Ok(vec![ServiceRecord {
            priority: 1,
            keys: vec![1, 4, 5, 6],
        }]))
    }

    fn rules(o: &Outcome) -> Vec<&str> {
        o.findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    fn credits(o: &Outcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    #[test]
    fn the_question_asked_is_the_one_the_real_answers_were_to() {
        let q = https_query(0x1234, "crypto.cloudflare.com").unwrap();
        // The answer repeats the question after its 12-byte header.
        assert_eq!(&WITH_ECH[12..12 + q.len() - 12], &q[12..]);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert!(https_query(1, "bad..name").is_none());
        assert!(https_query(1, &format!("{}.com", "a".repeat(64))).is_none());
    }

    #[test]
    fn real_answers_are_read_for_what_they_offer() {
        let with = https_answer(0x1234, WITH_ECH).unwrap();
        assert!(
            with.iter()
                .any(|r| r.priority > 0 && r.keys.contains(&ECH_KEY)),
            "{with:?}"
        );
        let without = https_answer(0x1234, WITHOUT_ECH).unwrap();
        assert!(!without.is_empty());
        assert!(
            without.iter().all(|r| !r.keys.contains(&ECH_KEY)),
            "{without:?}"
        );
        assert!(https_answer(0x1234, NO_RECORD).unwrap().is_empty());
    }

    #[test]
    fn an_answer_that_is_not_one_is_never_read_as_no_records() {
        // Another question's answer, a cut-off answer, a truncated one, and a server failure: each
        // is an error, never an empty list, which would read as "no ECH".
        assert!(https_answer(0x9999, WITH_ECH).is_err());
        assert!(https_answer(0x1234, &WITH_ECH[..60]).is_err());
        let mut truncated = WITH_ECH.to_vec();
        truncated[2] |= 0x02;
        assert!(https_answer(0x1234, &truncated).is_err());
        let mut failed = WITHOUT_ECH.to_vec();
        failed[3] = (failed[3] & 0xf0) | 2;
        assert!(https_answer(0x1234, &failed).is_err());
    }

    #[test]
    fn ech_offered_is_credited_and_missing_is_found() {
        let o = run(&mut ech(), "example.dev", Some(PRELOAD));
        assert!(credits(&o).contains(&NO_ECH.rule_id), "{:?}", o.findings);
        let o = run(
            &mut FakeDns(Ok(vec![ServiceRecord {
                priority: 1,
                keys: vec![1, 4, 6],
            }])),
            "example.dev",
            Some(PRELOAD),
        );
        assert_eq!(rules(&o), vec![NO_ECH.rule_id]);
        let o = run(&mut FakeDns(Ok(vec![])), "example.dev", Some(PRELOAD));
        assert_eq!(rules(&o), vec![NO_ECH.rule_id]);
    }

    #[test]
    fn a_dns_question_that_could_not_be_asked_settles_nothing() {
        let o = run(
            &mut FakeDns(Err("the resolver did not answer".into())),
            "example.dev",
            Some(PRELOAD),
        );
        assert!(!rules(&o).contains(&NO_ECH.rule_id));
        assert!(!credits(&o).contains(&NO_ECH.rule_id));
        assert!(o.not_assessed.iter().any(|(id, _)| id == "V12.1.5"));
    }

    #[test]
    fn a_record_that_only_points_elsewhere_is_not_read_as_no_ech() {
        let o = run(
            &mut FakeDns(Ok(vec![ServiceRecord {
                priority: 0,
                keys: vec![],
            }])),
            "example.dev",
            Some(PRELOAD),
        );
        assert!(!rules(&o).contains(&NO_ECH.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V12.1.5" && why.contains("points"))
        );
        // Even an alias that carries an `ech` key is not credited: an alias's parameters mean
        // nothing (RFC 9460), and the name it points at was not asked.
        let o = run(
            &mut FakeDns(Ok(vec![ServiceRecord {
                priority: 0,
                keys: vec![ECH_KEY],
            }])),
            "example.dev",
            Some(PRELOAD),
        );
        assert!(!credits(&o).contains(&NO_ECH.rule_id));
    }

    #[test]
    fn the_preload_list_covers_a_name_by_itself_or_a_parent_with_its_subdomains() {
        for (name, entry) in [
            ("github.com", Some("github.com")),
            ("gist.github.com", Some("github.com")),
            ("my-site.dev", Some("dev")),
            ("GitHub.com.", Some("github.com")),
            ("g.co", Some("g.co")),
            ("www.g.co", None),
            ("example.com", None),
        ] {
            assert_eq!(
                preload_entry(PRELOAD, name).unwrap().as_deref(),
                entry,
                "{name}"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_the_list_is_said_so() {
        assert!(preload_entry("not json", "github.com").is_err());
        assert!(preload_entry("{\"entries\": []}", "github.com").is_err());
        assert!(preload_entry("{\"pins\": []}", "github.com").is_err());
        let o = run(&mut ech(), "github.com", Some("{}"));
        assert!(o.not_assessed.iter().any(|(id, _)| id == "V3.7.4"));
        assert!(!rules(&o).contains(&NOT_PRELOADED.rule_id));
    }

    #[test]
    fn preloaded_is_credited_missing_is_found_and_no_list_is_said() {
        let o = run(&mut ech(), "api.github.com", Some(PRELOAD));
        assert!(credits(&o).contains(&NOT_PRELOADED.rule_id));
        let o = run(&mut ech(), "shop.example.com", Some(PRELOAD));
        assert_eq!(rules(&o), vec![NOT_PRELOADED.rule_id]);
        let o = run(&mut ech(), "shop.example.com", None);
        assert!(rules(&o).is_empty() && !credits(&o).contains(&NOT_PRELOADED.rule_id));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V3.7.4" && why.contains("--hsts-preload"))
        );
    }

    #[test]
    fn a_port_in_the_address_is_not_part_of_the_name() {
        let o = run(&mut ech(), "api.github.com:8443", Some(PRELOAD));
        assert!(
            credits(&o).contains(&NOT_PRELOADED.rule_id),
            "{:?}",
            o.findings
        );
    }

    #[test]
    fn an_answer_missing_its_last_byte_is_not_read() {
        // Every field before the last parameter's value is there, so without its length checked
        // this would read as a complete answer.
        for answer in [WITH_ECH, WITHOUT_ECH] {
            assert!(https_answer(0x1234, &answer[..answer.len() - 1]).is_err());
        }
    }

    #[test]
    fn a_real_answer_to_another_question_or_with_a_failure_is_not_read() {
        assert!(https_answer(0x4321, WITHOUT_ECH).is_err());
        assert!(https_answer(0x0000, NO_RECORD).is_err());
        let mut truncated = NO_RECORD.to_vec();
        truncated[2] |= 0x02;
        assert!(https_answer(0x1234, &truncated).is_err());
        let mut refused = NO_RECORD.to_vec();
        refused[3] = (refused[3] & 0xf0) | 5;
        assert!(https_answer(0x1234, &refused).is_err());
    }

    #[test]
    fn only_a_forced_https_entry_counts() {
        let list = r#"// a comment
{ "entries": [
    { "name": "example.com", "policy": "custom", "mode": "report-only", "include_subdomains": true },
    { "name": "example.org", "policy": "custom", "mode": "force-https" }
] }"#;
        assert_eq!(preload_entry(list, "example.com").unwrap(), None);
        assert_eq!(preload_entry(list, "shop.example.com").unwrap(), None);
        assert_eq!(
            preload_entry(list, "example.org").unwrap().as_deref(),
            Some("example.org")
        );
    }

    #[test]
    fn a_parent_entry_without_subdomains_does_not_cover_them() {
        let list = r#"{ "entries": [ { "name": "example.org", "mode": "force-https" } ] }"#;
        assert_eq!(preload_entry(list, "www.example.org").unwrap(), None);
        let o = run(&mut ech(), "www.g.co", Some(PRELOAD));
        assert_eq!(rules(&o), vec![NOT_PRELOADED.rule_id]);
    }

    #[test]
    fn an_empty_list_is_not_a_list_the_site_is_missing_from() {
        let o = run(&mut ech(), "shop.example.com", Some("{ \"entries\": [] }"));
        assert!(!rules(&o).contains(&NOT_PRELOADED.rule_id));
        assert!(o.not_assessed.iter().any(|(id, _)| id == "V3.7.4"));
    }

    #[test]
    fn with_a_port_the_name_is_still_found_on_the_list_and_asked_of_dns() {
        struct Seen(Vec<String>);
        impl Dns for Seen {
            fn https_records(&mut self, host: &str) -> Result<Vec<ServiceRecord>, String> {
                self.0.push(host.to_owned());
                Ok(vec![])
            }
        }
        let mut dns = Seen(Vec::new());
        run(&mut dns, "github.com:8443", Some(PRELOAD));
        assert_eq!(dns.0, vec!["github.com".to_owned()]);
    }

    #[test]
    fn a_resolver_that_does_not_answer_is_not_a_missing_record() {
        let o = run(
            &mut FakeDns(Err("the resolver at 10.0.0.1 did not answer".into())),
            "shop.example.com",
            None,
        );
        assert!(o.findings.is_empty(), "{:?}", o.findings);
    }

    #[test]
    fn an_alias_beside_nothing_else_is_said_and_neither_credited_nor_found() {
        let o = run(
            &mut FakeDns(Ok(vec![ServiceRecord {
                priority: 0,
                keys: vec![1, ECH_KEY],
            }])),
            "shop.example.com",
            None,
        );
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(o.verified.is_empty());
        assert!(
            o.not_assessed
                .iter()
                .any(|(_, why)| why.contains("points at another name"))
        );
    }

    #[test]
    fn an_answer_cut_inside_its_ech_configuration_is_not_read_as_offering_it() {
        // Two bytes short: the `ech` key and its length are there, its configuration is not.
        assert!(https_answer(0x1234, &WITH_ECH[..WITH_ECH.len() - 2]).is_err());
    }

    #[test]
    fn a_site_whose_only_entry_is_not_forced_https_is_found_missing() {
        let list = r#"{ "entries": [ { "name": "example.com", "mode": "report-only", "include_subdomains": true } ] }"#;
        let o = run(&mut ech(), "example.com", Some(list));
        assert_eq!(rules(&o), vec![NOT_PRELOADED.rule_id]);
    }
}
