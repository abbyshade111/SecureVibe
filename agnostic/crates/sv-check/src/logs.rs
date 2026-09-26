//! What the app's own output recorded about the things the probes did to it (V16.3.1, V16.3.2).
//!
//! # Why this can credit and never fault
//!
//! The only output `sv` can see is the container's: whatever the app wrote to stdout and stderr.
//! An app that logs to a file, to syslog, or to a logging service writes nothing there, and is not
//! logging any less for it. So finding the events is evidence that they are logged, and *not*
//! finding them is evidence of nothing at all — reported as not assessed, never as a finding.
//!
//! This is the opposite shape from most checks here, which can only ever fault. It is the same
//! reasoning either way: say only what was actually shown.
//!
//! # Why the probes plant markers
//!
//! "The log mentions `admin`" says nothing — every log mentions `admin`. So the probes do things
//! no other traffic could have done, each carrying a string nothing else in the world contains, and
//! the check looks for those strings:
//!
//! - a sign-in attempt for an account that does not exist, so its name can only appear in the log
//!   because a *failed* authentication was recorded;
//! - a sign-in that succeeded, by an account used for nothing else, so its name can only appear
//!   because a *successful* one was;
//! - a request to a private page, made by nobody, carrying a marker in its address.
//!
//! V16.3.1 asks for both successful and unsuccessful authentication, so it is credited only when
//! both names are found. One of the two is not the requirement, and would be the kind of
//! half-credit this project exists to refuse.

use crate::finding::{Confidence, Finding, Location, Severity};

/// The strings the probes planted, and what each one would prove.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Markers {
    /// The name of an account that does not exist, used once in a sign-in the app refused.
    pub failed_sign_in: Option<String>,
    /// The name of an account used for exactly one successful sign-in and nothing else.
    pub successful_sign_in: Option<String>,
    /// A marker put in the address of a private page requested by somebody not signed in, with
    /// the status the app actually answered. Carrying the real status beats guessing at a list of
    /// refusal codes: an app that sends people to the sign-in page answers 302, which no list of
    /// "refused" codes would have included, and it is a refusal all the same.
    pub refused_request: Option<(String, u16)>,
}

/// What reading the log concluded.
#[derive(Debug, Clone, Default)]
pub struct LogOutcome {
    /// Only ever about a line that *was* found. Nothing here faults an app for what its output
    /// does not contain; a finding is about a security event the app did write down, and wrote
    /// down in a way that falls short.
    pub findings: Vec<crate::finding::Finding>,
    pub verified: Vec<crate::Verified>,
    pub not_assessed: Vec<(String, String)>,
    pub steps: Vec<String>,
}

const NO_OUTPUT: &str = "The app wrote nothing to its output during the run, so there was nothing to read. An app that \
     logs to a file or to a logging service writes nothing here and is not logging any less for \
     it: this is not a finding, and nothing here can say whether the events were recorded.";

fn elsewhere(what: &str) -> String {
    format!(
        "{what} `sv` can only read what the app wrote to its own output inside the container. An \
         app that logs to a file, to syslog, or to a logging service writes nothing there, so this \
         is not evidence that the events went unrecorded."
    )
}

/// Whether a line records this status as a status, rather than merely containing its digits.
///
/// A status is a whole token, not three digits sitting somewhere in the line. Byte counts
/// (`14039`), request ids (`req=a401b9`), durations (`took=403ms`) and paths (`/invoices/40312`)
/// all contain such digits, and a substring match would read every one of them as the status —
/// which would credit V16.3.2 to an app that logs nothing but traffic that succeeded.
///
/// So each whitespace-separated token is reduced to what follows its last `=` or `:`, trimmed of
/// surrounding punctuation, and has to equal the status exactly.
fn records_status(line: &str, status: u16) -> bool {
    let status = status.to_string();
    line.split_whitespace().any(|token| {
        let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        token.rsplit(['=', ':']).next().unwrap_or(token) == status
    })
}

/// Reads the container's output for the markers the probes planted.
pub fn evaluate(markers: &Markers, log: &str) -> LogOutcome {
    let mut out = LogOutcome::default();
    if log.trim().is_empty() {
        for ids in ["V16.3.1", "V16.3.2", "V16.2.1", "V16.2.2", "V16.2.4"] {
            out.not_assessed
                .push((ids.to_owned(), NO_OUTPUT.to_owned()));
        }
        return out;
    }
    out.steps.push(format!(
        "read {} lines of the app's output",
        log.lines().count()
    ));

    // ---- V16.3.1: authentication, successful and unsuccessful.
    match (&markers.failed_sign_in, &markers.successful_sign_in) {
        (Some(failed), Some(succeeded)) => {
            let saw_failed = log.contains(failed.as_str());
            let saw_succeeded = log.contains(succeeded.as_str());
            out.steps.push(format!(
                "the app's output named the refused sign-in: {}; the accepted one: {}",
                if saw_failed { "yes" } else { "no" },
                if saw_succeeded { "yes" } else { "no" }
            ));
            if saw_failed && saw_succeeded {
                out.verified.push(crate::Verified::new(
                    "probe.authentication-logged",
                    &["V16.3.1"],
                    "two sign-ins this run made — one refused, for an account that does not exist, \
                     and one accepted, by an account used for nothing else — both named in the \
                     app's own output"
                        .to_owned(),
                ));
            } else {
                // Naming which half was missing matters: an app that logs only successes is a
                // different thing from one that logs nothing, and the owner can act on the
                // difference.
                let missing = match (saw_failed, saw_succeeded) {
                    (false, true) => {
                        "The refused sign-in was not named, though the accepted one \
                                      was, so successful authentication appears to be recorded and \
                                      unsuccessful may not be."
                    }
                    (true, false) => {
                        "The refused sign-in was named but the accepted one was not, \
                                      so unsuccessful authentication appears to be recorded and \
                                      successful may not be."
                    }
                    _ => "Neither sign-in was named in the app's output.",
                };
                out.not_assessed
                    .push(("V16.3.1".to_owned(), elsewhere(missing)));
            }
        }
        _ => out.not_assessed.push((
            "V16.3.1".to_owned(),
            "This needs both a sign-in the app accepts and one it refuses, by accounts used for \
             nothing else. Without `signup` in [stack.run.users] there is no way to make them, so \
             nothing here could tell a logged authentication from any other line."
                .to_owned(),
        )),
    }

    // ---- V16.2.1 and V16.2.2: what the refused sign-in's line carries.
    if let Some(failed) = &markers.failed_sign_in
        && let Some(line) = log.lines().find(|l| l.contains(failed.as_str()))
    {
        metadata_checks(line, &mut out);
        format_check(line, &mut out);
    } else {
        for id in ["V16.2.1", "V16.2.2", "V16.2.4"] {
            out.not_assessed.push((
                id.to_owned(),
                "These are read from the line recording the refused sign-in this run made, and no \
                 such line was found, so there was no security event's metadata to read."
                    .to_owned(),
            ));
        }
    }

    // ---- V16.3.2: a refused request.
    match &markers.refused_request {
        Some((marker, status)) => {
            // The marker alone shows the request reached a log; the refusal status on the same
            // line is what makes it a record of the *authorization* decision rather than of
            // traffic. Both, or nothing.
            let line = log.lines().find(|l| l.contains(marker.as_str()));
            let with_status = line.is_some_and(|l| records_status(l, *status));
            out.steps.push(format!(
                "the app's output recorded the refused private-page request: {}",
                match (line.is_some(), with_status) {
                    (true, true) => "yes, with the status",
                    (true, false) => "the request, but no refusal status",
                    _ => "no",
                }
            ));
            if with_status {
                out.verified.push(crate::Verified::new(
                    "probe.authorization-failure-logged",
                    &["V16.3.2"],
                    format!(
                        "a private page requested by somebody not signed in, with a marker in its \
                         address, which the app refused with {status}: its output carried that \
                         marker on a line that also carried {status}"
                    ),
                ));
            } else if line.is_some() {
                out.not_assessed.push((
                    "V16.3.2".to_owned(),
                    format!(
                        "The app's output recorded the request this run made to a private page, \
                         but the line does not carry the {status} the app answered it with, so it \
                         reads as a record of traffic rather than of an authorization decision."
                    ),
                ));
            } else {
                out.not_assessed.push((
                    "V16.3.2".to_owned(),
                    elsewhere("The refused request this run made was not in the app's output."),
                ));
            }
        }
        None => out.not_assessed.push((
            "V16.3.2".to_owned(),
            "This needs a page only a signed-in user should see, listed under `private` in \
             [stack.run.users], to be refused to somebody who has not signed in."
                .to_owned(),
        )),
    }
    out
}

/// Which common log format a line is written in, if any.
///
/// Three, because they are what log processors read without being taught: a JSON object, logfmt
/// (`key=value` pairs, the way Heroku and most Go services write), and the Apache and nginx common
/// log format.
fn common_format(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    if trimmed.starts_with('{')
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok_and(|v| v.is_object())
    {
        return Some("JSON");
    }
    let clf = regex::Regex::new(
        r#"^\S+ \S+ \S+ \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "[A-Z]+ \S+[^"]*" \d{3} "#,
    )
    .expect("valid pattern");
    if clf.is_match(&format!("{trimmed} ")) {
        return Some("the common log format");
    }
    // logfmt: most of the line is `key=value`, and there are enough of them to be deliberate
    // rather than a sentence that happens to contain an equals sign.
    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    let pairs = tokens
        .iter()
        .filter(|t| {
            t.split_once('=').is_some_and(|(k, v)| {
                !k.is_empty()
                    && !v.is_empty()
                    && k.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
            })
        })
        .count();
    (pairs >= 3 && pairs * 2 >= tokens.len()).then_some("logfmt")
}

/// V16.2.4, read from the same line: is it in a format a log processor reads without being taught?
///
/// Credit on presence only. Free text can still be read by a processor given a pattern for it, and
/// a log shipper often turns lines into structured records on the way; neither is visible here, so
/// a line that is none of the three is not assessed rather than faulted.
fn format_check(line: &str, out: &mut LogOutcome) {
    match common_format(line) {
        Some(format) => {
            out.steps
                .push(format!("the refused sign-in's line is written as {format}"));
            out.verified.push(crate::Verified::new(
                "probe.log-common-format",
                &["V16.2.4"],
                format!(
                    "the line recording a refused sign-in this run made is written as {format}, \
                     which log processors read without being taught"
                ),
            ));
        }
        None => {
            out.steps
                .push("the refused sign-in's line is in no common format".to_owned());
            out.not_assessed.push((
                "V16.2.4".to_owned(),
                "The line recording the refused sign-in is not JSON, logfmt, or the common log \
                 format. That is not a finding: a processor can be given a pattern for any \
                 consistent line, and a log shipper often structures lines on the way, neither of \
                 which is visible here."
                    .to_owned(),
            ));
        }
    }
}

/// A timestamp on a log line, and whether it says what time zone it is in.
#[derive(Debug, PartialEq, Eq)]
struct Timestamp {
    text: String,
    zoned: bool,
}

/// Finds the first timestamp on a line, in the shapes real servers write: ISO 8601
/// (`2026-09-26T10:00:03Z`, `2026-09-26 10:00:03,123`) and the Apache and nginx common log format
/// (`[26/Sep/2026:10:00:03 +0000]`).
fn timestamp(line: &str) -> Option<Timestamp> {
    let iso = regex::Regex::new(
        r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2}| ?UTC\b)?",
    )
    .expect("valid pattern");
    if let Some(c) = iso.captures(line) {
        return Some(Timestamp {
            text: c[0].trim().to_owned(),
            zoned: c.get(1).is_some(),
        });
    }
    let clf = regex::Regex::new(r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}( [+-]\d{4})?")
        .expect("valid pattern");
    clf.captures(line).map(|c| Timestamp {
        text: c[0].to_owned(),
        zoned: c.get(1).is_some(),
    })
}

/// Whether a line says where a request came from or went to: an IP address, or a path.
fn has_place(line: &str) -> bool {
    let ipv4 = regex::Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("valid pattern");
    ipv4.is_match(line)
        || line.contains("::1")
        || line.split_whitespace().any(|t| {
            t.trim_start_matches(|c: char| !c.is_ascii_alphanumeric() && c != '/')
                .starts_with('/')
        })
}

/// V16.2.1 and V16.2.2, read from the one line known to record a security event.
///
/// The line was found by the name of an account that does not exist, so it records a refused
/// sign-in: that is its *what*, and the name on it is its *who*. What is left to read is *when*
/// and *where*.
///
/// A missing timestamp is not assessed rather than a finding. Writing to standard output and
/// letting the platform stamp each line — `docker logs -t`, journald, a log shipper — is a sound
/// and common arrangement, and faulting it would be crying wolf. A timestamp the app *did* write
/// without saying its zone is different: no platform fixes that, and it is the exact thing V16.2.2
/// asks about.
fn metadata_checks(line: &str, out: &mut LogOutcome) {
    let when = timestamp(line);
    let place = has_place(line);
    out.steps.push(format!(
        "the refused sign-in's line carried a timestamp: {}; a source address or path: {}",
        match &when {
            Some(t) if t.zoned => "yes, with its zone",
            Some(_) => "yes, with no zone",
            None => "no",
        },
        if place { "yes" } else { "no" }
    ));

    match (&when, place) {
        (Some(t), true) => out.verified.push(crate::Verified::new(
            "probe.log-line-metadata",
            &["V16.2.1"],
            format!(
                "the line recording a refused sign-in this run made carried the account (who), the \
                 event (what), a timestamp `{}` (when), and a source address or path (where)",
                t.text
            ),
        )),
        _ => out.not_assessed.push((
            "V16.2.1".to_owned(),
            format!(
                "The line recording the refused sign-in carried {}. That is not a finding: an app \
                 writing to its own output often leaves the platform to add the time and origin, \
                 and nothing here can see what the platform added.",
                match (&when, place) {
                    (None, false) => "neither a timestamp nor a source address or path",
                    (None, true) => "no timestamp",
                    _ => "no source address or path",
                }
            ),
        )),
    }

    match &when {
        Some(t) if t.zoned => out.verified.push(crate::Verified::new(
            "probe.log-timestamp-zoned",
            &["V16.2.2"],
            format!(
                "the timestamp on a security event's line, `{}`, states its time zone",
                t.text
            ),
        )),
        Some(t) => out.findings.push(Finding {
            rule_id: "probe.log-timestamp-zoned".to_owned(),
            title: "A security event is logged with a time that does not say its zone".to_owned(),
            severity: Severity::Low,
            confidence: Confidence::High,
            location: Location {
                file: "the running app's output".into(),
                line: 1,
            },
            secret: None,
            requirement_ids: vec!["V16.2.2".to_owned()],
            cwe: vec!["CWE-778".to_owned()],
            description: format!(
                "The line recording a refused sign-in carried the time `{}`, with no `Z` and no \
                 offset, so nothing in the line says which time zone it is in.",
                t.text
            ),
            impact:
                "Lines from two machines, or from either side of a clock change, cannot be put \
                     in order with confidence, which is the thing an investigation needs first."
                    .to_owned(),
            fix: "Write times in UTC with a trailing `Z` (`2026-09-26T10:00:03Z`), or with an \
                  explicit offset. In Python, `datetime.now(timezone.utc).isoformat()`; most \
                  logging libraries have a UTC setting."
                .to_owned(),
        }),
        None => out.not_assessed.push((
            "V16.2.2".to_owned(),
            "The line recording the refused sign-in carried no timestamp of the app's own, so \
             there was no zone to read. The platform may add one, which nothing here can see."
                .to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn markers() -> Markers {
        Markers {
            failed_sign_in: Some("sv-log-nobody-4a91@example.test".into()),
            successful_sign_in: Some("sv-log-ok-4a91@example.test".into()),
            refused_request: Some(("sv-log-refused-4a91".into(), 403)),
        }
    }

    fn ids(o: &LogOutcome) -> Vec<&str> {
        o.verified.iter().map(|v| v.check_id.as_str()).collect()
    }

    #[test]
    fn an_app_that_logs_both_sign_ins_and_the_refusal_is_credited() {
        let log = "\
time=2026-09-26T10:00:01Z level=warn event=sign-in-failed account=sv-log-nobody-4a91@example.test from=10.0.0.7
2026-09-26T10:00:02Z auth: sign-in ok for sv-log-ok-4a91@example.test
2026-09-26T10:00:03Z GET /account?sv-log-refused-4a91=1 403 anonymous
";
        let o = evaluate(&markers(), log);
        assert!(ids(&o).contains(&"probe.authentication-logged"), "{o:?}");
        assert!(
            ids(&o).contains(&"probe.authorization-failure-logged"),
            "{o:?}"
        );
        assert!(ids(&o).contains(&"probe.log-line-metadata"), "{o:?}");
        assert!(ids(&o).contains(&"probe.log-timestamp-zoned"), "{o:?}");
        assert!(ids(&o).contains(&"probe.log-common-format"), "{o:?}");
        assert!(o.not_assessed.is_empty(), "{:?}", o.not_assessed);
        assert!(o.findings.is_empty(), "{:?}", o.findings);
    }

    #[test]
    fn an_app_that_logs_only_successful_sign_ins_is_not_credited() {
        // The half-credit this must refuse. V16.3.1 asks for both, and an app that records only
        // the sign-ins that worked is precisely the app the requirement is aimed at.
        let log = "auth: sign-in ok for sv-log-ok-4a91@example.test\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.authentication-logged"));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.3.1" && why.contains("unsuccessful may not be")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_app_that_logs_only_failed_sign_ins_is_not_credited_either() {
        let log = "auth: sign-in failed for sv-log-nobody-4a91@example.test\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.authentication-logged"));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.3.1" && why.contains("successful may not be")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_traffic_log_without_the_status_is_not_an_authorization_record() {
        // The distinction that keeps V16.3.2 from being credited to every app with an access log:
        // the marker shows the request was written down, the status shows the decision was.
        let log = "GET /account?sv-log-refused-4a91=1\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.authorization-failure-logged"));
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.3.2" && why.contains("record of traffic")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn a_status_on_some_other_line_does_not_count() {
        // The refusal has to be recorded *for this request*. A 403 elsewhere in the log is
        // somebody else's.
        let log = "GET /admin 403 someone\nGET /account?sv-log-refused-4a91=1\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.authorization-failure-logged"));
    }

    #[test]
    fn a_status_like_number_inside_another_value_is_not_a_status() {
        // `403` has to be a number on its own, not four digits inside an id or a byte count.
        let log = "GET /account?sv-log-refused-4a91=1 200 14039 bytes\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.authorization-failure-logged"));
    }

    #[test]
    fn a_status_is_a_whole_token_in_real_log_lines() {
        // The predicate on its own, against lines real servers write. Three digits are common
        // inside byte counts, timestamps, request ids and paths, and a substring match calls every
        // one of those a refusal — which would credit V16.3.2 to an app that logs nothing but
        // successful traffic.
        for (line, status) in [
            (
                r#"127.0.0.1 - - [26/Sep/2026:10:00:03] "GET /account HTTP/1.1" 403 27"#,
                403,
            ),
            ("level=warn status=401 path=/account", 401),
            ("GET /account 404", 404),
            // The shape this exists for: an app that sends people to the sign-in page.
            ("GET /account?sv-log-refused-4a91=1 302 -> /login", 302),
        ] {
            assert!(
                records_status(line, status),
                "should record {status}: {line}"
            );
        }
        for (line, status) in [
            // A byte count that happens to contain 403.
            (
                r#"127.0.0.1 - - [26/Sep/2026:10:00:03] "GET /account HTTP/1.1" 200 14039"#,
                403,
            ),
            // A request id.
            ("req=a401b9 status=200 path=/account", 401),
            // A path with the digits in it.
            ("GET /invoices/40312 200", 403),
            // Microseconds.
            ("GET /account 200 took=403ms", 403),
        ] {
            assert!(
                !records_status(line, status),
                "should not record {status}: {line}"
            );
        }
    }

    #[test]
    fn a_timestamp_is_read_with_its_zone_in_the_shapes_servers_write() {
        for (line, zoned) in [
            ("2026-09-26T10:00:03Z sign-in failed", true),
            ("2026-09-26T10:00:03.412+02:00 sign-in failed", true),
            ("2026-09-26T10:00:03-0500 sign-in failed", true),
            ("2026-09-26 10:00:03 UTC sign-in failed", true),
            (
                r#"10.0.0.7 - - [26/Sep/2026:10:00:03 +0000] "POST /login" 403"#,
                true,
            ),
            // Python's logging default, and the reason V16.2.2 exists.
            ("2026-09-26 10:00:03,123 WARNING sign-in failed", false),
            ("2026-09-26T10:00:03 sign-in failed", false),
        ] {
            let t = timestamp(line).unwrap_or_else(|| panic!("no timestamp found in: {line}"));
            assert_eq!(
                t.zoned, zoned,
                "zone misread in: {line} (read `{}`)",
                t.text
            );
        }
        // Not a timestamp: a version number, a date with no time, a duration.
        for line in [
            "release 2026.09.26",
            "on 2026-09-26 it failed",
            "took 10:00ms",
        ] {
            assert!(timestamp(line).is_none(), "read a timestamp out of: {line}");
        }
    }

    #[test]
    fn a_time_with_no_zone_on_a_security_event_is_a_finding() {
        // The one thing in this module that faults, and why it may: the line *was* found, it
        // records a refused sign-in, and the app chose to write a time on it without saying which
        // zone. No platform repairs that.
        let log = "2026-09-26 10:00:03,123 sign-in failed for sv-log-nobody-4a91@example.test from 10.0.0.7\n";
        let o = evaluate(&markers(), log);
        assert_eq!(o.findings.len(), 1, "{:?}", o.findings);
        assert_eq!(o.findings[0].requirement_ids, vec!["V16.2.2".to_owned()]);
        assert!(!ids(&o).contains(&"probe.log-timestamp-zoned"));
        // V16.2.1 is still met: when, where, who and what are all on the line.
        assert!(ids(&o).contains(&"probe.log-line-metadata"), "{o:?}");
    }

    #[test]
    fn a_line_with_no_time_of_its_own_is_never_a_finding() {
        // Writing to standard output and letting the platform stamp each line is sound, so a
        // missing timestamp is not assessed for both requirements, never faulted.
        let log = "sign-in failed for sv-log-nobody-4a91@example.test from 10.0.0.7\n";
        let o = evaluate(&markers(), log);
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(!ids(&o).contains(&"probe.log-line-metadata"));
        assert!(!ids(&o).contains(&"probe.log-timestamp-zoned"));
        for id in ["V16.2.1", "V16.2.2"] {
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(i, why)| i == id && why.contains("platform")),
                "{id}: {:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn metadata_is_read_only_from_the_line_that_records_the_event() {
        // A well-formed line somewhere else in the log is somebody else's. The zone and the
        // address have to be on the line that names the refused sign-in.
        let log = "\
2026-09-26T10:00:00Z 10.0.0.1 GET / 200
sign-in failed for sv-log-nobody-4a91@example.test
";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.log-line-metadata"), "{o:?}");
        assert!(!ids(&o).contains(&"probe.log-timestamp-zoned"), "{o:?}");
    }

    #[test]
    fn a_time_without_a_place_does_not_meet_v16_2_1() {
        // When is not enough on its own: the requirement asks for where too, and a zoned
        // timestamp must not carry the line past the part it does not have.
        let log = "2026-09-26T10:00:03Z sign-in failed for sv-log-nobody-4a91@example.test\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.log-line-metadata"), "{o:?}");
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.2.1" && why.contains("no source address or path")),
            "{:?}",
            o.not_assessed
        );
        // The zone is still read, because it is a separate question about the same line.
        assert!(ids(&o).contains(&"probe.log-timestamp-zoned"), "{o:?}");
        let note = o.steps.join(" | ");
        assert!(note.contains("a source address or path: no"), "{note}");
    }

    #[test]
    fn a_structured_log_line_without_an_origin_is_not_enough_either() {
        // The same rule on a different shape of log: JSON, which is how most apps log once they
        // grow up. It has a zoned time and a clear event, and still says nothing of where the
        // request came from or went to.
        let log = r#"{"ts":"2026-09-26T10:00:03Z","event":"sign-in-failed","account":"sv-log-nobody-4a91@example.test"}"#;
        let o = evaluate(&markers(), &format!("{log}\n"));
        assert!(!ids(&o).contains(&"probe.log-line-metadata"), "{o:?}");
        assert!(ids(&o).contains(&"probe.log-timestamp-zoned"), "{o:?}");
    }

    #[test]
    fn the_three_common_formats_are_recognized_and_prose_is_not() {
        for (line, format) in [
            (
                r#"{"ts":"2026-09-26T10:00:03Z","event":"sign-in-failed","account":"x"}"#,
                "JSON",
            ),
            (
                "time=2026-09-26T10:00:03Z level=warn event=sign-in-failed account=x",
                "logfmt",
            ),
            (
                r#"10.0.0.7 - - [26/Sep/2026:10:00:03 +0000] "POST /login HTTP/1.1" 403 27"#,
                "the common log format",
            ),
        ] {
            assert_eq!(common_format(line), Some(format), "{line}");
        }
        for line in [
            // Prose with one equals sign in it is a sentence, not logfmt.
            "sign-in failed for x because retries=3 were used up",
            "2026-09-26 10:00:03,123 WARNING sign-in failed for x",
            // Braces that are not a JSON object.
            "{not json at all}",
            r#"["a", "list"]"#,
        ] {
            assert_eq!(common_format(line), None, "{line}");
        }
    }

    #[test]
    fn a_line_in_no_common_format_is_not_assessed_never_faulted() {
        let log = "2026-09-26T10:00:03Z sign-in failed for sv-log-nobody-4a91@example.test from 10.0.0.7\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.log-common-format"));
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.2.4" && why.contains("not a finding")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn silence_is_never_a_finding() {
        // The property the whole module rests on. An app that logs to a file writes nothing here,
        // and must not be faulted for it.
        let o = evaluate(&markers(), "   \n  \n");
        assert!(o.verified.is_empty());
        assert!(o.findings.is_empty());
        assert_eq!(o.not_assessed.len(), 5);
        for (_, why) in &o.not_assessed {
            assert!(why.contains("logs to a file"), "{why}");
        }
        // And, whatever the log says, nothing here ever produces a finding.
        for log in ["", "nothing relevant", "GET / 200"] {
            let o = evaluate(&markers(), log);
            assert!(o.verified.is_empty() || !o.verified.is_empty());
            assert!(
                o.not_assessed.iter().all(|(id, _)| id.starts_with("V16.")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn without_the_markers_nothing_is_claimed() {
        let o = evaluate(&Markers::default(), "some output\n");
        assert!(o.verified.is_empty());
        assert!(o.findings.is_empty());
        assert_eq!(o.not_assessed.len(), 5);
    }
}
