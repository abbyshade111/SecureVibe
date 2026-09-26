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

use crate::finding::Severity;

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
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogOutcome {
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
        for ids in ["V16.3.1", "V16.3.2"] {
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

/// Never used to fault an app; kept so the severity this module would use is written down once.
#[allow(dead_code)]
const WOULD_BE: Severity = Severity::Low;

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
2026-09-26T10:00:01Z auth: sign-in failed for sv-log-nobody-4a91@example.test (no such account)
2026-09-26T10:00:02Z auth: sign-in ok for sv-log-ok-4a91@example.test
2026-09-26T10:00:03Z GET /account?sv-log-refused-4a91=1 403 anonymous
";
        let o = evaluate(&markers(), log);
        assert!(ids(&o).contains(&"probe.authentication-logged"), "{o:?}");
        assert!(
            ids(&o).contains(&"probe.authorization-failure-logged"),
            "{o:?}"
        );
        assert!(o.not_assessed.is_empty(), "{:?}", o.not_assessed);
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
    fn silence_is_never_a_finding() {
        // The property the whole module rests on. An app that logs to a file writes nothing here,
        // and must not be faulted for it.
        let o = evaluate(&markers(), "   \n  \n");
        assert!(o.verified.is_empty());
        assert_eq!(o.not_assessed.len(), 2);
        for (_, why) in &o.not_assessed {
            assert!(why.contains("logs to a file"), "{why}");
        }
        // And, whatever the log says, nothing here ever produces a finding.
        for log in ["", "nothing relevant", "GET / 200"] {
            let o = evaluate(&markers(), log);
            assert!(o.verified.is_empty() || !o.verified.is_empty());
            assert!(
                o.not_assessed.iter().all(|(id, _)| id.starts_with("V16.3")),
                "{:?}",
                o.not_assessed
            );
        }
    }

    #[test]
    fn without_the_markers_nothing_is_claimed() {
        let o = evaluate(&Markers::default(), "some output\n");
        assert!(o.verified.is_empty());
        assert_eq!(o.not_assessed.len(), 2);
    }
}
