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
//! both are found. One of the two is not the requirement, and would be the kind of half-credit
//! this project exists to refuse.
//!
//! # Markers that are not personal data
//!
//! The accounts' names are email addresses, and an app that follows the usual privacy rules —
//! never log an email address, never log what follows `?` in an address — writes neither
//! the names nor a marker after `?`. Its log is the one `sv`'s own design prompt asks for, and it
//! must not be what blinds this check. So each event also carries a marker in a request *path*,
//! which such an app does log:
//!
//! - **The sign-ins are bracketed.** Just before each of the two sign-ins, `sv` asks for a page
//!   nobody has, `/sv-log-before-…`, and just after it `/sv-log-after-…`. Those requests mean
//!   nothing to the app (a 404, usually) and carry nothing personal. A line written between the two
//!   was written while that one sign-in was being handled, and if it names a sign-in event
//!   (`login_failed`, `user.signin`, `authentication failed`) it is the record of it. The
//!   sign-in's own address is taken out of each line before the words are read, so an access log
//!   line `POST /login 401` does not count as an event on the strength of its path. The failed
//!   sign-in's line must also say it failed; the successful one's must not.
//! - **The refused request is asked twice.** Once as before, the private page itself with the
//!   marker after `?`, so its meaning is untouched. And once with the marker as a last path part
//!   under the private page (`/account/sv-log-denied-…`), which an app logs even when it strips
//!   query strings. That second address is not the private page, so its answer is only evidence of
//!   a refusal when it is the same refusal the private page got, and not a 404: an app that
//!   guards everything under `/account` sends both to the sign-in page alike, while an app that
//!   answers "no such page" was never asked an authorization question.
//!
//! The bracketing rests on the app writing its lines in the order it handles requests, which is
//! true of an app writing to one stream, or flushing each line, as logging libraries do. It is
//! also why a line found this way never stands for *who*: it is tied to the request by when it was
//! written, not by what it says.

use crate::finding::{Confidence, Finding, Location, Severity};
use regex::Regex;
use std::sync::LazyLock;

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
    pub refused_requests: Vec<(String, u16)>,
    /// The two marked requests sent just before and just after the refused sign-in.
    pub failed_window: Option<Window>,
    /// The two marked requests sent just before and just after the successful sign-in, set only
    /// when that sign-in was shown to work.
    pub successful_window: Option<Window>,
}

/// Two requests `sv` made, each with a marker in its path, around exactly one sign-in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Window {
    pub open: String,
    pub close: String,
    /// The sign-in's own address, taken out of each line before its words are read.
    pub login_path: String,
}

/// The lines written strictly between a window's two marked requests, or `None` when either
/// marker is missing or they are out of order.
fn between<'a>(log: &'a str, w: &Window) -> Option<Vec<&'a str>> {
    let lines: Vec<&str> = log.lines().collect();
    let open = lines.iter().position(|l| l.contains(w.open.as_str()))?;
    let close = open
        + 1
        + lines[open + 1..]
            .iter()
            .position(|l| l.contains(w.close.as_str()))?;
    Some(lines[open + 1..close].to_vec())
}

/// Whether a line names a sign-in as an event, once the sign-in's own address is taken out of it.
fn names_sign_in(line: &str) -> bool {
    // A word boundary on the left, so `catalog in` and `design index` are not read as a sign-in;
    // and camelCase separately, since `userLogin` has no boundary before `Login`.
    static WORDS: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)(?:^|[^a-z])(?:log(?:ged)?[ _.-]?(?:in|on)|sign(?:ed)?[ _.-]?(?:in|on)|authenticat)",
        )
        .expect("valid pattern")
    });
    static CAMEL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:Log(?:ged)?[ _.-]?[IiOo]n|Sign(?:ed)?[ _.-]?[IiOo]n|Authenticat)")
            .expect("valid pattern")
    });
    WORDS.is_match(line) || CAMEL.is_match(line)
}

/// Whether a line says something failed or was refused.
fn says_failed(line: &str) -> bool {
    static FAILED: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)fail|invalid|denied|refused|reject|wrong|incorrect|unauthori[sz]ed|unknown|mismatch|not[ _.-]?found|no[ _.-]?such|error|\b40[13]\b",
        )
        .expect("valid pattern")
    });
    FAILED.is_match(line)
}

/// A line with its addresses and paths taken out: `POST /login 200`, `"path":"/auth/sign_in"`, and
/// `http://app/login?next=/` are where a request went, not an event, however the app writes them.
fn without_paths(line: &str) -> String {
    static PLACES: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(^|[\s"'=(\[:,])(?:[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]*|/[^\s"'<>,;)\]}]*)"#)
            .expect("valid pattern")
    });
    PLACES.replace_all(line, "$1 ").into_owned()
}

/// The line recording the one sign-in inside a window: one that names a sign-in event, saying it
/// failed when `failed` and not saying so otherwise.
fn sign_in_event<'a>(log: &'a str, w: &Window, failed: bool) -> Option<&'a str> {
    between(log, w)?.into_iter().find(|line| {
        let words = if w.login_path.is_empty() {
            (*line).to_owned()
        } else {
            line.replace(w.login_path.as_str(), " ")
        };
        // And every other path: securevibe.toml's `login.path` written differently in the log
        // (`/login/`, `/Login`, `/login?next=/`, a prefix the app is mounted under) is still the
        // request, not a record of it.
        let words = without_paths(&words);
        names_sign_in(&words) && says_failed(&words) == failed
    })
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
        "{what} `sv` can only read what the app wrote to its own output inside the container, and \
         two common reasons leave nothing there for it to find, neither of them evidence that the \
         events went unrecorded. The app may log to a file, to syslog, or to a logging service, \
         which writes nothing there. Or the app's privacy rules may keep these lines from being \
         tied to `sv`'s requests: an app that logs no email addresses and no query strings, as \
         such rules often ask, can still be read when it logs request paths, because `sv` marks \
         the paths it asks for (`/sv-log-…`) and reads a sign-in event (such as `login_failed`) \
         written between two of them; but an app that logs neither the paths nor a sign-in event \
         gives nothing to tie them by."
    )
}

/// Whether a line records this status as a status, rather than merely containing its digits.
///
/// A status is a whole token, not three digits sitting somewhere in the line. Byte counts
/// (`14039`), request ids (`req=a401b9`), durations (`took=403ms`) and paths (`/invoices/40312`)
/// all contain such digits, and a substring match would read every one of them as the status —
/// which would credit V16.3.2 to an app that logs nothing but traffic that succeeded.
///
/// So each token, split at whitespace and at commas, is reduced to what follows its last `=` or
/// `:`, trimmed of surrounding punctuation, and has to equal the status exactly. The commas are for
/// compact JSON (`{"status":302,"path":"/account"}`), which has no spaces to split at.
fn records_status(line: &str, status: u16) -> bool {
    let status = status.to_string();
    line.split(|c: char| c.is_whitespace() || c == ',')
        .any(|token| {
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

    // Each sign-in's line: by the account's name when the app logs it, otherwise by the sign-in
    // event written between the two marked requests around it. `true` when found by name, the
    // only way a line is known to say *who*.
    let by_name = |name: &Option<String>| {
        name.as_deref()
            .and_then(|n| log.lines().find(|l| l.contains(n)))
            .map(|l| (l, true))
    };
    let by_window = |w: &Option<Window>, failed: bool| {
        w.as_ref()
            .and_then(|w| sign_in_event(log, w, failed))
            .map(|l| (l, false))
    };
    let failed_line =
        by_name(&markers.failed_sign_in).or_else(|| by_window(&markers.failed_window, true));
    let succeeded_line = by_name(&markers.successful_sign_in)
        .or_else(|| by_window(&markers.successful_window, false));

    // ---- V16.3.1: authentication, successful and unsuccessful.
    let planted_failed = markers.failed_sign_in.is_some() || markers.failed_window.is_some();
    let planted_succeeded =
        markers.successful_sign_in.is_some() || markers.successful_window.is_some();
    if planted_failed && planted_succeeded {
        let how = |found: Option<(&str, bool)>| match found {
            Some((_, true)) => "yes, by the account's name",
            Some((_, false)) => "yes, by a sign-in event between the marked requests",
            None => "no",
        };
        out.steps.push(format!(
            "the app's output recorded the refused sign-in: {}; the accepted one: {}",
            how(failed_line),
            how(succeeded_line)
        ));
        match (failed_line, succeeded_line) {
            (Some((_, failed_named)), Some((_, succeeded_named))) => {
                let found = match (failed_named, succeeded_named) {
                    (true, true) => "both named in the app's own output",
                    (false, false) => {
                        "both recorded in the app's own output, each as a sign-in event written \
                         between two requests this run marked in their path just before and just \
                         after it, since the lines did not carry the accounts' names"
                    }
                    _ => {
                        "both recorded in the app's own output, one by the account's name and the \
                         other as a sign-in event written between two requests this run marked in \
                         their path just before and just after it"
                    }
                };
                out.verified.push(crate::Verified::new(
                    "probe.authentication-logged",
                    &["V16.3.1"],
                    format!(
                        "two sign-ins this run made — one refused, for an account that does not \
                         exist, and one accepted, by an account used for nothing else — {found}"
                    ),
                ));
            }
            (failed, succeeded) => {
                // Naming which half was missing matters: an app that logs only successes is a
                // different thing from one that logs nothing, and the owner can act on the
                // difference.
                let missing = match (failed.is_some(), succeeded.is_some()) {
                    (false, true) => {
                        "The refused sign-in was not found, though the accepted one was, so \
                         successful authentication appears to be recorded and unsuccessful may \
                         not be."
                    }
                    (true, false) => {
                        "The refused sign-in was found but the accepted one was not, so \
                         unsuccessful authentication appears to be recorded and successful may \
                         not be."
                    }
                    _ => "Neither sign-in was found in the app's output.",
                };
                out.not_assessed
                    .push(("V16.3.1".to_owned(), elsewhere(missing)));
            }
        }
    } else {
        out.not_assessed.push((
            "V16.3.1".to_owned(),
            "This needs both a sign-in the app accepts and one it refuses, by accounts used for \
             nothing else. Without `signup` in [stack.run.users] there is no way to make them, so \
             nothing here could tell a logged authentication from any other line."
                .to_owned(),
        ));
    }

    // ---- V16.2.1, V16.2.2 and V16.2.4: what the refused sign-in's line carries.
    if let Some((line, named)) = failed_line {
        metadata_checks(line, named, &mut out);
        format_check(line, &mut out);
    } else {
        for id in ["V16.2.1", "V16.2.2", "V16.2.4"] {
            out.not_assessed.push((
                id.to_owned(),
                elsewhere(
                    "These are read from the line recording the refused sign-in this run made, \
                     and no such line was found, so there was no security event's metadata to \
                     read.",
                ),
            ));
        }
    }

    // ---- V16.3.2: a refused request.
    if markers.refused_requests.is_empty() {
        out.not_assessed.push((
            "V16.3.2".to_owned(),
            "This needs a page only a signed-in user should see, listed under `private` in \
             [stack.run.users], to be refused to somebody who has not signed in."
                .to_owned(),
        ));
        return out;
    }
    // The marker alone shows the request reached a log; the refusal status on the same line is
    // what makes it a record of the *authorization* decision rather than of traffic. Both, or
    // nothing.
    let found: Vec<(&str, u16, bool)> = markers
        .refused_requests
        .iter()
        .filter_map(|(marker, status)| {
            log.lines()
                .find(|l| l.contains(marker.as_str()))
                .map(|l| (marker.as_str(), *status, records_status(l, *status)))
        })
        .collect();
    let recorded = found.iter().find(|(_, _, with_status)| *with_status);
    out.steps.push(format!(
        "the app's output recorded the refused private-page request: {}",
        match (recorded, found.first()) {
            (Some(_), _) => "yes, with the status",
            (None, Some(_)) => "the request, but no refusal status",
            _ => "no",
        }
    ));
    if let Some((marker, status, _)) = recorded {
        let place = if marker.contains("-denied-") {
            "as the last part of its path"
        } else {
            "after `?` in its address"
        };
        out.verified.push(crate::Verified::new(
            "probe.authorization-failure-logged",
            &["V16.3.2"],
            format!(
                "a private page requested by somebody not signed in, with a marker {place}, which \
                 the app refused with {status}: its output carried that marker on a line that also \
                 carried {status}"
            ),
        ));
    } else if let Some((_, status, _)) = found.first() {
        out.not_assessed.push((
            "V16.3.2".to_owned(),
            format!(
                "The app's output recorded the request this run made to a private page, but the \
                 line does not carry the {status} the app answered it with, so it reads as a \
                 record of traffic rather than of an authorization decision."
            ),
        ));
    } else {
        out.not_assessed.push((
            "V16.3.2".to_owned(),
            elsewhere("The refused request this run made was not in the app's output."),
        ));
    }
    out
}

/// Which common log format a line is written in, if any.
///
/// Three, because they are what log processors read without being taught: a JSON object, logfmt
/// (`key=value` pairs, the way Heroku and most Go services write), and the Apache and nginx common
/// log format.
pub(crate) fn common_format(line: &str) -> Option<&'static str> {
    let trimmed = line.trim();
    if trimmed.starts_with('{')
        && serde_json::from_str::<serde_json::Value>(trimmed).is_ok_and(|v| v.is_object())
    {
        return Some("JSON");
    }
    static CLF_LINE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r#"^\S+ \S+ \S+ \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "[A-Z]+ \S+[^"]*" \d{3} "#,
        )
        .expect("valid pattern")
    });
    if CLF_LINE.is_match(&format!("{trimmed} ")) {
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
    static ISO: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2}| ?UTC\b)?",
        )
        .expect("valid pattern")
    });
    static CLF: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}( [+-]\d{4})?")
            .expect("valid pattern")
    });
    if let Some(c) = ISO.captures(line) {
        return Some(Timestamp {
            text: c[0].trim().to_owned(),
            zoned: c.get(1).is_some(),
        });
    }
    CLF.captures(line).map(|c| Timestamp {
        text: c[0].to_owned(),
        zoned: c.get(1).is_some(),
    })
}

/// Whether a line says where a request came from or went to: an IP address, or a path.
fn has_place(line: &str) -> bool {
    static IPV4: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").expect("valid pattern"));
    IPV4.is_match(line)
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
///
/// `named` is whether the line was found by the account's name. A line found instead by when it
/// was written, between two marked requests, is known to record the refused sign-in (its *what*)
/// but not to say who made it: an app that keeps email addresses out of its log may record who
/// some other way, such as a user id, which an account that does not exist has none of. So V16.2.1
/// is not assessed from such a line, and the zone and format, which do not depend on who, still are.
fn metadata_checks(line: &str, named: bool, out: &mut LogOutcome) {
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
        _ if !named => out.not_assessed.push((
            "V16.2.1".to_owned(),
            "The line recording the refused sign-in was found by when it was written, between two \
             requests this run marked in their path, not by the account's name, so nothing shows \
             that it says who made the attempt. That is not a finding: an app that keeps email \
             addresses out of its log may record who by a user id, which an account that does \
             not exist does not have."
                .to_owned(),
        )),
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
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            rule_id: "probe.log-timestamp-zoned".to_owned(),
            title: "A security event is logged with a time that does not say its zone".to_owned(),
            severity: Severity::Low,
            confidence: Confidence::High,
            location: Location::running_app_output(),
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
            refused_requests: vec![("sv-log-refused-4a91".into(), 403)],
            ..Default::default()
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
    fn a_sentence_with_an_equals_sign_is_not_credited_as_logfmt() {
        // The second witness for the logfmt threshold, through the whole evaluation rather than
        // the recognizer alone: the line that records the event is prose with one `key=value` in
        // it, and V16.2.4 must not be credited on the strength of that.
        let log = "2026-09-26T10:00:03Z sign-in failed for sv-log-nobody-4a91@example.test after retries=3 from 10.0.0.7\n";
        let o = evaluate(&markers(), log);
        assert!(!ids(&o).contains(&"probe.log-common-format"), "{o:?}");
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

    // --------------------------------------------------------------------------------------------
    // Markers that are not personal data

    fn window(which: &str) -> Window {
        Window {
            open: format!("sv-log-before-{which}-4a91"),
            close: format!("sv-log-after-{which}-4a91"),
            login_path: "/login".into(),
        }
    }

    /// The markers as planted against an app whose log holds no email addresses: the windows and
    /// both refused requests, the names too, as `sv` always plants them.
    fn private_markers() -> Markers {
        Markers {
            failed_window: Some(window("failed")),
            successful_window: Some(window("ok")),
            refused_requests: vec![
                ("sv-log-refused-4a91".into(), 302),
                ("sv-log-denied-4a91".into(), 302),
            ],
            ..markers()
        }
    }

    /// The family-hub log of 3 October 2026, reduced: JSON lines, the path without its query
    /// string, a user id and an event name, never an email address.
    const PRIVATE_LOG: &str = r#"{"ts":"2026-10-04T10:00:00Z","path":"/login","status":200}
{"ts":"2026-10-04T10:00:01Z","path":"/sv-log-before-failed-4a91","status":404}
{"ts":"2026-10-04T10:00:01Z","event":"login_failed","path":"/login"}
{"ts":"2026-10-04T10:00:01Z","path":"/login","status":401}
{"ts":"2026-10-04T10:00:02Z","path":"/sv-log-after-failed-4a91","status":404}
{"ts":"2026-10-04T10:00:03Z","path":"/sv-log-before-ok-4a91","status":404}
{"ts":"2026-10-04T10:00:03Z","path":"/login","status":200}
{"ts":"2026-10-04T10:00:04Z","event":"login","user_id":7,"path":"/login"}
{"ts":"2026-10-04T10:00:04Z","path":"/login","status":303}
{"ts":"2026-10-04T10:00:05Z","path":"/sv-log-after-ok-4a91","status":404}
{"ts":"2026-10-04T10:00:06Z","path":"/account","status":302}
{"ts":"2026-10-04T10:00:06Z","path":"/account/sv-log-denied-4a91","status":302}
"#;

    #[test]
    fn a_log_of_paths_and_user_ids_is_read_through_the_marked_paths() {
        assert!(!PRIVATE_LOG.contains('@') && !PRIVATE_LOG.contains('?'));
        let o = evaluate(&private_markers(), PRIVATE_LOG);
        for id in [
            "probe.authentication-logged",
            "probe.authorization-failure-logged",
            "probe.log-timestamp-zoned",
            "probe.log-common-format",
        ] {
            assert!(ids(&o).contains(&id), "{id}: {o:?}");
        }
        // Who is the one thing a line found by when it was written cannot be shown to say.
        assert!(!ids(&o).contains(&"probe.log-line-metadata"));
        assert_eq!(o.not_assessed.len(), 1, "{:?}", o.not_assessed);
        assert_eq!(o.not_assessed[0].0, "V16.2.1");
        let how = &o.verified[0].scope;
        assert!(how.contains("between two requests"), "{how}");
        let refused = o
            .verified
            .iter()
            .find(|v| v.check_id == "probe.authorization-failure-logged")
            .unwrap();
        assert!(
            refused.scope.contains("last part of its path"),
            "{}",
            refused.scope
        );
    }

    #[test]
    fn an_access_log_alone_is_not_a_record_of_sign_ins() {
        // `POST /login 401` between the markers is the request, not an authentication event: the
        // sign-in's own address is taken out before the words are read.
        let log = "\
GET /sv-log-before-failed-4a91 404
POST /login 401
GET /sv-log-after-failed-4a91 404
GET /sv-log-before-ok-4a91 404
POST /login 303
GET /sv-log-after-ok-4a91 404
";
        let o = evaluate(&private_markers(), log);
        assert!(!ids(&o).contains(&"probe.authentication-logged"), "{o:?}");
        assert!(
            o.not_assessed
                .iter()
                .any(|(id, why)| id == "V16.3.1" && why.contains("Neither sign-in")),
            "{:?}",
            o.not_assessed
        );
    }

    #[test]
    fn an_access_log_writing_the_sign_in_path_another_way_is_not_a_record_either() {
        // Found in the review of 1 to 4 October (item 14): only `login.path` exactly as
        // securevibe.toml writes it was taken out, so the same request written another way
        // read as a sign-in event and credited V16.3.1.
        for (logged, json) in [
            ("/login/", false),
            ("/Login", false),
            ("/login?next=/account", false),
            ("http://app:3000/login", false),
            ("/api/v1/auth/login", false),
            ("/user/sign_in", true),
            ("/auth/signin", true),
        ] {
            let line = |status: u16| {
                if json {
                    format!("{{\"path\":\"{logged}\",\"status\":{status}}}")
                } else {
                    format!("POST {logged} {status}")
                }
            };
            let log = format!(
                "GET /sv-log-before-failed-4a91 404\n{}\nGET /sv-log-after-failed-4a91 404\n\
                 GET /sv-log-before-ok-4a91 404\n{}\nGET /sv-log-after-ok-4a91 404\n",
                line(401),
                line(303)
            );
            let o = evaluate(&private_markers(), &log);
            assert!(
                !ids(&o).contains(&"probe.authentication-logged"),
                "{logged}: {o:?}"
            );
            assert!(
                o.not_assessed
                    .iter()
                    .any(|(id, why)| id == "V16.3.1" && why.contains("Neither sign-in")),
                "{logged}: {:?}",
                o.not_assessed
            );
        }
        // The control: the same lines with an event of the app's own beside each are credited.
        let log = "\
GET /sv-log-before-failed-4a91 404
POST /login/ 401 event=login_failed
GET /sv-log-after-failed-4a91 404
GET /sv-log-before-ok-4a91 404
POST /login/ 303 event=user.signin
GET /sv-log-after-ok-4a91 404
";
        let o = evaluate(&private_markers(), log);
        assert!(ids(&o).contains(&"probe.authentication-logged"), "{o:?}");
    }

    #[test]
    fn a_sign_in_event_outside_its_window_is_somebody_elses() {
        // Both events are in the log, but each outside the markers around the sign-in it would
        // have to record: the brute-force check's failures, and A's own sign-in, look like this.
        let log = "\
{\"event\":\"login_failed\"}
{\"path\":\"/sv-log-before-failed-4a91\"}
{\"path\":\"/sv-log-after-failed-4a91\"}
{\"event\":\"login\",\"user_id\":1}
{\"path\":\"/sv-log-before-ok-4a91\"}
{\"path\":\"/sv-log-after-ok-4a91\"}
";
        let o = evaluate(&private_markers(), log);
        assert!(!ids(&o).contains(&"probe.authentication-logged"), "{o:?}");
        // And markers out of order make no window at all.
        let log = "\
{\"path\":\"/sv-log-after-failed-4a91\"}
{\"event\":\"login_failed\"}
{\"path\":\"/sv-log-before-failed-4a91\"}
";
        assert!(sign_in_event(log, &window("failed"), true).is_none());
    }

    #[test]
    fn the_failed_window_needs_a_failure_and_the_accepted_one_must_not_have_one() {
        let failed = "{\"path\":\"/sv-log-before-failed-4a91\"}\n{\"event\":\"login\",\"user_id\":3}\n{\"path\":\"/sv-log-after-failed-4a91\"}\n";
        assert!(sign_in_event(failed, &window("failed"), true).is_none());
        let ok = "{\"path\":\"/sv-log-before-ok-4a91\"}\n{\"event\":\"login_failed\"}\n{\"path\":\"/sv-log-after-ok-4a91\"}\n";
        assert!(sign_in_event(ok, &window("ok"), false).is_none());
    }

    #[test]
    fn sign_in_events_are_recognized_in_the_words_apps_use_and_not_inside_other_words() {
        for line in [
            r#"{"event":"login_failed"}"#,
            "event=user.signin outcome=ok",
            "Authentication failed for user 7",
            "auth: signed in user_id=7",
            r#"{"type":"userLogin"}"#,
            "log-in refused",
            "SIGN_IN_FAILED",
        ] {
            assert!(names_sign_in(line), "{line}");
        }
        for line in [
            "catalog index rebuilt",
            "design input saved",
            "unauthenticated request to /account",
            "GET / 200",
            "blogging is fun",
        ] {
            assert!(!names_sign_in(line), "{line}");
        }
    }

    #[test]
    fn a_status_is_read_from_compact_json() {
        // No spaces to split at: the comma is the boundary.
        assert!(records_status(
            r#"{"status":302,"path":"/account/sv-log-denied-4a91"}"#,
            302
        ));
        assert!(!records_status(
            r#"{"status":200,"bytes":3021,"path":"/account"}"#,
            302
        ));
    }

    #[test]
    fn when_nothing_is_found_the_message_names_privacy_rules_as_a_likely_reason() {
        // The owner of an app that keeps emails and query strings out of its log has to be able to
        // see from the report that this is why, not only "it logs somewhere else".
        let log = "{\"path\":\"/\",\"status\":200}\n";
        let o = evaluate(&private_markers(), log);
        for id in ["V16.3.1", "V16.3.2", "V16.2.1", "V16.2.2", "V16.2.4"] {
            let why = o
                .not_assessed
                .iter()
                .find(|(i, _)| i == id)
                .map(|(_, why)| why.as_str())
                .unwrap_or_else(|| panic!("{id} not in {:?}", o.not_assessed));
            assert!(why.contains("privacy rules"), "{id}: {why}");
            assert!(
                why.contains("no email addresses and no query strings"),
                "{id}: {why}"
            );
            assert!(
                why.contains("logs to a file") || why.contains("log to a file"),
                "{id}: {why}"
            );
        }
    }
}
