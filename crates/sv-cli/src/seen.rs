//! What `sv` saw of the running app, made ready to keep beside the report (ADR-082): each question
//! asked as somebody not signed in, and what came back, with every credential cut down first.
//!
//! Two passes, and a header pass before them. A header that carries a session or a sign-in
//! (`set-cookie`, `authorization`, and the others in `SESSION_HEADERS`) keeps its name and, for a
//! cookie, the cookie's name, and loses its value whatever it looks like: a session id is random
//! letters and digits, and no rule for keys knows it from any other. Then every header value and
//! every body goes through `secrets::redact_text`, which cuts what the secrets scan would find and
//! any value a name says is a credential. The test that plants a key built from pieces in each
//! place (`seen_tests`) fails if any of it reaches the record.

use sv_check::probes::{ProbeRequest, ProbeResponse};
use sv_check::secrets::{SecretRules, redact_text};
use sv_report::seen::{Exchange, MOST_EXCHANGES, Seen};

/// Headers whose value is a session or a sign-in, so it is cut whatever it looks like.
const SESSION_HEADERS: &[&str] = &[
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
];

/// The record of `asked` and the `answered` that came back. `rate_limited` are the ids the app's
/// rate limiter answered in its place, which the run leaves out of `answered`.
pub fn record(
    rules: &SecretRules,
    asked: &[ProbeRequest],
    answered: &[ProbeResponse],
    rate_limited: &[String],
) -> Seen {
    let mut seen = Seen::default();
    for request in asked {
        let Some(response) = answered.iter().find(|r| r.id == request.id) else {
            let why = if rate_limited
                .iter()
                .any(|l| l.starts_with(&format!("{} (", request.id)))
            {
                "answered by the app's rate limiter in its place"
            } else {
                "no answer"
            };
            seen.not_answered.push(format!("{} ({why})", request.id));
            continue;
        };
        if seen.exchanges.len() == MOST_EXCHANGES {
            seen.left_out += 1;
            continue;
        }
        let mut cut = |text: &str| {
            let (text, n) = redact_text(rules, text);
            seen.credentials_removed += n;
            text
        };
        let headers = response
            .headers
            .iter()
            .map(|(name, value)| {
                let value = if SESSION_HEADERS.contains(&name.as_str()) {
                    session_value(name, value)
                } else {
                    value.clone()
                };
                (name.clone(), cut(&value))
            })
            .collect();
        let body = cut(&response.body);
        let path = cut(&request.path);
        seen.exchanges.push(Exchange {
            id: request.id.clone(),
            method: request.method.clone(),
            path,
            status: response.status,
            headers,
            body,
        });
    }
    seen
}

/// A session header's value with the value itself taken out: a cookie keeps its name and its
/// attributes (`Path`, `HttpOnly`, `Secure`, `SameSite`), which the checks read and a person
/// following a finding needs, and anything else keeps its scheme word (`Bearer`, `Basic`).
fn session_value(name: &str, value: &str) -> String {
    if name == "set-cookie" || name == "cookie" {
        return value
            .split(';')
            .map(str::trim)
            .enumerate()
            .map(|(i, part)| match part.split_once('=') {
                // The cookie itself, in `set-cookie` the first part and in `cookie` every one.
                Some((cookie, v)) if i == 0 || name == "cookie" => {
                    format!("{cookie}=[removed, {} characters]", v.chars().count())
                }
                _ => part.to_owned(),
            })
            .collect::<Vec<_>>()
            .join("; ");
    }
    match value.split_once(' ') {
        Some((scheme, rest))
            if !scheme.is_empty() && scheme.chars().all(|c| c.is_ascii_alphabetic()) =>
        {
            format!("{scheme} [removed, {} characters]", rest.chars().count())
        }
        _ => format!("[removed, {} characters]", value.chars().count()),
    }
}

#[cfg(test)]
#[path = "seen_tests.rs"]
mod seen_tests;
