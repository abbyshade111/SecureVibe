//! `seen.json`: what `sv` saw of the running app, kept beside the report (ADR-082).
//!
//! The report says what `sv` concluded; this says what the conclusions rest on. For each question
//! asked of the running app as somebody not signed in: its id, the method, the path, and what came
//! back (the status, the headers, and the start of the body `sv` keeps, `sv_check::probes::KEPT_CHARS`).
//! The probes read their findings and credits from these answers, by the same ids.
//!
//! Everything here is the app's own text, with every credential in it cut down first (`sv-cli`'s
//! `seen` module, which builds this): this crate only holds it and writes it out. It is a report
//! file, so the seal covers it with the other five.

use crate::Report;
use serde::Serialize;

/// What `sv` saw of the running app.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct Seen {
    /// The questions asked and what came back, in the order they were asked.
    pub exchanges: Vec<Exchange>,
    /// Questions asked that got no answer the record holds: unanswered, or answered by the app's
    /// rate limiter in its place, as `id (why)`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_answered: Vec<String>,
    /// Answers left out because the record holds no more than `MOST_EXCHANGES`.
    pub left_out: usize,
    /// How many credentials were cut out of what is kept.
    pub credentials_removed: usize,
}

/// One question asked of the running app, and what it answered.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Exchange {
    /// The id a finding or a credit names it by.
    pub id: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    /// The response headers, names lowercased, as name and value.
    pub headers: Vec<(String, String)>,
    /// The start of the body, as much as the run keeps.
    pub body: String,
}

/// The most answers the record holds: the anonymous questions are fewer than a hundred today, and
/// each answer is at most a few thousand characters, so the file stays under a megabyte.
pub const MOST_EXCHANGES: usize = 200;

/// The name of the file.
pub const FILE: &str = "seen.json";

/// What the file says about itself, read first.
const ABOUT: &str = "What sv saw of the running app while it made this report: each question it asked \
as somebody not signed in, and what the app answered. This is the app's own text, with every \
credential sv recognized cut down to its first four characters and its length, and the value \
of every cookie and sign-in header taken out. It can hold \
personal data the app was given during the run; only sv's own test accounts were used. Each \
answer's id is the one sv's checks read it by.";

/// `seen.json` for `report`.
pub fn render(report: &Report) -> String {
    let value = match &report.seen {
        Some(seen) => serde_json::json!({
            "app": report.app_name,
            "about": ABOUT,
            "exchanges": seen.exchanges,
            "not_answered": seen.not_answered,
            "left_out": seen.left_out,
            "most_kept": MOST_EXCHANGES,
            "credentials_removed": seen.credentials_removed,
        }),
        None => serde_json::json!({
            "app": report.app_name,
            "about": "sv did not ask the running app anything for this report, so there is nothing \
                      it saw to keep. The report says why the app was not run.",
            "exchanges": [],
        }),
    };
    serde_json::to_string_pretty(&value).expect("a JSON value serializes") + "\n"
}
