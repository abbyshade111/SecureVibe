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
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
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
    /// What `sv`'s stand-in services received during the run (backlog 0229, part 2). Empty when
    /// none ran.
    #[serde(skip_serializing_if = "StandIns::is_empty")]
    pub stand_ins: StandIns,
    /// The lines of the app's own output the log checks read, and its last lines (backlog 0229,
    /// part 3). Empty when no log check ran.
    #[serde(skip_serializing_if = "AppLog::is_empty")]
    pub app_log: AppLog,
    /// Each outside tool's own report, when `--keep-tool-output` asked for them (backlog 0229,
    /// part 4). Empty otherwise.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tool_output: Vec<ToolOutput>,
}

/// One outside tool's own report, as it wrote it, with the credentials in it cut out.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToolOutput {
    /// The program that wrote it.
    pub program: String,
    /// The rules `sv` reads it as (`semgrep.`, `bandit.`), which the report's findings carry.
    pub rules: String,
    /// What it wrote, cut at `MOST_TOOL_CHARS` characters.
    pub report: String,
    /// How many characters were cut from the end; 0 when it is whole.
    pub cut_chars: usize,
}

/// The most characters of one tool's report kept: a few megabytes of SARIF at most, so the file
/// stays well within what the seal reads.
pub const MOST_TOOL_CHARS: usize = 2_000_000;

/// What `sv` kept of the app's own output.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct AppLog {
    /// Each line a log check read a conclusion from, with what it was read for.
    pub lines_read: Vec<LogLine>,
    /// The last lines of its output when the log was read.
    pub last_lines: Vec<String>,
    /// Lines cut at `KEPT_CHARS` characters.
    pub cut: usize,
}

impl AppLog {
    pub fn is_empty(&self) -> bool {
        self.lines_read.is_empty() && self.last_lines.is_empty()
    }
}

/// One line of the app's output, and what a log check read it for.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct LogLine {
    pub read_for: String,
    pub line: String,
}

/// What `sv`'s stand-in services received: the test model, the test sign-in provider, and the mail
/// catcher, each `None` when it did not run.
#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct StandIns {
    /// What arrived at the test model for each message (`seen`), and the tags fetched through it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<serde_json::Value>,
    /// The requests the test sign-in provider was sent: method, path, and the names of the query's
    /// parameters, never their values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_in_provider: Option<serde_json::Value>,
    /// Each message the app sent: who it was to, its subject, and when. Never its body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mail: Option<Vec<Mail>>,
    /// The stand-ins that ran and whose record could not be read.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_read: Vec<String>,
    /// Text and entries left out to keep the record bounded: strings cut at `KEPT_CHARS`
    /// characters, and lists at `MOST_EXCHANGES` entries.
    pub cut: usize,
}

impl StandIns {
    pub fn is_empty(&self) -> bool {
        self.model.is_none()
            && self.sign_in_provider.is_none()
            && self.mail.is_none()
            && self.not_read.is_empty()
    }
}

/// One message the app sent, without its body.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Mail {
    pub to: Vec<String>,
    pub subject: String,
    pub at: String,
}

/// The most characters of any one piece of text a stand-in received that the record keeps: as
/// much as the run keeps of an answer's body.
pub const KEPT_CHARS: usize = 4000;

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
as somebody not signed in, and what the app answered; and, under stand_ins, what sv's own stand-ins \
for the services the app uses received from it (the test model, the test sign-in provider, and the \
mail catcher, of whose mail only who it was to, its subject, and when are kept); and, under app_log, \
the lines of the app's own output the log checks read, and its last lines; and, under tool_output, \
when --keep-tool-output asked for them, each outside tool's own report, which quotes the app's code. This is the app's own text, with every \
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
            "stand_ins": seen.stand_ins,
            "app_log": seen.app_log,
            "tool_output": seen.tool_output,
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
