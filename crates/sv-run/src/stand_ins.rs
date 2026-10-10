//! What `sv`'s stand-in services received during a run, read from each before its container is
//! removed, for `sv` to keep beside the report (ADR-082, backlog 0229, part 2).
//!
//! The test model keeps what arrived for each message it was sent (the instructions it came with,
//! the tools it was offered, what the app's tools returned) and the addresses fetched through it.
//! The test sign-in provider keeps each request's method, path, and the names of its query
//! parameters, never their values. Of the mail, only who each message was to, its subject, and when
//! it came are kept, never its body, which holds the reset links and codes sent to `sv`'s test
//! accounts; a subject's long numbers and addresses are left out for the same reason.
//!
//! `sv`'s own test secrets (the accounts' passwords and two-factor secrets, the sign-in provider's
//! client secret, the MCP token) are blanked here by value, before anything is parsed, since only
//! this crate knows them; every other credential is cut where the record is written
//! (`sv-cli`'s `seen` module).

use serde_json::Value;

/// What a test secret is replaced with.
pub const TEST_SECRET: &str = "[a test secret, left out]";

/// What the stand-ins received.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct StandIns {
    /// The test model's record, as it handed it over: `seen` (what arrived for each tag) and
    /// `fetched` (the tags fetched through it). `None` when it was not running.
    pub model: Option<Value>,
    /// The test sign-in provider's record of the requests it was sent. `None` when it was not running.
    pub provider: Option<Value>,
    /// The mail the app sent. `None` when the mail catcher was not running.
    pub mail: Option<Vec<Mail>>,
    /// The stand-ins that were running and whose record could not be read, by name.
    pub unread: Vec<&'static str>,
}

/// One message the app sent, without its body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    pub to: Vec<String>,
    pub subject: String,
    pub at: String,
}

/// `text` with each of `secrets` replaced by `TEST_SECRET`.
pub fn without_test_secrets(text: &str, secrets: &[String]) -> String {
    let mut text = text.to_owned();
    // The longest first, so a secret that holds another is blanked whole.
    let mut secrets: Vec<&String> = secrets.iter().filter(|s| !s.is_empty()).collect();
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for secret in secrets {
        text = text.replace(secret.as_str(), TEST_SECRET);
    }
    text
}

/// The lines of the app's output a suite kept (`log_lines`, `log_tail`), with each of `secrets`
/// blanked.
pub fn blank_log(asked: &mut sv_check::signed_in::Outcome, secrets: &[String]) {
    for kept in &mut asked.log_lines {
        kept.line = without_test_secrets(&kept.line, secrets);
    }
    for line in &mut asked.log_tail {
        *line = without_test_secrets(line, secrets);
    }
}

/// A stand-in's JSON answer, read with the test secrets blanked first.
pub fn read_json(text: &str, secrets: &[String]) -> Option<Value> {
    serde_json::from_str(&without_test_secrets(text, secrets)).ok()
}

/// The mail in Mailpit's listing (`/api/v1/messages`), without bodies, oldest first.
pub fn mail_of(listing: &str, secrets: &[String]) -> Option<Vec<Mail>> {
    let value = read_json(listing, secrets)?;
    let messages = value.get("messages")?.as_array()?;
    let text = |m: &Value, name: &str| m.get(name).and_then(Value::as_str).unwrap_or("").to_owned();
    let mut mail: Vec<Mail> = messages
        .iter()
        .map(|m| Mail {
            to: ["To", "Cc", "Bcc"]
                .iter()
                .filter_map(|field| m.get(*field)?.as_array())
                .flatten()
                .filter_map(|r| r.get("Address")?.as_str().map(str::to_owned))
                .collect(),
            subject: without_codes(&text(m, "Subject")),
            at: text(m, "Created"),
        })
        .collect();
    // Mailpit lists the newest first.
    mail.reverse();
    Some(mail)
}

/// `subject` with every run of four or more digits and every web address left out: a subject is
/// where an app puts the code it is sending ("Your code is 482913") as often as the body.
pub fn without_codes(subject: &str) -> String {
    const LEFT_OUT: &str = "[left out]";
    let words: Vec<String> = subject
        .split(' ')
        .map(|word| {
            if word.contains("://") {
                return LEFT_OUT.to_owned();
            }
            let mut out = String::new();
            let mut digits = String::new();
            for c in word.chars().chain(std::iter::once(' ')) {
                if c.is_ascii_digit() {
                    digits.push(c);
                    continue;
                }
                if digits.len() >= 4 {
                    out.push_str(LEFT_OUT);
                } else {
                    out.push_str(&digits);
                }
                digits.clear();
                if c != ' ' {
                    out.push(c);
                }
            }
            out
        })
        .collect();
    words.join(" ")
}

#[cfg(test)]
#[path = "stand_ins_tests.rs"]
mod stand_ins_tests;
