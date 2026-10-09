//! What the app's own code says about the answers that set its level (gap analysis of 7 October
//! 2026, finding 17; ADR-024, Later, 9 October 2026).
//!
//! An app is held to ASVS level 1 only on two answers in `stackvet.toml`: that only its owner or
//! their team uses it, and that it holds nothing sensitive about people. The AI coding tool usually
//! writes both. When the code has a sign-up route open to strangers, or fields named for health,
//! financial, card, or identity information, the report asks the owner about it under the level
//! line. Never a finding, and it changes no level: a name in the code is a hint, not proof of what
//! the app holds, and the owner is the one who knows.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use sv_scan::files::Listing;

/// What `data/level-hints.json` holds.
#[derive(Debug, Clone, Deserialize)]
pub struct Hints {
    /// The extensions of the code files read.
    pub extensions: Vec<String>,
    /// Route paths, without their leading slash, that let a stranger make an account.
    pub signup_routes: Vec<String>,
    /// For each sensitive data category, the field names that suggest it.
    pub categories: BTreeMap<String, Vec<String>>,
}

impl Hints {
    pub fn load(path: &Path) -> Result<Hints, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("{} could not be read ({e})", path.display()))?;
        serde_json::from_str(&text)
            .map_err(|e| format!("{} is not as expected: {e}", path.display()))
    }
}

/// One thing the code shows that the answers do not: the first place it was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hint {
    /// `sign-up` for a sign-up route, or the data category a field name suggests.
    pub kind: String,
    /// What was seen, as written in the code: `/register`, `blood_pressure`.
    pub seen: String,
    pub file: String,
    pub line: usize,
}

/// What the answers say, as far as the hints need them.
pub struct Answers<'a> {
    /// The audience is the owner or their team: a sign-up route is then worth asking about.
    pub private_audience: bool,
    /// The data categories listed, as written.
    pub listed: &'a [String],
}

/// The hints for an app, at most one per kind: a sign-up route first, then each data category in
/// alphabetical order, each at the first place it was seen. Files under a test folder, and
/// under any folder in `set_apart`, are not read: neither is the app as it runs.
pub fn find(
    listing: &Listing,
    hints: &Hints,
    answers: &Answers<'_>,
    set_apart: &BTreeSet<String>,
) -> Vec<Hint> {
    let listed: BTreeSet<String> = answers.listed.iter().map(|c| normalized(c)).collect();
    // Each data category to look for, with its names normalized; a category already listed is
    // already an answer, so it is not asked about.
    let categories: Vec<(&String, BTreeSet<String>)> = hints
        .categories
        .iter()
        .filter(|(category, _)| !listed.contains(&normalized(category)))
        .map(|(category, names)| (category, names.iter().map(|n| normalized(n)).collect()))
        .collect();
    let route = (answers.private_audience && !hints.signup_routes.is_empty()).then(|| {
        let alternatives: Vec<String> = hints
            .signup_routes
            .iter()
            .map(|r| regex::escape(r.trim_matches('/')))
            .collect();
        Regex::new(&format!(
            r#"["'`](/(?:{}))/?["'`?]"#,
            alternatives.join("|")
        ))
        .expect("the route pattern is built from escaped names")
    });
    let identifier = Regex::new(r"[A-Za-z_][A-Za-z0-9_\-]*").expect("a fixed pattern");

    let mut found: BTreeMap<String, Hint> = BTreeMap::new();
    let wanted = categories.len() + usize::from(route.is_some());
    for entry in &listing.files {
        if found.len() == wanted {
            break;
        }
        let relative = entry.relative.as_str();
        let extension = relative
            .rsplit_once('.')
            .map(|(_, e)| e.to_ascii_lowercase());
        if !extension.is_some_and(|e| hints.extensions.contains(&e))
            || crate::finding::is_test_path(relative)
            || set_apart
                .iter()
                .any(|folder| relative.starts_with(&format!("{}/", folder.trim_end_matches('/'))))
        {
            continue;
        }
        let Ok(text) = entry.read_text() else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            if let Some(route) = &route
                && !found.contains_key(SIGN_UP)
                && let Some(seen) = route.captures(line).and_then(|c| c.get(1))
            {
                found.insert(
                    SIGN_UP.to_owned(),
                    Hint {
                        kind: SIGN_UP.to_owned(),
                        seen: seen.as_str().to_owned(),
                        file: relative.to_owned(),
                        line: number + 1,
                    },
                );
            }
            for word in identifier.find_iter(line) {
                let name = normalized(word.as_str());
                for (category, names) in &categories {
                    if !found.contains_key(category.as_str()) && names.contains(&name) {
                        found.insert(
                            (*category).clone(),
                            Hint {
                                kind: (*category).clone(),
                                seen: word.as_str().to_owned(),
                                file: relative.to_owned(),
                                line: number + 1,
                            },
                        );
                    }
                }
            }
        }
    }
    // A sign-up route first, then the categories in alphabetical order.
    let mut ordered = Vec::new();
    if let Some(hint) = found.remove(SIGN_UP) {
        ordered.push(hint);
    }
    for (category, _) in &categories {
        if let Some(hint) = found.remove(category.as_str()) {
            ordered.push(hint);
        }
    }
    ordered
}

/// The kind a sign-up route is reported under.
pub const SIGN_UP: &str = "sign-up";

/// A name as compared: lower case, without `_`, `-`, or spaces, so `bloodPressure` is
/// `blood_pressure`, and a category written `" Health "` is `health`, as the manifest reads it.
fn normalized(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '_' && *c != '-' && !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// The question under the level line, or `None` when the code shows nothing the answers do not.
pub fn question(hints: &[Hint]) -> Option<String> {
    if hints.is_empty() {
        return None;
    }
    let seen: Vec<String> = hints
        .iter()
        .map(|h| {
            let what = if h.kind == SIGN_UP {
                "a sign-up page open to strangers".to_owned()
            } else {
                format!("{} information", said_as(&h.kind))
            };
            format!("{what} (`{}`, {} line {})", h.seen, h.file, h.line)
        })
        .collect();
    let list = match seen.as_slice() {
        [one] => one.clone(),
        [first, second] => format!("{first} and {second}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
        [] => unreachable!("not empty"),
    };
    Some(format!(
        "The code suggests {list}, which the answers do not say. A name in the code is only a \
         hint: if it is right, change the answer in stackvet.toml and the app is held to level 2."
    ))
}

/// A data category as a person reads it: `government-id` is "government ID".
fn said_as(category: &str) -> String {
    match category {
        "government-id" => "government ID".to_owned(),
        "payment-card" => "card".to_owned(),
        other => other.replace('-', " "),
    }
}
