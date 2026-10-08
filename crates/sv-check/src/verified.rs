//! What a check looked at and found nothing wrong with.
//!
//! The mirror of `Finding`, and the harder of the two to get right. A finding is a claim about
//! something that is there; this is a claim about something that is *not*, and a claim of absence is
//! only worth the coverage behind it. Three rules hold everywhere one of these is produced:
//!
//! **Fail closed.** A check emits nothing unless it read everything it would have needed to read. A
//! credential scan that skipped four files has not established that the app holds no credentials; it
//! has established nothing, and the skipped files are already reported as a gap. Emitting a weakened
//! claim instead would put a reassuring line in the report next to a caveat nobody reads.
//!
//! **Say the scope in the words a person would use.** `scope` is printed beside the claim, because
//! "checked" means nothing without "over what". A reader who can see *12 Python files* can tell at a
//! glance that the Ruby half of their app was not part of it.
//!
//! **Only what the check actually tests.** `requirement_ids` here are the same ids the check cites
//! when it fails. A check that names more requirements when it passes than when it fails is claiming
//! credit for work it did not do, and that is the one direction this type must never move in.

use serde::Serialize;

/// Whose word a credit rests on, which decides what a requirement with no finding is called in the
/// report (ADR-022, ADR-050): a check of `sv`'s own outranks the app's tests, which outrank a
/// person's written answer, which outranks a check a person made by hand, which outranks the
/// owner's `yes` to a design question, which outranks the AI coding tool's. Until 8 October 2026 a
/// credit landed in a tier by which list it was passed to the report in, and the owner's `yes` was
/// told from the tool's by the check's name; now each credit says, and the report reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    /// A check of `sv`'s own read the app or watched it run: *checked*.
    #[default]
    Checked,
    /// The app's own tests name the requirement and passed (ADR-050): *tested by the app's own
    /// tests*, never folded into *checked*.
    AppTested,
    /// The owner answered the question in the security notes, recorded through `sv review`
    /// (ADR-017): *documented*.
    Documented,
    /// The owner checked it by hand and recorded what they saw (ADR-022): *checked by hand*.
    ByHand,
    /// The owner answered `yes` to a design question, recorded through `sv review`: *attested*.
    Attested,
    /// The AI coding tool answered, or nobody recorded that the owner did: *stated*, the lowest.
    Stated,
}

impl Tier {
    /// Whether a machine read the app for this credit, rather than a person's word being taken.
    pub fn is_a_check(self) -> bool {
        matches!(self, Tier::Checked | Tier::AppTested)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verified {
    /// The rule or check that ran, named the same way its findings are.
    pub check_id: String,
    /// The requirements this is evidence about. Empty is allowed and means evidence about the app in
    /// general rather than about any requirement — a fair thing to be, and visible rather than assumed.
    pub requirement_ids: Vec<String>,
    /// What was examined, in a person's words: "12 Python files", "48 files, against 8 known
    /// credential formats". Printed beside the claim.
    pub scope: String,
    /// The check tried only part of what its requirements ask, so it is evidence *in part*: a
    /// requirement whose only credit is in part is *checked in part*, never *checked* (ADR-053).
    /// V8.2.2 is the first: another user refused reading a record, with changing and deleting it
    /// not tried. Left out of the JSON when false, so nothing else's output changes.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub in_part: bool,
    /// Whose word this rests on. Not written into any report: the report says it as the
    /// requirement's status, which is what a reader is given.
    #[serde(skip)]
    pub tier: Tier,
}

impl Verified {
    #[track_caller]
    pub fn new(check_id: &str, requirement_ids: &[&str], scope: String) -> Self {
        #[cfg(debug_assertions)]
        census(check_id, requirement_ids, std::panic::Location::caller());
        Verified {
            check_id: check_id.to_owned(),
            requirement_ids: requirement_ids.iter().map(|s| (*s).to_owned()).collect(),
            scope,
            in_part: false,
            tier: Tier::Checked,
        }
    }

    /// The same credit, marked as resting on part of what its requirements ask (ADR-053).
    pub fn in_part(mut self) -> Self {
        self.in_part = true;
        self
    }

    /// The same credit, resting on `tier`'s word rather than a check of `sv`'s own.
    pub fn resting_on(mut self, tier: Tier) -> Self {
        self.tier = tier;
        self
    }
}

/// Where a check that withholds without a finding has run: when `verified` holds no credit from it, it
/// withheld, saying "not assessed" or nothing, and in a debug build that is written to the census of
/// findings beside the credits (`finding::found`), with the place that called this. A check that says
/// no with a finding is seen there already; one that says no without one is seen only through this
/// (backlog item 32). It decides nothing and changes nothing: a release build does nothing here.
#[track_caller]
pub fn unless_credited(check_id: &str, verified: &[Verified]) {
    #[cfg(debug_assertions)]
    if !verified.iter().any(|v| v.check_id == check_id) {
        crate::finding::withheld_census(check_id, std::panic::Location::caller());
    }
    #[cfg(not(debug_assertions))]
    let _ = (check_id, verified);
}

/// In a debug build (the test suite), with `SV_CREDIT_LOG` set, each credit is added to that file as
/// one line: the check, its requirements, and the place in the code that gave it.
/// `tools/coverage.py --credits` reads the file, to tell which checks the suite saw give credit.
#[cfg(debug_assertions)]
fn census(check_id: &str, requirement_ids: &[&str], at: &std::panic::Location) {
    use std::io::Write;
    let Some(log) = std::env::var_os("SV_CREDIT_LOG") else {
        return;
    };
    let line = format!(
        "{check_id}\t{}\t{}:{}\n",
        requirement_ids.join(","),
        at.file(),
        at.line()
    );
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
    {
        let _ = file.write_all(line.as_bytes());
    }
}
