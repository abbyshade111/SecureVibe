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
}

impl Verified {
    pub fn new(check_id: &str, requirement_ids: &[&str], scope: String) -> Self {
        Verified {
            check_id: check_id.to_owned(),
            requirement_ids: requirement_ids.iter().map(|s| (*s).to_owned()).collect(),
            scope,
        }
    }
}
