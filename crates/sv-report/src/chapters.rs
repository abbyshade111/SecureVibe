//! The requirements, counted chapter by chapter, for the compliance page.
//!
//! The owner's decision (28 September 2026): group the requirements that apply by chapter, with each
//! chapter's count in bold and the full text in an appendix, and show beside it how many in the same
//! chapter do not apply. A page that opens on 230 rows of *not verified* reads as an app that is
//! nowhere; a chapter that says *33 apply, 2 do not* tells the owner the standard was read against
//! their app and some of it was set aside for a reason, and where the work is.
//!
//! The counts are made from the same lists the headline counts are made from, so each column adds up
//! to the report's own total for it (the tests hold that). *Does not apply* is its own column and is
//! never added to anything that sounds like progress.
//!
//! The requirements about how the app is built with an AI coding tool (OWASP AISVS Appendix C) that
//! nothing has reached are counted apart everywhere else in the report, and they are here too: their
//! chapter's row counts only the ones among the app's own requirements, the ones that do not apply,
//! and the ones nobody has placed, and the page says how many are counted apart.

use crate::{APPENDIX_C, Report, RequirementLine, Status};

/// One chapter's counts, and its requirements that apply.
#[derive(Debug)]
pub struct Chapter<'a> {
    /// The id's prefix: `V6`, `SBD-AC`, `C12`, `AC`.
    pub key: String,
    /// The chapter's name in its standard, or empty when the standard gives none.
    pub name: String,
    pub needs_attention: usize,
    pub checked: usize,
    /// Checked only in part (ADR-053): never counted as checked.
    pub checked_in_part: usize,
    /// Passed the app's own tests and nothing more (ADR-050): never counted as checked.
    pub app_tested: usize,
    /// Documented, attested, or checked by hand: the owner's word, or a confirmer's, never a check.
    pub your_word: usize,
    /// Stated by the AI coding tool, which ranks below the owner's word.
    pub tool_word: usize,
    pub not_verified: usize,
    pub does_not_apply: usize,
    pub not_placed: usize,
    /// The requirements that apply, level 1 first, then by id.
    pub lines: Vec<&'a RequirementLine>,
}

impl Chapter<'_> {
    /// How many of this chapter's requirements apply to the app.
    pub fn applies(&self) -> usize {
        self.lines.len()
    }

    /// The chapter as a heading names it: `V6 Authentication`.
    ///
    /// Appendix C is one row for all its sections, so it is named for the appendix. The name of
    /// whichever section happened to come first would have titled every one of them with it.
    pub fn title(&self) -> String {
        if self.key == APPENDIX_C.trim_end_matches('.') {
            return "AISVS Appendix C: how the app is built with AI".to_owned();
        }
        if self.name.is_empty() {
            self.key.clone()
        } else {
            format!("{} {}", self.key, self.name)
        }
    }
}

/// The chapter an id belongs to, by its prefix.
///
/// By the id rather than by the chapter's name, because two standards share names ("Monitoring,
/// Logging & Anomaly Detection" is AISVS C12; the checklist has "Monitoring, Testing & Incident
/// Readiness"), and a key must not merge two chapters that only sound alike.
pub fn key(id: &str) -> String {
    if let Some(rest) = id.strip_prefix("SBD-") {
        let part = rest.split('-').next().unwrap_or(rest);
        return format!("SBD-{part}");
    }
    id.split('.').next().unwrap_or(id).to_owned()
}

/// Where a chapter goes: ASVS by number, then the Secure by Design checklist, then AISVS by number,
/// then Appendix C last, since it is about how the app is built rather than the app.
fn order(key: &str) -> (u8, u32, String) {
    let number = |s: &str| s.parse::<u32>().unwrap_or(u32::MAX);
    if key == APPENDIX_C.trim_end_matches('.') {
        (3, 0, String::new())
    } else if key.starts_with("SBD-") {
        (1, 0, key.to_owned())
    } else if let Some(n) = key.strip_prefix('V') {
        (0, number(n), String::new())
    } else if let Some(n) = key.strip_prefix('C') {
        (2, number(n), String::new())
    } else {
        (4, 0, key.to_owned())
    }
}

/// Every chapter any requirement in the report belongs to, in the standards' order.
///
/// A chapter appears when anything in it applies, does not apply, or waits on a question; one where
/// nothing does is left out. Every requirement that applies is in exactly one chapter's `lines`.
pub fn by_chapter(report: &Report) -> Vec<Chapter<'_>> {
    let mut chapters: Vec<Chapter<'_>> = Vec::new();
    let mut at = |id: &str, name: &str| -> usize {
        let k = key(id);
        if let Some(i) = chapters.iter().position(|c| c.key == k) {
            if chapters[i].name.is_empty() {
                chapters[i].name = name.to_owned();
            }
            return i;
        }
        chapters.push(Chapter {
            key: k,
            name: name.to_owned(),
            needs_attention: 0,
            checked: 0,
            checked_in_part: 0,
            app_tested: 0,
            your_word: 0,
            tool_word: 0,
            not_verified: 0,
            does_not_apply: 0,
            not_placed: 0,
            lines: Vec::new(),
        });
        chapters.len() - 1
    };
    let mut placed: Vec<(usize, &RequirementLine)> = Vec::new();
    for line in &report.requirements {
        placed.push((at(&line.id, &line.chapter), line));
    }
    let excluded: Vec<usize> = report
        .excluded
        .iter()
        .map(|e| at(&e.id, &e.chapter))
        .collect();
    let undecided: Vec<usize> = report
        .undecided
        .iter()
        .map(|u| at(&u.id, &u.chapter))
        .collect();
    for (i, line) in placed {
        let c = &mut chapters[i];
        match line.status {
            Status::NeedsAttention => c.needs_attention += 1,
            Status::Checked => c.checked += 1,
            Status::CheckedInPart => c.checked_in_part += 1,
            Status::AppTested => c.app_tested += 1,
            Status::Documented | Status::Attested | Status::ByHand => c.your_word += 1,
            Status::Stated => c.tool_word += 1,
            Status::NotVerified => c.not_verified += 1,
        }
        c.lines.push(line);
    }
    for i in excluded {
        chapters[i].does_not_apply += 1;
    }
    for i in undecided {
        chapters[i].not_placed += 1;
    }
    let natural = |id: &str| -> Vec<u32> {
        id.split(|c: char| !c.is_ascii_digit())
            .filter_map(|n| n.parse().ok())
            .collect()
    };
    for c in &mut chapters {
        c.lines.sort_by(|a, b| {
            a.level
                .cmp(&b.level)
                .then_with(|| natural(&a.id).cmp(&natural(&b.id)))
        });
    }
    chapters.sort_by_key(|c| order(&c.key));
    chapters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_the_chapter_part_of_the_id() {
        assert_eq!(key("V6.2.1"), "V6");
        assert_eq!(key("V16.5.1"), "V16");
        assert_eq!(key("C12.2.2"), "C12");
        assert_eq!(key("SBD-AC-05"), "SBD-AC");
        assert_eq!(key("AC.1.2"), "AC");
    }

    #[test]
    fn chapters_go_in_the_standards_order_and_by_number_not_by_spelling() {
        // V10 sorted as text comes before V2; a reader looking for chapter 2 looks near the top.
        let mut keys = vec!["C2", "AC", "V10", "SBD-DM", "V2", "C10", "SBD-AC"];
        keys.sort_by_key(|k| order(k));
        assert_eq!(keys, ["V2", "V10", "SBD-AC", "SBD-DM", "C2", "C10", "AC"]);
    }
}
