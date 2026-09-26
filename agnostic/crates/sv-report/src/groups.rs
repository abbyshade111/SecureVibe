//! Splitting the long tables into something a person can work through.
//!
//! "Requirements that apply" was one table of 220 rows, and "Requirements nobody has placed" one of
//! 243. At that size a table stops being a list and becomes a reference document: the reader cannot
//! tell which rows they are expected to do something about, so they do nothing about any of them.
//!
//! The split is by ASVS level, level 1 first, because that is the order the standard itself asks for
//! and the order the work should be done in. Level 1 is the short list somebody could actually get
//! through; burying it among the level 2 rows is what made the whole thing feel inert.
//!
//! Controls with no ASVS level of their own — the Secure by Design checklist, the AISVS appendix —
//! go last under their own heading rather than being folded into level 1. `sv` assigns them a level
//! from an ASVS counterpart where it can, and that inferred level is the right basis for deciding
//! whether they apply; it is the wrong basis for telling the owner what to do first, because a
//! design-review control is not a thing to go and fix this afternoon.

use crate::RequirementLine;

/// A heading and the rows under it.
pub struct Group<'a> {
    pub heading: String,
    pub lines: Vec<&'a RequirementLine>,
}

/// Level 1, then level 2 and above, then the controls with no level of their own.
///
/// Empty groups are dropped: a heading over nothing is noise, and on a level 1 app the level 2
/// group does not exist at all.
pub fn by_level(lines: &[RequirementLine]) -> Vec<Group<'_>> {
    let pick = |f: &dyn Fn(&RequirementLine) -> bool| -> Vec<&RequirementLine> {
        lines.iter().filter(|l| f(l)).collect()
    };
    let candidates = [
        (
            "Level 1 — start here".to_owned(),
            pick(&|l: &RequirementLine| l.level == 1 && is_asvs(&l.id)),
        ),
        (
            "Level 2".to_owned(),
            pick(&|l: &RequirementLine| l.level >= 2 && is_asvs(&l.id)),
        ),
        (
            "Design review, which no tool settles at any level".to_owned(),
            pick(&|l: &RequirementLine| !is_asvs(&l.id)),
        ),
    ];
    candidates
        .into_iter()
        .filter(|(_, lines)| !lines.is_empty())
        .map(|(heading, lines)| Group { heading, lines })
        .collect()
}

/// An ASVS requirement, as opposed to a Secure by Design control or an AISVS appendix entry.
///
/// By the shape of the id rather than by the level, because `sv` gives the others an inferred level
/// and that inference is for deciding applicability, not for telling somebody what to do first.
fn is_asvs(id: &str) -> bool {
    id.starts_with('V') && id[1..].chars().next().is_some_and(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Status;

    fn line(id: &str, level: u8) -> RequirementLine {
        RequirementLine {
            id: id.into(),
            description: String::new(),
            chapter: String::new(),
            level,
            status: Status::NotVerified,
            findings: Vec::new(),
            checked_by: Vec::new(),
            supported_by: Vec::new(),
            documented_by: Vec::new(),
            attested_by: Vec::new(),
        }
    }

    #[test]
    fn level_one_comes_first() {
        let lines = vec![line("V2.1.1", 2), line("V1.2.4", 1)];
        let groups = by_level(&lines);
        assert!(
            groups[0].heading.starts_with("Level 1"),
            "{}",
            groups[0].heading
        );
        assert_eq!(groups[0].lines[0].id, "V1.2.4");
    }

    #[test]
    fn a_design_review_control_is_not_filed_under_level_one() {
        // `sv` gives a Secure by Design control a level inferred from an ASVS counterpart, and 14
        // of them come out at level 1. That inference decides whether the control applies; it must
        // not put "is an incident response plan rehearsed" at the top of a list headed "start here"
        // beside a concrete check somebody could do this afternoon.
        let lines = vec![line("SBD-AC-01", 1), line("C1.1.1", 1), line("V1.2.4", 1)];
        let groups = by_level(&lines);
        let first = &groups[0];
        assert!(first.heading.starts_with("Level 1"));
        assert_eq!(
            first
                .lines
                .iter()
                .map(|l| l.id.as_str())
                .collect::<Vec<_>>(),
            ["V1.2.4"],
            "only the ASVS requirement belongs at the top"
        );
        let last = groups.last().expect("a group for the rest");
        assert!(last.heading.contains("Design review"), "{}", last.heading);
        assert_eq!(last.lines.len(), 2);
    }

    #[test]
    fn an_empty_group_gets_no_heading() {
        // A level 1 app has no level 2 rows, and a heading over nothing is noise.
        let lines = vec![line("V1.2.4", 1)];
        let groups = by_level(&lines);
        assert_eq!(
            groups.len(),
            1,
            "{:?}",
            groups.iter().map(|g| &g.heading).collect::<Vec<_>>()
        );
    }

    #[test]
    fn every_line_lands_in_exactly_one_group() {
        // The property that matters most: this is the report's main table, and a requirement that
        // falls between two groups has silently vanished from it.
        let lines = vec![
            line("V1.2.4", 1),
            line("V2.1.1", 2),
            line("V10.4.12", 3),
            line("SBD-AC-01", 1),
            line("C1.1.1", 0),
        ];
        let groups = by_level(&lines);
        let mut seen: Vec<&str> = groups
            .iter()
            .flat_map(|g| g.lines.iter().map(|l| l.id.as_str()))
            .collect();
        seen.sort_unstable();
        let mut want: Vec<&str> = lines.iter().map(|l| l.id.as_str()).collect();
        want.sort_unstable();
        assert_eq!(seen, want, "a requirement fell between the groups");
    }

    #[test]
    fn a_level_above_two_is_grouped_with_level_two_rather_than_dropped() {
        // An app at level 2 can still carry a level 3 requirement, through the checklist crosswalk.
        // It must appear somewhere, and "Level 2" is where a reader would look for "not level 1".
        let lines = vec![line("V10.4.12", 3)];
        let groups = by_level(&lines);
        assert_eq!(groups.len(), 1);
        assert!(groups[0].heading.starts_with("Level 2"));
    }
}
