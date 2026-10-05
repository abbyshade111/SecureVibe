//! `design-decisions.md`: the decisions the design-time prompts write down before the code.
//!
//! Four of the prompts in `data/design-prompts.json` write a section of this file, each under a
//! heading of its own words and no requirement id. Two of them count toward a Secure by Design
//! checklist control and are read through `crate::notes`, with the catalog in
//! `data/design-decisions.json`: "What we do if something goes wrong" (SBD-MT-06) and "Rules that
//! might apply" (SBD-AC-06). The other two count toward nothing and are read here:
//!
//! - **"When to bring in a person"** says whether the app needs a person's security review as well
//!   as `sv`'s checks. Its words are repeated in the report, where what was not examined is listed,
//!   since no tool can make that review; `sv` does not decide what they recommend, and credits
//!   nothing for them.
//! - **"Safe defaults"** is read in a later change.
//!
//! The owner's decisions of 5 October 2026 (BACKLOG, design-time item 9).

/// The file, beside the app's securevibe.toml.
pub const FILE: &str = "design-decisions.md";

/// The heading the "when to bring in a person" prompt writes.
pub const BRING_IN_A_PERSON: &str = "When to bring in a person";

/// The most of a section repeated in the report, in characters: enough for a recommendation and
/// its reason, short enough that a long section does not take over the report.
const MOST_REPEATED: usize = 600;

/// What is written under `heading` in the file, as one line of text: `None` when there is no such
/// section or nothing under it. The section ends at the next heading of the first three levels, as
/// a notes section does. The line saying who wrote it, and a seal, are not repeated.
pub fn section(text: &str, heading: &str) -> Option<String> {
    let wanted = plain(heading);
    let mut lines = text.lines();
    lines.find(|line| {
        ["## ", "### "]
            .iter()
            .find_map(|prefix| line.trim_end().strip_prefix(prefix))
            .is_some_and(|rest| plain(rest) == wanted)
    })?;
    let words: Vec<&str> = lines
        .take_while(|line| {
            !["# ", "## ", "### "]
                .iter()
                .any(|prefix| line.trim_end().starts_with(prefix))
        })
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with(crate::notes::WRITTEN_BY)
                && !line.starts_with(crate::notes::SEALED_BY)
        })
        .collect();
    let joined = words.join(" ");
    if joined.is_empty() {
        return None;
    }
    Some(match joined.char_indices().nth(MOST_REPEATED) {
        Some((cut, _)) => format!("{}…", joined[..cut].trim_end()),
        None => joined,
    })
}

/// A heading as compared: trimmed, without a trailing colon or full stop, in lower case.
fn plain(text: &str) -> String {
    text.trim()
        .trim_end_matches([':', '.'])
        .trim()
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_section_is_read_to_the_next_heading_without_who_wrote_it() {
        let text = "# Design decisions\n\n## When to bring in a person\n\nWritten by: AI coding tool\n\n\
                    The app keeps health data, so ask someone who knows security to look at the \
                    design before it goes live.\n\n## Safe defaults\n\nDebug mode is off.\n";
        let read = section(text, BRING_IN_A_PERSON).expect("the section is there");
        assert!(read.starts_with("The app keeps health data"), "{read}");
        assert!(read.ends_with("before it goes live."), "{read}");
        assert!(!read.contains("Written by"), "{read}");
        assert!(
            !read.contains("Debug mode"),
            "the next section is not part of it: {read}"
        );
    }

    #[test]
    fn the_heading_is_matched_in_any_case_and_with_a_trailing_colon() {
        let text = "### when to bring in a person:\nRecommend a review.\n";
        assert_eq!(
            section(text, BRING_IN_A_PERSON).as_deref(),
            Some("Recommend a review.")
        );
    }

    #[test]
    fn no_section_or_nothing_under_it_is_none() {
        assert_eq!(section("## Safe defaults\nOff.\n", BRING_IN_A_PERSON), None);
        assert_eq!(
            section(
                "## When to bring in a person\n\nWritten by: owner\n\n## Safe defaults\n",
                BRING_IN_A_PERSON
            ),
            None,
            "a mark of who wrote it is not something written"
        );
        // A heading that only starts with the words is another heading.
        assert_eq!(
            section(
                "## When to bring in a person later\nNo.\n",
                BRING_IN_A_PERSON
            ),
            None
        );
    }

    #[test]
    fn a_long_section_is_cut_and_says_so() {
        let long = "word ".repeat(400);
        let read = section(
            &format!("## When to bring in a person\n{long}\n"),
            BRING_IN_A_PERSON,
        )
        .unwrap();
        assert!(read.ends_with('…'), "{read}");
        assert!(read.chars().count() <= MOST_REPEATED + 1, "{}", read.len());
    }
}
