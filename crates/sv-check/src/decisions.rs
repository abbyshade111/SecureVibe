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
//! - **"Safe defaults"** lists every feature and switch the app has and what was turned off. Three
//!   of its lines have a fixed form, each a switch a check of the running app can see:
//!   `- debug mode: off`, `- cross-site access: own site only`, and `- default accounts: none`.
//!   A switch decided the safe way that the check finds the other way is a finding of its own,
//!   *decided, not held to* (`decisions.not-held-to`), beside the check's. Nothing is credited for
//!   a decision the check agrees with: the check's own credit already says what it saw. The rest of
//!   the section is for a person.
//!
//! The owner's decisions of 5 October 2026 (BACKLOG, design-time item 9).

/// The file, beside the app's securevibe.toml.
pub const FILE: &str = "design-decisions.md";

/// The heading the "when to bring in a person" prompt writes.
pub const BRING_IN_A_PERSON: &str = "When to bring in a person";

/// The heading the "safe defaults" prompt writes.
pub const SAFE_DEFAULTS: &str = "Safe defaults";

/// The rule a decision broken by the code is reported under.
pub const NOT_HELD_TO: &str = "decisions.not-held-to";

/// A switch the "Safe defaults" section decides on one line, and the check that sees it.
#[derive(Debug, PartialEq, Eq)]
pub struct Switch {
    /// The words before the colon.
    pub name: &'static str,
    /// The safe value, the one the prompt asks for.
    pub safe: &'static str,
    /// The other value a person may decide, which is not held against the code.
    pub other: &'static str,
    /// The check whose finding means the code does not do what `safe` says.
    pub rule_id: &'static str,
}

/// The three switches, each with a check of the running app that sees it. Debug mode is held only
/// to a development console answering, which happens only with debug on; an error page with a
/// stack trace can come from other causes, so it is not taken to mean debug mode.
pub const SWITCHES: [Switch; 3] = [
    Switch {
        name: "debug mode",
        safe: "off",
        other: "on",
        rule_id: "probe.development-console-open",
    },
    Switch {
        name: "cross-site access",
        safe: "own site only",
        other: "any site",
        rule_id: "probe.cors-any-origin",
    },
    Switch {
        name: "default accounts",
        safe: "none",
        other: "some",
        rule_id: "probe.default-account",
    },
];

/// One switch as the section decides it.
#[derive(Debug, PartialEq, Eq)]
pub struct Decided {
    pub switch: &'static Switch,
    /// Whether the decision is the safe value; otherwise it is `other`.
    pub safe: bool,
    /// The line it is on, counted from 1.
    pub line: usize,
}

/// What the "Safe defaults" section decides, switch by switch.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct SafeDefaults {
    pub decided: Vec<Decided>,
    /// A switch's line whose value is neither of the two, as written: named, not guessed at.
    pub unreadable: Vec<String>,
}

/// The fixed lines of the "Safe defaults" section. A switch named twice counts the first time.
pub fn safe_defaults(text: &str) -> SafeDefaults {
    let mut out = SafeDefaults::default();
    let wanted = plain(SAFE_DEFAULTS);
    let lines: Vec<&str> = text.lines().collect();
    let Some(start) = lines
        .iter()
        .position(|line| heading_of(line).is_some_and(|h| h == wanted))
    else {
        return out;
    };
    for (i, line) in lines.iter().enumerate().skip(start + 1) {
        if heading_of(line).is_some() || line.trim_start().starts_with("# ") {
            break;
        }
        let item = line.trim();
        let Some(item) = item.strip_prefix("- ").or_else(|| item.strip_prefix("* ")) else {
            continue;
        };
        let Some((name, value)) = item.split_once(':') else {
            continue;
        };
        let Some(switch) = SWITCHES.iter().find(|s| plain(name) == s.name) else {
            continue;
        };
        if out.decided.iter().any(|d| std::ptr::eq(d.switch, switch)) {
            continue;
        }
        // `own site only`. and own site only are the same decision.
        let value = plain(&plain(value).replace('`', ""));
        if value == switch.safe || value == switch.other {
            out.decided.push(Decided {
                switch,
                safe: value == switch.safe,
                line: i + 1,
            });
        } else {
            out.unreadable.push(item.to_owned());
        }
    }
    out
}

/// A finding for each switch decided the safe way whose check found the other way, beside that
/// check's own finding. The check's finding is the problem; this one is that the decision written
/// down is not what the app does.
pub fn not_held_to(decided: &[Decided], findings: &[crate::Finding]) -> Vec<crate::Finding> {
    decided
        .iter()
        .filter(|d| d.safe)
        .filter_map(|d| {
            let found = findings.iter().find(|f| f.rule_id == d.switch.rule_id)?;
            let said = format!("{}: {}", d.switch.name, d.switch.safe);
            Some(crate::Finding {
                also_reported_by: Vec::new(),
                fingerprint: String::new(),
                earlier_fingerprints: Vec::new(),
                marked_test_code: false,
                bundled_library: None,
                rule_id: NOT_HELD_TO.to_owned(),
                title: format!("Decided \"{said}\", and the running app does otherwise"),
                severity: crate::Severity::Low,
                confidence: found.confidence,
                location: crate::Location {
                    file: FILE.to_owned(),
                    line: d.line,
                },
                secret: None,
                requirement_ids: found.requirement_ids.clone(),
                cwe: found.cwe.clone(),
                description: format!(
                    "{FILE} says, under \"{SAFE_DEFAULTS}\", \"{said}\". The check {} found \
                     otherwise: {}",
                    found.rule_id, found.title
                ),
                impact: "A safe default written down and not held to reads as a decision kept \
                         when it is not: whoever reads the decisions file is told the app is safer \
                         than it is."
                    .to_owned(),
                fix: format!(
                    "Make the app do what was decided (the finding from {} says how), or, if the \
                     decision was changed on purpose, change the line in {FILE} and say why.",
                    found.rule_id
                ),
            })
        })
        .collect()
}

/// A heading of the first three levels, as compared: `None` for a line that is not one.
fn heading_of(line: &str) -> Option<String> {
    ["## ", "### "]
        .iter()
        .find_map(|prefix| line.trim_end().strip_prefix(prefix))
        .map(plain)
}

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

    const DEFAULTS: &str = "# Design decisions\n\n## Safe defaults\n\nWritten by: AI coding tool\n\n\
                            - debug mode: off\n- Cross-site access: `own site only`.\n\
                            * default accounts: some\n- the admin page: removed\n\n\
                            ## What we do if something goes wrong\n\n- debug mode: on\n";

    fn probe(rule_id: &str) -> crate::Finding {
        crate::Finding {
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            rule_id: rule_id.to_owned(),
            title: format!("what {rule_id} saw"),
            severity: crate::Severity::Medium,
            confidence: crate::Confidence::High,
            location: crate::Location {
                file: "/".to_owned(),
                line: 0,
            },
            secret: None,
            requirement_ids: vec!["V13.4.2".to_owned()],
            cwe: vec!["CWE-489".to_owned()],
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
        }
    }

    #[test]
    fn the_three_switches_are_read_from_their_own_section_only() {
        let read = safe_defaults(DEFAULTS);
        let got: Vec<(&str, bool, usize)> = read
            .decided
            .iter()
            .map(|d| (d.switch.name, d.safe, d.line))
            .collect();
        // The line after the heading is 3; the switches are on 7, 8, and 9. The admin page is the
        // section's own words, and the "debug mode: on" under the next heading is not this section's.
        assert_eq!(
            got,
            [
                ("debug mode", true, 7),
                ("cross-site access", true, 8),
                ("default accounts", false, 9)
            ]
        );
        assert!(read.unreadable.is_empty(), "{:?}", read.unreadable);
    }

    #[test]
    fn a_switch_with_another_value_is_named_and_the_first_line_counts() {
        let read = safe_defaults(
            "## Safe defaults:\n- debug mode: mostly off\n- default accounts: none\n- default accounts: some\n",
        );
        assert_eq!(read.unreadable, ["debug mode: mostly off"]);
        assert_eq!(read.decided.len(), 1);
        assert!(
            read.decided[0].safe,
            "the first line about a switch is the decision"
        );
        assert_eq!(
            safe_defaults("## When to bring in a person\n- debug mode: off\n"),
            SafeDefaults::default()
        );
        // A switch only in the section after it is that section's, not this one's.
        assert_eq!(
            safe_defaults(
                "## Safe defaults\nNothing to say.\n## Rules that might apply\n- debug mode: off\n"
            ),
            SafeDefaults::default()
        );
    }

    #[test]
    fn a_safe_decision_the_running_app_breaks_is_a_finding_and_no_other_is() {
        let decided = safe_defaults(DEFAULTS).decided;
        let findings = [
            probe("probe.development-console-open"),
            probe("probe.default-account"),
        ];
        let out = not_held_to(&decided, &findings);
        // Debug mode was decided off and a console answered. Default accounts were decided "some",
        // which is the owner's call and not held against the code. Cross-site access was decided
        // own site only and nothing found otherwise.
        assert_eq!(out.len(), 1, "{out:?}");
        let f = &out[0];
        assert_eq!(f.rule_id, NOT_HELD_TO);
        assert_eq!(
            f.title,
            "Decided \"debug mode: off\", and the running app does otherwise"
        );
        assert_eq!((f.location.file.as_str(), f.location.line), (FILE, 7));
        assert_eq!(f.severity, crate::Severity::Low);
        assert_eq!(
            f.requirement_ids,
            ["V13.4.2"],
            "the check's own requirements"
        );
        assert!(
            f.description.contains("probe.development-console-open"),
            "{}",
            f.description
        );
        // Nothing found, nothing said; and no decision, nothing held.
        assert!(not_held_to(&decided, &[]).is_empty());
        assert!(not_held_to(&[], &findings).is_empty());
        // Each switch to its own check: cross-site access, broken, is caught by its check alone.
        let cors = not_held_to(&decided, &[probe("probe.cors-any-origin")]);
        assert_eq!(cors.len(), 1);
        assert!(
            cors[0].title.contains("cross-site access: own site only"),
            "{}",
            cors[0].title
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
