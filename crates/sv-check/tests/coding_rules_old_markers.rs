//! A rules block written before the rename, between the old markers, is found and rewritten
//! between the new ones (ADR-062); everything outside the markers is kept as it was.

use std::path::PathBuf;
use sv_check::coding_rules::{BEGIN, CodingRules, END};
use sv_frameworks::names::{OLD_RULES_BEGIN, OLD_RULES_END};

fn rules() -> CodingRules {
    CodingRules::load(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/coding-rules.json"),
    )
    .unwrap()
}

#[test]
fn a_block_under_the_old_markers_is_replaced_and_rewritten_under_the_new() {
    let existing = format!(
        "# Mine\n\nMy notes.\n\n{OLD_RULES_BEGIN}\nold rules here\n{OLD_RULES_END}\n\nMore of mine.\n"
    );
    let out = rules()
        .into_agents_file(Some(&existing), "new rules here")
        .unwrap();
    assert!(out.starts_with("# Mine\n\nMy notes.\n\n"), "{out}");
    assert!(out.ends_with("\nMore of mine.\n"), "{out}");
    assert!(
        out.contains("new rules here") && !out.contains("old rules here"),
        "{out}"
    );
    assert_eq!(out.matches(BEGIN).count(), 1, "{out}");
    assert_eq!(out.matches(END).count(), 1, "{out}");
    assert!(
        !out.contains(OLD_RULES_BEGIN) && !out.contains(OLD_RULES_END),
        "{out}"
    );
    // Written again, the block under the new markers is the one replaced.
    let again = rules().into_agents_file(Some(&out), "newer").unwrap();
    assert_eq!(again.matches(BEGIN).count(), 1, "{again}");
    assert!(
        again.contains("newer") && !again.contains("new rules here"),
        "{again}"
    );
}

#[test]
fn one_old_marker_without_the_other_is_still_refused() {
    let existing = format!("# Mine\n{OLD_RULES_BEGIN}\nhalf a section\n");
    let err = rules().into_agents_file(Some(&existing), "x").unwrap_err();
    assert!(
        err.to_string()
            .contains("one of `sv`'s markers without the other"),
        "{err}"
    );
}
