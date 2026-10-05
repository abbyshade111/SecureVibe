//! data/design-decisions.json held to what it stands on: each section a real Secure by Design control
//! that the prompt writing its heading names, the heading the very words that prompt writes, and the
//! file the one `sv_check::decisions` reads.

use std::path::PathBuf;

fn data(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

/// A prompt's words with every run of white space one space, since a prompt wraps its lines.
fn flat(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn json(file: &str) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(data(file)).unwrap()).unwrap()
}

#[test]
fn each_section_is_a_control_its_prompt_names_under_the_heading_it_writes() {
    let catalog = sv_check::notes::Catalog::load(&data("design-decisions.json")).unwrap();
    assert_eq!(catalog.file, sv_check::decisions::FILE);
    assert_eq!(catalog.sections.len(), 2, "the owner chose two controls");
    let checklist = std::fs::read_to_string(data("frameworks/sbd-checklist-0.5.0.json")).unwrap();
    let prompts = json("design-prompts.json");
    let prompts = prompts["prompts"].as_array().unwrap();
    for section in &catalog.sections {
        let heading = section.heading.as_deref().expect("each goes by a heading");
        let short = section.id.trim_start_matches("SBD-");
        assert!(
            checklist.contains(&format!("\"id\": \"{short}\"")),
            "{} is not a control of the checklist",
            section.id
        );
        let writer: Vec<&serde_json::Value> = prompts
            .iter()
            .filter(|p| {
                p["prompt"].as_str().is_some_and(|text| {
                    text.contains(&format!("design-decisions.md, under \"{heading}\""))
                })
            })
            .collect();
        assert_eq!(writer.len(), 1, "{heading}: exactly one prompt writes it");
        assert!(
            writer[0]["sbd_controls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c == section.id.as_str()),
            "{}: the prompt writing \"{heading}\" does not name it",
            section.id
        );
        assert!(
            section
                .not_covered
                .as_deref()
                .is_some_and(|n| n.contains("not covered")),
            "{}: say what a written section does not show",
            section.id
        );
    }
}

#[test]
fn the_section_repeated_as_a_reminder_is_the_heading_its_prompt_writes() {
    let prompts = json("design-prompts.json");
    let wanted = format!(
        "design-decisions.md, under \"{}\"",
        sv_check::decisions::BRING_IN_A_PERSON
    );
    let writers = prompts["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| {
            p["prompt"]
                .as_str()
                .is_some_and(|t| flat(t).contains(&wanted))
        })
        .count();
    assert_eq!(writers, 1, "exactly one prompt writes {wanted}");
}
