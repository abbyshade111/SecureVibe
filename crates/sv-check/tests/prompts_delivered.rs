//! Gap analysis 4.6, its second half: "shown to work" read the same for a prompt pasted into the
//! request and for one `sv` gave the AI tool itself, though `ai-feature-guard`, shown when pasted, was
//! not shown when `sv` gave it. Every prompt's readings of the two delivery trials are held here to
//! each trial's own verdict file, and every copy of its status says them.

use std::collections::BTreeSet;
use std::path::PathBuf;
use sv_check::prompts::{Prompts, Status, Trial, Verdict};

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn library() -> Prompts {
    Prompts::load(&repo().join("data/prompts.json")).expect("the library loads")
}

/// Every (prompt, trial, model, verdict) a trial's verdict file records.
fn recorded() -> BTreeSet<(String, Trial, String, Verdict)> {
    let mut all = BTreeSet::new();
    for (trial, file) in [(Trial::Start, "start"), (Trial::Delivery, "delivery")] {
        let path = repo().join(format!("docs/prompts/library-trial/{file}-verdicts.json"));
        let verdicts: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for (key, entry) in verdicts.as_object().unwrap() {
            let (model, id) = key.split_once(':').expect("model:prompt");
            let verdict = match entry["verdict"].as_str().unwrap() {
                "works" => Verdict::Works,
                "not shown" => Verdict::NotShown,
                "no reading" => Verdict::NoReading,
                other => panic!("{key}: a verdict this test does not know: {other}"),
            };
            let model = format!("{}{}", model[..1].to_uppercase(), &model[1..]);
            all.insert((id.to_owned(), trial, model, verdict));
        }
    }
    all
}

#[test]
fn every_reading_is_the_one_its_trial_recorded() {
    let recorded = recorded();
    // The files have to be read, or an empty library would pass.
    assert!(recorded.len() >= 14, "{recorded:?}");
    let library = library();
    let mut held = BTreeSet::new();
    for p in &library.prompts {
        for r in p.tested.iter().flat_map(|t| &t.delivered) {
            held.insert((p.id.clone(), r.trial, r.model.clone(), r.verdict));
        }
    }
    let missing: Vec<_> = recorded.difference(&held).collect();
    let invented: Vec<_> = held.difference(&recorded).collect();
    assert!(
        missing.is_empty(),
        "readings a trial recorded that data/prompts.json does not: {missing:?}"
    );
    assert!(
        invented.is_empty(),
        "readings in data/prompts.json that no trial recorded: {invented:?}"
    );
}

#[test]
fn the_status_says_how_it_did_when_sv_gave_it() {
    let library = library();
    let said = |id: &str| {
        library
            .prompts
            .iter()
            .find(|p| p.id == id)
            .unwrap_or_else(|| panic!("{id} is in the library"))
            .status_sentence()
    };
    let env_prompt = said("secrets-in-the-environment");
    assert!(
        env_prompt.contains("at the start of a build, shown to work with Sonnet")
            && env_prompt
                .contains("in its briefs and guidance, not shown to work with Sonnet and Haiku"),
        "{env_prompt}"
    );
    let guard = said("ai-feature-guard");
    assert!(
        guard.starts_with("Shown to work, on 10 builds with it and 10 without.")
            && guard.contains("not shown to work with Sonnet")
            && !guard.contains("build, shown to work"),
        "{guard}"
    );
    // The control: a prompt shown to work when pasted, and never given by `sv` in a trial, says so
    // rather than nothing.
    let untried: Vec<_> = library
        .prompts
        .iter()
        .filter(|p| p.status == Status::Shown && p.tested.as_ref().unwrap().delivered.is_empty())
        .collect();
    assert!(!untried.is_empty());
    for p in untried {
        assert!(
            p.status_sentence().ends_with(
                "Given by `sv` rather than pasted into the request, it has not been tried."
            ),
            "{}: {}",
            p.id,
            p.status_sentence()
        );
    }
    // A prompt not shown to work, with no reading, says nothing more than that.
    let plain = library
        .prompts
        .iter()
        .find(|p| {
            p.status == Status::NotShown && p.tested.as_ref().is_none_or(|t| t.delivered.is_empty())
        })
        .expect("a prompt not shown, with no reading");
    assert_eq!(plain.status_sentence(), "Tried, not shown to work.");
}
