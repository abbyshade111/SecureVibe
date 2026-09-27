//! The security notes: the questions only the owner can answer, and what `sv` knows that bears on
//! each.
//!
//! Nineteen ASVS requirements at level 1 and 2 ask for a document and nothing else — the validation
//! rules, who may do what, how long a session lasts, how soon a vulnerable library is updated. No
//! scanner will ever settle one of them, because there is nothing in the code to read: the thing
//! being asked for is a written decision. Today they sit in the report as *not verified*, beside the
//! requirements nobody has looked at, which tells the owner nothing about what to do.
//!
//! So `sv notes` writes `security-notes.md`: one section per applicable requirement, headed by its
//! id, carrying the question in plain words and every fact `sv` found that bears on it — the outside
//! services by the package that showed each one, the kinds of data from the manifest, the package
//! ecosystems in use. The owner writes the answer underneath.
//!
//! # What an answer is worth
//!
//! A section the owner has written makes its requirement **documented**, which is its own tier and
//! not *checked*. Nothing here reads whether the answer is right, whether it is complete, or whether
//! the app does what it says: three of these requirements have a twin that asks for the behavior to
//! match the document (V2.3.2, V6.3.1, V16.2.3 among them), and those twins stay unverified. The
//! report says so where the tier first appears.
//!
//! # The template's own words are not an answer
//!
//! The one way this could lie is by counting the question as its answer, which would make every
//! requirement documented the moment the file was written. So the reader strips what `sv` itself
//! wrote — the heading, the quoted question, the facts, the placeholder — and asks whether anything
//! is left. `the_template_alone_documents_nothing` is the test that holds it to that.

use crate::Verified;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

/// The placeholder `sv` writes under each question, and the one line the reader must never count.
pub const PLACEHOLDER: &str = "_Nobody has written this yet._";

/// Under this many characters of the owner's own prose, a section says nothing.
///
/// Not a judgment of the answer — `sv` cannot make one — but a floor under "there is something
/// here". A stray word left while editing should not document a requirement.
const LEAST_ANSWER_CHARS: usize = 40;

#[derive(Debug, Clone, Deserialize)]
pub struct Section {
    pub id: String,
    pub title: String,
    /// The question, in the words a person who is not a programmer would use.
    pub asks: String,
    /// Which of the facts `sv` gathered belong under this question.
    #[serde(default)]
    pub facts: Vec<String>,
    /// Where to go and look to answer it, for the checklist of what only a person can check.
    ///
    /// The question says *what* to write down; this says where the answer is found. Absent where
    /// the question already implies it.
    #[serde(rename = "howToFindOut", default)]
    pub how_to_find_out: Option<String>,
}

/// A requirement whose words mention documentation and that has no section, with why.
///
/// Every one of these is a requirement somebody could reasonably expect to find in the notes. The
/// list is here so that leaving one out is a decision written down and tested
/// (`every_documentation_requirement_is_either_a_section_or_explained`), rather than an omission
/// nobody notices.
#[derive(Debug, Clone, Deserialize)]
pub struct Elsewhere {
    pub id: String,
    pub why: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    pub file: String,
    pub sections: Vec<Section>,
    #[serde(default)]
    pub elsewhere: Vec<Elsewhere>,
}

impl Catalog {
    pub fn load(path: &Path) -> Result<Catalog> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let catalog: Catalog =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        for section in &catalog.sections {
            if section.asks.trim().is_empty() {
                anyhow::bail!(
                    "{}: the section for {} asks nothing",
                    path.display(),
                    section.id
                );
            }
        }
        Ok(catalog)
    }

    pub fn section(&self, id: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.id == id)
    }
}

/// What `sv` found that belongs in the notes, so the owner starts from the app rather than a blank
/// page.
#[derive(Debug, Clone, Default)]
pub struct Facts {
    pub app_name: String,
    /// The kinds of data the manifest says the app holds.
    pub data_categories: Vec<String>,
    /// Each outside service, named by what showed it: "Stripe (the `stripe` package)".
    pub outside_services: Vec<String>,
    /// The package ecosystems in use: "npm (package.json)".
    pub ecosystems: Vec<String>,
    pub uploads: Option<bool>,
    pub sign_in: Option<bool>,
}

impl Facts {
    /// The lines that go under one question, as bullets. Empty when nothing was found for it: a
    /// question with no facts is still asked, because the owner is the one who knows.
    fn for_section(&self, section: &Section) -> Vec<String> {
        let mut out = Vec::new();
        for fact in &section.facts {
            match fact.as_str() {
                "app-name" if !self.app_name.is_empty() => {
                    out.push(format!("This app is called {}.", self.app_name));
                }
                "data" if !self.data_categories.is_empty() => {
                    out.push(format!(
                        "securevibe.toml says this app holds: {}.",
                        and_list(&self.data_categories)
                    ));
                }
                "outside-services" if !self.outside_services.is_empty() => {
                    out.push(format!(
                        "Outside services found in the code: {}.",
                        and_list(&self.outside_services)
                    ));
                }
                "ecosystems" if !self.ecosystems.is_empty() => {
                    out.push(format!(
                        "This app installs packages with {}.",
                        and_list(&self.ecosystems)
                    ));
                }
                "uploads" => match self.uploads {
                    Some(true) => out.push("securevibe.toml says people can upload files.".into()),
                    Some(false) => out.push(
                        "securevibe.toml says nobody can upload a file. If that changes, this \
                         question starts to matter."
                            .into(),
                    ),
                    None => {}
                },
                "sign-in" => match self.sign_in {
                    Some(true) => {
                        out.push("securevibe.toml says people sign in to this app.".into())
                    }
                    Some(false) => out.push(
                        "securevibe.toml says nobody signs in to this app. If that changes, this \
                         question starts to matter."
                            .into(),
                    ),
                    None => {}
                },
                _ => {}
            }
        }
        out
    }
}

/// "a, b, and c" — the Oxford comma, the way everything a person reads here is written.
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// The heading `sv` writes for a section, and the line the reader finds it by.
fn heading(section: &Section) -> String {
    format!("## {} — {}", section.id, section.title)
}

/// Writes the notes file for the requirements that apply, keeping every answer already written.
///
/// Rewriting is safe by construction: an existing section's answer is carried across verbatim, and a
/// section for a requirement that no longer applies is kept too, under a note, because the owner
/// wrote it and `sv` deciding it is now irrelevant is not `sv`'s call to make.
pub fn write_template(
    catalog: &Catalog,
    applicable: &BTreeSet<String>,
    facts: &Facts,
    existing: Option<&str>,
    describe: &dyn Fn(&str) -> Option<String>,
) -> String {
    let answers = existing.map(read_answers).unwrap_or_default();
    let mut out = String::new();
    out.push_str("# Security notes\n\n");
    out.push_str(
        "The questions about this app that no tool can answer, because what they ask for is a \
         written decision rather than something in the code. Each section is headed by the OWASP \
         ASVS requirement it answers. Write your answer under the question; `sv` keeps what you \
         have written when it writes this file again.\n\n",
    );
    out.push_str(
        "A section you have written makes its requirement **documented** in the report. That is \
         not the same as checked: nothing here reads whether your answer is right, or whether the \
         app does what it says.\n\n",
    );

    let mut wrote_any = false;
    for section in &catalog.sections {
        if !applicable.contains(&section.id) {
            continue;
        }
        wrote_any = true;
        push_section(
            &mut out,
            section,
            facts,
            answers.get_answer(&section.id),
            describe,
        );
    }
    if !wrote_any {
        out.push_str(
            "None of the requirements that ask for a document apply to this app, so there is \
             nothing to write here yet.\n",
        );
    }

    // A section whose requirement no longer applies, but which somebody has written. Kept, said
    // out loud: the manifest may be wrong, and deleting an owner's writing to tidy a file is the
    // kind of helpfulness nobody asked for.
    let orphans: Vec<&String> = answers
        .sections
        .iter()
        .filter(|(id, body)| !applicable.contains(id) && !body.trim().is_empty())
        .map(|(id, _)| id)
        .collect();
    if !orphans.is_empty() {
        out.push_str("## Answers for requirements that no longer apply\n\n");
        out.push_str(
            "You wrote these, and the answers to the questions in securevibe.toml now say they do \
             not apply to this app. They are kept here in case the manifest is what is wrong.\n\n",
        );
        for id in orphans {
            let title = catalog
                .section(id)
                .map(|s| s.title.clone())
                .unwrap_or_else(|| "a question that is no longer asked".to_owned());
            out.push_str(&format!("### {id} — {title}\n\n"));
            out.push_str(answers.get_answer(id).unwrap_or(""));
            out.push_str("\n\n");
        }
    }
    out
}

fn push_section(
    out: &mut String,
    section: &Section,
    facts: &Facts,
    answer: Option<&str>,
    describe: &dyn Fn(&str) -> Option<String>,
) {
    out.push_str(&heading(section));
    out.push_str("\n\n");
    for line in section.asks.split_terminator('\n') {
        out.push_str("> ");
        out.push_str(line.trim());
        out.push('\n');
    }
    out.push('\n');
    if let Some(text) = describe(&section.id) {
        out.push_str(&format!("*{} asks for this: {}*\n\n", section.id, text));
    }
    let bullets = facts.for_section(section);
    if !bullets.is_empty() {
        out.push_str("*What `sv` found:*\n\n");
        for bullet in bullets {
            out.push_str(&format!("- {bullet}\n"));
        }
        out.push('\n');
    }
    match answer {
        Some(text) if !text.trim().is_empty() => {
            out.push_str(text.trim());
            out.push_str("\n\n");
        }
        _ => {
            out.push_str(PLACEHOLDER);
            out.push_str("\n\n");
        }
    }
}

/// What a notes file says, section by section, with `sv`'s own words stripped out.
#[derive(Debug, Default)]
pub struct Answers {
    /// Requirement id → the owner's prose, with the question, the facts, and the placeholder gone.
    pub sections: Vec<(String, String)>,
}

impl Answers {
    fn get_answer(&self, id: &str) -> Option<&str> {
        self.sections
            .iter()
            .find(|(section, _)| section == id)
            .map(|(_, body)| body.as_str())
    }

    /// The requirements this file documents: a section with enough of the owner's own prose under it.
    pub fn documented(&self) -> BTreeSet<String> {
        self.sections
            .iter()
            .filter(|(_, body)| body.trim().chars().count() >= LEAST_ANSWER_CHARS)
            .map(|(id, _)| id.clone())
            .collect()
    }
}

/// Reads a notes file, keeping only what the owner wrote.
///
/// Everything `sv` puts in a section is recognizable and dropped: the heading, the quoted question
/// (`>`), the italic lines it writes for the requirement's own wording and the facts, the bullets
/// under them, and the placeholder. What is left is the answer, and nothing else can be.
pub fn read_answers(text: &str) -> Answers {
    let mut answers = Answers::default();
    let mut current: Option<(String, Vec<String>)> = None;
    let mut in_facts = false;
    for line in text.lines() {
        if let Some(id) = section_id(line) {
            if let Some((id, body)) = current.take() {
                answers
                    .sections
                    .push((id, body.join("\n").trim().to_owned()));
            }
            current = Some((id, Vec::new()));
            in_facts = false;
            continue;
        }
        let Some((_, body)) = current.as_mut() else {
            continue;
        };
        let trimmed = line.trim();
        // `sv`'s own lines, in the order they are written.
        if trimmed.starts_with('>') || trimmed == PLACEHOLDER {
            continue;
        }
        if trimmed.starts_with('*') && trimmed.ends_with('*') && trimmed.len() > 2 {
            // An italic line `sv` wrote. The facts follow as bullets, so remember which.
            in_facts = trimmed.contains("What `sv` found");
            continue;
        }
        if in_facts && trimmed.starts_with("- ") {
            continue;
        }
        if !trimmed.is_empty() {
            in_facts = false;
        }
        body.push(line.to_owned());
    }
    if let Some((id, body)) = current.take() {
        answers
            .sections
            .push((id, body.join("\n").trim().to_owned()));
    }
    answers
}

/// `## V6.1.1 — …` or `### V6.1.1 — …`, giving the requirement id.
fn section_id(line: &str) -> Option<String> {
    let rest = line
        .strip_prefix("## ")
        .or_else(|| line.strip_prefix("### "))?;
    let id = rest.split_whitespace().next()?;
    let looks_like_id = id.starts_with('V')
        && id.len() > 1
        && id[1..].chars().all(|c| c.is_ascii_digit() || c == '.');
    looks_like_id.then(|| id.to_owned())
}

/// Evidence for every requirement the notes document.
///
/// One `Verified` per section rather than one for the file, because the report shows the scope
/// beside each requirement and "the owner answered this question" is the scope that belongs there.
pub fn evidence(catalog: &Catalog, answers: &Answers, file: &str) -> Vec<Verified> {
    answers
        .documented()
        .into_iter()
        .filter_map(|id| {
            let section = catalog.section(&id)?;
            Some(Verified::new(
                "notes.documented",
                &[id.as_str()],
                format!("{file}, under \"{} — {}\"", section.id, section.title),
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> Catalog {
        Catalog {
            file: "security-notes.md".into(),
            sections: vec![
                Section {
                    id: "V6.1.1".into(),
                    title: "How sign-in is protected against guessing".into(),
                    asks: "How the app defends against someone trying many passwords.".into(),
                    facts: vec!["sign-in".into()],
                    how_to_find_out: None,
                },
                Section {
                    id: "V8.1.1".into(),
                    title: "Who may do what".into(),
                    asks: "Which kinds of users may use which functions.".into(),
                    facts: vec!["data".into()],
                    how_to_find_out: None,
                },
            ],
            elsewhere: Vec::new(),
        }
    }

    fn applicable(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    fn no_descriptions() -> impl Fn(&str) -> Option<String> {
        |_: &str| None
    }

    #[test]
    fn the_template_alone_documents_nothing() {
        // The one way this whole feature could lie: counting the question `sv` wrote as the answer
        // the owner did not. Every requirement would be documented the moment the file existed.
        let facts = Facts {
            app_name: "Notes".into(),
            data_categories: vec!["contact".into()],
            sign_in: Some(true),
            ..Facts::default()
        };
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &facts,
            None,
            &no_descriptions(),
        );
        assert!(
            template.contains("V6.1.1"),
            "the template must ask: {template}"
        );
        let documented = read_answers(&template).documented();
        assert!(
            documented.is_empty(),
            "a template nobody has written in documents nothing, got {documented:?}"
        );
    }

    #[test]
    fn an_answer_documents_its_requirement_and_only_that_one() {
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = template.replacen(
            PLACEHOLDER,
            "Five failed sign-ins from one address in fifteen minutes starts a one-minute delay \
             that doubles each time, and no account is ever locked.",
            1,
        );
        let documented = read_answers(&written).documented();
        assert_eq!(documented, applicable(&["V6.1.1"]), "got {documented:?}");
    }

    #[test]
    fn a_stray_word_is_not_an_answer() {
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = template.replacen(PLACEHOLDER, "todo", 1);
        assert!(
            read_answers(&written).documented().is_empty(),
            "a word left while editing is not a written policy"
        );
    }

    #[test]
    fn writing_the_file_again_keeps_what_the_owner_wrote() {
        let answer = "Administrators may open every page. Everyone else may read and change only \
                      the notes they created.";
        let first = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = first.replace(PLACEHOLDER, answer);
        let second = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        );
        assert_eq!(
            read_answers(&second).documented(),
            applicable(&["V6.1.1", "V8.1.1"]),
            "rewriting must not lose an answer"
        );
        assert!(
            !second.contains(PLACEHOLDER),
            "nothing is left to write: {second}"
        );
    }

    #[test]
    fn an_answer_to_a_question_that_stopped_applying_is_kept() {
        let answer = "People may upload a photograph of up to four megabytes, and nothing else at \
                      all is accepted by the server.";
        let first = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = first.replace(PLACEHOLDER, answer);
        // The owner answers no to the question that placed V8.1.1, by mistake or otherwise.
        let second = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        );
        assert!(
            second.contains("no longer apply") && second.matches(answer).count() == 2,
            "the answer must be kept where the owner can see it: {second}"
        );
    }

    #[test]
    fn a_question_nobody_applies_is_not_asked() {
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        assert!(template.contains("V6.1.1"));
        assert!(
            !template.contains("V8.1.1"),
            "a requirement that does not apply must not be asked about: {template}"
        );
    }

    #[test]
    fn the_facts_sv_found_are_written_under_the_question() {
        let facts = Facts {
            data_categories: vec!["contact".into(), "health".into()],
            sign_in: Some(true),
            ..Facts::default()
        };
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &facts,
            None,
            &no_descriptions(),
        );
        assert!(
            template.contains("people sign in to this app"),
            "{template}"
        );
        assert!(
            template.contains("contact and health"),
            "the data categories belong under who may do what: {template}"
        );
    }

    #[test]
    fn three_things_take_the_oxford_comma() {
        assert_eq!(
            and_list(&["contact".into(), "health".into(), "payment".into()]),
            "contact, health, and payment"
        );
        assert_eq!(
            and_list(&["contact".into(), "health".into()]),
            "contact and health"
        );
    }

    #[test]
    fn evidence_names_the_requirement_and_where_the_answer_is() {
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = template.replacen(
            PLACEHOLDER,
            "Five failed sign-ins in fifteen minutes start a delay that doubles, and no account \
             is locked.",
            1,
        );
        let evidence = evidence(&catalog(), &read_answers(&written), "security-notes.md");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].requirement_ids, vec!["V6.1.1".to_owned()]);
        assert!(
            evidence[0].scope.contains("security-notes.md"),
            "the scope must say where the answer is: {:?}",
            evidence[0].scope
        );
    }

    #[test]
    fn the_requirements_own_wording_is_quoted_where_it_is_known() {
        let describe = |id: &str| {
            (id == "V6.1.1").then(|| "Verify that application documentation defines…".to_owned())
        };
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            None,
            &describe,
        );
        assert!(
            template.contains("Verify that application documentation defines…"),
            "{template}"
        );
    }
}
