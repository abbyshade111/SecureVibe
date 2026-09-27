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
//!
//! # Who wrote it
//!
//! The AI coding tool usually writes this file, and it can write a section too: asked, it describes
//! from the code what the app does. That is the tool's word, not a decision the owner made, so it is
//! not *documented*. Each section says who wrote it on one line, `Written by: owner` or `Written by:
//! AI coding tool`, and nothing else is read for it: not "Decided by the owner", not a disclaimer in
//! italics. **A section without that line counts as the tool's** (the owner's decision, 27 September
//! 2026), for the reason a design answer without `by` does: the file is usually the tool's writing,
//! and crediting the owner on nobody's say-so is the direction that overstates. The tool's sections
//! are *stated by the AI coding tool*, as its design answers are, and are asked again in the
//! interview. A `Written by:` naming anyone else is unreadable and named, not guessed at.
//!
//! Found in the owner's first run in VS Code: the tool wrote nine sections from the code and marked
//! each with its own italic line, which the reader then threw away along with `sv`'s own italic
//! lines, so the report called all nine *documented by the owner*. The reader now drops only the two
//! italic lines `sv` itself writes, so a person's bold or italic line survives a rewrite as well.

use crate::Verified;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;

/// The placeholder `sv` writes under each question, and the one line the reader must never count.
pub const PLACEHOLDER: &str = "_Nobody has written this yet._";

/// The italic line `sv` writes above the facts it found.
const FACTS_LINE: &str = "*What `sv` found:*";

/// The line a section says who wrote it on, and the two things it may say.
pub const WRITTEN_BY: &str = "Written by:";
pub const BY_OWNER: &str = "owner";
pub const BY_AI_TOOL: &str = "AI coding tool";

/// Who wrote a section, from its `Written by:` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Writer {
    Owner,
    AiTool,
    /// No `Written by:` line: counts as the tool's.
    Unmarked,
    /// A `Written by:` that is neither word, or two that disagree.
    Unreadable,
}

/// The value of a `Written by:` line, with any bold or italic markers around it ignored.
fn written_by(line: &str) -> Option<String> {
    let plain: String = line.chars().filter(|c| *c != '*' && *c != '_').collect();
    let plain = plain.trim();
    let head = plain.get(..WRITTEN_BY.len())?;
    head.eq_ignore_ascii_case(WRITTEN_BY).then(|| {
        plain[WRITTEN_BY.len()..]
            .trim()
            .trim_end_matches('.')
            .trim()
            .to_owned()
    })
}

fn writer_of(body: &str) -> Writer {
    let mut found: Option<Writer> = None;
    for line in body.lines() {
        let Some(value) = written_by(line) else {
            continue;
        };
        let this = if value.eq_ignore_ascii_case(BY_OWNER) {
            Writer::Owner
        } else if value.eq_ignore_ascii_case(BY_AI_TOOL) || value.eq_ignore_ascii_case("ai-tool") {
            Writer::AiTool
        } else {
            return Writer::Unreadable;
        };
        match &found {
            Some(earlier) if *earlier != this => return Writer::Unreadable,
            _ => found = Some(this),
        }
    }
    found.unwrap_or(Writer::Unmarked)
}

/// A section's prose without its `Written by:` line, which says who and not what.
fn prose(body: &str) -> String {
    body.lines()
        .filter(|line| written_by(line).is_none())
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_owned()
}

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
    out.push_str(&format!(
        "Start each answer with a line saying who wrote it: `{WRITTEN_BY} {BY_OWNER}` for your own \
         decision, or one your AI coding tool wrote that you have read and agree with; \
         `{WRITTEN_BY} {BY_AI_TOOL}` for one the tool wrote from the code that you have not agreed \
         to. The tool's counts for less, as *stated by the AI coding tool*, and an answer without \
         the line counts as the tool's.\n\n"
    ));

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
        out.push_str(FACTS_LINE);
        out.push_str("\n\n");
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

    /// Every section with enough prose under it to be an answer, and who wrote it.
    pub fn answered(&self) -> Vec<(String, Writer)> {
        self.sections
            .iter()
            .filter(|(_, body)| prose(body).chars().count() >= LEAST_ANSWER_CHARS)
            .map(|(id, body)| (id.clone(), writer_of(body)))
            .collect()
    }

    fn answered_by(&self, keep: impl Fn(&Writer) -> bool) -> BTreeSet<String> {
        self.answered()
            .into_iter()
            .filter(|(_, who)| keep(who))
            .map(|(id, _)| id)
            .collect()
    }

    /// The requirements this file documents: a section the owner wrote, or read and agreed to.
    pub fn documented(&self) -> BTreeSet<String> {
        self.answered_by(|who| *who == Writer::Owner)
    }

    /// The sections the AI coding tool wrote, or that do not say who did.
    pub fn stated(&self) -> BTreeSet<String> {
        self.answered_by(|who| matches!(who, Writer::AiTool | Writer::Unmarked))
    }

    /// The sections whose `Written by:` line could not be read.
    pub fn unreadable(&self) -> BTreeSet<String> {
        self.answered_by(|who| *who == Writer::Unreadable)
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
        let Some((id, body)) = current.as_mut() else {
            continue;
        };
        let trimmed = line.trim();
        // `sv`'s own lines, in the order they are written.
        if trimmed.starts_with('>') || trimmed == PLACEHOLDER {
            continue;
        }
        // The two italic lines `sv` writes, and only those: a person's bold or italic line, or the
        // AI coding tool's, is part of their answer and survives a rewrite.
        if trimmed == FACTS_LINE {
            // The facts follow as bullets.
            in_facts = true;
            continue;
        }
        if trimmed.ends_with('*') && trimmed.starts_with(&format!("*{id} asks for this: ")) {
            in_facts = false;
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

/// What the notes are worth, section by section.
#[derive(Debug, Default)]
pub struct Evidence {
    /// Sections the owner wrote, or read and agreed to: *documented by the owner*.
    pub documented: Vec<Verified>,
    /// Sections the AI coding tool wrote, or that do not say who did: *stated by the AI coding tool*.
    pub stated: Vec<Verified>,
    /// Sections whose `Written by:` line names somebody else, or disagrees with itself.
    pub unreadable: Vec<String>,
}

/// Evidence for every requirement the notes answer.
///
/// One `Verified` per section rather than one for the file, because the report shows the scope
/// beside each requirement and "the owner answered this question" is the scope that belongs there.
pub fn evidence(catalog: &Catalog, answers: &Answers, file: &str) -> Evidence {
    let mut out = Evidence::default();
    for (id, who) in answers.answered() {
        let Some(section) = catalog.section(&id) else {
            continue;
        };
        let place = format!("{file}, under \"{} — {}\"", section.id, section.title);
        match who {
            Writer::Owner => {
                out.documented
                    .push(Verified::new("notes.documented", &[id.as_str()], place))
            }
            Writer::AiTool | Writer::Unmarked => out.stated.push(Verified::new(
                "notes.stated-by-ai",
                &[id.as_str()],
                format!(
                    "{place}: {}. This is the word of the tool that wrote the code, not a decision \
                     you made; read it, and mark it `{WRITTEN_BY} {BY_OWNER}` if you agree.",
                    if who == Writer::AiTool {
                        "your AI coding tool wrote it"
                    } else {
                        "it does not say who wrote it, so it counts as your AI coding tool's"
                    }
                ),
            )),
            Writer::Unreadable => out.unreadable.push(id),
        }
    }
    out
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
        let describe = |id: &str| {
            Some(format!(
                "Verify that the documentation for {id} defines what it should, at some length."
            ))
        };
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &facts,
            None,
            &describe,
        );
        assert!(
            template.contains("V6.1.1") && template.contains("asks for this"),
            "the template must ask, and quote the requirement: {template}"
        );
        let answers = read_answers(&template);
        assert!(
            answers.answered().is_empty(),
            "a template nobody has written in answers nothing, got {:?}",
            answers.answered()
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
            "Written by: owner\n\nFive failed sign-ins from one address in fifteen minutes \
             starts a one-minute delay that doubles each time, and no account is ever locked.",
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
        let answer = "Written by: owner\n\nAdministrators may open every page. Everyone else may \
                      read and change only the notes they created.";
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
            "Written by: owner\n\nFive failed sign-ins in fifteen minutes start a delay that \
             doubles, and no account is locked.",
            1,
        );
        let evidence = evidence(&catalog(), &read_answers(&written), "security-notes.md");
        assert!(evidence.stated.is_empty() && evidence.unreadable.is_empty());
        let documented = evidence.documented;
        assert_eq!(documented.len(), 1);
        assert_eq!(documented[0].requirement_ids, vec!["V6.1.1".to_owned()]);
        assert!(
            documented[0].scope.contains("security-notes.md"),
            "the scope must say where the answer is: {:?}",
            documented[0].scope
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

    /// A notes file with one section answered by `answer`, as it reads back.
    fn with_answer(answer: &str) -> Answers {
        let template = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts {
                data_categories: vec!["contact".into()],
                ..Facts::default()
            },
            None,
            &|_: &str| Some("Verify that authorization documentation defines rules.".to_owned()),
        );
        read_answers(&template.replacen(PLACEHOLDER, answer, 1))
    }

    const RULES: &str = "There is one kind of user, an anonymous visitor, who may read every page \
                         and change nothing at all.";

    #[test]
    fn an_answer_that_does_not_say_who_wrote_it_counts_as_the_ai_tools() {
        // The owner's decision, 27 September 2026: the file is usually the tool's writing, and
        // crediting the owner on nobody's say-so is the direction that overstates.
        let answers = with_answer(RULES);
        assert!(
            answers.documented().is_empty(),
            "an unmarked section is not the owner's: {:?}",
            answers.answered()
        );
        assert_eq!(answers.stated(), applicable(&["V8.1.1"]));
        let evidence = evidence(&catalog(), &answers, "security-notes.md");
        assert_eq!(evidence.stated.len(), 1);
        assert_eq!(evidence.stated[0].check_id, "notes.stated-by-ai");
        assert!(
            evidence.stated[0]
                .scope
                .contains("does not say who wrote it"),
            "{:?}",
            evidence.stated[0].scope
        );
    }

    #[test]
    fn the_ai_tools_own_disclaimer_is_not_the_owners_word() {
        // The owner's VS Code run: the tool marked what it wrote in its own words, in italics, and
        // the reader threw that line away with `sv`'s own italic lines and credited the owner.
        let answer = format!(
            "*Written by the AI coding tool from the code; review before relying on it.*\n\n{RULES}"
        );
        let answers = with_answer(&answer);
        assert!(answers.documented().is_empty(), "{:?}", answers.answered());
        assert_eq!(answers.stated(), applicable(&["V8.1.1"]));
        // And the disclaimer is the tool's writing, kept when the file is written again.
        let template = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = template.replacen(PLACEHOLDER, &answer, 1);
        let again = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        );
        assert!(
            again.contains("*Written by the AI coding tool from the code;"),
            "rewriting must not drop a line somebody else wrote: {again}"
        );
    }

    #[test]
    fn the_ai_tools_marker_is_stated_and_says_so() {
        let answers = with_answer(&format!("Written by: AI coding tool\n\n{RULES}"));
        assert!(answers.documented().is_empty());
        let evidence = evidence(&catalog(), &answers, "security-notes.md");
        assert_eq!(evidence.stated.len(), 1);
        assert!(
            evidence.stated[0]
                .scope
                .contains("your AI coding tool wrote it"),
            "{:?}",
            evidence.stated[0].scope
        );
    }

    #[test]
    fn the_owners_marker_documents_in_any_emphasis() {
        for marker in [
            "Written by: owner",
            "**Written by:** owner",
            "*Written by: Owner.*",
            "written by: OWNER",
        ] {
            let answers = with_answer(&format!("{marker}\n\n{RULES}"));
            assert_eq!(
                answers.documented(),
                applicable(&["V8.1.1"]),
                "{marker:?} is the owner's line"
            );
            assert!(answers.stated().is_empty(), "{marker:?}");
        }
    }

    #[test]
    fn the_owners_own_bold_line_survives_a_rewrite() {
        let answer =
            format!("Written by: owner\n\n**Decided by the owner (2026-09-26):**\n\n{RULES}");
        let first = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let written = first.replacen(PLACEHOLDER, &answer, 1);
        let again = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        );
        assert!(
            again.contains("**Decided by the owner (2026-09-26):**"),
            "{again}"
        );
        assert_eq!(read_answers(&again).documented(), applicable(&["V8.1.1"]));
    }

    #[test]
    fn a_writer_that_is_neither_word_is_unreadable_not_guessed() {
        for answer in [
            format!("Written by: Sam from the security team\n\n{RULES}"),
            format!("Written by: owner\n\n{RULES}\n\nWritten by: AI coding tool"),
        ] {
            let answers = with_answer(&answer);
            assert_eq!(answers.unreadable(), applicable(&["V8.1.1"]), "{answer:?}");
            assert!(answers.documented().is_empty() && answers.stated().is_empty());
            let evidence = evidence(&catalog(), &answers, "security-notes.md");
            assert_eq!(evidence.unreadable, vec!["V8.1.1".to_owned()]);
        }
    }

    #[test]
    fn the_marker_alone_is_not_an_answer() {
        // "Written by: …" is who, not what. The line is long enough to lift a stray word over the
        // floor on its own, which is what this holds: with nothing else, the section is empty.
        for marker in ["Written by: owner", "Written by: AI coding tool"] {
            let answer = format!("{marker}\n\nSee the code for details.");
            assert!(
                answer.chars().count() >= LEAST_ANSWER_CHARS,
                "the setup must reach the floor"
            );
            let answers = with_answer(&answer);
            assert!(
                answers.answered().is_empty(),
                "{marker}: {:?}",
                answers.answered()
            );
        }
    }
}
