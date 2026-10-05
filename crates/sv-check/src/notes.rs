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
//! Since 4 October 2026 (deep review R1, the owner's decision), `Written by: owner` is not enough on
//! its own: the AI coding tool can write that line as easily as the owner. A section counts as the
//! owner's only when `sv review` recorded it, which puts a line `Sealed by sv review: …` under it
//! (`crate::seal`). An owner's section without a seal that holds counts as the tool's word, and the
//! report says why and how to make it the owner's.
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

/// The line `sv review` puts in a section the owner recorded, before the seal.
pub const SEALED_BY: &str = "Sealed by sv review:";

/// The seal on a `Sealed by sv review:` line.
fn sealed_by(line: &str) -> Option<String> {
    let plain = line.trim();
    plain
        .strip_prefix(SEALED_BY)
        .map(|rest| rest.trim().to_owned())
}

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

/// A line wholly in emphasis that says in its own words who wrote the section, as the AI coding
/// tool marks its work: *Written by the AI coding tool from the code; review before relying on it.*
///
/// Like the `Written by:` line it says who and not what, so it is no part of an answer; unlike that
/// line, it is never read for who (the tool's own words are not a mark `sv` defines). Without this,
/// a section holding nothing but that line, which is longer than the floor below, read as an
/// answer. Only a line entirely in italics or bold counts, so a sentence of an answer that happens
/// to begin "Written by" is still the answer.
fn byline(line: &str) -> bool {
    let t = line.trim();
    let emphasized = t.chars().count() > 2
        && ((t.starts_with('*') && t.ends_with('*')) || (t.starts_with('_') && t.ends_with('_')));
    let plain: String = t.chars().filter(|c| *c != '*' && *c != '_').collect();
    emphasized && plain.trim().to_lowercase().starts_with("written by")
}

/// A section's prose without the lines that say who wrote it, which say who and not what.
fn prose(body: &str) -> String {
    body.lines()
        .filter(|line| written_by(line).is_none() && !byline(line) && sealed_by(line).is_none())
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
    write_template_with(catalog, applicable, facts, &answers, describe)
}

/// `write_template`, from answers already read, so one of them can be changed first.
pub fn write_template_with(
    catalog: &Catalog,
    applicable: &BTreeSet<String>,
    facts: &Facts,
    answers: &Answers,
    describe: &dyn Fn(&str) -> Option<String>,
) -> String {
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
         the line counts as the tool's. An answer marked as yours counts as yours once you have run \
         `sv review` in your own terminal, which records it and adds a line under it.\n\n"
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
        push_loose(&mut out, answers, &section.id);
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
    let orphan_ids: Vec<String> = orphans.iter().map(|id| (*id).clone()).collect();
    if !orphans.is_empty() {
        out.push_str(NO_LONGER_APPLY);
        out.push_str("\n\n");
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
            push_loose(&mut out, answers, id);
        }
    }
    // Writing that followed a section no longer written here: kept at the end, never dropped.
    let written: BTreeSet<&str> = catalog
        .sections
        .iter()
        .filter(|s| applicable.contains(&s.id))
        .map(|s| s.id.as_str())
        .chain(orphan_ids.iter().map(|id| id.as_str()))
        .collect();
    for block in answers
        .loose
        .iter()
        .filter(|b| !written.contains(b.after.as_str()))
    {
        out.push_str(&block.text);
        out.push_str("\n\n");
    }
    out
}

/// The writing under headings of somebody's own that followed the section `id`, as it was.
fn push_loose(out: &mut String, answers: &Answers, id: &str) {
    for block in answers.loose.iter().filter(|b| b.after == id) {
        out.push_str(&block.text);
        out.push_str("\n\n");
    }
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
    /// Writing under a heading of somebody's own: part of no section, credited to nothing, and
    /// written back where it was whenever `sv` writes the file again.
    pub loose: Vec<Loose>,
}

/// Writing under a heading that is not one of `sv`'s, after one of its sections.
///
/// Until 4 October 2026 such a heading ended nothing, so what followed it was read as the answer to
/// the section above, and a section nobody answered could count as answered (BACKLOG, "A heading of
/// the owner's own in `security-notes.md`"; ADR-029). Now it ends the section, what follows belongs
/// to no answer, and the report says it was not read as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loose {
    /// The section it followed.
    pub after: String,
    /// The heading's words, without its `#`s.
    pub heading: String,
    /// The heading line and everything under it, as written.
    pub text: String,
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

    /// Who wrote a section, however short what is under it: `None` when there is no such section.
    pub fn writer(&self, id: &str) -> Option<Writer> {
        self.get_answer(id).map(writer_of)
    }

    /// The prose of a section, without the line that says who wrote it.
    pub fn prose_of(&self, id: &str) -> Option<String> {
        self.get_answer(id).map(prose)
    }

    /// The seal `sv review` put on a section, if it has one (the last, if several).
    pub fn seal_of(&self, id: &str) -> Option<String> {
        self.get_answer(id)
            .and_then(|body| body.lines().filter_map(sealed_by).next_back())
    }

    /// Whether the owner's section counts as theirs where this runs: its seal, or why not.
    pub fn recorded(
        &self,
        id: &str,
        seals: &crate::seal::Checker,
    ) -> Result<crate::seal::Sealed, String> {
        let fields = crate::seal::notes_fields(id, &self.prose_of(id).unwrap_or_default());
        crate::seal::owner_recorded(seals, self.seal_of(id).as_deref(), &fields)
    }

    /// Puts `body` under the section, in place of whatever was there.
    pub fn set(&mut self, id: &str, body: String) {
        match self.sections.iter_mut().find(|(section, _)| section == id) {
            Some((_, old)) => *old = body,
            None => self.sections.push((id.to_owned(), body)),
        }
    }
}

/// An answer the AI coding tool asked `sv` to record, as the section's body: marked as the tool's,
/// and refused when the report would not read it back as exactly that. Each refusal below is one
/// way it would not; a test sends each, and one that read the file back after writing it was taken
/// out when no answer these let through could fail it.
///
/// `sv` cannot tell whether the person said something or the tool only says they did, so what the
/// tool records is always the tool's word (the owner's decision, 4 October 2026); it becomes the
/// owner's only when the owner changes the line themselves. Refused: an answer too short to count,
/// one that says who wrote it (a second `Written by:` line would make the section unreadable, or,
/// with the tool's own line taken away, the owner's), and one holding a heading or a line `sv`
/// writes itself, which would end the section or be read as `sv`'s own words.
pub fn tool_answer(answer: &str) -> std::result::Result<String, String> {
    let answer = answer.trim();
    for line in answer.lines() {
        let t = line.trim();
        if written_by(line).is_some() || byline(line) || sealed_by(line).is_some() {
            return Err(format!(
                "the answer says who wrote it (\"{t}\"); `sv` marks every answer it records as \
                 the AI coding tool's, so leave that line out"
            ));
        }
        if t.starts_with('#') {
            return Err(format!(
                "the answer has a heading (\"{t}\"), which would end its section; write it as \
                 plain sentences"
            ));
        }
        if t.starts_with('>')
            || t == PLACEHOLDER
            || t == FACTS_LINE
            || t.contains(" asks for this: ")
        {
            return Err(format!(
                "the answer has a line `sv` writes itself (\"{t}\"), which the report would not \
                 read as part of the answer"
            ));
        }
    }
    if prose(answer).chars().count() < LEAST_ANSWER_CHARS {
        return Err(format!(
            "the answer is shorter than {LEAST_ANSWER_CHARS} characters, which the report does not \
             count as an answer; write the decision in a sentence or two"
        ));
    }
    Ok(format!("{WRITTEN_BY} {BY_AI_TOOL}\n\n{answer}"))
}

/// Reads a notes file, keeping only what the owner wrote.
///
/// Everything `sv` puts in a section is recognizable and dropped: the heading, the quoted question
/// (`>`), the italic lines it writes for the requirement's own wording and the facts, the bullets
/// under them, and the placeholder. What is left is the answer, and nothing else can be.
pub fn read_answers(text: &str) -> Answers {
    let mut answers = Answers::default();
    let mut current: Option<(String, Vec<String>)> = None;
    // The section last seen, which a heading of somebody's own follows, and writing under one.
    let mut last: Option<String> = None;
    let mut loose: Option<Loose> = None;
    let mut in_sv_own = false;
    let mut in_facts = false;
    let close = |answers: &mut Answers,
                 current: &mut Option<(String, Vec<String>)>,
                 loose: &mut Option<Loose>| {
        if let Some((id, body)) = current.take() {
            answers
                .sections
                .push((id, body.join("\n").trim().to_owned()));
        }
        if let Some(mut block) = loose.take() {
            block.text = block.text.trim_end().to_owned();
            answers.loose.push(block);
        }
    };
    for line in text.lines() {
        if let Some(id) = section_id(line) {
            close(&mut answers, &mut current, &mut loose);
            last = Some(id.clone());
            current = Some((id, Vec::new()));
            in_sv_own = false;
            in_facts = false;
            continue;
        }
        // Headings before the first section are `sv`'s own title; after it, a heading ends the
        // section above, and what follows belongs to no answer.
        if let (Some(after), Some(heading)) = (last.as_ref(), other_heading(line)) {
            close(&mut answers, &mut current, &mut loose);
            in_facts = false;
            if line.trim_end() == NO_LONGER_APPLY {
                in_sv_own = true;
            } else {
                in_sv_own = false;
                loose = Some(Loose {
                    after: after.clone(),
                    heading,
                    text: line.to_owned(),
                });
            }
            continue;
        }
        if in_sv_own {
            continue;
        }
        if let Some(block) = loose.as_mut() {
            block.text.push('\n');
            block.text.push_str(line);
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
    close(&mut answers, &mut current, &mut loose);
    answers
}

/// The notes file with `seal` recorded under the section for `id`: any earlier seal line in it
/// taken out, and the new one put straight after its `Written by:` line. `None` when there is no
/// such section, or it has no `Written by:` line to put the seal under. Nothing else changes.
pub fn with_seal(text: &str, id: &str, seal: &str) -> Option<String> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines
        .iter()
        .position(|l| section_id(l).as_deref() == Some(id))?;
    let end = lines[start + 1..]
        .iter()
        .position(|l| ends_section(l))
        .map_or(lines.len(), |i| start + 1 + i);
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 1);
    let mut placed = false;
    for (i, line) in lines.iter().enumerate() {
        let inside = i > start && i < end;
        if inside && sealed_by(line).is_some() {
            continue;
        }
        out.push((*line).to_owned());
        if inside && !placed && written_by(line).is_some() {
            out.push(format!("{SEALED_BY} {seal}"));
            placed = true;
        }
    }
    if !placed {
        return None;
    }
    let mut joined = out.join("\n");
    if text.ends_with('\n') {
        joined.push('\n');
    }
    Some(joined)
}

/// The heading `sv` writes above the answers whose requirement no longer applies. It, and the
/// sentence under it, are `sv`'s own; the sections under it are headed by their ids as usual.
const NO_LONGER_APPLY: &str = "## Answers for requirements that no longer apply";

/// A heading of the first three levels, the ones `sv` writes, that is not a section's: the words
/// after its `#`s. A deeper heading (`####`) stays part of the answer it is in, so an answer can
/// have parts of its own.
fn other_heading(line: &str) -> Option<String> {
    if section_id(line).is_some() {
        return None;
    }
    ["# ", "## ", "### "]
        .iter()
        .find_map(|prefix| line.strip_prefix(prefix))
        .map(|rest| rest.trim().to_owned())
}

/// Whether a line ends the section above it: another section's heading, or any other heading of
/// the first three levels.
fn ends_section(line: &str) -> bool {
    section_id(line).is_some() || other_heading(line).is_some()
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
    /// Headings of somebody's own, each with the section it followed: what is under them was not
    /// read as an answer.
    pub not_read: Vec<String>,
}

/// Evidence for every requirement the notes answer.
///
/// One `Verified` per section rather than one for the file, because the report shows the scope
/// beside each requirement and "the owner answered this question" is the scope that belongs there.
pub fn evidence(
    catalog: &Catalog,
    answers: &Answers,
    file: &str,
    seals: &crate::seal::Checker,
) -> Evidence {
    let mut out = Evidence::default();
    for (id, who) in answers.answered() {
        let Some(section) = catalog.section(&id) else {
            continue;
        };
        let place = format!("{file}, under \"{} — {}\"", section.id, section.title);
        match who {
            Writer::Owner => match answers.recorded(&id, seals) {
                Ok(sealed) => out.documented.push(Verified::new(
                    "notes.documented",
                    &[id.as_str()],
                    format!("{place}{}", crate::seal::recorded_where(&sealed)),
                )),
                Err(why) => out.stated.push(Verified::new(
                    "notes.stated-by-ai",
                    &[id.as_str()],
                    format!(
                        "{place}: it is marked `{WRITTEN_BY} {BY_OWNER}`, but {why}, so it counts \
                         as your AI coding tool's word, not a decision you made. If it is yours, run \
                         `sv review` in your own terminal to record it."
                    ),
                )),
            },
            Writer::AiTool | Writer::Unmarked => out.stated.push(Verified::new(
                "notes.stated-by-ai",
                &[id.as_str()],
                format!(
                    "{place}: {}. This is the word of the tool that wrote the code, not a decision \
                     you made; read it, and if you agree, mark it `{WRITTEN_BY} {BY_OWNER}` and \
                     run `sv review` in your own terminal to record it as yours.",
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
    out.not_read = answers
        .loose
        .iter()
        .map(|b| format!("\"{}\", after {}", b.heading, b.after))
        .collect();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This computer's key in these tests, from the system's randomness.
    fn key() -> crate::seal::Key {
        static KEY: std::sync::OnceLock<crate::seal::Key> = std::sync::OnceLock::new();
        KEY.get_or_init(|| crate::seal::Key::random().unwrap())
            .clone()
    }

    /// `evidence` as on the computer where `sv review` recorded every section marked as the
    /// owner's: the rules below are about what a section says, so each is sealed as a person's.
    fn evidence(catalog: &Catalog, answers: &Answers, file: &str) -> Evidence {
        let mut sealed = Answers::default();
        for (id, body) in &answers.sections {
            let mut body = body.clone();
            if writer_of(&body) == Writer::Owner {
                let fields = crate::seal::notes_fields(id, &prose(&body));
                body.push_str(&format!(
                    "\n\n{SEALED_BY} {}",
                    key().seal(&crate::seal::as_strs(&fields))
                ));
            }
            sealed.sections.push((id.clone(), body));
        }
        sealed.loose = answers.loose.clone();
        super::evidence(catalog, &sealed, file, &crate::seal::Checker::Key(key()))
    }

    #[test]
    fn an_owners_section_counts_as_theirs_only_when_sv_review_recorded_it() {
        let body = "Written by: owner\n\nFive failed sign-ins in fifteen minutes lock the account \
                    for an hour.";
        let answers = Answers {
            sections: vec![("V6.1.1".into(), body.into())],
            ..Answers::default()
        };
        let here = crate::seal::Checker::Key(key());
        // As written into the file, by anyone: the tool's word.
        let out = super::evidence(&catalog(), &answers, "security-notes.md", &here);
        assert!(out.documented.is_empty());
        assert!(
            out.stated[0]
                .scope
                .contains("not recorded through `sv review`")
                && out.stated[0].scope.contains("run `sv review`"),
            "{}",
            out.stated[0].scope
        );
        // Sealed: the owner's. The seal line is not part of the answer, and never makes one.
        let out = evidence(&catalog(), &answers, "security-notes.md");
        assert_eq!(out.documented.len(), 1, "{out:?}");
        let fields = crate::seal::notes_fields("V6.1.1", &prose(body));
        let seal = key().seal(&crate::seal::as_strs(&fields));
        let sealed = Answers {
            sections: vec![("V6.1.1".into(), format!("{body}\n\n{SEALED_BY} {seal}"))],
            ..Answers::default()
        };
        assert_eq!(
            sealed.prose_of("V6.1.1").as_deref(),
            Some(prose(body).as_str())
        );
        let only_seal = Answers {
            sections: vec![(
                "V6.1.1".into(),
                format!("Written by: owner\n\n{SEALED_BY} {seal}"),
            )],
            ..Answers::default()
        };
        assert!(only_seal.answered().is_empty());
        // A word changed after it was sealed: the tool's word again.
        let changed = Answers {
            sections: vec![(
                "V6.1.1".into(),
                format!("{}\n\n{SEALED_BY} {seal}", body.replace("an hour", "a day")),
            )],
            ..Answers::default()
        };
        let out = super::evidence(&catalog(), &changed, "security-notes.md", &here);
        assert!(out.documented.is_empty());
        assert!(out.stated[0].scope.contains("does not match"));
        // The AI coding tool cannot record a seal line through `sv`.
        assert!(tool_answer(&format!("{} {SEALED_BY} {seal}", "x".repeat(50))).is_ok());
        assert!(tool_answer(&format!("{}\n{SEALED_BY} {seal}", "x".repeat(50))).is_err());
    }

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
    fn the_ai_tools_disclaimer_alone_is_no_answer() {
        // Longer than the floor on its own, and nobody's decision about anything.
        let disclaimer =
            "*Written by the AI coding tool from the code; review before relying on it.*";
        assert!(disclaimer.chars().count() > LEAST_ANSWER_CHARS);
        for body in [
            disclaimer.to_owned(),
            format!("{disclaimer}\n\nWritten by: AI coding tool"),
            "_Written by the AI coding tool from the code, to be reviewed by the owner._"
                .to_owned(),
            "**Written by the AI coding tool from what the code does today.**\n\nWritten by: owner"
                .to_owned(),
        ] {
            let answers = with_answer(&body);
            assert!(
                answers.answered().is_empty(),
                "{body:?} read as {:?}",
                answers.answered()
            );
        }
        // With an answer under it, the section is the tool's, as before.
        assert_eq!(
            with_answer(&format!("{disclaimer}\n\n{RULES}")).stated(),
            applicable(&["V8.1.1"])
        );
    }

    #[test]
    fn a_sentence_of_an_answer_that_begins_written_by_is_still_the_answer() {
        // Only a line entirely in emphasis is a byline.
        let answers = with_answer(
            "Written by our accountant: records are kept for seven years, then deleted.\n\n\
             Written by: owner",
        );
        assert_eq!(
            answers.documented(),
            applicable(&["V8.1.1"]),
            "{:?}",
            answers.answered()
        );
        let answers = with_answer(
            "*Written by our accountant:* records are kept for seven years, then deleted.\n\n\
             Written by: owner",
        );
        assert_eq!(
            answers.documented(),
            applicable(&["V8.1.1"]),
            "{:?}",
            answers.answered()
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

    const LONG: &str =
        "Each of these is decided and written down here, with enough words to be an answer.";

    /// The two-section template with V6.1.1 left unanswered and `extra` written under it.
    fn first_unanswered_with(extra: &str) -> String {
        let template = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        template.replacen("## V8.1.1", &format!("{extra}\n\n## V8.1.1"), 1)
    }

    #[test]
    fn a_heading_of_somebodys_own_ends_the_section_above_it() {
        // The control: the same words, without a heading of their own, answer the section.
        let plain = first_unanswered_with(&format!("Written by: AI coding tool\n\n{LONG}"));
        assert!(read_answers(&plain).stated().contains("V6.1.1"));
        for heading in ["# Mine", "## A note from me", "### Things to do later"] {
            let text = first_unanswered_with(&format!(
                "{heading}\n\nWritten by: AI coding tool\n\n{LONG}"
            ));
            let answers = read_answers(&text);
            assert!(
                answers.answered().is_empty(),
                "{heading}: {:?}",
                answers.answered()
            );
            assert_eq!(answers.loose.len(), 1, "{heading}");
            assert_eq!(answers.loose[0].after, "V6.1.1");
            assert_eq!(
                answers.loose[0].heading,
                heading.trim_start_matches('#').trim()
            );
            assert!(
                answers.loose[0].text.starts_with(heading) && answers.loose[0].text.ends_with(LONG)
            );
        }
    }

    #[test]
    fn a_deeper_heading_stays_part_of_the_answer_it_is_in() {
        let text = first_unanswered_with("").replacen(
            PLACEHOLDER,
            &format!("Written by: AI coding tool\n\n#### First\n\n{LONG}\n\n#### Second\n\nMore."),
            1,
        );
        let answers = read_answers(&text);
        assert!(answers.loose.is_empty());
        let prose = answers.prose_of("V6.1.1").unwrap();
        assert!(
            prose.contains("#### Second") && prose.ends_with("More."),
            "{prose}"
        );
    }

    #[test]
    fn writing_the_file_again_puts_a_note_of_ones_own_back_where_it_was() {
        let note = format!("## A note from me\n\n{LONG}");
        let written = first_unanswered_with(&note);
        let again = |text: &str, ids: &[&str]| {
            write_template(
                &catalog(),
                &applicable(ids),
                &Facts::default(),
                Some(text),
                &no_descriptions(),
            )
        };
        let second = again(&written, &["V6.1.1", "V8.1.1"]);
        assert_eq!(
            second.matches(note.as_str()).count(),
            1,
            "kept once: {second}"
        );
        let at = |t: &str, what: &str| t.find(what).unwrap();
        assert!(
            at(&second, "## V6.1.1") < at(&second, &note)
                && at(&second, &note) < at(&second, "## V8.1.1")
        );
        assert_eq!(
            again(&second, &["V6.1.1", "V8.1.1"]),
            second,
            "writing it again changes nothing more"
        );
        assert!(read_answers(&second).answered().is_empty());
        // After a section no longer written, it is kept at the end, never dropped.
        let third = again(&written, &["V8.1.1"]);
        assert_eq!(third.matches(note.as_str()).count(), 1, "{third}");
        assert!(at(&third, "## V8.1.1") < at(&third, &note));
    }

    #[test]
    fn the_heading_sv_writes_for_answers_that_no_longer_apply_is_nobodys_answer() {
        // V8.1.1 answered, then no longer applying, so `sv` writes its heading and sentence after
        // V6.1.1, which nobody answered.
        let first = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            None,
            &no_descriptions(),
        );
        let at = first.rfind(PLACEHOLDER).unwrap();
        let written = format!(
            "{}Written by: owner\n\n{LONG}{}",
            &first[..at],
            &first[at + PLACEHOLDER.len()..]
        );
        let second = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        );
        assert!(second.contains(NO_LONGER_APPLY), "the setup: {second}");
        let answers = read_answers(&second);
        assert!(
            !answers.documented().contains("V6.1.1") && !answers.stated().contains("V6.1.1"),
            "{:?}",
            answers.answered()
        );
        assert!(answers.loose.is_empty(), "{:?}", answers.loose);
        assert!(
            answers.documented().contains("V8.1.1"),
            "the answer that stopped applying is still read"
        );
    }

    #[test]
    fn a_seal_is_never_placed_under_a_heading_of_somebodys_own() {
        let text =
            first_unanswered_with(&format!("## A note from me\n\nWritten by: owner\n\n{LONG}"));
        assert_eq!(
            with_seal(&text, "V6.1.1", "v1:0:0"),
            None,
            "V6.1.1 has no line of its own to seal"
        );
        // The control: with its own line, the seal goes under it.
        let own = text.replacen(PLACEHOLDER, &format!("Written by: owner\n\n{LONG}"), 1);
        let sealed = with_seal(&own, "V6.1.1", "v1:0:0").unwrap();
        assert!(sealed.find(SEALED_BY).unwrap() < sealed.find("## A note from me").unwrap());
        assert_eq!(sealed.matches(SEALED_BY).count(), 1);
    }

    #[test]
    fn evidence_names_what_was_not_read_as_an_answer() {
        let text = first_unanswered_with(&format!("## A note from me\n\n{LONG}"));
        let out = evidence(&catalog(), &read_answers(&text), "security-notes.md");
        assert_eq!(
            out.not_read,
            vec!["\"A note from me\", after V6.1.1".to_owned()]
        );
        assert!(out.stated.is_empty() && out.documented.is_empty());
    }
}
