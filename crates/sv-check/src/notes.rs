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

/// The line `sv` heads the file with.
const TITLE_LINE: &str = "# Security notes";

/// The paragraphs `sv` writes at the top of the file, each on one line.
const INTRO_WHAT: &str = "The questions about this app that no tool can answer, because what they ask for is a \
     written decision rather than something in the code. Each section is headed by the OWASP \
     ASVS requirement it answers. Write your answer under the question; `sv` keeps what you \
     have written when it writes this file again.";
const INTRO_DOCUMENTED: &str = "A section you have written makes its requirement **documented** in the report. That is \
     not the same as checked: nothing here reads whether your answer is right, or whether the \
     app does what it says.";
/// The paragraph on who wrote an answer, as `sv` wrote it from 27 September to 4 October 2026.
/// Still recognized as `sv`'s, so a file written then does not have it kept as the owner's.
const INTRO_WHO_BEFORE_REVIEW: &str = "Start each answer with a line saying who wrote it: `Written by: owner` for your own \
     decision, or one your AI coding tool wrote that you have read and agree with; \
     `Written by: AI coding tool` for one the tool wrote from the code that you have not agreed \
     to. The tool's counts for less, as *stated by the AI coding tool*, and an answer without \
     the line counts as the tool's.";
const INTRO_WHO_REVIEW: &str = " An answer marked as yours counts as yours once you have run \
     `sv review` in your own terminal, which records it and adds a line under it.";
const NOTHING_APPLIES: &str = "None of the requirements that ask for a document apply to this app, so there is \
     nothing to write here yet.";

/// The heading `sv` puts over answers to questions that no longer apply, and what it says under it.
pub const ORPHANS_HEADING: &str = "## Answers for requirements that no longer apply";
const ORPHANS_WHY: &str = "You wrote these, and the answers to the questions in securevibe.toml now say they do \
     not apply to this app. They are kept here in case the manifest is what is wrong.";
/// The title `sv` gave an answer whose question it no longer has.
const NO_LONGER_ASKED: &str = "a question that is no longer asked";

/// The heading over text in the file that is not under any question (deep review R7), and what it
/// says under it.
pub const KEPT_HEADING: &str = "## Kept as you wrote it: text that is not under a question";
const KEPT_WHY: &str = "`sv` found this in the file outside the answers to its questions, so it is not an \
     answer to any of them and the report does not read it. It is kept here, word for word and in \
     the order it was in, each time `sv` writes this file. Move any of it under a question if it \
     answers one, or delete what you do not need.";

/// The lines `sv` writes whole, in any version since the file was first written, which the reader
/// drops wherever it finds them. Each is long and particular enough that no person writes it.
fn own_lines() -> [String; 7] {
    [
        INTRO_WHAT.to_owned(),
        INTRO_DOCUMENTED.to_owned(),
        INTRO_WHO_BEFORE_REVIEW.to_owned(),
        format!("{INTRO_WHO_BEFORE_REVIEW}{INTRO_WHO_REVIEW}"),
        NOTHING_APPLIES.to_owned(),
        ORPHANS_WHY.to_owned(),
        KEPT_WHY.to_owned(),
    ]
}

/// How each fact `sv` writes under a question begins (`Facts::for_section`). A bullet in the facts
/// list that begins with one of these is `sv`'s, rewritten each time from the app as it is now;
/// any other bullet there is the owner's and kept.
const FACT_OPENINGS: [&str; 4] = [
    "This app is called ",
    "securevibe.toml says ",
    "Outside services found in the code: ",
    "This app installs packages with ",
];

/// Writes the notes file for the requirements that apply, keeping everything already written in it
/// that `sv` did not write itself.
///
/// An existing section's answer is carried across as it was, and its heading too. A section for a
/// requirement that no longer applies is kept, under a note, because the owner wrote it and `sv`
/// deciding it is now irrelevant is not `sv`'s call to make. Anything else in the file that `sv`
/// did not write, wherever it was, is kept word for word in a section of its own at the top (deep
/// review R7: until 4 October 2026 it was silently dropped). Refused, with why, when the file has
/// two sections for one requirement: which one is the answer is the owner's to say, and keeping
/// both would leave the file read in two ways.
pub fn write_template(
    catalog: &Catalog,
    applicable: &BTreeSet<String>,
    facts: &Facts,
    existing: Option<&str>,
    describe: &dyn Fn(&str) -> Option<String>,
) -> std::result::Result<String, String> {
    let answers = existing
        .map(|text| read_answers(catalog, text))
        .unwrap_or_default();
    write_template_with(catalog, applicable, facts, &answers, describe)
}

/// `write_template`, from answers already read, so one of them can be changed first.
pub fn write_template_with(
    catalog: &Catalog,
    applicable: &BTreeSet<String>,
    facts: &Facts,
    answers: &Answers,
    describe: &dyn Fn(&str) -> Option<String>,
) -> std::result::Result<String, String> {
    if let Some((id, first, second)) = answers.duplicates.first() {
        return Err(format!(
            "{} has two sections for {id}, at lines {first} and {second}. `sv` cannot tell which \
             one is the answer, so it has written nothing. Put what you want kept under one \
             heading for {id}, take the other heading out, and run it again.",
            catalog.file
        ));
    }
    let mut out = String::new();
    out.push_str(TITLE_LINE);
    out.push_str("\n\n");
    for paragraph in [
        INTRO_WHAT.to_owned(),
        INTRO_DOCUMENTED.to_owned(),
        format!("{INTRO_WHO_BEFORE_REVIEW}{INTRO_WHO_REVIEW}"),
    ] {
        out.push_str(&paragraph);
        out.push_str("\n\n");
    }
    if !answers.kept.is_empty() {
        out.push_str(KEPT_HEADING);
        out.push_str("\n\n");
        out.push_str(KEPT_WHY);
        out.push_str("\n\n");
        out.push_str(&answers.kept);
        out.push_str("\n\n");
    }

    let mut wrote_any = false;
    for section in &catalog.sections {
        if !applicable.contains(&section.id) {
            continue;
        }
        wrote_any = true;
        let heading = answers
            .heading_of(&section.id)
            .map(|rest| format!("## {rest}"))
            .unwrap_or_else(|| heading(section));
        push_section(
            &mut out,
            &heading,
            section,
            facts,
            answers.get_answer(&section.id),
            describe,
        );
    }
    if !wrote_any {
        out.push_str(NOTHING_APPLIES);
        out.push('\n');
    }

    // A section whose requirement no longer applies, but which somebody has written, or whose
    // heading is not one `sv` wrote. Kept, said out loud: the manifest may be wrong, and deleting an
    // owner's writing to tidy a file is the kind of helpfulness nobody asked for.
    let orphans: Vec<(&String, &String)> = answers
        .sections
        .iter()
        .filter(|(id, body)| {
            !applicable.contains(id)
                && (!body.trim().is_empty() || answers.heading_is_not_svs(catalog, id))
        })
        .map(|(id, body)| (id, body))
        .collect();
    if !orphans.is_empty() {
        out.push_str(ORPHANS_HEADING);
        out.push_str("\n\n");
        out.push_str(ORPHANS_WHY);
        out.push_str("\n\n");
        for (id, body) in orphans {
            let rest = answers
                .heading_of(id)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    let title = catalog
                        .section(id)
                        .map_or(NO_LONGER_ASKED, |s| s.title.as_str());
                    format!("{id} — {title}")
                });
            out.push_str(&format!("### {rest}\n\n"));
            let body = blank_lines_trimmed(body);
            if !body.is_empty() {
                out.push_str(&body);
                out.push_str("\n\n");
            }
        }
    }
    Ok(out)
}

/// The question as `sv` writes it under a section's heading, one quoted line each.
fn question_lines(section: &Section) -> Vec<String> {
    section
        .asks
        .split_terminator('\n')
        .map(|line| format!("> {}", line.trim()))
        .collect()
}

fn push_section(
    out: &mut String,
    heading: &str,
    section: &Section,
    facts: &Facts,
    answer: Option<&str>,
    describe: &dyn Fn(&str) -> Option<String>,
) {
    out.push_str(heading);
    out.push_str("\n\n");
    for line in question_lines(section) {
        out.push_str(&line);
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
    let answer = answer.map(blank_lines_trimmed).unwrap_or_default();
    if answer.is_empty() {
        out.push_str(PLACEHOLDER);
    } else {
        // As it was written: only blank lines before and after it are left out.
        out.push_str(&answer);
    }
    out.push_str("\n\n");
}

/// `text` without the blank lines at its start and end, and nothing else changed: not the spaces
/// at the start of its first line, nor any line's own ending.
fn blank_lines_trimmed(text: &str) -> String {
    let lines: Vec<&str> = text.split('\n').collect();
    let first = lines.iter().position(|l| !l.trim().is_empty());
    let last = lines.iter().rposition(|l| !l.trim().is_empty());
    match (first, last) {
        (Some(first), Some(last)) => lines[first..=last].join("\n"),
        _ => String::new(),
    }
}

/// What a notes file says, section by section, with `sv`'s own words stripped out.
#[derive(Debug, Default)]
pub struct Answers {
    /// Requirement id → the owner's prose, with the question, the facts, and the placeholder gone.
    pub sections: Vec<(String, String)>,
    /// Requirement id → its heading as the file has it, without the `## ` in front.
    pub headings: Vec<(String, String)>,
    /// Everything in the file that is neither `sv`'s nor under a question, word for word and in
    /// order: paragraphs separated by a blank line, without blank lines at either end.
    pub kept: String,
    /// A requirement with two sections, and the line each starts on (counted from 1).
    pub duplicates: Vec<(String, usize, usize)>,
}

impl Answers {
    /// The heading of the section for `id` as the file has it, without the `## ` in front.
    pub fn heading_of(&self, id: &str) -> Option<&str> {
        self.headings
            .iter()
            .find(|(section, _)| section == id)
            .map(|(_, rest)| rest.as_str())
    }

    /// Whether the section for `id` has a heading `sv` did not write: one the owner gave it, or
    /// for a requirement `sv` never asked about.
    fn heading_is_not_svs(&self, catalog: &Catalog, id: &str) -> bool {
        let title = catalog
            .section(id)
            .map_or(NO_LONGER_ASKED, |s| s.title.as_str());
        self.heading_of(id)
            .is_some_and(|rest| rest != format!("{id} — {title}"))
    }

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
/// Everything `sv` puts in a section is recognizable and dropped: the heading, the question as
/// `catalog` asks it (`>`), the italic lines it writes for the requirement's own wording and the
/// facts, the facts under them, and the placeholder. What is left under a heading is the answer,
/// as it was written. A quoted block at the top of a section that is not the question as `sv` asks
/// it now (an earlier wording, or the owner's own) is not counted as an answer and not dropped
/// either: it goes to `kept`, with everything else in the file that is not under a question.
pub fn read_answers(catalog: &Catalog, text: &str) -> Answers {
    let own = own_lines();
    let is_own = |t: &str| own.iter().any(|line| line == t);
    let mut answers = Answers::default();
    let mut kept = Kept::default();
    let mut first_line: std::collections::HashMap<String, usize> = Default::default();
    let mut open: Option<Open> = None;
    let mut before_any_heading = true;
    // Split on `\n` alone, so a line keeps a `\r` it ends in, and is kept as it was.
    for (n, raw) in text.split('\n').enumerate() {
        let t = raw.trim();
        if let Some(id) = section_id(raw) {
            if let Some(done) = open.take() {
                done.close(&mut answers, &mut kept);
            }
            match first_line.get(&id) {
                Some(first) => answers.duplicates.push((id.clone(), *first, n + 1)),
                None => {
                    first_line.insert(id.clone(), n + 1);
                }
            }
            let rest = raw
                .trim_end()
                .trim_start_matches('#')
                .trim_start()
                .to_owned();
            open = Some(Open::new(id, rest, catalog));
            kept.break_chunk();
            before_any_heading = false;
            continue;
        }
        if t == ORPHANS_HEADING || t == KEPT_HEADING {
            if let Some(done) = open.take() {
                done.close(&mut answers, &mut kept);
            }
            kept.break_chunk();
            before_any_heading = false;
            continue;
        }
        match open.as_mut() {
            Some(section) => section.line(raw, t, &is_own, &mut kept),
            None if is_own(t) || (before_any_heading && t == TITLE_LINE) => kept.after_own(),
            None => kept.push(raw),
        }
    }
    if let Some(done) = open.take() {
        done.close(&mut answers, &mut kept);
    }
    answers.kept = kept.finish();
    answers
}

/// Text that is not under a question, gathered in order.
#[derive(Default)]
struct Kept<'a> {
    chunks: Vec<Vec<&'a str>>,
    current: Vec<&'a str>,
    /// Blank lines straight after `sv`'s own line, or at the start of a stretch, are not kept: they
    /// only separated `sv`'s line from the next.
    skip_blank: bool,
}

impl<'a> Kept<'a> {
    fn push(&mut self, raw: &'a str) {
        let blank = raw.trim().is_empty();
        if blank && (self.skip_blank || self.current.is_empty()) {
            return;
        }
        self.skip_blank = false;
        self.current.push(raw);
    }

    fn after_own(&mut self) {
        self.skip_blank = true;
    }

    /// A heading came between: what follows is a paragraph of its own.
    fn break_chunk(&mut self) {
        while self.current.last().is_some_and(|l| l.trim().is_empty()) {
            self.current.pop();
        }
        if !self.current.is_empty() {
            self.chunks.push(std::mem::take(&mut self.current));
        }
        self.skip_blank = true;
    }

    fn push_chunk(&mut self, lines: Vec<&'a str>) {
        self.break_chunk();
        self.chunks.push(lines);
    }

    fn finish(mut self) -> String {
        self.break_chunk();
        self.chunks
            .iter()
            .map(|chunk| chunk.join("\n"))
            .collect::<Vec<_>>()
            .join("\n\n")
    }
}

/// The section being read.
struct Open<'a> {
    id: String,
    heading: String,
    question: Vec<String>,
    body: Vec<&'a str>,
    /// A run of quoted lines, held until it ends to see whether it is the question.
    quote: Vec<&'a str>,
    quotes_seen: bool,
    /// How the italic line quoting the requirement's own wording begins.
    describe: String,
    /// Under `sv`'s facts line, before a line that is not one of `sv`'s facts.
    in_facts: bool,
}

impl<'a> Open<'a> {
    fn new(id: String, heading: String, catalog: &Catalog) -> Open<'a> {
        let question = catalog.section(&id).map(question_lines).unwrap_or_default();
        Open {
            describe: format!("*{id} asks for this: "),
            id,
            heading,
            question,
            body: Vec::new(),
            quote: Vec::new(),
            quotes_seen: false,
            in_facts: false,
        }
    }

    fn owner_began(&self) -> bool {
        self.body.iter().any(|l| !l.trim().is_empty())
    }

    fn line(&mut self, raw: &'a str, t: &str, is_own: &dyn Fn(&str) -> bool, kept: &mut Kept<'a>) {
        if t.starts_with('>') {
            self.in_facts = false;
            self.quote.push(raw);
            return;
        }
        self.end_quote(kept);
        if self.in_facts {
            // The blank lines around `sv`'s facts, and the facts themselves.
            if t.is_empty() {
                return;
            }
            if t.strip_prefix("- ")
                .is_some_and(|fact| FACT_OPENINGS.iter().any(|o| fact.starts_with(o)))
            {
                return;
            }
            self.in_facts = false;
        }
        if t == PLACEHOLDER || is_own(t) {
            return;
        }
        if t == FACTS_LINE {
            self.in_facts = true;
            return;
        }
        if t.ends_with('*') && t.starts_with(&self.describe) {
            return;
        }
        self.body.push(raw);
    }

    /// A run of quoted lines has ended. The question as `sv` asks it is `sv`'s; another at the top
    /// of the section, before anything the owner wrote, may be an earlier wording of it, so it is
    /// neither counted as an answer nor dropped; one further down is part of the answer.
    fn end_quote(&mut self, kept: &mut Kept<'a>) {
        if self.quote.is_empty() {
            return;
        }
        let run = std::mem::take(&mut self.quote);
        let first = !self.quotes_seen;
        self.quotes_seen = true;
        let is_question = !self.question.is_empty()
            && run.len() == self.question.len()
            && run.iter().zip(&self.question).all(|(l, q)| l.trim() == q);
        if is_question {
            return;
        }
        if first && !self.owner_began() {
            kept.push_chunk(run);
        } else {
            self.body.extend(run);
        }
    }

    fn close(mut self, answers: &mut Answers, kept: &mut Kept<'a>) {
        self.end_quote(kept);
        let body = blank_lines_trimmed(&self.body.join("\n"));
        answers.sections.push((self.id.clone(), body));
        answers.headings.push((self.id, self.heading));
    }
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
        .position(|l| section_id(l).is_some())
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
        super::evidence(catalog, &sealed, file, &crate::seal::Checker::Key(key()))
    }

    #[test]
    fn an_owners_section_counts_as_theirs_only_when_sv_review_recorded_it() {
        let body = "Written by: owner\n\nFive failed sign-ins in fifteen minutes lock the account \
                    for an hour.";
        let answers = Answers {
            sections: vec![("V6.1.1".into(), body.into())],
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        };
        assert!(only_seal.answered().is_empty());
        // A word changed after it was sealed: the tool's word again.
        let changed = Answers {
            sections: vec![(
                "V6.1.1".into(),
                format!("{}\n\n{SEALED_BY} {seal}", body.replace("an hour", "a day")),
            )],
            ..Default::default()
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
        )
        .unwrap();
        assert!(
            template.contains("V6.1.1") && template.contains("asks for this"),
            "the template must ask, and quote the requirement: {template}"
        );
        let answers = read_answers(&catalog(), &template);
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
        )
        .unwrap();
        let written = template.replacen(
            PLACEHOLDER,
            "Written by: owner\n\nFive failed sign-ins from one address in fifteen minutes \
             starts a one-minute delay that doubles each time, and no account is ever locked.",
            1,
        );
        let documented = read_answers(&catalog(), &written).documented();
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
        )
        .unwrap();
        let written = template.replacen(PLACEHOLDER, "todo", 1);
        assert!(
            read_answers(&catalog(), &written).documented().is_empty(),
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
        )
        .unwrap();
        let written = first.replace(PLACEHOLDER, answer);
        let second = write_template(
            &catalog(),
            &applicable(&["V6.1.1", "V8.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        )
        .unwrap();
        assert_eq!(
            read_answers(&catalog(), &second).documented(),
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
        )
        .unwrap();
        let written = first.replace(PLACEHOLDER, answer);
        // The owner answers no to the question that placed V8.1.1, by mistake or otherwise.
        let second = write_template(
            &catalog(),
            &applicable(&["V6.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        )
        .unwrap();
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
        )
        .unwrap();
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
        )
        .unwrap();
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
        )
        .unwrap();
        let written = template.replacen(
            PLACEHOLDER,
            "Written by: owner\n\nFive failed sign-ins in fifteen minutes start a delay that \
             doubles, and no account is locked.",
            1,
        );
        let evidence = evidence(
            &catalog(),
            &read_answers(&catalog(), &written),
            "security-notes.md",
        );
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
        )
        .unwrap();
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
        )
        .unwrap();
        read_answers(&catalog(), &template.replacen(PLACEHOLDER, answer, 1))
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
        )
        .unwrap();
        let written = template.replacen(PLACEHOLDER, &answer, 1);
        let again = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        )
        .unwrap();
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
        )
        .unwrap();
        let written = first.replacen(PLACEHOLDER, &answer, 1);
        let again = write_template(
            &catalog(),
            &applicable(&["V8.1.1"]),
            &Facts::default(),
            Some(&written),
            &no_descriptions(),
        )
        .unwrap();
        assert!(
            again.contains("**Decided by the owner (2026-09-26):**"),
            "{again}"
        );
        assert_eq!(
            read_answers(&catalog(), &again).documented(),
            applicable(&["V8.1.1"])
        );
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

    // Deep review R7: everything in the file that `sv` did not write survives a rewrite.

    fn every_fact() -> Facts {
        Facts {
            app_name: "Corner Shop".into(),
            data_categories: vec!["email addresses".into(), "orders".into()],
            outside_services: vec!["Stripe (the `stripe` package)".into()],
            ecosystems: vec!["npm (package.json)".into()],
            uploads: Some(true),
            sign_in: Some(true),
        }
    }

    fn quoting() -> impl Fn(&str) -> Option<String> {
        |id: &str| Some(format!("Verify that what {id} asks for is documented."))
    }

    /// The file `sv notes` writes for both questions, from `existing`.
    fn rewrite(existing: Option<&str>, ids: &[&str]) -> std::result::Result<String, String> {
        write_template(
            &catalog(),
            &applicable(ids),
            &every_fact(),
            existing,
            &quoting(),
        )
    }

    /// Each of `lines` is a whole line of `text`, in this order.
    fn in_order(text: &str, lines: &[&str]) {
        let all: Vec<&str> = text.split('\n').collect();
        let mut from = 0;
        for line in lines {
            let at = all[from..]
                .iter()
                .position(|l| l == line)
                .unwrap_or_else(|| panic!("{line:?} is gone, or out of order:\n{text}"));
            from += at + 1;
        }
    }

    /// Only the questions and the answers, without the kept section, to see what is where.
    fn kept_section(text: &str) -> &str {
        let Some(start) = text.find(KEPT_HEADING) else {
            return "";
        };
        let rest = &text[start..];
        let end = rest.find("\n## V").map_or(rest.len(), |i| i + 1);
        &rest[..end]
    }

    #[test]
    fn owner_text_before_between_and_after_sv_sections_is_kept_in_order() {
        let first = rewrite(None, &["V6.1.1", "V8.1.1"]).unwrap();
        // Setup: the facts list and the requirement's wording are really there to sit beside.
        let data_fact = "- securevibe.toml says this app holds: email addresses and orders.\n";
        assert!(first.contains(data_fact) && first.contains("*V8.1.1 asks for this: "));
        let edited = first
            .replacen(
                "# Security notes\n\n",
                "# Security notes\n\nBEFORE one: reviewed with Sam on 1 October.\n\n",
                1,
            )
            .replacen(
                INTRO_DOCUMENTED,
                &format!("{INTRO_DOCUMENTED}\n\nBEFORE two: between the paragraphs sv wrote."),
                1,
            )
            .replacen(
                PLACEHOLDER,
                "Written by: owner\n\nANSWER: five wrong passwords and the account waits ten \
                 minutes.\n\n> QUOTE: from our lawyer, word for word.\n\n- BULLET one",
                1,
            )
            .replacen(
                "## V8.1.1",
                "BETWEEN: after the first answer, before the next heading.\n\n## V8.1.1",
                1,
            )
            .replacen(
                data_fact,
                &format!("{data_fact}- BULLET two: added to the list sv wrote\n"),
                1,
            )
            + "\nAFTER: the very end of the file.\n";
        let owner = [
            "BEFORE one: reviewed with Sam on 1 October.",
            "BEFORE two: between the paragraphs sv wrote.",
            "Written by: owner",
            "ANSWER: five wrong passwords and the account waits ten minutes.",
            "> QUOTE: from our lawyer, word for word.",
            "- BULLET one",
            "BETWEEN: after the first answer, before the next heading.",
            "- BULLET two: added to the list sv wrote",
            "AFTER: the very end of the file.",
        ];
        in_order(&edited, &owner);

        let second = rewrite(Some(&edited), &["V6.1.1", "V8.1.1"]).unwrap();
        in_order(&second, &owner);
        // The two before the first question are in the kept section; the rest under their
        // questions, where they were.
        let kept = kept_section(&second);
        assert!(
            kept.contains(owner[0]) && kept.contains(owner[1]),
            "{second}"
        );
        let answers = read_answers(&catalog(), &second);
        let v6 = answers.prose_of("V6.1.1").unwrap();
        for line in &owner[3..7] {
            assert!(v6.contains(line), "{line} is not in the answer: {v6}");
        }
        let v8 = answers.prose_of("V8.1.1").unwrap();
        assert!(v8.contains(owner[7]) && v8.contains(owner[8]), "{v8}");
        // sv's own lines are written once, not kept as well.
        assert_eq!(second.matches(data_fact).count(), 1, "{second}");
        assert_eq!(second.matches(INTRO_DOCUMENTED).count(), 1);
        assert_eq!(second.matches("*V8.1.1 asks for this: ").count(), 1);
        // And again, byte for byte.
        assert_eq!(
            rewrite(Some(&second), &["V6.1.1", "V8.1.1"]).unwrap(),
            second
        );
    }

    #[test]
    fn kept_text_is_never_an_answer() {
        let first = rewrite(None, &["V6.1.1"]).unwrap();
        let long =
            "Written by: owner. We decided this in a meeting and it is long enough to count.";
        let edited = first.replacen(
            "# Security notes\n\n",
            &format!("# Security notes\n\n{long}\n\n"),
            1,
        );
        // And an earlier wording of the question, long enough to count were it read as an answer.
        let question = "> How the app defends against someone trying many passwords.";
        let earlier = "> How does the app defend itself against someone trying many passwords?";
        // And a heading of the owner's own with nothing under it yet.
        let empty = "## V42.2 — Our own heading, nothing under it yet";
        let edited = edited.replacen(question, earlier, 1) + "\n" + empty + "\n";
        let second = rewrite(Some(&edited), &["V6.1.1"]).unwrap();
        let kept = kept_section(&second);
        assert!(kept.contains(long) && kept.contains(earlier), "{second}");
        assert!(second.contains(&format!("\n#{empty}\n")), "{second}");
        let answers = read_answers(&catalog(), &second);
        assert!(answers.answered().is_empty(), "{:?}", answers.answered());
    }

    #[test]
    fn sv_s_own_paragraph_under_a_question_is_not_an_answer() {
        // An earlier file, or a paragraph moved by hand: sv's words under a heading are still sv's.
        let first = rewrite(None, &["V6.1.1", "V8.1.1"]).unwrap();
        for paragraph in [ORPHANS_WHY, INTRO_WHAT, INTRO_WHO_BEFORE_REVIEW] {
            let edited = first.replacen(PLACEHOLDER, paragraph, 1);
            let answers = read_answers(&catalog(), &edited);
            assert!(answers.answered().is_empty(), "{paragraph}");
            let second = rewrite(Some(&edited), &["V6.1.1", "V8.1.1"]).unwrap();
            assert_eq!(second, first, "{paragraph}");
        }
    }

    #[test]
    fn text_that_looks_like_a_section_heading_is_kept() {
        let first = rewrite(None, &["V6.1.1", "V8.1.1"]).unwrap();
        let answer = "Written by: owner\n\n## Notes we keep\n\n#### V8.1.1 is related\n\n\
                      ##V8.1.1 without a space\n\nFive wrong passwords and the account waits.";
        let edited = first
            .replacen(
                "# Security notes\n\n",
                "# Security notes\n\n## My plan\n\nPLAN: ask Sam.\n\n",
                1,
            )
            .replacen(PLACEHOLDER, answer, 1)
            .replacen(
                "## V8.1.1 — Who may do what",
                "## V8.1.1 — Who may do what (our own wording)",
                1,
            )
            + "\n## V99.9.9 — Our own list of suppliers\n\nACME for parts and Bolt for shipping, \
               and nobody else.\n\n### V42.1 — A heading with nothing under it\n";
        let second = rewrite(Some(&edited), &["V6.1.1", "V8.1.1"]).unwrap();
        let kept = kept_section(&second);
        assert!(kept.contains("## My plan\n\nPLAN: ask Sam."), "{second}");
        let answers = read_answers(&catalog(), &second);
        assert!(
            answers.prose_of("V6.1.1").unwrap().contains(&answer[19..]),
            "{second}"
        );
        assert!(second.contains("\n## V8.1.1 — Who may do what (our own wording)\n"));
        let orphans = &second[second.find(ORPHANS_HEADING).expect("an orphans section")..];
        assert!(orphans.contains(
            "### V99.9.9 — Our own list of suppliers\n\nACME for parts and Bolt for shipping, and \
             nobody else."
        ));
        assert!(orphans.contains("### V42.1 — A heading with nothing under it"));
        // The heading-like lines are part of the owner's answer, and no new question appears.
        assert_eq!(answers.documented(), applicable(&["V6.1.1"]));
        assert_eq!(
            rewrite(Some(&second), &["V6.1.1", "V8.1.1"]).unwrap(),
            second
        );
    }

    #[test]
    fn two_sections_for_one_question_are_refused_not_merged() {
        let first = rewrite(None, &["V6.1.1", "V8.1.1"]).unwrap();
        let edited = format!(
            "{first}## V6.1.1 — How sign-in is protected against guessing\n\nA second answer, \
             written further down by somebody else.\n"
        );
        let why = rewrite(Some(&edited), &["V6.1.1", "V8.1.1"]).unwrap_err();
        let first_line = first
            .lines()
            .position(|l| l.starts_with("## V6.1.1"))
            .unwrap()
            + 1;
        assert!(
            why.contains("V6.1.1") && why.contains(&format!("lines {first_line} and ")),
            "{why}"
        );
    }

    #[test]
    fn an_empty_file_is_written_as_a_new_one() {
        let new = rewrite(None, &["V6.1.1"]).unwrap();
        for empty in ["", "\n", "  \n\n\t\n"] {
            assert_eq!(rewrite(Some(empty), &["V6.1.1"]).unwrap(), new, "{empty:?}");
        }
        assert!(!new.contains(KEPT_HEADING));
    }

    #[test]
    fn a_huge_file_is_kept_whole() {
        let first = rewrite(None, &["V6.1.1"]).unwrap();
        let block: String = (0..100_000)
            .map(|i| format!("Line {i} of the owner's own long notes, kept as it is.\n"))
            .collect();
        let block = block.trim_end();
        assert!(block.len() > 5_000_000, "the setup must be large");
        let answer = format!("Written by: owner\n\n{block}");
        let edited = first
            .replacen(
                "# Security notes\n\n",
                &format!("# Security notes\n\n{block}\n\n"),
                1,
            )
            .replacen(PLACEHOLDER, &answer, 1);
        let second = rewrite(Some(&edited), &["V6.1.1"]).unwrap();
        assert!(kept_section(&second).contains(block));
        assert_eq!(
            read_answers(&catalog(), &second)
                .prose_of("V6.1.1")
                .unwrap(),
            block
        );
        assert_eq!(
            second.len(),
            edited.len() + KEPT_HEADING.len() + KEPT_WHY.len() + 4
        );
    }

    #[test]
    fn a_rewrite_keeps_the_owners_text_byte_for_byte() {
        // A file `sv` wrote comes back unchanged.
        let first = rewrite(None, &["V6.1.1", "V8.1.1"]).unwrap();
        assert_eq!(rewrite(Some(&first), &["V6.1.1", "V8.1.1"]).unwrap(), first);
        // And so does every byte the owner wrote: Windows line endings, an indented first line,
        // spaces at the end of a line, runs of blank lines, a fenced block, tabs, and accents.
        let answer = "    Written by: owner (indented)\r\nTrailing spaces here   \r\n\r\n\r\n\
                      ```\n> not a question, in a fence\n- a bullet\n```\nÜnïcödé — ✓\tand a tab";
        let preface = "Our preface\r\n\r\n\tindented with a tab\r\nlast line  ";
        let edited = first
            .replacen(
                "# Security notes\n\n",
                &format!("# Security notes\n\n{preface}\n\n"),
                1,
            )
            .replacen(PLACEHOLDER, answer, 1)
            .replacen(
                "- securevibe.toml says this app holds: email addresses and orders.\n",
                "- securevibe.toml says this app holds: email addresses and orders.\n- Ours: and \
                 photographs.\n",
                1,
            );
        let second = rewrite(Some(&edited), &["V6.1.1", "V8.1.1"]).unwrap();
        assert!(second.contains(&format!("\n{answer}\n")), "{second}");
        assert!(second.contains("\n- Ours: and photographs.\n"), "{second}");
        assert!(second.contains(&format!("\n{preface}\n")), "{second}");
        assert_eq!(
            rewrite(Some(&second), &["V6.1.1", "V8.1.1"]).unwrap(),
            second
        );
        // Taking the kept section and the answer out again gives the file sv wrote.
        let back = second
            .replacen(
                &format!("{KEPT_HEADING}\n\n{KEPT_WHY}\n\n{preface}\n\n"),
                "",
                1,
            )
            .replacen("- Ours: and photographs.", PLACEHOLDER, 1)
            .replacen(answer, PLACEHOLDER, 1);
        assert_eq!(back, first);
    }

    #[test]
    fn the_heading_over_old_answers_does_not_become_an_answer() {
        let first = rewrite(None, &["V6.1.1", "V8.1.1"]).unwrap();
        let answer =
            "Written by: owner\n\nOnly the owner may open the admin page, and nobody else.";
        // The second placeholder is V8.1.1's.
        let at = first.rfind(PLACEHOLDER).unwrap();
        let written = format!(
            "{}{answer}{}",
            &first[..at],
            &first[at + PLACEHOLDER.len()..]
        );
        let second = rewrite(Some(&written), &["V6.1.1"]).unwrap();
        let third = rewrite(Some(&second), &["V6.1.1"]).unwrap();
        // Until R7, the orphans' heading and its paragraph were read as the answer to the last
        // question above them, which then counted as stated by the AI coding tool.
        let answers = read_answers(&catalog(), &third);
        let answered: Vec<String> = answers.answered().into_iter().map(|(id, _)| id).collect();
        assert_eq!(answered, vec!["V8.1.1".to_owned()], "{third}");
        assert_eq!(third, second);
        assert_eq!(third.matches(ORPHANS_WHY).count(), 1);
    }

    #[test]
    fn a_quote_that_is_not_the_question_is_kept_and_not_counted() {
        let first = rewrite(None, &["V6.1.1"]).unwrap();
        let question = "> How the app defends against someone trying many passwords.";
        assert!(first.contains(question), "the setup must have the question");
        // An earlier wording of the question, or the owner's own quote in its place.
        let other = "> How the app defends itself against people trying many, many passwords.";
        let edited = first.replacen(question, other, 1);
        let second = rewrite(Some(&edited), &["V6.1.1"]).unwrap();
        assert!(kept_section(&second).contains(other), "{second}");
        assert!(read_answers(&catalog(), &second).answered().is_empty());
        // The question as sv asks it, below a line the owner put first, is still sv's.
        let above = first.replacen(question, &format!("Written by: owner\n\n{question}"), 1);
        let answers = read_answers(&catalog(), &above);
        assert_eq!(answers.prose_of("V6.1.1").as_deref(), Some(""), "{above}");
    }

    #[test]
    fn every_fact_sv_writes_is_recognized_as_sv_s() {
        let mut all = catalog().sections[0].clone();
        all.facts = [
            "app-name",
            "data",
            "outside-services",
            "ecosystems",
            "uploads",
            "sign-in",
        ]
        .map(String::from)
        .to_vec();
        for facts in [
            every_fact(),
            Facts {
                uploads: Some(false),
                sign_in: Some(false),
                ..every_fact()
            },
        ] {
            let bullets = facts.for_section(&all);
            assert_eq!(bullets.len(), 6, "the setup must write every fact");
            for bullet in bullets {
                assert!(
                    FACT_OPENINGS.iter().any(|o| bullet.starts_with(o)),
                    "{bullet} would be kept as the owner's"
                );
            }
        }
        let catalog = Catalog {
            sections: vec![all],
            ..catalog()
        };
        let template = write_template(
            &catalog,
            &applicable(&["V6.1.1"]),
            &every_fact(),
            None,
            &quoting(),
        )
        .unwrap();
        let answers = read_answers(&catalog, &template);
        assert!(answers.answered().is_empty() && answers.kept.is_empty());
        assert_eq!(answers.prose_of("V6.1.1").as_deref(), Some(""));
    }

    #[test]
    fn a_file_from_an_earlier_version_keeps_nothing_of_sv_s() {
        let now = rewrite(None, &["V6.1.1"]).unwrap();
        let then = now.replacen(
            &format!("{INTRO_WHO_BEFORE_REVIEW}{INTRO_WHO_REVIEW}"),
            INTRO_WHO_BEFORE_REVIEW,
            1,
        );
        assert_ne!(then, now, "the setup must hold the earlier paragraph");
        assert_eq!(rewrite(Some(&then), &["V6.1.1"]).unwrap(), now);
    }
}
