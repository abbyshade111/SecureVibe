//! `sv review`: a person records, in their own terminal, the findings they set aside and the answers
//! they confirm, and `sv` seals each so the AI coding tool's own entries can be told apart (deep
//! review R1; the owner's decision of 4 October 2026, in `sv_check::seal`).
//!
//! It goes through every entry in securevibe.toml that does not yet count on this computer: a
//! `[[finding-review]]` entry and a `confirmed` under `[design]` or `[checked-by-hand]`, whether the
//! AI coding tool proposed it or someone wrote it by hand. For each it shows what is being decided
//! and asks for the person's name. What they record is written back into securevibe.toml, with `by`,
//! today's date and the seal, and nothing else in the file is changed, except one thing: a finding's
//! fingerprint in the form used before 5 October 2026 that names one line is written in today's
//! form, which also watches the lines that set the values that line uses (deep review A2).
//!
//! It refuses to run unless both what it reads and what it writes are a terminal, since an AI coding
//! tool runs commands without one. That stops the easy path, not a tool set on faking a terminal;
//! the seal module says so too.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use sv_check::advisories::Day;
use sv_check::seal::{App, AppKey, Checker, Key};

/// One entry waiting for a person.
enum Waiting {
    Finding(usize),
    Confirmation {
        section: &'static str,
        id: String,
    },
    /// An answer under `[design]` given as the owner's.
    DesignAnswer(String),
    /// A result under `[checked-by-hand]` given as the owner's.
    HandAnswer(String),
    /// A section marked `Written by: owner`, in the security notes (0) or design-decisions.md (1):
    /// the index into the files `review` reads sections from.
    Notes(usize, String),
}

pub fn cmd_review(path: Option<PathBuf>) -> Result<()> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        bail!(
            "`sv review` records your own decisions, so it runs only in a terminal you are typing \
             in, and this is not one. If your AI coding tool ran it, that is why it stopped: open a \
             terminal yourself and run `sv review` there."
        );
    }
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut out = Visible(std::io::stdout());
    review(
        &path.unwrap_or_else(|| PathBuf::from(".")),
        Key::folder(),
        &mut input,
        &mut out,
    )
}

/// A terminal written through `sv_report::visible`, as everything `sv` prints is: `sv review` shows
/// findings in the app's own words, and an escape character in one could rewrite what the owner is
/// asked to agree to (the deep review's improvement 5).
struct Visible<W: Write>(W);

impl<W: Write> Write for Visible<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // `write!` hands over whole pieces of text, so no character is split across two writes.
        let text = String::from_utf8_lossy(buf);
        self.0.write_all(sv_report::visible(&text).as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// The review itself, reading the person's answers from `input`.
fn review(
    app_dir: &Path,
    key_folder: Option<PathBuf>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    let manifest_path = app_dir.join("securevibe.toml");
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = sv_manifest::Manifest::load(&manifest_path)?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let Some(folder) = key_folder else {
        bail!(
            "`sv review` keeps this computer's review key in your home folder, and neither HOME nor \
             XDG_CONFIG_HOME says where that is."
        );
    };
    let (key, made) = Key::load_or_make_in(&folder).map_err(anyhow::Error::msg)?;
    if made {
        writeln!(
            out,
            "Made this computer's review key, in {}. It seals what you record here. Keep it \
             private: anyone who can read it can seal entries as you. Seals made with it count on \
             this computer only, and only in the app they were recorded for; on a computer with no \
             review key, such as CI, they cannot be checked and do not count, and the report says \
             so.\n",
            folder.join(sv_check::seal::KEY_FILE).display()
        )?;
    }
    let today = Day::today().context("this computer's clock is before 1970")?;
    // Sealed for this app alone, so an answer copied into another app does not count there.
    let key = key.for_app(&App::of(app_dir).map_err(anyhow::Error::msg)?);
    let checker = Checker::Key(key.clone());
    let rules = sv_check::secrets::SecretRules::load(&super::secret_rules_path())?;

    let mut waiting = Vec::new();
    for (i, entry) in manifest.finding_review.iter().enumerate() {
        let fields = sv_check::seal::finding_review_fields(entry);
        if checker
            .check(entry.seal.as_deref(), &sv_check::seal::as_strs(&fields))
            .is_err()
        {
            waiting.push(Waiting::Finding(i));
        }
    }
    let confirmations = manifest
        .design
        .iter()
        .filter_map(|(id, a)| Some(("design", id, a.confirmed.as_ref()?)))
        .chain(
            manifest
                .checked_by_hand
                .iter()
                .filter_map(|(id, h)| Some(("checked-by-hand", id, h.confirmed.as_ref()?))),
        );
    for (section, id, c) in confirmations {
        let fields = sv_check::seal::manifest_confirmation_fields(section, id, c);
        if checker
            .check(c.seal.as_deref(), &sv_check::seal::as_strs(&fields))
            .is_err()
        {
            waiting.push(Waiting::Confirmation {
                section,
                id: id.clone(),
            });
        }
    }
    // The owner's own answers: each counts as theirs only once recorded here.
    for (id, a) in &manifest.design {
        if a.by.as_deref() == Some(sv_check::design::OWNER)
            && sv_check::seal::owner_recorded(
                &checker,
                a.seal.as_deref(),
                &sv_check::seal::design_answer_fields(id, a),
            )
            .is_err()
        {
            waiting.push(Waiting::DesignAnswer(id.clone()));
        }
    }
    for (id, h) in &manifest.checked_by_hand {
        if h.by.as_deref() == Some(sv_check::design::OWNER)
            && sv_check::seal::owner_recorded(
                &checker,
                h.seal.as_deref(),
                &sv_check::seal::hand_check_fields(id, h),
            )
            .is_err()
        {
            waiting.push(Waiting::HandAnswer(id.clone()));
        }
    }
    // The files whose sections say who wrote them: the security notes, and the decisions the
    // design-time prompts write, read the same way (`sv_check::decisions`).
    let notes_catalog = sv_check::notes::Catalog::load(&super::notes_path())?;
    let files: Vec<(sv_check::notes::Catalog, PathBuf)> = [
        notes_catalog.clone(),
        sv_check::notes::Catalog::load(&super::decisions_path())?,
    ]
    .into_iter()
    .map(|catalog| {
        let path = app_dir.join(&catalog.file);
        (catalog, path)
    })
    .collect();
    for (which, (catalog, path)) in files.iter().enumerate() {
        if let Some(text) = notes_text(path)? {
            let answers = sv_check::notes::read_answers(catalog, &text);
            for (id, who) in answers.answered() {
                if who == sv_check::notes::Writer::Owner && answers.recorded(&id, &checker).is_err()
                {
                    waiting.push(Waiting::Notes(which, id));
                }
            }
        }
    }
    if waiting.is_empty() {
        writeln!(
            out,
            "Nothing in {} or {} is waiting for you: every finding set aside, every answer \
             confirmed, and every answer given as yours there was recorded through `sv review` on \
             this computer.",
            manifest_path.display(),
            notes_catalog.file
        )?;
        return Ok(());
    }
    writeln!(
        out,
        "{} {} not recorded as yours on this computer. Each was proposed by your AI coding tool \
         or written into a file by hand, so for now it counts for less than your word, or for \
         nothing. Read the code before you answer.",
        if waiting.len() == 1 {
            "1 entry".to_owned()
        } else {
            format!("{} entries", waiting.len())
        },
        if waiting.len() == 1 { "is" } else { "are" }
    )?;

    let mut recorded = 0;
    let total = waiting.len();
    for (n, item) in waiting.into_iter().enumerate() {
        writeln!(out, "\n[{} of {total}]", n + 1)?;
        let done = match item {
            Waiting::Finding(i) => {
                let entry = &manifest.finding_review[i];
                match record_finding(app_dir, entry, &rules, today, &key, input, out)? {
                    Some(recorded) => {
                        set_finding(&mut doc, i, &recorded).context("writing the entry")?;
                        Some(Waiting::Finding(i))
                    }
                    None => None,
                }
            }
            Waiting::Confirmation { section, id } => {
                let (confirmed, current) = match section {
                    "design" => {
                        let a = &manifest.design[&id];
                        (
                            a.confirmed.clone().unwrap_or_default(),
                            Current::Design {
                                answer: a.answer.clone(),
                                location: a.r#where.clone(),
                            },
                        )
                    }
                    _ => {
                        let h = &manifest.checked_by_hand[&id];
                        (
                            h.confirmed.clone().unwrap_or_default(),
                            Current::Hand {
                                result: h.result.clone(),
                            },
                        )
                    }
                };
                match record_confirmation(
                    section, &id, &confirmed, &current, today, &key, input, out,
                )? {
                    Some(c) => {
                        set_confirmation(&mut doc, section, &id, &c)
                            .with_context(|| format!("writing {section} {id}"))?;
                        Some(Waiting::Confirmation { section, id })
                    }
                    None => None,
                }
            }
            Waiting::DesignAnswer(id) => {
                let a = &manifest.design[&id];
                let what = format!(
                    "Your answer to requirement {id}, as securevibe.toml gives it: {}{}.",
                    a.answer,
                    a.r#where
                        .as_deref()
                        .map(|w| format!(", pointing at {w}"))
                        .unwrap_or_default()
                );
                let fields = sv_check::seal::design_answer_fields(&id, a);
                match record_own(&what, &fields, &key, input, out)? {
                    Some(seal) => {
                        set_seal(&mut doc, "design", &id, &seal)?;
                        Some(Waiting::DesignAnswer(id))
                    }
                    None => None,
                }
            }
            Waiting::HandAnswer(id) => {
                let h = &manifest.checked_by_hand[&id];
                let what = format!(
                    "Your check made by hand for requirement {id}, as securevibe.toml gives it: {}, \
                     on {}: \"{}\"",
                    h.result,
                    h.on.as_deref().unwrap_or("no date"),
                    h.how.as_deref().unwrap_or("nothing written").trim()
                );
                let fields = sv_check::seal::hand_check_fields(&id, h);
                match record_own(&what, &fields, &key, input, out)? {
                    Some(seal) => {
                        set_seal(&mut doc, "checked-by-hand", &id, &seal)?;
                        Some(Waiting::HandAnswer(id))
                    }
                    None => None,
                }
            }
            Waiting::Notes(which, id) => {
                let (catalog, path) = &files[which];
                let text =
                    notes_text(path)?.with_context(|| format!("{} is gone", catalog.file))?;
                let answers = sv_check::notes::read_answers(catalog, &text);
                let prose = answers.prose_of(&id).unwrap_or_default();
                let what = format!(
                    "Your answer to requirement {id} in {}, marked `Written by: owner`:\n\n{}\n",
                    catalog.file,
                    prose
                        .lines()
                        .map(|l| format!("    {l}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                let fields = sv_check::seal::notes_fields(&id, &prose);
                if let Some(seal) = record_own(&what, &fields, &key, input, out)? {
                    let sealed = sv_check::notes::with_seal_in(catalog, &text, &id, &seal)
                        .context("the section is not where it was")?;
                    save_text(path, &sealed, &|| {
                        notes_text(path).ok().flatten().is_some_and(|t| {
                            sv_check::notes::read_answers(catalog, &t)
                                .recorded(&id, &checker)
                                .is_ok()
                        })
                    })?;
                    recorded += 1;
                }
                None
            }
        };
        if let Some(which) = done {
            save(&manifest_path, &doc, &|m| counts(m, &which, &checker))?;
            recorded += 1;
        }
    }
    writeln!(
        out,
        "\nRecorded {recorded} of {total} as yours.{}",
        if recorded < total {
            " The rest are still proposals; run `sv review` again when you have looked at them."
        } else {
            ""
        }
    )?;
    Ok(())
}

/// The answer or result a confirmation is of, as the manifest says it now.
enum Current {
    Design {
        answer: String,
        location: Option<String>,
    },
    Hand {
        result: String,
    },
}

/// Reads one line, trimmed. `None` at the end of input.
fn ask(input: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<Option<String>> {
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = String::new();
    if input.read_line(&mut line)? == 0 {
        writeln!(out)?;
        return Ok(None);
    }
    Ok(Some(line.trim().to_owned()))
}

/// The name the person types, refused when it names the AI coding tool.
fn is_tool(name: &str) -> bool {
    name.eq_ignore_ascii_case(sv_check::design::AI_TOOL)
        || name.eq_ignore_ascii_case("AI coding tool")
}

const NAME_PROMPT: &str = "Type your name, or `owner` if this is your app, to record it as your \
    decision; `edit` to write it in your own words first; or press Enter to leave it as a proposal.\n> ";

/// What `sv review` writes into a `[[finding-review]]` entry the person records.
struct Recorded {
    /// The entry's fingerprint, in today's form when it was in the earlier one and named one line.
    fingerprint: String,
    by: String,
    why: String,
    on: String,
    seal: String,
}

/// Asks about one `[[finding-review]]` entry. What to write when the person records it: `by`,
/// `why`, `on`, the seal, and the fingerprint in today's form.
#[allow(clippy::too_many_arguments)]
fn record_finding(
    app_dir: &Path,
    entry: &sv_manifest::FindingReview,
    rules: &sv_check::secrets::SecretRules,
    today: Day,
    key: &AppKey,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Option<Recorded>> {
    let secret = entry.rule.starts_with("secrets.");
    writeln!(
        out,
        "A finding proposed as {}.\n  Rule: {}\n  File: {}",
        match entry.verdict.as_str() {
            sv_check::review::FALSE_ALARM => "a false alarm: the code is fine",
            sv_check::review::ACCEPTED_RISK =>
                "an accepted risk: a real problem you live with for now",
            _ => "something that is neither a false alarm nor an accepted risk",
        },
        entry.rule,
        entry.file
    )?;
    let lines = sv_check::review::lines_with_fingerprint(
        app_dir,
        &entry.rule,
        &entry.file,
        &entry.fingerprint,
    );
    match lines.as_slice() {
        [(n, line)]
            if secret || !sv_check::secrets::scan_text(rules, &entry.file, line).is_empty() =>
        {
            writeln!(
                out,
                "  Line {n}, not shown here because it may hold a key or a password: open the file \
                 to read it."
            )?;
        }
        [(n, line)] => writeln!(out, "  Line {n}: {line}")?,
        [] => writeln!(
            out,
            "  No line of the file has this fingerprint ({}) now. It may be a finding about the \
             app as a whole rather than one line, or the line has changed; `sv report` lists each \
             finding with its fingerprint.",
            entry.fingerprint
        )?,
        many => {
            // A fingerprint in the form used before 5 October 2026 named a line by its text alone,
            // so on lines that read the same it names them all, and counts for none of them.
            let numbers: Vec<String> = many.iter().map(|(n, _)| n.to_string()).collect();
            writeln!(
                out,
                "  Lines {} read the same, and this fingerprint ({}), in the form `sv` used before \
                 5 October 2026, names a line by its text alone, so it cannot say which one it \
                 means and would count for none of them. Left as it is: ask for the entry to be \
                 written again with the fingerprint `sv report` now prints beside the one you mean.",
                numbers.join(", "),
                entry.fingerprint
            )?;
            return Ok(None);
        }
    }
    // Recorded with today's fingerprint, which also watches the lines that set the values the line
    // uses and tells identical lines apart (deep review A2), when the earlier one names one line.
    let fingerprint =
        sv_check::review::todays_form(app_dir, &entry.rule, &entry.file, &entry.fingerprint)
            .unwrap_or_else(|| entry.fingerprint.clone());
    writeln!(
        out,
        "  Reason given: \"{}\"\n  Written by: {}",
        entry.why.trim(),
        entry.by.as_deref().unwrap_or("nobody named")
    )?;
    if entry.verdict != sv_check::review::FALSE_ALARM
        && entry.verdict != sv_check::review::ACCEPTED_RISK
    {
        writeln!(
            out,
            "  Its verdict, \"{}\", is not `false-alarm` or `accepted-risk`, so it cannot count. \
             Fix it in securevibe.toml first.",
            entry.verdict
        )?;
        return Ok(None);
    }
    if secret && entry.verdict == sv_check::review::ACCEPTED_RISK {
        writeln!(
            out,
            "  A key or password in the code cannot be an accepted risk: a real one is replaced and \
             taken out of the code. Left as it is."
        )?;
        return Ok(None);
    }
    let least = if secret {
        sv_check::review::LEAST_WHY_CHARS_SECRET
    } else {
        sv_check::review::LEAST_WHY_CHARS
    };
    let mut why = entry.why.trim().to_owned();
    loop {
        let Some(answer) = ask(input, out, NAME_PROMPT)? else {
            return Ok(None);
        };
        if answer.is_empty() {
            writeln!(out, "  Left as a proposal.")?;
            return Ok(None);
        }
        if answer.eq_ignore_ascii_case("edit") {
            let Some(own) = ask(
                input,
                out,
                "Your reason, in one line: what you looked at, and what it showed.\n> ",
            )?
            else {
                return Ok(None);
            };
            why = own;
            continue;
        }
        if is_tool(&answer) {
            writeln!(
                out,
                "  The AI coding tool cannot record a decision. Type your own name, or `owner`."
            )?;
            continue;
        }
        if why.chars().count() < least {
            writeln!(
                out,
                "  The reason is shorter than {least} characters, so it would not count. Type `edit` \
                 to write a longer one{}.",
                if secret {
                    ", saying why the key is not a real one"
                } else {
                    ""
                }
            )?;
            continue;
        }
        let on = today.show();
        let recorded = sv_manifest::FindingReview {
            fingerprint: fingerprint.clone(),
            by: Some(answer.clone()),
            why: why.clone(),
            on: Some(on.clone()),
            seal: None,
            ..entry.clone()
        };
        let fields = sv_check::seal::finding_review_fields(&recorded);
        let seal = key.seal(&sv_check::seal::as_strs(&fields));
        writeln!(out, "  Recorded as {answer}'s decision, dated {on}.")?;
        return Ok(Some(Recorded {
            fingerprint,
            by: answer,
            why,
            on,
            seal,
        }));
    }
}

/// Asks about one confirmation. The confirmation to write when the person records it.
#[allow(clippy::too_many_arguments)]
fn record_confirmation(
    section: &str,
    id: &str,
    proposed: &sv_manifest::Confirmed,
    current: &Current,
    today: Day,
    key: &AppKey,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Option<sv_manifest::Confirmed>> {
    match current {
        Current::Design { answer, location } => writeln!(
            out,
            "An answer your AI coding tool gave to requirement {id}, proposed as confirmed by a \
             person who looked for themselves.\n  The answer: {answer}{}",
            location
                .as_deref()
                .map(|w| format!(", pointing at {w}"))
                .unwrap_or_default()
        )?,
        Current::Hand { result } => writeln!(
            out,
            "A check your AI coding tool made by hand for requirement {id}, proposed as confirmed \
             by a person who looked for themselves.\n  The result: {result}"
        )?,
    }
    writeln!(
        out,
        "  What was looked at: \"{}\"\n  Written by: {}",
        proposed.how.as_deref().unwrap_or("nothing written").trim(),
        proposed.by.as_deref().unwrap_or("nobody named")
    )?;
    let mut how = proposed.how.as_deref().unwrap_or("").trim().to_owned();
    loop {
        let Some(answer) = ask(input, out, NAME_PROMPT)? else {
            return Ok(None);
        };
        if answer.is_empty() {
            writeln!(out, "  Left as a proposal.")?;
            return Ok(None);
        }
        if answer.eq_ignore_ascii_case("edit") {
            let Some(own) = ask(
                input,
                out,
                "What you looked at or tried, and what you saw, in one line.\n> ",
            )?
            else {
                return Ok(None);
            };
            how = own;
            continue;
        }
        if is_tool(&answer) {
            writeln!(
                out,
                "  The AI coding tool cannot confirm its own answer. Type your own name, or `owner`."
            )?;
            continue;
        }
        if how.is_empty() {
            writeln!(
                out,
                "  Nothing says what was looked at, and that is the whole of the evidence. Type \
                 `edit` to write it."
            )?;
            continue;
        }
        let mut c = sv_manifest::Confirmed {
            by: Some(answer.clone()),
            on: Some(today.show()),
            how: Some(how.clone()),
            answer: None,
            r#where: None,
            result: None,
            seal: None,
        };
        // What was confirmed is what was shown, so an answer changed later is not carried.
        match current {
            Current::Design { answer, location } => {
                c.answer = Some(answer.clone());
                c.r#where = location.clone();
            }
            Current::Hand { result } => c.result = Some(result.clone()),
        }
        let fields = sv_check::seal::manifest_confirmation_fields(section, id, &c);
        c.seal = Some(key.seal(&sv_check::seal::as_strs(&fields)));
        writeln!(
            out,
            "  Recorded as confirmed by {answer}, dated {}.",
            today.show()
        )?;
        return Ok(Some(c));
    }
}

/// The notes file's text, or `None` when there is none.
fn notes_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Asks the owner whether an answer given as theirs is theirs. The seal to write when it is.
fn record_own(
    what: &str,
    fields: &[String],
    key: &AppKey,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Option<String>> {
    writeln!(
        out,
        "{what}\n  It is given as yours, but it was not recorded through `sv review`, so for now it \
         counts as your AI coding tool's word. If it is wrong, change it in the file first."
    )?;
    loop {
        let Some(answer) = ask(
            input,
            out,
            "Type `owner` if this is your own answer, to record it as yours; or press Enter to \
             leave it as it is.\n> ",
        )?
        else {
            return Ok(None);
        };
        if answer.is_empty() {
            writeln!(out, "  Left as it is.")?;
            return Ok(None);
        }
        if !answer.eq_ignore_ascii_case(sv_check::design::OWNER) {
            writeln!(
                out,
                "  Only the app's owner gives these answers. Type `owner` if that is you; someone \
                 else who has looked can confirm the AI coding tool's answer instead."
            )?;
            continue;
        }
        writeln!(out, "  Recorded as your own answer.")?;
        return Ok(Some(key.seal(&sv_check::seal::as_strs(fields))));
    }
}

/// Puts `seal` on the answer to `id` in `section` of securevibe.toml, changing nothing else.
fn set_seal(doc: &mut toml_edit::DocumentMut, section: &str, id: &str, seal: &str) -> Result<()> {
    doc.get_mut(section)
        .and_then(toml_edit::Item::as_table_like_mut)
        .and_then(|t| t.get_mut(id))
        .and_then(toml_edit::Item::as_table_like_mut)
        .with_context(|| format!("{section} {id} is not where it was"))?
        .insert("seal", toml_edit::value(seal));
    Ok(())
}

fn set_finding(doc: &mut toml_edit::DocumentMut, i: usize, recorded: &Recorded) -> Result<()> {
    let table: Option<&mut dyn toml_edit::TableLike> = match doc.get_mut("finding-review") {
        Some(toml_edit::Item::ArrayOfTables(tables)) => tables
            .get_mut(i)
            .map(|t| t as &mut dyn toml_edit::TableLike),
        Some(toml_edit::Item::Value(toml_edit::Value::Array(array))) => array
            .get_mut(i)
            .and_then(toml_edit::Value::as_inline_table_mut)
            .map(|t| t as &mut dyn toml_edit::TableLike),
        _ => None,
    };
    let table = table.context("the entry is not where it was")?;
    if table.get("fingerprint").and_then(|f| f.as_str()) != Some(recorded.fingerprint.as_str()) {
        table.insert("fingerprint", toml_edit::value(&recorded.fingerprint));
    }
    table.insert("why", toml_edit::value(&recorded.why));
    table.insert("by", toml_edit::value(&recorded.by));
    table.insert("on", toml_edit::value(&recorded.on));
    table.insert("seal", toml_edit::value(&recorded.seal));
    Ok(())
}

/// Whether what was just recorded counts, as the report will read it.
fn counts(manifest: &sv_manifest::Manifest, which: &Waiting, checker: &Checker) -> bool {
    match which {
        Waiting::Finding(i) => manifest.finding_review.get(*i).is_some_and(|e| {
            let fields = sv_check::seal::finding_review_fields(e);
            checker
                .check(e.seal.as_deref(), &sv_check::seal::as_strs(&fields))
                .is_ok()
        }),
        Waiting::DesignAnswer(id) => manifest.design.get(id).is_some_and(|a| {
            sv_check::seal::owner_recorded(
                checker,
                a.seal.as_deref(),
                &sv_check::seal::design_answer_fields(id, a),
            )
            .is_ok()
        }),
        Waiting::HandAnswer(id) => manifest.checked_by_hand.get(id).is_some_and(|h| {
            sv_check::seal::owner_recorded(
                checker,
                h.seal.as_deref(),
                &sv_check::seal::hand_check_fields(id, h),
            )
            .is_ok()
        }),
        Waiting::Notes(..) => false,
        Waiting::Confirmation { section, id } => {
            let c = match *section {
                "design" => manifest.design.get(id).and_then(|a| a.confirmed.as_ref()),
                _ => manifest
                    .checked_by_hand
                    .get(id)
                    .and_then(|h| h.confirmed.as_ref()),
            };
            c.is_some_and(|c| {
                let fields = sv_check::seal::manifest_confirmation_fields(section, id, c);
                checker
                    .check(c.seal.as_deref(), &sv_check::seal::as_strs(&fields))
                    .is_ok()
            })
        }
    }
}

fn set_confirmation(
    doc: &mut toml_edit::DocumentMut,
    section: &str,
    id: &str,
    c: &sv_manifest::Confirmed,
) -> Result<()> {
    let entry = doc
        .get_mut(section)
        .and_then(toml_edit::Item::as_table_like_mut)
        .and_then(|t| t.get_mut(id))
        .and_then(toml_edit::Item::as_table_like_mut)
        .context("the entry is not where it was")?;
    let mut table = toml_edit::InlineTable::new();
    let fields = [
        ("by", &c.by),
        ("on", &c.on),
        ("answer", &c.answer),
        ("where", &c.r#where),
        ("result", &c.result),
        ("how", &c.how),
        ("seal", &c.seal),
    ];
    for (name, value) in fields {
        if let Some(value) = value {
            table.insert(name, value.as_str().into());
        }
    }
    entry.insert("confirmed", toml_edit::value(table));
    Ok(())
}

/// Writes the file, then reads it back and checks that what was recorded counts. If it does not,
/// the file is put back as it was before this write and nothing is claimed.
fn save(
    path: &Path,
    doc: &toml_edit::DocumentMut,
    counts: &dyn Fn(&sv_manifest::Manifest) -> bool,
) -> Result<()> {
    save_text(path, &doc.to_string(), &|| {
        sv_manifest::Manifest::load(path).is_ok_and(|m| counts(&m))
    })
}

/// The same for any file: `counts` reads it back.
fn save_text(path: &Path, text: &str, counts: &dyn Fn() -> bool) -> Result<()> {
    let before =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    if counts() {
        return Ok(());
    }
    std::fs::write(path, before).ok();
    bail!(
        "{} was put back as it was, because after writing it what was recorded would not count \
         as written. Nothing was recorded.",
        path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("sv-review-{name}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(dir.join("app")).unwrap();
            Scratch(dir)
        }
        fn app(&self) -> PathBuf {
            self.0.join("app")
        }
        fn keys(&self) -> PathBuf {
            self.0.join("config").join("securevibe")
        }
        fn manifest(&self) -> String {
            std::fs::read_to_string(self.app().join("securevibe.toml")).unwrap()
        }
        fn run(&self, typed: &str) -> (Result<()>, String) {
            let mut out = Vec::new();
            let result = review(
                &self.app(),
                Some(self.keys()),
                &mut std::io::Cursor::new(typed.as_bytes().to_vec()),
                &mut out,
            );
            (result, String::from_utf8(out).unwrap())
        }
        fn checker(&self) -> Checker {
            Checker::Key(
                Key::load_from(&self.keys())
                    .unwrap()
                    .expect("a key was made")
                    .for_app(&App::of(&self.app()).unwrap()),
            )
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    const HEAD: &str =
        "manifest-version = 1\n[app]\nname = \"R\"\n[stack]\nlanguages = [\"python\"]\n";
    const LINE: &str = "return redirect(request.args.get(\"next\"))";
    const WHY: &str = "The next= value is looked up in a fixed list of our own paths first.";

    fn proposal(why: &str) -> String {
        format!(
            "\n# The AI coding tool's proposal.\n[[finding-review]]\nrule = \"ast.open-redirect\"\n\
             file = \"app.py\"\nfingerprint = \"{}\"\nverdict = \"false-alarm\"\nwhy = \"{why}\"\n\
             by = \"ai-tool\"\n",
            sv_check::review::named("ast.open-redirect", "app.py", LINE)
        )
    }

    fn with_app(s: &Scratch, manifest: &str) {
        std::fs::write(s.app().join("app.py"), format!("def go():\n    {LINE}\n")).unwrap();
        std::fs::write(s.app().join("securevibe.toml"), manifest).unwrap();
    }

    fn finding_counts(s: &Scratch, i: usize) -> bool {
        let m = sv_manifest::Manifest::load(&s.app().join("securevibe.toml")).unwrap();
        counts(&m, &Waiting::Finding(i), &s.checker())
    }

    #[test]
    fn a_finding_is_recorded_only_with_a_persons_name_and_a_reason_long_enough() {
        let s = Scratch::new("finding");
        with_app(&s, &format!("{HEAD}{}", proposal("fine.")));
        let (result, out) = s.run(&format!("ai-tool\nowner\nedit\n{WHY}\nowner\n"));
        result.unwrap();
        // The setup: the line the fingerprint names was found and shown.
        assert!(out.contains(&format!("Line 2: {LINE}")), "{out}");
        assert!(out.contains("cannot record a decision"), "{out}");
        assert!(out.contains("shorter than 40 characters"), "{out}");
        assert!(out.contains("Recorded 1 of 1"), "{out}");
        let after = s.manifest();
        assert!(
            after.contains("# The AI coding tool's proposal."),
            "{after}"
        );
        assert!(after.contains("by = \"owner\""), "{after}");
        assert!(after.contains(WHY), "{after}");
        assert!(finding_counts(&s, 0));
        // Nothing waits the second time.
        let (result, out) = s.run("");
        result.unwrap();
        assert!(out.contains("Nothing in"), "{out}");
    }

    #[test]
    fn enter_or_the_end_of_input_leaves_the_file_as_it_was() {
        let s = Scratch::new("left");
        let manifest = format!("{HEAD}{}", proposal(WHY));
        with_app(&s, &manifest);
        for typed in ["\n", ""] {
            let (result, out) = s.run(typed);
            result.unwrap();
            assert!(out.contains("Recorded 0 of 1"), "{out}");
            assert_eq!(s.manifest(), manifest);
        }
    }

    #[test]
    fn an_entry_written_as_an_inline_array_is_recorded_in_place() {
        let s = Scratch::new("inline");
        let fp = sv_check::review::named("ast.open-redirect", "app.py", LINE);
        with_app(
            &s,
            &format!(
                "finding-review = [{{ rule = \"ast.open-redirect\", file = \"app.py\", \
                 fingerprint = \"{fp}\", verdict = \"false-alarm\", why = \"{WHY}\" }}]\n{HEAD}"
            ),
        );
        let (result, out) = s.run("Sam Lee\n");
        result.unwrap();
        assert!(out.contains("Recorded 1 of 1"), "{out}");
        assert!(finding_counts(&s, 0));
    }

    #[test]
    fn a_line_that_may_hold_a_key_is_never_shown() {
        // Built from pieces, so this file holds no key.
        let key = ["AKIA", "Q7RZ2KV9LP4WN8HF"].concat();
        let line = format!("aws = \"{key}\"");
        for rule in ["ast.something", "secrets.aws-access-key"] {
            let s = Scratch::new(&format!("secret-{rule}"));
            std::fs::write(s.app().join("app.py"), format!("{line}\n")).unwrap();
            std::fs::write(
                s.app().join("securevibe.toml"),
                format!(
                    "{HEAD}[[finding-review]]\nrule = \"{rule}\"\nfile = \"app.py\"\n\
                     fingerprint = \"{}\"\nverdict = \"false-alarm\"\nwhy = \"short\"\n",
                    sv_check::review::named(rule, "app.py", &sv_check::review::masked(&line))
                ),
            )
            .unwrap();
            let (result, out) = s.run("\n");
            result.unwrap();
            // A secrets finding's line is not shown at all; any other is shown masked, as the
            // report shows it.
            let shown = if rule.starts_with("secrets.") {
                "Line 1, not shown".to_owned()
            } else {
                format!("Line 1: {}", sv_check::review::masked(&line))
            };
            assert!(out.contains(&shown), "{rule}: the setup\n{out}");
            assert!(!out.contains(&key[4..]), "{rule}: the key was shown");
        }
    }

    #[test]
    fn a_file_outside_the_app_folder_is_never_read() {
        let s = Scratch::new("outside");
        std::fs::write(s.0.join("private.txt"), format!("{LINE}\n")).unwrap();
        with_app(
            &s,
            &format!(
                "{HEAD}[[finding-review]]\nrule = \"ast.open-redirect\"\nfile = \"../private.txt\"\n\
                 fingerprint = \"{}\"\nverdict = \"false-alarm\"\nwhy = \"{WHY}\"\n",
                sv_check::review::named("ast.open-redirect", "../private.txt", LINE)
            ),
        );
        let (result, out) = s.run("\n");
        result.unwrap();
        assert!(!out.contains(LINE), "{out}");
        assert!(out.contains("No line of the file"), "{out}");
    }

    #[test]
    fn a_confirmation_records_what_was_shown_in_whichever_form_it_was_written() {
        let s = Scratch::new("confirm");
        with_app(
            &s,
            &format!(
                "{HEAD}[design]\n\"V8.3.1\" = {{ answer = \"yes\", where = \"app.py\", by = \"ai-tool\", \
                 confirmed = {{ by = \"owner\", answer = \"no\", how = \"Sent a POST and got 405.\" }} }}\n\n\
                 [checked-by-hand.'V12.2.2']\nresult = \"done\"\non = \"2026-10-01\"\nby = \"ai-tool\"\n\
                 how = \"Fetched it.\"\n\n[checked-by-hand.'V12.2.2'.confirmed]\nby = \"ai-tool\"\n"
            ),
        );
        let (result, out) =
            s.run("owner\nowner\nedit\nOpened the site; the padlock is green.\nSam Lee\n");
        result.unwrap();
        assert!(out.contains("Nothing says what was looked at"), "{out}");
        assert!(out.contains("Recorded 2 of 2"), "{out}");
        let m = sv_manifest::Manifest::load(&s.app().join("securevibe.toml")).unwrap();
        let design = m.design["V8.3.1"].confirmed.clone().unwrap();
        // What was confirmed is the answer shown, not the "no" the proposal named.
        assert_eq!(design.answer.as_deref(), Some("yes"));
        assert_eq!(design.r#where.as_deref(), Some("app.py"));
        let hand = m.checked_by_hand["V12.2.2"].confirmed.clone().unwrap();
        assert_eq!(hand.by.as_deref(), Some("Sam Lee"));
        assert_eq!(hand.result.as_deref(), Some("done"));
        for (section, id) in [("design", "V8.3.1"), ("checked-by-hand", "V12.2.2")] {
            assert!(
                counts(
                    &m,
                    &Waiting::Confirmation {
                        section,
                        id: id.to_owned()
                    },
                    &s.checker()
                ),
                "{section} {id}"
            );
        }
    }

    #[test]
    fn a_write_that_would_not_count_is_put_back() {
        let s = Scratch::new("put-back");
        let manifest = format!("{HEAD}{}", proposal(WHY));
        with_app(&s, &manifest);
        let path = s.app().join("securevibe.toml");
        let mut doc: toml_edit::DocumentMut = manifest.parse().unwrap();
        let fingerprint = sv_check::review::named("ast.open-redirect", "app.py", LINE);
        set_finding(
            &mut doc,
            0,
            &Recorded {
                fingerprint,
                by: "owner".into(),
                why: WHY.into(),
                on: "2026-10-04".into(),
                seal: "v1:0:0".into(),
            },
        )
        .unwrap();
        let err = save(&path, &doc, &|_| false).unwrap_err();
        assert!(format!("{err}").contains("put back"), "{err}");
        assert_eq!(s.manifest(), manifest);
        save(&path, &doc, &|_| true).unwrap();
        assert!(s.manifest().contains("by = \"owner\""));
    }

    #[test]
    fn the_owners_own_answers_are_recorded_only_as_the_owners() {
        let s = Scratch::new("own");
        with_app(
            &s,
            &format!(
                "{HEAD}\n# Kept as written.\n[design]\n\"V8.3.1\" = {{ answer = \"yes\", where = \"app.py\", \
                 by = \"owner\" }}\n\"V2.2.2\" = {{ answer = \"yes\", by = \"ai-tool\" }}\n\n\
                 [checked-by-hand.'V12.2.2']\nresult = \"done\"\non = \"2026-10-01\"\nby = \"owner\"\n\
                 how = \"Opened the live site; the padlock shows a trusted certificate.\"\n"
            ),
        );
        let notes = "# Security notes\n\n## V6.1.1 — Sign-in\n\n> How is sign-in protected?\n\n\
                     Written by: owner\n\nFive failed sign-ins in fifteen minutes lock the account for \
                     an hour.\n\n## V8.1.1 — Who may do what\n\nWritten by: AI coding tool\n\n\
                     Administrators may open every page; everyone else only their own.\n\n\
                     ## V2.1.1 — Valid input\n\nWritten by: owner\nSealed by sv review: v1:0000000000000000:\
                     0000000000000000000000000000000000000000000000000000000000000000\n\nNames are at \
                     most eighty letters, and dates are never in the future.\n";
        std::fs::write(s.app().join("security-notes.md"), notes).unwrap();
        let (result, out) = s.run("owner\nSam Lee\nowner\nowner\nowner\n");
        result.unwrap();
        // The tool's own answers are not offered as the owner's.
        assert!(!out.contains("V2.2.2") && !out.contains("V8.1.1"), "{out}");
        assert!(
            out.contains("Only the app's owner gives these answers"),
            "{out}"
        );
        assert!(out.contains("Five failed sign-ins"), "{out}");
        assert!(out.contains("Recorded 4 of 4"), "{out}");
        let m = sv_manifest::Manifest::load(&s.app().join("securevibe.toml")).unwrap();
        for which in [
            Waiting::DesignAnswer("V8.3.1".into()),
            Waiting::HandAnswer("V12.2.2".into()),
        ] {
            assert!(counts(&m, &which, &s.checker()));
        }
        assert!(m.design["V2.2.2"].seal.is_none());
        assert!(s.manifest().contains("# Kept as written."));
        let after = std::fs::read_to_string(s.app().join("security-notes.md")).unwrap();
        let catalog = sv_check::notes::Catalog::load(&crate::notes_path()).unwrap();
        let answers = sv_check::notes::read_answers(&catalog, &after);
        assert!(answers.recorded("V6.1.1", &s.checker()).is_ok(), "{after}");
        assert!(answers.recorded("V8.1.1", &s.checker()).is_err());
        // A seal that did not hold was replaced, not added to.
        assert!(answers.recorded("V2.1.1", &s.checker()).is_ok(), "{after}");
        assert_eq!(
            after.matches(sv_check::notes::SEALED_BY).count(),
            2,
            "{after}"
        );
        // Only the seal lines changed.
        let added: Vec<&str> = after
            .lines()
            .filter(|l| !notes.lines().any(|n| n == *l))
            .collect();
        assert_eq!(added.len(), 2, "{after}");
        assert!(
            added
                .iter()
                .all(|l| l.starts_with(sv_check::notes::SEALED_BY))
        );
        // Nothing waits the second time.
        let (result, out) = s.run("");
        result.unwrap();
        assert!(out.contains("Nothing in"), "{out}");
    }

    #[test]
    fn an_owners_section_of_the_decisions_file_is_recorded_under_its_own_heading() {
        // design-decisions.md's sections go by headings with no id (`sv_check::decisions`); the one
        // marked as the owner's is offered and sealed, the tool's is not, and a section that counts
        // toward nothing is never offered.
        let s = Scratch::new("decisions");
        with_app(&s, HEAD);
        let decisions = "# Design decisions\n\n## When to bring in a person\n\nWritten by: owner\n\n\
                         The app keeps health data, so a person should review the design.\n\n\
                         ## What we do if something goes wrong\n\nWritten by: owner\n\nTake the app \
                         offline from the hosting dashboard, rotate the database password, and email \
                         everyone affected within three days.\n\n## Rules that might apply\n\n\
                         Written by: AI coding tool\n\nHealth data of people in Europe: the GDPR may \
                         apply, so ask someone qualified.\n";
        std::fs::write(s.app().join(sv_check::decisions::FILE), decisions).unwrap();
        let (result, out) = s.run("owner\n");
        result.unwrap();
        assert!(
            out.contains("SBD-MT-06") && out.contains("Take the app"),
            "{out}"
        );
        assert!(
            !out.contains("SBD-AC-06") && !out.contains("health data, so a person"),
            "{out}"
        );
        assert!(out.contains("Recorded 1 of 1"), "{out}");
        let after = std::fs::read_to_string(s.app().join(sv_check::decisions::FILE)).unwrap();
        let catalog = sv_check::notes::Catalog::load(&crate::decisions_path()).unwrap();
        let answers = sv_check::notes::read_answers(&catalog, &after);
        assert!(
            answers.recorded("SBD-MT-06", &s.checker()).is_ok(),
            "{after}"
        );
        assert!(answers.recorded("SBD-AC-06", &s.checker()).is_err());
        // Only the seal line was added, under the section it is for.
        let added: Vec<&str> = after
            .lines()
            .filter(|l| !decisions.lines().any(|n| n == *l))
            .collect();
        assert_eq!(added.len(), 1, "{after}");
        let seal_at = after.find(sv_check::notes::SEALED_BY).unwrap();
        assert!(
            after.find("## What we do if").unwrap() < seal_at
                && seal_at < after.find("## Rules that might apply").unwrap(),
            "{after}"
        );
        let (result, out) = s.run("");
        result.unwrap();
        assert!(out.contains("Nothing in"), "{out}");
    }

    #[test]
    fn without_a_home_folder_nothing_is_asked() {
        let s = Scratch::new("no-home");
        with_app(&s, &format!("{HEAD}{}", proposal(WHY)));
        let mut out = Vec::new();
        let result = review(
            &s.app(),
            None,
            &mut std::io::Cursor::new(b"owner\n".to_vec()),
            &mut out,
        );
        assert!(result.is_err());
        assert!(!s.manifest().contains("seal"));
    }

    #[test]
    fn an_earlier_fingerprint_on_identical_lines_is_left_and_todays_shows_its_one_line() {
        let s = Scratch::new("identical");
        std::fs::write(
            s.app().join("app.py"),
            format!("def a():\n    {LINE}\n\ndef b():\n    {LINE}\n"),
        )
        .unwrap();
        let entry = |fp: &str| {
            format!(
                "{HEAD}[[finding-review]]\nrule = \"ast.open-redirect\"\nfile = \"app.py\"\n\
                 fingerprint = \"{fp}\"\nverdict = \"false-alarm\"\nwhy = \"{WHY}\"\n"
            )
        };
        // The earlier form names both lines, so recording it would count for neither: left.
        let earlier = entry(&sv_check::review::named(
            "ast.open-redirect",
            "app.py",
            LINE,
        ));
        std::fs::write(s.app().join("securevibe.toml"), &earlier).unwrap();
        let (result, out) = s.run("owner\n");
        result.unwrap();
        assert!(
            out.contains("Lines 2, 5 read the same") && out.contains("Left as it is"),
            "{out}"
        );
        assert!(out.contains("Recorded 0 of 1"), "{out}");
        assert_eq!(s.manifest(), earlier);
        // Today's form names the second line alone, and is recorded as it is.
        let mut second = vec![sv_check::finding::Finding {
            rule_id: "ast.open-redirect".into(),
            location: sv_check::finding::Location {
                file: "app.py".into(),
                line: 5,
            },
            ..first_finding()
        }];
        sv_check::review::fill_fingerprints(&s.app(), &mut second);
        let todays = entry(&second[0].fingerprint);
        std::fs::write(s.app().join("securevibe.toml"), &todays).unwrap();
        let (result, out) = s.run("owner\n");
        result.unwrap();
        assert!(out.contains(&format!("Line 5: {LINE}")), "{out}");
        assert!(out.contains("Recorded 1 of 1"), "{out}");
        assert!(s.manifest().contains(&second[0].fingerprint));
        assert!(finding_counts(&s, 0));
    }

    fn first_finding() -> sv_check::finding::Finding {
        sv_check::finding::Finding {
            rule_id: String::new(),
            title: String::new(),
            severity: sv_check::finding::Severity::High,
            confidence: sv_check::finding::Confidence::Medium,
            location: sv_check::finding::Location {
                file: String::new(),
                line: 1,
            },
            secret: None,
            requirement_ids: Vec::new(),
            cwe: Vec::new(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
        }
    }

    #[test]
    fn what_the_review_writes_shows_control_characters_rather_than_sending_them() {
        let mut out = Visible(Vec::new());
        write!(out, "Set aside \u{1b}]52;c;cHduZWQ=\u{7}this?\n\tyes\r").unwrap();
        let shown = String::from_utf8(out.0).unwrap();
        assert_eq!(
            shown,
            "Set aside \\u{001b}]52;c;cHduZWQ=\\u{0007}this?\n\tyes\\u{000d}"
        );
    }
}
