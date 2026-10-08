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
use sv_check::seal::{App, Checker, Key, Sealed};
use sv_check::signed::{Signer, SigningKey, Stored};

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
        &mut hidden,
    )
}

/// Reads one line from the terminal without showing what is typed: a passphrase.
fn hidden(input: &mut dyn BufRead, out: &mut dyn Write, prompt: &str) -> Result<Option<String>> {
    // What the terminal shows is put back however this returns.
    struct Shown(Option<libc::termios>);
    impl Drop for Shown {
        fn drop(&mut self) {
            if let Some(was) = self.0 {
                // SAFETY: `was` is the terminal's own settings, read below from the same descriptor.
                unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &was) };
            }
        }
    }
    let mut shown = Shown(None);
    // SAFETY: a zeroed termios is only written into by `tcgetattr`, and used only if that succeeds.
    let mut was: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut was) } == 0 {
        let mut quiet = was;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: as above; `quiet` is the terminal's settings with echo turned off.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &quiet) } == 0 {
            shown.0 = Some(was);
        }
    }
    let line = ask(input, out, prompt)?;
    drop(shown);
    writeln!(out)?;
    Ok(line)
}

/// How `review` reads a passphrase: hidden in a terminal, as typed in a test.
type Secret<'a> =
    &'a mut dyn FnMut(&mut dyn BufRead, &mut dyn Write, &str) -> Result<Option<String>>;

/// This computer's signing key (ADR-043): made now if there is none, with a passphrase if the
/// person wants one, or unlocked with its passphrase. `None` when the person stopped.
fn signing_key(
    folder: &Path,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
    secret: Secret<'_>,
) -> Result<Option<SigningKey>> {
    match SigningKey::load_from(folder).map_err(anyhow::Error::msg)? {
        Some(Stored::Ready(key)) => Ok(Some(key)),
        Some(Stored::Locked(locked)) => {
            for _ in 0..3 {
                let Some(typed) = secret(
                    input,
                    out,
                    &format!(
                        "The passphrase of this computer's signing key ({}): ",
                        locked.fingerprint()
                    ),
                )?
                else {
                    return Ok(None);
                };
                match locked.unlock(&typed) {
                    Ok(key) => return Ok(Some(key)),
                    Err(why) => writeln!(out, "  {why}.")?,
                }
            }
            bail!("Three passphrases did not unlock the signing key, so nothing was recorded.")
        }
        None => {
            writeln!(
                out,
                "`sv review` signs what you record with a key of its own, which it makes now, in \
                 {}. A passphrase on it means nothing can sign as you without it, your AI coding \
                 tool included, since the passphrase is only in your head; you then type it each \
                 time you run `sv review`.",
                folder.display()
            )?;
            let Some(wanted) = ask(
                input,
                out,
                "Protect the key with a passphrase? Type `yes`, or press Enter for none.\n> ",
            )?
            else {
                return Ok(None);
            };
            let passphrase = if wanted.eq_ignore_ascii_case("yes") {
                loop {
                    let Some(first) = secret(input, out, "Passphrase: ")? else {
                        return Ok(None);
                    };
                    if first.is_empty() {
                        writeln!(out, "  A passphrase cannot be empty.")?;
                        continue;
                    }
                    let Some(again) = secret(input, out, "The same passphrase again: ")? else {
                        return Ok(None);
                    };
                    if first == again {
                        break Some(first);
                    }
                    writeln!(out, "  The two were not the same. Try again.")?;
                }
            } else {
                None
            };
            let key =
                SigningKey::make_in(folder, passphrase.as_deref()).map_err(anyhow::Error::msg)?;
            writeln!(
                out,
                "Made this computer's signing key, in {}, with its public half beside it. Its \
                 fingerprint is {}: the report names the key it trusted by it, so you can tell it \
                 is this one. Keep the key file private: anyone who can read it{} can sign \
                 entries as you.\n",
                folder.join(sv_check::signed::SIGNING_KEY_FILE).display(),
                key.fingerprint(),
                if passphrase.is_some() {
                    " and knows the passphrase"
                } else {
                    ""
                }
            )?;
            Ok(Some(key))
        }
    }
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
    secret: Secret<'_>,
) -> Result<()> {
    let manifest_path = app_dir.join("securevibe.toml");
    // The files this writes are looked at before anything is asked: a link planted at one of their
    // names would otherwise be found only after the person had typed their answers (and perhaps
    // made a key), and a file outside the app must never be written over through it.
    crate::refuse_link(&manifest_path, crate::FILE_LINK)?;
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
    for (_, path) in &files {
        crate::refuse_link(path, crate::FILE_LINK)?;
    }
    let text = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let manifest = sv_manifest::Manifest::load(&manifest_path)?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("reading {}", manifest_path.display()))?;
    let Some(folder) = key_folder else {
        bail!(
            "`sv review` keeps this computer's signing key in your home folder, and neither HOME nor \
             XDG_CONFIG_HOME says where that is."
        );
    };
    // What is recorded is signed (ADR-043). The review key, if this computer has one, is only
    // read, to check the seals made with it before signing began.
    let app = App::of(app_dir).map_err(anyhow::Error::msg)?;
    let Some(signing) = signing_key(&folder, input, out, secret)? else {
        writeln!(out, "\nNothing was recorded.")?;
        return Ok(());
    };
    if sv_check::signed::trust_here(&folder, &signing, &app).map_err(anyhow::Error::msg)? {
        writeln!(
            out,
            "This app is now on this computer's list of trusted keys, {}, so what you record here \
             counts here. For CI, the container, or another computer to count it too, give it \
             this line as the variable {} (on GitHub: the repository's Settings, then Secrets and \
             variables, then Actions, then Variables). It is the public half of the key, made to \
             be shared: it lets a computer check a seal, never make one.\n\n{}\n",
            folder.join(sv_check::signed::TRUSTED_FILE).display(),
            sv_check::signed::TRUSTED_VARIABLE,
            signing.trusted_line(&app).map_err(anyhow::Error::msg)?
        )?;
    }
    let today = Day::today().context("this computer's clock is before 1970")?;
    // Signed for this app alone, so an answer copied into another app does not count there.
    let key = signing.for_app(&app);
    let checker = Checker::in_folder(Some(&folder), app_dir);
    let rules = sv_check::secrets::SecretRules::load(&super::secret_rules_path())?;

    let mut waiting = Vec::new();
    // Entries whose seal was made with the review key and holds here: signed again at one yes.
    let mut older = Vec::new();
    let mut sort = |state: Result<Sealed, ()>, which: Waiting| match state {
        Err(()) => waiting.push(which),
        Ok(Sealed::Here) => older.push(which),
        Ok(Sealed::Signed { .. }) => {}
    };
    for (i, entry) in manifest.finding_review.iter().enumerate() {
        let fields = sv_check::seal::finding_review_fields(entry);
        sort(
            checker
                .recorded(entry.seal.as_deref(), &sv_check::seal::as_strs(&fields))
                .map_err(drop),
            Waiting::Finding(i),
        );
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
        sort(
            checker
                .recorded(c.seal.as_deref(), &sv_check::seal::as_strs(&fields))
                .map_err(drop),
            Waiting::Confirmation {
                section,
                id: id.clone(),
            },
        );
    }
    // The owner's own answers: each counts as theirs only once recorded here.
    for (id, a) in &manifest.design {
        if a.by.as_deref() == Some(sv_check::design::OWNER) {
            sort(
                sv_check::seal::owner_recorded(
                    &checker,
                    a.seal.as_deref(),
                    &sv_check::seal::design_answer_fields(id, a),
                )
                .map_err(drop),
                Waiting::DesignAnswer(id.clone()),
            );
        }
    }
    for (id, h) in &manifest.checked_by_hand {
        if h.by.as_deref() == Some(sv_check::design::OWNER) {
            sort(
                sv_check::seal::owner_recorded(
                    &checker,
                    h.seal.as_deref(),
                    &sv_check::seal::hand_check_fields(id, h),
                )
                .map_err(drop),
                Waiting::HandAnswer(id.clone()),
            );
        }
    }
    for (which, (catalog, path)) in files.iter().enumerate() {
        if let Some(text) = notes_text(path)? {
            let answers = sv_check::notes::read_answers(catalog, &text);
            for (id, who) in answers.answered() {
                if who == sv_check::notes::Writer::Owner {
                    sort(
                        answers.recorded(&id, &checker).map_err(drop),
                        Waiting::Notes(which, id),
                    );
                }
            }
        }
    }
    if !older.is_empty() {
        sign_again(
            &older,
            &manifest,
            &mut doc,
            &manifest_path,
            &files,
            &key,
            &checker,
            input,
            out,
        )?;
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

/// Signs again, at one yes, the entries whose seal was made with this computer's review key and
/// holds here (ADR-043): such a seal already shows the entry was recorded here, so nothing is asked
/// again. Each is signed over what it says now, which is what its seal holds for.
#[allow(clippy::too_many_arguments)]
fn sign_again(
    older: &[Waiting],
    manifest: &sv_manifest::Manifest,
    doc: &mut toml_edit::DocumentMut,
    manifest_path: &Path,
    files: &[(sv_check::notes::Catalog, PathBuf)],
    key: &Signer,
    checker: &Checker,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(
        out,
        "{} recorded through `sv review` on this computer before it signed what it records. \
         {} here, and only here. Signed again with this computer's signing key, {} any computer \
         given your list of trusted keys, CI included. Nothing in {} changes but the seal.",
        if older.len() == 1 {
            "1 entry was".to_owned()
        } else {
            format!("{} entries were", older.len())
        },
        if older.len() == 1 {
            "Its seal holds"
        } else {
            "Their seals hold"
        },
        if older.len() == 1 {
            "it would count on"
        } else {
            "they would count on"
        },
        if older.len() == 1 { "it" } else { "them" }
    )?;
    let Some(yes) = ask(
        input,
        out,
        "Sign them again? Type `yes`, or press Enter to leave them as they are.\n> ",
    )?
    else {
        return Ok(());
    };
    if !yes.eq_ignore_ascii_case("yes") {
        writeln!(out, "  Left as they are.\n")?;
        return Ok(());
    }
    let sign = |fields: &[String]| -> Result<String> {
        key.seal(&sv_check::seal::as_strs(fields))
            .map_err(anyhow::Error::msg)
    };
    let mut signed = 0;
    let mut in_manifest = Vec::new();
    for which in older {
        match which {
            Waiting::Finding(i) => {
                let seal = sign(&sv_check::seal::finding_review_fields(
                    &manifest.finding_review[*i],
                ))?;
                finding_table(doc, *i)?.insert("seal", toml_edit::value(seal));
                in_manifest.push(which);
            }
            Waiting::Confirmation { section, id } => {
                let c = match *section {
                    "design" => manifest.design[id].confirmed.as_ref(),
                    _ => manifest.checked_by_hand[id].confirmed.as_ref(),
                }
                .context("the confirmation is not where it was")?;
                let seal = sign(&sv_check::seal::manifest_confirmation_fields(
                    section, id, c,
                ))?;
                doc.get_mut(section)
                    .and_then(toml_edit::Item::as_table_like_mut)
                    .and_then(|t| t.get_mut(id))
                    .and_then(toml_edit::Item::as_table_like_mut)
                    .and_then(|t| t.get_mut("confirmed"))
                    .and_then(toml_edit::Item::as_table_like_mut)
                    .with_context(|| format!("{section} {id} is not where it was"))?
                    .insert("seal", toml_edit::value(seal));
                in_manifest.push(which);
            }
            Waiting::DesignAnswer(id) => {
                let seal = sign(&sv_check::seal::design_answer_fields(
                    id,
                    &manifest.design[id],
                ))?;
                set_seal(doc, "design", id, &seal)?;
                in_manifest.push(which);
            }
            Waiting::HandAnswer(id) => {
                let seal = sign(&sv_check::seal::hand_check_fields(
                    id,
                    &manifest.checked_by_hand[id],
                ))?;
                set_seal(doc, "checked-by-hand", id, &seal)?;
                in_manifest.push(which);
            }
            Waiting::Notes(file, id) => {
                let (catalog, path) = &files[*file];
                let text =
                    notes_text(path)?.with_context(|| format!("{} is gone", catalog.file))?;
                let prose = sv_check::notes::read_answers(catalog, &text)
                    .prose_of(id)
                    .unwrap_or_default();
                let seal = sign(&sv_check::seal::notes_fields(id, &prose))?;
                let resealed = sv_check::notes::with_seal_in(catalog, &text, id, &seal)
                    .context("the section is not where it was")?;
                save_text(path, &resealed, &|| {
                    notes_text(path).ok().flatten().is_some_and(|t| {
                        matches!(
                            sv_check::notes::read_answers(catalog, &t).recorded(id, checker),
                            Ok(Sealed::Signed { .. })
                        )
                    })
                })?;
                signed += 1;
            }
        }
    }
    if !in_manifest.is_empty() {
        save(manifest_path, doc, &|m| {
            in_manifest.iter().all(|which| counts(m, which, checker))
        })?;
        signed += in_manifest.len();
    }
    writeln!(out, "  Signed {signed} again.\n")?;
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
    key: &Signer,
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
        let seal = key
            .seal(&sv_check::seal::as_strs(&fields))
            .map_err(anyhow::Error::msg)?;
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
    key: &Signer,
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
        c.seal = Some(
            key.seal(&sv_check::seal::as_strs(&fields))
                .map_err(anyhow::Error::msg)?,
        );
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
    key: &Signer,
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
        return Ok(Some(
            key.seal(&sv_check::seal::as_strs(fields))
                .map_err(anyhow::Error::msg)?,
        ));
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
    let table = finding_table(doc, i)?;
    if table.get("fingerprint").and_then(|f| f.as_str()) != Some(recorded.fingerprint.as_str()) {
        table.insert("fingerprint", toml_edit::value(&recorded.fingerprint));
    }
    table.insert("why", toml_edit::value(&recorded.why));
    table.insert("by", toml_edit::value(&recorded.by));
    table.insert("on", toml_edit::value(&recorded.on));
    table.insert("seal", toml_edit::value(&recorded.seal));
    Ok(())
}

/// The `i`th `[[finding-review]]` entry, written either way TOML allows.
fn finding_table(
    doc: &mut toml_edit::DocumentMut,
    i: usize,
) -> Result<&mut dyn toml_edit::TableLike> {
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
    table.context("the entry is not where it was")
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
///
/// Never through a link, and never half-written: the text goes to a new file beside it, which is
/// then renamed over the name (`write_without_following`, as every other file `sv` writes into
/// the app), so a link planted at the name since `review` looked is replaced rather than written
/// through, and a run cut short leaves the file as it was.
fn save_text(path: &Path, text: &str, counts: &dyn Fn() -> bool) -> Result<()> {
    crate::refuse_link(path, crate::FILE_LINK)?;
    let before =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let dir = path.parent().unwrap_or_else(|| Path::new(""));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{} has no file name", path.display()))?;
    crate::write_without_following(dir, name, text.as_bytes())?;
    if counts() {
        return Ok(());
    }
    crate::write_without_following(dir, name, before.as_bytes()).ok();
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
        /// `sv review`, with `typed` as what the person types. The first run is asked whether the
        /// signing key it makes should have a passphrase, and the answer is no.
        fn run(&self, typed: &str) -> (Result<()>, String) {
            let first = !self
                .keys()
                .join(sv_check::signed::SIGNING_KEY_FILE)
                .exists();
            self.run_as_typed(&format!("{}{typed}", if first { "\n" } else { "" }))
        }
        fn run_as_typed(&self, typed: &str) -> (Result<()>, String) {
            let mut out = Vec::new();
            let result = review(
                &self.app(),
                Some(self.keys()),
                &mut std::io::Cursor::new(typed.as_bytes().to_vec()),
                &mut out,
                &mut ask,
            );
            (result, String::from_utf8(out).unwrap())
        }
        fn checker(&self) -> Checker {
            Checker::in_folder(Some(&self.keys()), &self.app())
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
    fn seals_made_with_the_review_key_are_signed_again_at_one_yes() {
        // ADR-043: an entry sealed with this computer's review key before signing began counts
        // here only. `sv review` signs each again at one yes, asking nothing else, and then it
        // counts on a computer given only the public list.
        let s = Scratch::new("again");
        let fp = sv_check::review::named("ast.open-redirect", "app.py", LINE);
        with_app(
            &s,
            &format!(
                "{HEAD}\n[[finding-review]]\nrule = \"ast.open-redirect\"\nfile = \"app.py\"\n\
                 fingerprint = \"{fp}\"\nverdict = \"false-alarm\"\nwhy = \"{WHY}\"\nby = \"owner\"\n\
                 on = \"2026-10-05\"\n\n[design]\n\"V8.3.1\" = {{ answer = \"yes\", where = \"app.py\", \
                 by = \"owner\" }}\n\"V2.2.2\" = {{ answer = \"yes\", by = \"ai-tool\", confirmed = {{ \
                 by = \"Sam Lee\", on = \"2026-10-05\", answer = \"yes\", how = \"Read the handler and \
                 the route list.\" }} }}\n\n[checked-by-hand.'V12.2.2']\nresult = \"done\"\n\
                 on = \"2026-10-01\"\nby = \"owner\"\nhow = \"Opened the live site; the padlock shows a \
                 trusted certificate.\"\n"
            ),
        );
        let notes = "# Security notes\n\n## V6.1.1 — Sign-in\n\n> How is sign-in protected?\n\n\
                     Written by: owner\n\nFive failed sign-ins in fifteen minutes lock the account for \
                     an hour.\n";
        // Sealed as `sv review` sealed before 6 October 2026's signing: with the review key.
        let (old, _) = Key::load_or_make_in(&s.keys()).unwrap();
        let old = old.for_app(&App::of(&s.app()).unwrap());
        let seal = |fields: &[String]| old.seal(&sv_check::seal::as_strs(fields));
        let m = sv_manifest::Manifest::load(&s.app().join("securevibe.toml")).unwrap();
        let mut doc: toml_edit::DocumentMut = s.manifest().parse().unwrap();
        finding_table(&mut doc, 0).unwrap().insert(
            "seal",
            toml_edit::value(seal(&sv_check::seal::finding_review_fields(
                &m.finding_review[0],
            ))),
        );
        set_seal(
            &mut doc,
            "design",
            "V8.3.1",
            &seal(&sv_check::seal::design_answer_fields(
                "V8.3.1",
                &m.design["V8.3.1"],
            )),
        )
        .unwrap();
        set_seal(
            &mut doc,
            "checked-by-hand",
            "V12.2.2",
            &seal(&sv_check::seal::hand_check_fields(
                "V12.2.2",
                &m.checked_by_hand["V12.2.2"],
            )),
        )
        .unwrap();
        let mut c = m.design["V2.2.2"].confirmed.clone().unwrap();
        c.seal = Some(seal(&sv_check::seal::manifest_confirmation_fields(
            "design", "V2.2.2", &c,
        )));
        set_confirmation(&mut doc, "design", "V2.2.2", &c).unwrap();
        std::fs::write(s.app().join("securevibe.toml"), doc.to_string()).unwrap();
        let catalog = sv_check::notes::Catalog::load(&crate::notes_path()).unwrap();
        let prose = sv_check::notes::read_answers(&catalog, notes)
            .prose_of("V6.1.1")
            .unwrap();
        let notes = sv_check::notes::with_seal_in(
            &catalog,
            notes,
            "V6.1.1",
            &seal(&sv_check::seal::notes_fields("V6.1.1", &prose)),
        )
        .unwrap();
        std::fs::write(s.app().join("security-notes.md"), &notes).unwrap();
        let sealed = s.manifest();
        assert_eq!(
            sealed.matches("seal = \"v2:").count(),
            4,
            "the setup: {sealed}"
        );

        // Left as they are: each still counts here, on the review key.
        let (result, out) = s.run("\n");
        result.unwrap();
        assert!(out.contains("5 entries were recorded"), "{out}");
        assert!(out.contains("Left as they are"), "{out}");
        assert!(out.contains("Nothing in"), "{out}");
        assert_eq!(s.manifest(), sealed);
        // Signed again at one yes.
        let (result, out) = s.run("yes\n");
        result.unwrap();
        assert!(out.contains("Signed 5 again"), "{out}");
        let after = s.manifest();
        assert!(!after.contains("v2:"), "{after}");
        assert_eq!(after.matches("seal = \"v3:").count(), 4, "{after}");
        // Only the seals changed.
        let changed: Vec<&str> = after
            .lines()
            .filter(|l| !sealed.lines().any(|n| n == *l))
            .collect();
        assert!(
            changed.iter().all(|l| l.contains("seal = \"v3:")),
            "{changed:?}"
        );
        let notes_after = std::fs::read_to_string(s.app().join("security-notes.md")).unwrap();
        assert_eq!(
            notes_after.replace(
                notes_after
                    .lines()
                    .find(|l| l.starts_with(sv_check::notes::SEALED_BY))
                    .unwrap(),
                ""
            ),
            notes.replace(
                notes
                    .lines()
                    .find(|l| l.starts_with(sv_check::notes::SEALED_BY))
                    .unwrap(),
                ""
            )
        );
        // Each now counts on a computer given only the public list, with no review key and the
        // app in another folder.
        let list = std::fs::read_to_string(s.keys().join(sv_check::signed::TRUSTED_FILE)).unwrap();
        let elsewhere = s.0.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let ci = Checker::no_key().trusting(
            sv_check::signed::Trust::load(None, Some(list.into())),
            Some(App::of(&elsewhere).unwrap()),
        );
        let m = sv_manifest::Manifest::load(&s.app().join("securevibe.toml")).unwrap();
        for which in [
            Waiting::Finding(0),
            Waiting::DesignAnswer("V8.3.1".into()),
            Waiting::HandAnswer("V12.2.2".into()),
            Waiting::Confirmation {
                section: "design",
                id: "V2.2.2".into(),
            },
        ] {
            assert!(counts(&m, &which, &ci));
            assert!(counts(&m, &which, &s.checker()));
        }
        let answers = sv_check::notes::read_answers(&catalog, &notes_after);
        assert!(matches!(
            answers.recorded("V6.1.1", &ci),
            Ok(Sealed::Signed { .. })
        ));
        // Nothing is asked the third time.
        let (result, out) = s.run("");
        result.unwrap();
        assert!(!out.contains("Sign them again"), "{out}");
        assert!(out.contains("Nothing in"), "{out}");
    }

    #[test]
    fn only_an_older_seal_that_holds_here_is_signed_again_without_asking() {
        // One entry sealed with this computer's review key, and one with another computer's: the
        // first is offered to be signed again at one yes, the second is asked about, since this
        // computer cannot tell it from one the AI coding tool made up.
        let s = Scratch::new("older");
        let fp = sv_check::review::named("ast.open-redirect", "app.py", LINE);
        let entry = |why: &str| {
            format!(
                "\n[[finding-review]]\nrule = \"ast.open-redirect\"\nfile = \"app.py\"\n\
                 fingerprint = \"{fp}\"\nverdict = \"false-alarm\"\nwhy = \"{why}\"\n\
                 by = \"owner\"\non = \"2026-10-05\"\n"
            )
        };
        let theirs_why = "Another reason, on another computer, and long enough to be one.";
        with_app(&s, &format!("{HEAD}{}{}", entry(WHY), entry(theirs_why)));
        let (here, _) = Key::load_or_make_in(&s.keys()).unwrap();
        let (there, _) = Key::load_or_make_in(&s.0.join("there")).unwrap();
        let app = App::of(&s.app()).unwrap();
        let m = sv_manifest::Manifest::load(&s.app().join("securevibe.toml")).unwrap();
        let mut doc: toml_edit::DocumentMut = s.manifest().parse().unwrap();
        for (i, key) in [(0, &here), (1, &there)] {
            let seal = key.for_app(&app).seal(&sv_check::seal::as_strs(
                &sv_check::seal::finding_review_fields(&m.finding_review[i]),
            ));
            finding_table(&mut doc, i)
                .unwrap()
                .insert("seal", toml_edit::value(seal));
        }
        std::fs::write(s.app().join("securevibe.toml"), doc.to_string()).unwrap();
        // Yes to signing again; then Enter for the other, which is asked about.
        let (result, out) = s.run("yes\n\n");
        result.unwrap();
        assert!(out.contains("1 entry was recorded"), "{out}");
        assert!(out.contains("Signed 1 again"), "{out}");
        assert!(out.contains("[1 of 1]"), "{out}");
        assert!(out.contains(theirs_why), "{out}");
        assert!(out.contains("Recorded 0 of 1"), "{out}");
        assert!(finding_counts(&s, 0));
        assert!(!finding_counts(&s, 1));
        let after = s.manifest();
        assert_eq!(after.matches("seal = \"v3:").count(), 1, "{after}");
        assert_eq!(after.matches("seal = \"v2:").count(), 1, "{after}");
        // The signing key `sv review` made is its owner's alone.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(s.keys().join(sv_check::signed::SIGNING_KEY_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_list_of_trusted_keys_sv_cannot_read_in_full_is_never_added_to() {
        let s = Scratch::new("bad-list");
        with_app(&s, &format!("{HEAD}{}", proposal(WHY)));
        let manifest = s.manifest();
        std::fs::create_dir_all(s.keys()).unwrap();
        let theirs = sv_check::signed::SigningKey::make_in(&s.0.join("theirs"), None).unwrap();
        let line = theirs
            .trusted_line(&App::of(&s.app()).unwrap())
            .unwrap()
            .replace("namespaces=", "cert-authority,namespaces=");
        std::fs::write(
            s.keys().join(sv_check::signed::TRUSTED_FILE),
            format!("{line}\n"),
        )
        .unwrap();
        let (result, _) = s.run("owner\n");
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("cert-authority"), "{err}");
        assert_eq!(s.manifest(), manifest);
        assert_eq!(
            std::fs::read_to_string(s.keys().join(sv_check::signed::TRUSTED_FILE)).unwrap(),
            format!("{line}\n")
        );
    }

    #[test]
    fn a_passphrase_is_asked_for_when_chosen_and_nothing_signs_without_it() {
        let s = Scratch::new("passphrase");
        with_app(&s, &format!("{HEAD}{}", proposal(WHY)));
        let (result, out) = s.run_as_typed(
            "yes\nhorse one\nhorse two\nhorse battery staple\nhorse battery staple\nowner\n",
        );
        result.unwrap();
        assert!(out.contains("The two were not the same"), "{out}");
        assert!(out.contains("Recorded 1 of 1"), "{out}");
        assert!(!out.contains("horse"), "{out}");
        assert!(matches!(
            sv_check::signed::SigningKey::load_from(&s.keys()).unwrap(),
            Some(Stored::Locked(_))
        ));
        assert!(finding_counts(&s, 0));
        // Three wrong passphrases: nothing is recorded, and nothing is asked.
        let manifest = s.manifest();
        std::fs::write(
            s.app().join("securevibe.toml"),
            format!(
                "{manifest}{}",
                proposal("A second reason, long enough to be a reason.")
            ),
        )
        .unwrap();
        let before = s.manifest();
        let (result, out) = s.run_as_typed("wrong\nwrong\nwrong\nowner\n");
        assert!(format!("{}", result.unwrap_err()).contains("Three passphrases"));
        assert!(!out.contains("[1 of 1]"), "{out}");
        assert_eq!(s.manifest(), before);
        // The right one unlocks it.
        let (result, out) = s.run_as_typed("horse battery staple\nowner\n");
        result.unwrap();
        assert!(out.contains("Recorded 1 of 1"), "{out}");
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
            &mut ask,
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
            outranked: None,
            also_on_this_line: Vec::new(),
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
