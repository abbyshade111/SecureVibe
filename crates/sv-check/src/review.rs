//! A person's record that a finding is a false alarm, or a risk they accept for now.
//!
//! The owner's decisions, 27 September 2026 (BACKLOG, "False alarms, part 2"). Two verdicts:
//! *false alarm*, the code is fine; *accepted risk*, a real problem lived with for now. Only a
//! person's word counts: the AI coding tool rewrites code until a warning stops, and a switch that
//! makes a warning stop is the easiest rewrite of all, so an entry the tool wrote is shown as its
//! proposal and the finding still counts. Since 4 October 2026 (deep review R1) that means an entry
//! recorded through `sv review`, which seals it (`crate::seal`): `by = "owner"` written into the file
//! by anyone else is a proposal too. A false alarm lapses when the flagged line changes, because
//! the fingerprint it names stops matching; an accepted risk lapses after 90 days; a finding that has
//! no line of code (a running-app probe, a settings check) has nothing to watch, so a false alarm
//! about one lapses after 90 days as well. An entry that does not count is listed with its reason,
//! never dropped quietly.
//!
//! A false alarm leaves the list of things to fix. An accepted risk stays on it, labeled. Neither
//! credits anything: the report sends a requirement whose finding was set aside back to what else is
//! known about it, and never to *checked*.

use crate::advisories::Day;
use crate::finding::Finding;
use crate::seal::{Checker, Sealed};
use std::path::Path;
use sv_manifest::FindingReview;

/// Who an entry says made the decision, as a sentence reads it: "the owner" for `owner`, otherwise
/// the name as written. Only what stackvet.toml says: `sv` cannot tell who wrote the entry
/// (deep review R1), so every report puts it as "stackvet.toml says".
pub fn who_said(by: &str) -> String {
    if by.trim().eq_ignore_ascii_case("owner") {
        "the owner".to_owned()
    } else {
        by.trim().to_owned()
    }
}

/// How long a verdict holds when nothing else ends it.
pub const CURRENT_FOR_DAYS: u32 = 90;
/// The shortest reason that can say what was looked at and what it showed.
pub const LEAST_WHY_CHARS: usize = 40;
/// The shortest for a key or password found in the code: saying why it is not a real one takes more.
pub const LEAST_WHY_CHARS_SECRET: usize = 80;

pub const FALSE_ALARM: &str = "false-alarm";
pub const ACCEPTED_RISK: &str = "accepted-risk";

/// A finding a person set aside, with what they decided.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SetAside {
    pub finding: Finding,
    pub verdict: String,
    pub why: String,
    pub by: String,
    pub on: String,
    /// Where its seal was checked: on this computer, or nowhere, this computer having no key.
    pub sealed: Sealed,
}

/// What the entries came to.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Every finding that still counts, accepted risks among them.
    pub findings: Vec<Finding>,
    /// Every entry that counts: false alarms, which left `findings`, and accepted risks, which did not.
    pub set_aside: Vec<SetAside>,
    /// Entries that do not count, each with its reason, for the report to list.
    pub not_counted: Vec<String>,
}

/// What a fingerprint made since 5 October 2026 starts with (deep review A2). A fingerprint of
/// sixteen hex characters and nothing else is the earlier form, which named a line by its text
/// alone; entries written with it still count where it names one finding (`apply`).
pub const FINGERPRINT_V2: &str = "v2-";

/// The most lines above a flagged line that are kept for one name it uses: the assignment that
/// sets it, and the ones that add to it after.
const MOST_ASSIGNMENTS: usize = 8;

/// The name a review gives a finding.
///
/// For a finding on a line of code: its rule, its file, the text of that line with its spaces
/// trimmed, the lines above it that set a name the line uses (for each name, the nearest line that
/// assigns it, and any that add to it after), and which of the lines with all of that the same it
/// is, counted from the top of the file. So moving the line keeps the name; changing it, or
/// changing a line that sets a value it uses, does not; and two identical lines each have their
/// own (deep review A2). A finding with no line of code is named by its title instead, as before.
/// Only a hash of these is kept, sixteen hex characters of SHA-256 after `v2-`.
///
/// Every line read for it, the flagged line and the lines above alike, is first masked as the report
/// masks a credential (`masked`), so the hash says nothing about a credential the report does not:
/// hashed as written, a line holding a weak password could be found again by guessing, since the
/// report shows the name, the first four characters, and the length, and a test password was
/// recovered in 190 guesses (deep review R4).
pub fn fingerprint(app_dir: &Path, f: &Finding) -> String {
    Texts::new(app_dir).fingerprint(f, &f.rule_id)
}

/// A line of code as a review names and shows it: trimmed, with every credential in it masked as the
/// report masks it, its first four characters and its length (`Secret::redact`). Empty when the
/// credential rules could not be read, which they always are where `sv` finds its data: the line is then
/// never named or shown as written, at the cost of reviews telling lines in one file apart only by
/// where they are.
pub fn masked(line: &str) -> String {
    masked_in("", line)
}

/// `masked`, for a line of the file at `relative` in the app, masked in the shapes the scan reads
/// that file's values in (`secrets::redact_text_in`), so a line is masked as far as it is found.
pub fn masked_in(relative: &str, line: &str) -> String {
    static RULES: std::sync::LazyLock<Option<crate::secrets::SecretRules>> =
        std::sync::LazyLock::new(|| {
            crate::secrets::SecretRules::load(&sv_frameworks::data::file("secret-rules.json")).ok()
        });
    match &*RULES {
        Some(rules) => crate::secrets::redact_text_in(rules, relative, line.trim()).0,
        None => String::new(),
    }
}

/// The earlier fingerprint of what a finding names, from its rule, its file, and its masked line
/// (or its title, for a finding with no line of code): sixteen hex characters. Still the
/// fingerprint of a finding with no line of code; for a line of code, only read back from entries
/// written before 5 October 2026, and given beside today's as `earlier_fingerprints`. Always over
/// the masked line (R4): on a line with no credential that is the line as written, so entries
/// written before either change still match it; on a line holding one, only the masked form is
/// ever computed or published.
pub fn named(rule: &str, file: &str, what: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(format!("{rule}\n{file}\n{what}").as_bytes());
    digest.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Whether a fingerprint is in the form used before 5 October 2026: sixteen hex characters.
pub fn is_earlier_form(fingerprint: &str) -> bool {
    fingerprint.len() == 16 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The fingerprint of line `index` (from 0) of `lines`, under `rule` in `file`.
fn line_fingerprint(rule: &str, file: &str, lines: &[String], index: usize) -> String {
    use sha2::{Digest, Sha256};
    let what = lines[index].trim();
    let reaching = reaching(lines, index);
    let occurrence = (0..index)
        .filter(|&j| lines[j].trim() == what && reaching_eq(lines, j, &reaching))
        .count();
    let digest = Sha256::digest(
        format!(
            "v2\n{rule}\n{file}\n{what}\n{}\n{}\n{occurrence}",
            reaching.len(),
            reaching.join("\n")
        )
        .as_bytes(),
    );
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{FINGERPRINT_V2}{hex}")
}

fn reaching_eq(lines: &[String], index: usize, reaching_of_other: &[String]) -> bool {
    reaching(lines, index) == reaching_of_other
}

/// The lines above line `index` that set a name it uses, each as `name: trimmed line`: for each
/// name, in the order the line first uses it, the nearest line above that assigns it with `=`,
/// `:=`, or a declaration, and any line between that adds to it (`+=`, `.=`, `||=`, ...).
///
/// Read as text, the same in every language: a line that assigns the name inside a string, or
/// passes it as a keyword argument, counts too. That only ever adds a line to watch, so a false
/// alarm comes back for looking at again more often, never less.
fn reaching(lines: &[String], index: usize) -> Vec<String> {
    let line = &lines[index];
    let mut names: Vec<&str> = Vec::new();
    let mut start = None;
    for (i, c) in line
        .char_indices()
        .chain(std::iter::once((line.len(), ' ')))
    {
        let word = c.is_ascii_alphanumeric() || c == '_' || c == '$';
        match (start, word) {
            (None, true) if !c.is_ascii_digit() => start = Some(i),
            (Some(s), false) => {
                let name = &line[s..i];
                if !names.contains(&name) {
                    names.push(name);
                }
                start = None;
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    for name in names {
        let Some(re) = assignment(name) else {
            continue;
        };
        let mut kept = 0;
        for above in lines[..index].iter().rev() {
            if !above.contains(name) {
                continue;
            }
            let Some(m) = re.captures(above) else {
                continue;
            };
            out.push(format!("{name}: {}", above.trim()));
            kept += 1;
            let adds_to = m.get(1).is_some();
            if !adds_to || kept == MOST_ASSIGNMENTS {
                break;
            }
        }
    }
    out
}

/// A pattern for a line that assigns `name`: the name as a whole word, an optional type after a
/// colon, and `=` (not `==`, `=>`, or `=~`), with the operator of an assignment that adds to it in
/// the first group.
fn assignment(name: &str) -> Option<regex::Regex> {
    regex::Regex::new(&format!(
        r"(?:^|[^A-Za-z0-9_$]){}\s*(?::[^=;(){{}}]*?)?\s*(\+|-|\*\*|\*|//|/|%|\.|\|\||&&|\?\?|\||&|\^|<<|>>)?:?=(?:[^=>~]|$)",
        regex::escape(name)
    ))
    .ok()
}

/// The app's files as a review reads them, each read once.
struct Texts<'a> {
    app_dir: &'a Path,
    read: std::collections::HashMap<String, Option<Vec<String>>>,
}

impl<'a> Texts<'a> {
    fn new(app_dir: &'a Path) -> Self {
        Texts {
            app_dir,
            read: std::collections::HashMap::new(),
        }
    }

    /// The lines of `file`, each masked (`masked`), or `None` when it is outside the app folder or
    /// cannot be read. The only way this module reads a file's lines for a fingerprint, so no
    /// fingerprint is ever computed over a credential as written.
    fn lines(&mut self, file: &str) -> Option<&[String]> {
        let app_dir = self.app_dir;
        self.read
            .entry(file.to_owned())
            .or_insert_with(|| {
                let inside = Path::new(file)
                    .components()
                    .all(|c| matches!(c, std::path::Component::Normal(_)));
                if !inside {
                    return None;
                }
                std::fs::read_to_string(app_dir.join(file))
                    .ok()
                    .map(|t| t.lines().map(|l| masked_in(file, l)).collect())
            })
            .as_deref()
    }

    /// `f`'s fingerprint as if `rule` had reported it.
    fn fingerprint(&mut self, f: &Finding, rule: &str) -> String {
        if !crate::finding::reads_code(f) {
            return named(rule, &f.location.file, &f.title);
        }
        let n = f.location.line;
        match self.lines(&f.location.file) {
            Some(lines) if n >= 1 && n <= lines.len() => {
                line_fingerprint(rule, &f.location.file, lines, n - 1)
            }
            _ => named(rule, &f.location.file, &format!("line {n}")),
        }
    }

    /// `f`'s fingerprint in the form used before 5 October 2026, as if `rule` had reported it.
    fn earlier_fingerprint(&mut self, f: &Finding, rule: &str) -> String {
        if !crate::finding::reads_code(f) {
            return named(rule, &f.location.file, &f.title);
        }
        let n = f.location.line;
        let what = self
            .lines(&f.location.file)
            .and_then(|lines| lines.get(n.saturating_sub(1)))
            .cloned()
            .unwrap_or_else(|| format!("line {n}"));
        named(rule, &f.location.file, &what)
    }
}

/// The lines of `file` an entry's fingerprint names, as their numbers and their text with spaces
/// trimmed, for `sv review` to show the person what they are deciding about. At most one, except
/// for a fingerprint in the earlier form on lines that read the same, which names them all (and so
/// counts for none of them). Empty when no line matches (the line changed, or the finding is not
/// about a line), and for a file outside the app folder, whose lines are never read.
pub fn lines_with_fingerprint(
    app_dir: &Path,
    rule: &str,
    file: &str,
    fingerprint: &str,
) -> Vec<(usize, String)> {
    let mut texts = Texts::new(app_dir);
    let Some(lines) = texts.lines(file) else {
        return Vec::new();
    };
    let earlier = is_earlier_form(fingerprint);
    if !earlier && !fingerprint.starts_with(FINGERPRINT_V2) {
        return Vec::new();
    }
    let mut found = Vec::new();
    for (i, l) in lines.iter().enumerate() {
        let matches = if earlier {
            named(rule, file, l.trim()) == fingerprint
        } else {
            line_fingerprint(rule, file, lines, i) == fingerprint
        };
        if matches {
            found.push((i + 1, l.trim().to_owned()));
            if !earlier {
                break;
            }
        }
    }
    found
}

/// The fingerprint, in today's form, of the one line an entry's earlier-form fingerprint names, for
/// `sv review` to write in its place when a person records the entry. `None` when the fingerprint
/// is already in today's form, or names no line or more than one.
pub fn todays_form(app_dir: &Path, rule: &str, file: &str, fingerprint: &str) -> Option<String> {
    if !is_earlier_form(fingerprint) {
        return None;
    }
    let found = lines_with_fingerprint(app_dir, rule, file, fingerprint);
    let [(n, _)] = found.as_slice() else {
        return None;
    };
    let mut texts = Texts::new(app_dir);
    let lines = texts.lines(file)?;
    Some(line_fingerprint(rule, file, lines, n - 1))
}

/// Whether an entry names, by the older unmasked fingerprint, a line of its file that holds a
/// credential: a review recorded before R4, which no longer matches and is said to be so, rather
/// than said to name a line that changed. Never for a file outside the app folder. The unmasked
/// hash is only compared here, never kept or shown.
fn written_unmasked(app_dir: &Path, entry: &FindingReview) -> bool {
    let inside = Path::new(&entry.file)
        .components()
        .all(|c| matches!(c, std::path::Component::Normal(_)));
    if !inside {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(app_dir.join(&entry.file)) else {
        return false;
    };
    text.lines().any(|l| {
        named(&entry.rule, &entry.file, l.trim()) == entry.fingerprint
            && masked_in(&entry.file, l) != l.trim()
    })
}

/// Fills in every finding's fingerprint.
pub fn fill_fingerprints(app_dir: &Path, findings: &mut [Finding]) {
    let mut texts = Texts::new(app_dir);
    for f in findings {
        let fingerprint = texts.fingerprint(f, &f.rule_id);
        let earlier = texts.earlier_fingerprint(f, &f.rule_id);
        f.earlier_fingerprints = if earlier == fingerprint {
            Vec::new()
        } else {
            vec![earlier]
        };
        f.fingerprint = fingerprint;
    }
}

/// Whether this run looked for what an entry's rule reports, in the entry's file: what tells an
/// entry whose finding is gone from one whose finding nobody looked for this time (deep review R3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Looked {
    /// The check that reports the rule ran over the file, so a finding missing from it is gone.
    Ran,
    /// The rule is one this version has, and it did not look at the file this time, for this
    /// reason: it needs `--run` or `--tools`, the file's language was not read, the file was not
    /// opened, and so on.
    NotThisTime(String),
    /// This version of `sv` has no such rule, so nothing in it could report one.
    Unknown,
}

/// Applies the entries to the findings, which must already have their fingerprints. `looked` says,
/// for an entry that matches no finding, whether its rule looked at its file this time.
///
/// An entry may name a rule that was merged into a finding rather than the one kept (see
/// `merge_same_place`): the rule kept on a line can change when a tool is added or `sv`'s choice
/// of words changes, and a person's review of that line should not be lost with it. Such an entry
/// counts when its fingerprint is the one the finding would have had under the rule it names
/// (its line read from `app_dir`).
///
/// One entry answers for one finding. Each entry that counts takes the first finding it matches
/// that no earlier entry has taken, so two identical lines with an entry each are both answered.
/// An entry that counts and finds every finding it matches already taken says the same thing again,
/// or says the opposite: the first adds nothing, and the second leaves the finding to be decided,
/// so neither entry counts. Until 5 October 2026 both were applied, a conflicting pair as a false
/// alarm and an accepted risk at once (R11 of the deep review).
///
/// The one exception, the owner's decision of 5 October 2026: an entry with a fingerprint in the
/// earlier form, which named a line by its text alone, matches the finding it always did when only
/// one finding is on a line with that text; when several are, it answers for none of them, and
/// says so, rather than taking the first in order (deep review A2).
pub fn apply(
    app_dir: &Path,
    entries: &[FindingReview],
    findings: Vec<Finding>,
    today: Day,
    seals: &Checker,
    looked: &dyn Fn(&str, &str) -> Looked,
) -> Outcome {
    let mut texts = Texts::new(app_dir);
    let named = |entry: &FindingReview| {
        format!("`{}` in {} ({})", entry.rule, entry.file, entry.fingerprint)
    };
    let mut not_counted = Vec::new();
    // Which entry has taken each finding, and what each counting entry decided.
    let mut taken: Vec<Option<usize>> = vec![None; findings.len()];
    let mut counting: Vec<(usize, usize, Sealed)> = Vec::new();
    let mut voided: Vec<bool> = vec![false; entries.len()];
    for (k, entry) in entries.iter().enumerate() {
        let earlier = is_earlier_form(&entry.fingerprint);
        let candidates: Vec<usize> = findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                if f.location.file != entry.file {
                    return false;
                }
                let kept = f.rule_id == entry.rule;
                let merged = f.also_reported_by.contains(&entry.rule);
                if !kept && !merged {
                    return false;
                }
                let own = if earlier {
                    texts.earlier_fingerprint(f, &f.rule_id)
                } else {
                    f.fingerprint.clone()
                };
                own == entry.fingerprint
                    || (merged
                        && (if earlier {
                            texts.earlier_fingerprint(f, &entry.rule)
                        } else {
                            texts.fingerprint(f, &entry.rule)
                        }) == entry.fingerprint)
            })
            .map(|(i, _)| i)
            .collect();
        let Some(&first) = candidates.first() else {
            if earlier && written_unmasked(app_dir, entry) {
                // Named without its fingerprint: that hash is the one that could give the
                // credential back, and the report is read by more people than stackvet.toml.
                not_counted.push(format!(
                    "`{}` in {}: recorded by an older `sv`, which named a line holding a credential \
                     in a way that could give the credential back, so its fingerprint is not \
                     repeated here. The line is still there; record the review again with \
                     `sv review`, which names it safely, and remove this entry.",
                    entry.rule, entry.file
                ));
                continue;
            }
            not_counted.push(unmatched(
                &named(entry),
                entry,
                looked(&entry.rule, &entry.file),
            ));
            continue;
        };
        if earlier {
            let places: std::collections::BTreeSet<usize> = candidates
                .iter()
                .map(|&i| findings[i].location.line)
                .collect();
            if places.len() > 1 {
                let lines: Vec<String> = places.iter().map(usize::to_string).collect();
                not_counted.push(format!(
                    "{}: its fingerprint is in the form `sv` used before 5 October 2026, which \
                     named a line by its text alone, and {} findings are on lines that read the \
                     same (lines {}), so which one it means cannot be told, and it applies to none \
                     of them. Write the entry again with the fingerprint the report now prints \
                     beside the one you mean, record it through `sv review`, and remove this one.",
                    named(entry),
                    places.len(),
                    and_list(&lines)
                ));
                continue;
            }
        }
        let sealed = match judge(entry, &findings[first], today, seals) {
            Err(why) => {
                not_counted.push(format!("{}: {why}", named(entry)));
                continue;
            }
            Ok(sealed) => sealed,
        };
        if let Some(&free) = candidates.iter().find(|i| taken[**i].is_none()) {
            taken[free] = Some(k);
            counting.push((k, free, sealed));
            continue;
        }
        // Every finding it matches is answered already: by an entry saying the same, or the
        // opposite. Never "gone": the finding is there.
        let before = taken[first].expect("taken");
        if entries[before].verdict == entry.verdict {
            not_counted.push(format!(
                "{}: an earlier entry already answers for this finding in the same way, so this one \
                 adds nothing and can be removed.",
                named(entry)
            ));
        } else {
            voided[before] = true;
            voided[k] = true;
            not_counted.push(format!(
                "{}: it says {} and an earlier entry for the same finding says {}, so neither \
                 counts and the finding stands until one of them is removed.",
                named(entry),
                entry.verdict,
                entries[before].verdict
            ));
        }
    }
    let mut set_aside = Vec::new();
    let mut gone = Vec::new();
    for (k, i, sealed) in counting {
        let entry = &entries[k];
        if voided[k] {
            continue;
        }
        if entry.verdict == FALSE_ALARM {
            gone.push(i);
        }
        set_aside.push(SetAside {
            finding: findings[i].clone(),
            verdict: entry.verdict.clone(),
            why: entry.why.trim().to_owned(),
            by: entry.by.clone().unwrap_or_default(),
            on: entry.on.clone().unwrap_or_default(),
            sealed,
        });
    }
    let findings = findings
        .into_iter()
        .enumerate()
        .filter(|(i, _)| !gone.contains(i))
        .map(|(_, f)| f)
        .collect();
    Outcome {
        findings,
        set_aside,
        not_counted,
    }
}

/// What the report says of an entry that matches no finding: one of three things, because they
/// ask different things of the owner, and only the last is a sign the finding may be fixed.
fn unmatched(named: &str, entry: &FindingReview, looked: Looked) -> String {
    match looked {
        Looked::Ran => format!(
            "{named}: no finding matches it any more, and the check that reports it looked at this \
             file. The flagged line changed, or a line above it that sets a value it uses, so the \
             finding has a new fingerprint and needs looking at again; or the finding is gone and \
             the entry can be removed."
        ),
        Looked::NotThisTime(why) => format!(
            "{named}: not looked for this time ({why}), so whether the finding is still there is \
             not known. This is not a sign the finding was fixed: keep the entry, and it applies \
             again on a run that looks for it."
        ),
        Looked::Unknown => format!(
            "{named}: this version of `sv` ({}) has no rule `{}`, so nothing in it could find this. \
             The entry may come from another version of `sv`, or the rule's name may be misspelled. \
             This is not a sign the finding was fixed: the entry applies to nothing until a version \
             with that rule reads it.",
            env!("CARGO_PKG_VERSION"),
            entry.rule
        ),
    }
}

/// "3", "3 and 9", "3, 9, and 12".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Whether an entry counts, and why not when it does not.
fn judge(
    entry: &FindingReview,
    finding: &Finding,
    today: Day,
    seals: &Checker,
) -> Result<Sealed, String> {
    let secret = finding.rule_id.starts_with("secrets.")
        || finding
            .also_reported_by
            .iter()
            .any(|r| r.starts_with("secrets."));
    match entry.verdict.as_str() {
        FALSE_ALARM => {}
        ACCEPTED_RISK if secret => {
            return Err(
                "a key or password found in the code cannot be an accepted risk: a real one is \
                 replaced and taken out of the code, and one that is not real is a false alarm, \
                 with a reason that says why."
                    .to_owned(),
            );
        }
        ACCEPTED_RISK => {}
        other => {
            return Err(format!(
                "`verdict = \"{other}\"` is not one of the two: `false-alarm` or `accepted-risk`."
            ));
        }
    }
    let by = entry.by.as_deref().map(str::trim).unwrap_or("");
    if by.is_empty()
        || by.eq_ignore_ascii_case(crate::design::AI_TOOL)
        || by.eq_ignore_ascii_case("AI coding tool")
    {
        return Err(format!(
            "the AI coding tool's proposal, not a person's decision, so the finding still counts. \
             It says: \"{}\". {AGREE}",
            entry.why.trim()
        ));
    }
    let fields = crate::seal::finding_review_fields(entry);
    let sealed = seals
        .check(entry.seal.as_deref(), &crate::seal::as_strs(&fields))
        .map_err(|why| format!("{why}. It says: \"{}\". {AGREE}", entry.why.trim()))?;
    let Some(on) = entry.on.as_deref().and_then(Day::parse) else {
        return Err("it has no date in `on` (YYYY-MM-DD), so how old it is cannot be told.".into());
    };
    if on > today {
        return Err(format!(
            "it is dated {}, which has not come yet.",
            entry.on.as_deref().unwrap_or("")
        ));
    }
    let least = if secret {
        LEAST_WHY_CHARS_SECRET
    } else {
        LEAST_WHY_CHARS
    };
    if entry.why.trim().chars().count() < least {
        return Err(if secret {
            format!(
                "for a key or password, the reason has to say why it is not a real one (a test \
                 value, a published example, one already revoked), in at least {least} characters."
            )
        } else {
            format!(
                "the reason is shorter than {least} characters; say what was looked at and what it \
                 showed."
            )
        });
    }
    let watches_a_line = crate::finding::reads_code(finding);
    if (entry.verdict == ACCEPTED_RISK || !watches_a_line) && on.plus(CURRENT_FOR_DAYS) < today {
        return Err(format!(
            "it was decided on {} and has lapsed after {CURRENT_FOR_DAYS} days{}; look again and \
             date it anew if it still holds.",
            on.show(),
            if watches_a_line {
                ""
            } else {
                ", since this finding has no line of code whose change would end it"
            }
        ));
    }
    Ok(sealed)
}

/// What the owner does to make a proposal count.
pub const AGREE: &str = "If you agree after reading the code, run `sv review` in your own terminal \
    to record it as your decision.";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{Confidence, Location, Severity};

    /// A credential-shaped value built from pieces at run time, so this file holds none.
    fn aws_key(tail: &str) -> String {
        ["AKIA", tail].concat()
    }

    fn app_with_line(tag: &str, line: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-review-fp-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.py"), format!("import os\n    {line}\n")).unwrap();
        dir
    }

    /// Every fingerprint that could be computed over these lines with a credential in them as
    /// written, in either form, and that the mask changes: the ones that read a credential. None
    /// of them may be published.
    fn unmasked_fingerprints(rule: &str, file: &str, raw: &[&str]) -> Vec<String> {
        let lines: Vec<String> = raw.iter().map(|l| l.trim().to_owned()).collect();
        let safe: Vec<String> = raw.iter().map(|l| masked(l)).collect();
        (0..lines.len())
            .flat_map(|i| {
                [
                    (named(rule, file, &lines[i]), named(rule, file, &safe[i])),
                    (
                        line_fingerprint(rule, file, &lines, i),
                        line_fingerprint(rule, file, &safe, i),
                    ),
                ]
            })
            .filter(|(as_written, as_masked)| as_written != as_masked)
            .map(|(as_written, _)| as_written)
            .collect()
    }

    #[test]
    fn a_fingerprint_in_a_configuration_file_says_nothing_past_an_ampersand() {
        // Item 17 of the review of 1 to 4 October: a YAML value with `&` in it was found whole and
        // masked only up to the `&`, so the rest of the credential went into the fingerprint.
        let f = finding("secrets.credential-assignment", "config.yml", 2);
        let app = |tag: &str, tail: &str| {
            let dir =
                std::env::temp_dir().join(format!("sv-review-yml-{tag}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            let value = ["Xk7mQ92v", "&", tail].concat();
            std::fs::write(
                dir.join("config.yml"),
                format!("db:\n  password: {value}\n"),
            )
            .unwrap();
            dir
        };
        let (a, b) = (app("a", "LpR4sTz"), app("b", "ZZZZZZZ"));
        // The setup: the scan finds the value there.
        let text = std::fs::read_to_string(a.join("config.yml")).unwrap();
        let rules =
            crate::secrets::SecretRules::load(&sv_frameworks::data::file("secret-rules.json"))
                .unwrap();
        assert!(!crate::secrets::scan_text(&rules, "config.yml", &text).is_empty());
        assert_eq!(
            fingerprint(&a, &f),
            fingerprint(&b, &f),
            "the part after the `&` showed through the fingerprint"
        );
        for dir in [a, b] {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn a_fingerprint_says_nothing_about_a_credential_the_report_does_not() {
        // Two keys alike in their first four characters and their length, which is what the report
        // shows, and different everywhere else: one fingerprint, so it cannot tell them apart, and
        // guessing the rest against it finds nothing.
        let one = aws_key("Q7RZ2KV9LP4WN8HA");
        let other = aws_key("ZZZZZZZZZZZZZZZZ");
        let f = finding("secrets.aws-access-key", "config.py", 2);
        let a = app_with_line("a", &format!("KEY = \"{one}\""));
        let b = app_with_line("b", &format!("KEY = \"{other}\""));
        let (fa, fb) = (fingerprint(&a, &f), fingerprint(&b, &f));
        assert_eq!(fa, fb, "the key showed through the fingerprint");
        // No hash of the line as written is kept, in either form.
        let raw = ["import os".to_owned(), format!("KEY = \"{one}\"")];
        let raw: Vec<&str> = raw.iter().map(String::as_str).collect();
        assert!(!unmasked_fingerprints(&f.rule_id, "config.py", &raw).contains(&fa));
        // A key whose length or first four characters change still changes it, so a placeholder
        // replaced by a real key is not covered by a review of the placeholder.
        let c = app_with_line("c", "KEY = \"AKIAPLACEHOLDER\"");
        assert_ne!(fingerprint(&c, &f), fa);
        // And `sv review` shows the line masked, never the key.
        let shown = lines_with_fingerprint(&a, &f.rule_id, "config.py", &fa);
        assert_eq!(shown.len(), 1, "the line is found");
        assert_eq!(shown[0].0, 2);
        assert!(!shown[0].1.contains(&one), "the line shown holds the key");
        assert!(
            shown[0].1.contains("[redacted:"),
            "{}",
            shown[0].1.replace(&one, "<key>")
        );
        for dir in [a, b, c] {
            std::fs::remove_dir_all(dir).ok();
        }
    }

    #[test]
    fn no_fingerprint_given_for_a_finding_is_over_a_credential_as_written() {
        // A credential on the flagged line, and one on a line above that sets a name it uses:
        // neither shows through today's fingerprint or the earlier one given beside it.
        let key = aws_key("Q7RZ2KV9LP4WN8HA");
        let raw = [
            "import os".to_owned(),
            format!("password = \"{key}\""),
            "login(user, password)".to_owned(),
        ];
        let dir = std::env::temp_dir().join(format!("sv-review-fp-given-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("app.py"), raw.join("\n")).unwrap();
        let mut found = vec![
            finding("secrets.credential-assignment", "app.py", 2),
            finding("ast.login", "app.py", 3),
        ];
        fill_fingerprints(&dir, &mut found);
        std::fs::remove_dir_all(&dir).ok();
        let raw: Vec<&str> = raw.iter().map(String::as_str).collect();
        for f in &found {
            let unsafe_ones = unmasked_fingerprints(&f.rule_id, "app.py", &raw);
            // The setup: the line above really holds a credential the mask changes, and the
            // finding really has an earlier name given beside today's.
            assert_ne!(masked(raw[1]), raw[1]);
            assert_eq!(f.earlier_fingerprints.len(), 1, "{}", f.rule_id);
            assert!(
                !unsafe_ones.is_empty(),
                "{}: nothing reads the key",
                f.rule_id
            );
            let given: Vec<&String> = std::iter::once(&f.fingerprint)
                .chain(f.earlier_fingerprints.iter())
                .collect();
            for g in given {
                assert!(
                    !unsafe_ones.contains(g),
                    "{}: {g} is over the key",
                    f.rule_id
                );
            }
            let json = serde_json::to_string(f).unwrap();
            assert!(
                !unsafe_ones.iter().any(|u| json.contains(u.as_str())) && !json.contains(&key),
                "{}",
                f.rule_id
            );
        }
        // The control: had the line been hashed as written, the check above finds it.
        let planted = named("secrets.credential-assignment", "app.py", raw[1]);
        assert!(
            unmasked_fingerprints("secrets.credential-assignment", "app.py", &raw)
                .contains(&planted)
        );
    }

    #[test]
    fn a_review_recorded_before_masking_is_said_to_be_one() {
        // A false alarm recorded by an older `sv` names a credential's line as written. It no
        // longer matches, as it should not, and it is said why, rather than that the line changed.
        let key = aws_key("Q7RZ2KV9LP4WN8HA");
        let line = format!("KEY = \"{key}\"");
        let dir = app_with_line("older", &line);
        let mut f = finding("secrets.aws-access-key", "config.py", 2);
        f.fingerprint = fingerprint(&dir, &f);
        let mut older = entry(
            "secrets.aws-access-key",
            FALSE_ALARM,
            Some("owner"),
            "2026-09-27",
            SECRET_WHY,
        );
        older.file = "config.py".into();
        older.fingerprint = named("secrets.aws-access-key", "config.py", &line);
        let out = apply_in(&dir, &[older.clone()], vec![f.clone()], today());
        // The controls: the same entry, named as `sv review` named it after R4, and as it names
        // it now, counts.
        older.fingerprint = named("secrets.aws-access-key", "config.py", &masked(&line));
        let masked_form = apply_in(&dir, &[older.clone()], vec![f.clone()], today());
        older.fingerprint = f.fingerprint.clone();
        let now = apply_in(&dir, &[older], vec![f], today());
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.not_counted.len(), 1);
        assert!(
            out.not_counted[0].contains("recorded by an older `sv`"),
            "{}",
            out.not_counted[0].replace(&key, "<key>")
        );
        assert!(
            !out.not_counted[0].contains(&key),
            "the reason holds the key"
        );
        assert!(
            !out.not_counted[0].contains(&named("secrets.aws-access-key", "config.py", &line)),
            "the reason repeats the unmasked fingerprint"
        );
        assert!(
            masked_form.findings.is_empty(),
            "{:?}",
            masked_form.not_counted
        );
        assert!(now.findings.is_empty(), "{:?}", now.not_counted);

        // And a review of a line with no credential, whose finding has gone, is told the usual
        // reason: only a credential's line was ever named in a way that could give it back.
        let dir = app_with_line("older-plain", "x = 1");
        let mut plain = entry(
            "ast.open-redirect",
            FALSE_ALARM,
            Some("owner"),
            "2026-09-27",
            SECRET_WHY,
        );
        plain.file = "config.py".into();
        plain.fingerprint = named("ast.open-redirect", "config.py", "x = 1");
        let out = apply_in(&dir, &[plain], Vec::new(), today());
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            out.not_counted[0].contains("no finding matches it any more"),
            "{:?}",
            out.not_counted
        );
    }

    #[test]
    fn a_line_with_no_credential_is_named_as_it_reads() {
        // Masking changes nothing on a line with no credential in it, so its earlier fingerprint,
        // and every review already written with it, is the hash of the line as written.
        let line = "return redirect(request.args.get('next'))";
        let dir = app_with_line("plain", line);
        let mut found = vec![finding("ast.open-redirect", "config.py", 2)];
        fill_fingerprints(&dir, &mut found);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            found[0].earlier_fingerprints,
            vec![named("ast.open-redirect", "config.py", line)]
        );
        let raw = vec!["import os".to_owned(), line.to_owned()];
        assert_eq!(
            found[0].fingerprint,
            line_fingerprint("ast.open-redirect", "config.py", &raw, 1)
        );
    }

    fn finding(rule: &str, file: &str, line: usize) -> Finding {
        Finding {
            rule_id: rule.into(),
            title: format!("found by {rule}"),
            severity: Severity::High,
            confidence: Confidence::Medium,
            location: Location {
                file: file.into(),
                line,
            },
            secret: None,
            requirement_ids: Vec::new(),
            cwe: Vec::new(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
            also_reported_by: Vec::new(),
            fingerprint: format!("fp-{rule}"),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
        }
    }

    const WHY: &str = "The next= value is checked against our own paths on the line above.";
    const SECRET_WHY: &str =
        "This is the AWS documentation's published example key, used only by the test suite here.";

    fn entry(rule: &str, verdict: &str, by: Option<&str>, on: &str, why: &str) -> FindingReview {
        FindingReview {
            rule: rule.into(),
            file: "app.py".into(),
            fingerprint: format!("fp-{rule}"),
            verdict: verdict.into(),
            why: why.into(),
            by: by.map(str::to_owned),
            on: Some(on.into()),
            seal: Some(RESEAL.into()),
        }
    }

    /// Stands for the seal `sv review` would write over the entry as it is when applied, so a test
    /// can change a field after making the entry.
    const RESEAL: &str = "reseal";

    /// This computer's key in these tests, from the system's randomness.
    /// This computer's key in the test, sealing for the app the test reads.
    fn key() -> crate::seal::AppKey {
        computer_key().for_app(&crate::seal::App::named_for_tests("app"))
    }

    fn computer_key() -> crate::seal::Key {
        static KEY: std::sync::OnceLock<crate::seal::Key> = std::sync::OnceLock::new();
        KEY.get_or_init(|| crate::seal::Key::random().unwrap())
            .clone()
    }

    /// `apply` as on the computer whose key sealed the entries.
    fn apply(entries: &[FindingReview], findings: Vec<Finding>, today: Day) -> Outcome {
        apply_in(Path::new("/no/app/folder"), entries, findings, today)
    }

    /// `apply`, with the app's lines read from `app_dir`.
    fn apply_in(
        app_dir: &Path,
        entries: &[FindingReview],
        findings: Vec<Finding>,
        today: Day,
    ) -> Outcome {
        let sealed: Vec<FindingReview> = entries
            .iter()
            .map(|e| {
                let mut e = e.clone();
                if e.seal.as_deref() == Some(RESEAL) {
                    let fields = crate::seal::finding_review_fields(&e);
                    e.seal = Some(key().seal(&crate::seal::as_strs(&fields)));
                }
                e
            })
            .collect();
        super::apply(
            app_dir,
            &sealed,
            findings,
            today,
            &Checker::key(key()),
            &|_, _| Looked::Ran,
        )
    }

    fn today() -> Day {
        Day::parse("2026-09-27").unwrap()
    }

    #[test]
    fn a_false_alarm_leaves_the_list_and_an_accepted_risk_stays_on_it() {
        let out = apply(
            &[
                entry("ast.a", FALSE_ALARM, Some("owner"), "2026-09-27", WHY),
                entry("ast.b", ACCEPTED_RISK, Some("Sam Lee"), "2026-09-20", WHY),
            ],
            vec![finding("ast.a", "app.py", 5), finding("ast.b", "app.py", 9)],
            today(),
        );
        assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
        let still: Vec<&str> = out.findings.iter().map(|f| f.rule_id.as_str()).collect();
        assert_eq!(still, vec!["ast.b"]);
        assert_eq!(out.set_aside.len(), 2);
        assert_eq!(out.set_aside[1].by, "Sam Lee");
    }

    #[test]
    fn one_entry_answers_for_one_finding_and_a_pair_that_disagree_leaves_it_standing() {
        // R11 of the deep review: duplicate and conflicting entries were each applied.
        let a = || finding("ast.a", "app.py", 5);
        let fa = |by: &str| entry("ast.a", FALSE_ALARM, Some(by), "2026-09-27", WHY);
        let ar = |by: &str| entry("ast.a", ACCEPTED_RISK, Some(by), "2026-09-27", WHY);

        // The same answer twice: the first counts, the second adds nothing and says so.
        let out = apply(&[ar("owner"), ar("Sam Lee")], vec![a()], today());
        assert_eq!(out.set_aside.len(), 1, "{:?}", out.set_aside);
        assert_eq!(out.set_aside[0].by, "owner");
        assert_eq!(out.findings.len(), 1, "an accepted risk stays on the list");
        assert!(
            out.not_counted[0].contains("adds nothing"),
            "{:?}",
            out.not_counted
        );

        // Opposite answers: neither counts, and the finding stands, in either order.
        for pair in [[fa("owner"), ar("owner")], [ar("owner"), fa("owner")]] {
            let out = apply(&pair, vec![a()], today());
            assert!(out.set_aside.is_empty(), "{:?}", out.set_aside);
            assert_eq!(out.findings.len(), 1, "the finding stands");
            assert!(
                out.not_counted.iter().any(|n| n.contains("neither")),
                "{:?}",
                out.not_counted
            );
        }

        // Two identical lines, an entry for each: both are answered, as before.
        let out = apply(
            &[fa("owner"), fa("owner")],
            vec![a(), finding("ast.a", "app.py", 9)],
            today(),
        );
        assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
        assert_eq!(out.set_aside.len(), 2);
        assert!(out.findings.is_empty());

        // An entry that does not count takes nothing: the one after it still answers.
        let mut unsealed = fa("owner");
        unsealed.seal = None;
        let out = apply(&[unsealed, fa("owner")], vec![a()], today());
        assert_eq!(out.set_aside.len(), 1, "{:?}", out.not_counted);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn a_false_alarm_on_one_problem_never_sets_aside_another_on_its_line() {
        // The line is gathered after the reviews (ADR-023, Later, 6 October 2026), so a verdict
        // on one rule leaves the other problem on the same line standing, and still counted.
        let sql = finding("ast.sql", "app.py", 5);
        let eval = finding("ast.eval", "app.py", 5);
        let out = apply(
            &[entry(
                "ast.eval",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                WHY,
            )],
            vec![sql, eval],
            today(),
        );
        assert_eq!(out.set_aside.len(), 1, "{:?}", out.not_counted);
        let line = crate::finding::one_per_line(out.findings);
        assert_eq!(line.len(), 1);
        assert_eq!(line[0].rule_id, "ast.sql");
        assert!(line[0].also_on_this_line.is_empty());
        // The control: with no verdict, both are on the line.
        let both = apply(
            &[],
            vec![
                finding("ast.sql", "app.py", 5),
                finding("ast.eval", "app.py", 5),
            ],
            today(),
        );
        let line = crate::finding::one_per_line(both.findings);
        assert_eq!(line.len(), 1);
        assert_eq!(line[0].also_on_this_line.len(), 1);
    }

    #[test]
    fn a_rule_merged_into_another_finding_can_still_be_named() {
        let mut f = finding("semgrep.sqli", "app.py", 5);
        f.also_reported_by = vec!["ast.sql".into()];
        f.fingerprint = "fp-ast.sql".into();
        let out = apply(
            &[entry(
                "ast.sql",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                WHY,
            )],
            vec![f],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
    }

    #[test]
    fn a_review_of_the_rule_that_used_to_be_kept_still_counts_when_another_is_kept() {
        // Bandit's B105 was kept on the family-hub line until 4 October 2026, and `sv`'s own rule
        // is now; a review written against Bandit's fingerprint must still find its line.
        let dir = std::env::temp_dir().join(format!("sv-review-merged-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("app.py"),
            "WRONG_PASSWORD = \"Your current password isn't right.\"\nOTHER = 1\n",
        )
        .unwrap();
        let kept = || {
            let mut f = finding("secrets.credential-assignment", "app.py", 1);
            f.also_reported_by = vec!["bandit.B105".into()];
            f.fingerprint = fingerprint(&dir, &f);
            f
        };
        let reviewed = |rule: &str, line: &str| {
            let mut e = entry(rule, FALSE_ALARM, Some("owner"), "2026-09-27", SECRET_WHY);
            // As `sv review` wrote it after R4 and before today's form: the line masked.
            e.fingerprint = named(rule, "app.py", &masked(line));
            e
        };
        let line = "WRONG_PASSWORD = \"Your current password isn't right.\"";
        // The setup: the kept finding's own fingerprint is not the one the entry holds.
        assert_ne!(kept().fingerprint, named("bandit.B105", "app.py", line));
        let out = apply_in(
            &dir,
            &[reviewed("bandit.B105", line)],
            vec![kept()],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        // The controls: another line under the same rule, and a rule not merged into this finding.
        for e in [
            reviewed("bandit.B105", "OTHER = 1"),
            reviewed("semgrep.hardcoded-password", line),
        ] {
            let out = apply_in(&dir, &[e], vec![kept()], today());
            assert_eq!(
                out.findings.len(),
                1,
                "an entry for another finding counted"
            );
            assert_eq!(out.not_counted.len(), 1);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_entry_counts_only_as_sv_review_sealed_it() {
        let finding = || vec![finding("ast.a", "app.py", 5)];
        let sealed =
            |e: &FindingReview| {
                let mut e = e.clone();
                e.seal = Some(key().seal(&crate::seal::as_strs(
                    &crate::seal::finding_review_fields(&e),
                )));
                e
            };
        let good = sealed(&entry(
            "ast.a",
            FALSE_ALARM,
            Some("owner"),
            "2026-09-27",
            WHY,
        ));
        let here = super::apply(
            Path::new("/no/app/folder"),
            std::slice::from_ref(&good),
            finding(),
            today(),
            &Checker::key(key()),
            &|_, _| Looked::Ran,
        );
        assert!(here.findings.is_empty(), "{:?}", here.not_counted);
        assert_eq!(here.set_aside[0].sealed, Sealed::Here);

        // `by = "owner"` with no seal, as the AI coding tool would write it: a proposal.
        let unsealed = FindingReview {
            seal: None,
            ..good.clone()
        };
        // The reason changed after it was sealed.
        let changed = FindingReview {
            why: format!("{WHY} Also fine."),
            ..good.clone()
        };
        // Sealed with another computer's key.
        let other = crate::seal::Key::random()
            .unwrap()
            .for_app(&crate::seal::App::named_for_tests("app"));
        let elsewhere = sealed(&FindingReview {
            seal: None,
            ..good.clone()
        });
        let elsewhere = FindingReview {
            seal: Some(
                other.seal(&crate::seal::as_strs(&crate::seal::finding_review_fields(
                    &elsewhere,
                ))),
            ),
            ..elsewhere
        };
        for (e, says) in [
            (&unsealed, "not recorded through `sv review`"),
            (&changed, "does not match"),
            (&elsewhere, "not this computer's"),
        ] {
            let out = super::apply(
                Path::new("/no/app/folder"),
                std::slice::from_ref(e),
                finding(),
                today(),
                &Checker::key(key()),
                &|_, _| Looked::Ran,
            );
            assert_eq!(out.findings.len(), 1, "{says}");
            assert!(out.set_aside.is_empty(), "{says}");
            assert!(
                out.not_counted[0].contains(says)
                    && out.not_counted[0].contains("sv review")
                    && out.not_counted[0].contains(WHY),
                "{says}: {:?}",
                out.not_counted
            );
        }

        // Where there is no key to check with, a sealed entry does not count either, and says
        // what to do (item 8 of the review of 1 to 4 October); nor does one sealed for another
        // app on this computer (item 11).
        let shop = Checker::key(computer_key().for_app(&crate::seal::App::named_for_tests("shop")));
        for (checker, says) in [
            (&Checker::no_key(), "run `sv review` once on this computer"),
            (&shop, "another folder"),
        ] {
            let out = super::apply(
                Path::new("/no/app/folder"),
                std::slice::from_ref(&good),
                finding(),
                today(),
                checker,
                &|_, _| Looked::Ran,
            );
            assert_eq!(out.findings.len(), 1, "{says}");
            assert!(out.set_aside.is_empty(), "{says}");
            assert!(out.not_counted[0].contains(says), "{:?}", out.not_counted);
        }
        let no_key = super::apply(
            Path::new("/no/app/folder"),
            &[unsealed],
            finding(),
            today(),
            &Checker::no_key(),
            &|_, _| Looked::Ran,
        );
        assert_eq!(no_key.findings.len(), 1);
    }

    #[test]
    fn only_a_persons_word_counts() {
        for by in [None, Some("ai-tool"), Some("AI coding tool"), Some("  ")] {
            let out = apply(
                &[entry("ast.a", FALSE_ALARM, by, "2026-09-27", WHY)],
                vec![finding("ast.a", "app.py", 5)],
                today(),
            );
            assert_eq!(out.findings.len(), 1, "{by:?} set a finding aside");
            assert!(out.set_aside.is_empty());
            assert!(
                out.not_counted[0].contains("proposal") && out.not_counted[0].contains(WHY),
                "the proposal is shown, with what the tool said: {:?}",
                out.not_counted
            );
        }
    }

    #[test]
    fn an_entry_that_does_not_count_says_why_and_the_finding_stays() {
        for (e, reason) in [
            (
                entry("ast.a", "wontfix", Some("owner"), "2026-09-27", WHY),
                "not one of the two",
            ),
            (
                entry("ast.a", FALSE_ALARM, Some("owner"), "2026-09-27", "fine"),
                "shorter than 40",
            ),
            (
                entry("ast.a", FALSE_ALARM, Some("owner"), "2026-10-02", WHY),
                "has not come yet",
            ),
            (
                entry("ast.a", FALSE_ALARM, Some("owner"), "someday", WHY),
                "no date",
            ),
            (
                entry("ast.a", ACCEPTED_RISK, Some("owner"), "2026-06-28", WHY),
                "lapsed after 90 days",
            ),
            (
                FindingReview {
                    fingerprint: "fp-changed".into(),
                    ..entry("ast.a", FALSE_ALARM, Some("owner"), "2026-09-27", WHY)
                },
                "no finding matches it any more",
            ),
        ] {
            let out = apply(&[e], vec![finding("ast.a", "app.py", 5)], today());
            assert_eq!(out.findings.len(), 1, "{reason}");
            assert!(out.set_aside.is_empty(), "{reason}");
            assert!(
                out.not_counted.len() == 1 && out.not_counted[0].contains(reason),
                "{reason}: {:?}",
                out.not_counted
            );
        }
    }

    #[test]
    fn a_false_alarm_on_a_line_of_code_holds_until_the_line_changes_but_one_without_a_line_lapses()
    {
        // Old, and still matching: the line has not changed, so it holds.
        let out = apply(
            &[entry(
                "ast.a",
                FALSE_ALARM,
                Some("owner"),
                "2025-01-01",
                WHY,
            )],
            vec![finding("ast.a", "app.py", 5)],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        // A probe of the running app has no line to watch.
        let mut probe = finding("probe.a", "the running app", 1);
        probe.fingerprint = "fp-probe.a".into();
        let mut e = entry("probe.a", FALSE_ALARM, Some("owner"), "2025-01-01", WHY);
        e.file = "the running app".into();
        let out = apply(&[e.clone()], vec![probe.clone()], today());
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.not_counted[0].contains("no line of code"),
            "{:?}",
            out.not_counted
        );
        e.on = Some("2026-09-01".into());
        assert!(apply(&[e], vec![probe], today()).findings.is_empty());
    }

    #[test]
    fn a_key_or_password_needs_a_longer_reason_and_cannot_be_an_accepted_risk() {
        let key = || finding("secrets.aws-access-key", "app.py", 3);
        let out = apply(
            &[entry(
                "secrets.aws-access-key",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                WHY,
            )],
            vec![key()],
            today(),
        );
        assert_eq!(out.findings.len(), 1, "a 40-character reason is not enough");
        assert!(out.not_counted[0].contains("not a real one"));
        let out = apply(
            &[entry(
                "secrets.aws-access-key",
                FALSE_ALARM,
                Some("owner"),
                "2026-09-27",
                SECRET_WHY,
            )],
            vec![key()],
            today(),
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        let out = apply(
            &[entry(
                "secrets.aws-access-key",
                ACCEPTED_RISK,
                Some("owner"),
                "2026-09-27",
                SECRET_WHY,
            )],
            vec![key()],
            today(),
        );
        assert_eq!(out.findings.len(), 1);
        assert!(out.not_counted[0].contains("cannot be an accepted risk"));
    }

    #[test]
    fn a_finding_says_what_it_was_called_before_its_fingerprint_changed_form() {
        // For a tracker that keys findings by fingerprint across runs (cato-pipeline's POA&M):
        // the earlier name is given when it differs, and only then.
        let dir = std::env::temp_dir().join(format!("sv-review-earlier-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let line = "    cur.execute(\"SELECT * FROM t WHERE id = \" + user_id)";
        std::fs::write(dir.join("app.py"), format!("import x\n{line}\n")).unwrap();
        let mut findings = vec![finding("ast.sql", "app.py", 2)];
        fill_fingerprints(&dir, &mut findings);
        let f = &findings[0];
        assert!(
            f.fingerprint.starts_with(FINGERPRINT_V2),
            "the setup: today's form"
        );
        assert_eq!(
            f.earlier_fingerprints,
            vec![named("ast.sql", "app.py", line.trim())],
            "the earlier form, by the line's text"
        );
        let json = serde_json::to_value(f).unwrap();
        assert_eq!(
            json["earlier_fingerprints"][0],
            f.earlier_fingerprints[0].as_str()
        );
        // A finding about no line of code is named as before, so nothing earlier is given.
        let mut about_the_app = finding("config.security-contact", "", 0);
        about_the_app.location.file = String::new();
        let mut findings = vec![about_the_app];
        fill_fingerprints(&dir, &mut findings);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            findings[0].earlier_fingerprints.is_empty(),
            "{:?}",
            findings[0].fingerprint
        );
        assert!(
            serde_json::to_value(&findings[0])
                .unwrap()
                .get("earlier_fingerprints")
                .is_none()
        );
    }

    #[test]
    fn the_fingerprint_follows_the_lines_text_not_its_number_and_never_holds_it() {
        let dir = std::env::temp_dir().join(format!("sv-review-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let line = "    cur.execute(\"SELECT * FROM t WHERE id = \" + user_id)";
        std::fs::write(dir.join("app.py"), format!("import x\n{line}\n")).unwrap();
        let mut f = finding("ast.sql", "app.py", 2);
        let first = fingerprint(&dir, &f);
        // Two lines added above: the finding moves, and keeps its name.
        std::fs::write(dir.join("app.py"), format!("import x\n\n\n{line}\n")).unwrap();
        f.location.line = 4;
        assert_eq!(fingerprint(&dir, &f), first);
        // The line itself changes: a new name, so a false alarm about the old line lapses.
        std::fs::write(dir.join("app.py"), format!("import x\n{line} # changed\n")).unwrap();
        f.location.line = 2;
        assert_ne!(fingerprint(&dir, &f), first);
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(first.len(), 19);
        assert!(first.starts_with(FINGERPRINT_V2));
        assert!(first[3..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(!first.contains("SELECT"));
    }

    /// A scratch app folder holding `app.py`, removed when dropped.
    struct App(std::path::PathBuf);

    impl App {
        fn new(name: &str, text: &str) -> App {
            let dir =
                std::env::temp_dir().join(format!("sv-review-app-{name}-{}", std::process::id()));
            std::fs::remove_dir_all(&dir).ok();
            std::fs::create_dir_all(&dir).unwrap();
            let app = App(dir);
            app.write(text);
            app
        }

        fn write(&self, text: &str) {
            std::fs::write(self.0.join("app.py"), text).unwrap();
        }

        /// The findings of `rule` on these lines, with the fingerprints the report gives them.
        fn findings(&self, rule: &str, lines: &[usize]) -> Vec<Finding> {
            let mut found: Vec<Finding> =
                lines.iter().map(|&n| finding(rule, "app.py", n)).collect();
            fill_fingerprints(&self.0, &mut found);
            found
        }
    }

    impl Drop for App {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn reviewed(rule: &str, fingerprint: &str) -> FindingReview {
        FindingReview {
            fingerprint: fingerprint.to_owned(),
            ..entry(rule, FALSE_ALARM, Some("owner"), "2026-09-27", WHY)
        }
    }

    /// `apply` with what `looked` says of an entry that matches nothing.
    fn apply_looked(
        app: &App,
        entries: &[FindingReview],
        findings: Vec<Finding>,
        looked: Looked,
    ) -> Outcome {
        let sealed: Vec<FindingReview> = entries
            .iter()
            .map(|e| {
                let mut e = e.clone();
                let fields = crate::seal::finding_review_fields(&e);
                e.seal = Some(key().seal(&crate::seal::as_strs(&fields)));
                e
            })
            .collect();
        super::apply(
            &app.0,
            &sealed,
            findings,
            today(),
            &Checker::key(key()),
            &move |_, _| looked.clone(),
        )
    }

    const TWO_QUERIES: &str = "def mine(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    cur.execute(sql, (uid,))\n\ndef theirs(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    cur.execute(sql, (uid,))\n";

    #[test]
    fn identical_lines_each_need_their_own_review() {
        let app = App::new("identical", TWO_QUERIES);
        let found = app.findings("ast.sql", &[3, 7]);
        // The setup: the two lines read the same, and the earlier fingerprint could not tell them
        // apart.
        assert_eq!(
            Texts::new(&app.0).earlier_fingerprint(&found[0], "ast.sql"),
            Texts::new(&app.0).earlier_fingerprint(&found[1], "ast.sql")
        );
        assert_ne!(found[0].fingerprint, found[1].fingerprint);
        // A review of the second sets aside the second and nothing else, and the other way round.
        for (reviewed_one, still) in [(1, 3), (0, 7)] {
            let out = apply_looked(
                &app,
                &[reviewed("ast.sql", &found[reviewed_one].fingerprint)],
                found.clone(),
                Looked::Ran,
            );
            assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
            assert_eq!(out.set_aside.len(), 1);
            let lines: Vec<usize> = out.findings.iter().map(|f| f.location.line).collect();
            assert_eq!(lines, vec![still]);
        }
        // Each needs its own: both reviewed, both set aside.
        let out = apply_looked(
            &app,
            &[
                reviewed("ast.sql", &found[0].fingerprint),
                reviewed("ast.sql", &found[1].fingerprint),
            ],
            found.clone(),
            Looked::Ran,
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);
        // `sv review` shows the one line each names.
        for f in &found {
            let lines = lines_with_fingerprint(&app.0, "ast.sql", "app.py", &f.fingerprint);
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0].0, f.location.line);
        }
    }

    #[test]
    fn a_change_to_the_line_that_sets_its_value_ends_the_review_and_others_do_not() {
        let safe = "def find(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    cur.execute(sql, (uid,))\n";
        let app = App::new("reaching", safe);
        let before = app.findings("ast.sql", &[3])[0].fingerprint.clone();
        let entry = reviewed("ast.sql", &before);
        // The setup: it counts while nothing has changed.
        let out = apply_looked(
            &app,
            std::slice::from_ref(&entry),
            app.findings("ast.sql", &[3]),
            Looked::Ran,
        );
        assert!(out.findings.is_empty(), "{:?}", out.not_counted);

        // Changes that leave what reaches the line alone keep its name: a line added above, a
        // comment, another function.
        for (text, line) in [
            (format!("import os\n\n{safe}"), 5),
            (format!("{safe}\ndef other():\n    return 1\n"), 3),
            (
                safe.replace(
                    "def find(cur, uid):\n",
                    "def find(cur, uid):\n    # the owner's notes\n",
                ),
                4,
            ),
        ] {
            app.write(&text);
            assert_eq!(
                app.findings("ast.sql", &[line])[0].fingerprint,
                before,
                "{text}"
            );
        }

        // Changes to what the flagged line uses: the value built from input, or added to after.
        for (text, line) in [
            (safe.replace("= ?\"", "= \" + uid"), 3),
            (
                safe.replace("    cur.execute", "    sql += \" OR 1=1\"\n    cur.execute"),
                4,
            ),
            (
                safe.replace(
                    "    cur.execute",
                    "    cur = other_db.cursor()\n    cur.execute",
                ),
                4,
            ),
        ] {
            app.write(&text);
            let now = app.findings("ast.sql", &[line]);
            assert_ne!(now[0].fingerprint, before, "{text}");
            let out = apply_looked(&app, std::slice::from_ref(&entry), now, Looked::Ran);
            assert_eq!(out.findings.len(), 1, "{text}");
            assert!(
                out.not_counted[0].contains("no finding matches it any more")
                    && out.not_counted[0].contains("a line above it that sets a value it uses"),
                "{:?}",
                out.not_counted
            );
        }
    }

    #[test]
    fn a_value_built_over_several_lines_is_watched_back_to_where_it_is_set() {
        // `sql +=` adds to what `sql =` set, so the line that sets it is watched too, not only the
        // nearest.
        let safe = "def find(cur, uid):\n    sql = \"SELECT * FROM notes WHERE owner = ?\"\n    sql += \" ORDER BY id\"\n    cur.execute(sql, (uid,))\n";
        let app = App::new("chain", safe);
        let before = app.findings("ast.sql", &[4])[0].fingerprint.clone();
        app.write(&safe.replace("= ?\"", "= \" + uid"));
        assert_ne!(app.findings("ast.sql", &[4])[0].fingerprint, before);
        // The setup: with the first line as it was, the fingerprint is as it was.
        app.write(safe);
        assert_eq!(app.findings("ast.sql", &[4])[0].fingerprint, before);
    }

    #[test]
    fn an_entry_with_the_earlier_fingerprint_matches_its_one_finding_and_says_when_it_cannot_tell()
    {
        // As family-hub's 25 entries were written: sixteen hex characters over the rule, the file,
        // and the trimmed line.
        let app = App::new(
            "earlier",
            &format!(
                "{TWO_QUERIES}\ndef one(cur, name):\n    cur.execute(\"SELECT 1 WHERE a = \" + name)\n"
            ),
        );
        let found = app.findings("ast.sql", &[3, 7, 10]);
        let unique = named(
            "ast.sql",
            "app.py",
            "cur.execute(\"SELECT 1 WHERE a = \" + name)",
        );
        let twice = named("ast.sql", "app.py", "cur.execute(sql, (uid,))");
        assert!(is_earlier_form(&unique) && is_earlier_form(&twice));
        assert!(
            found
                .iter()
                .all(|f| f.fingerprint.starts_with(FINGERPRINT_V2))
        );

        // Where one finding is on a line with that text: it matches that finding, as it did, and
        // the seal `sv review` made over it still holds.
        let out = apply_looked(
            &app,
            &[reviewed("ast.sql", &unique)],
            found.clone(),
            Looked::Ran,
        );
        assert!(out.not_counted.is_empty(), "{:?}", out.not_counted);
        assert_eq!(out.set_aside[0].finding.location.line, 10);
        assert_eq!(out.set_aside[0].sealed, Sealed::Here);
        assert_eq!(out.findings.len(), 2);

        // Where two are on lines that read the same: neither, and it says why and what to do.
        let out = apply_looked(
            &app,
            &[reviewed("ast.sql", &twice)],
            found.clone(),
            Looked::Ran,
        );
        assert_eq!(out.findings.len(), 3);
        assert!(out.set_aside.is_empty());
        assert!(
            out.not_counted[0].contains("before 5 October 2026")
                && out.not_counted[0].contains("lines 3 and 7")
                && out.not_counted[0].contains("applies to none of them")
                && out.not_counted[0].contains("record it through `sv review`"),
            "{:?}",
            out.not_counted
        );
        // `sv review` sees both lines, and has no one line to write today's fingerprint for.
        assert_eq!(
            lines_with_fingerprint(&app.0, "ast.sql", "app.py", &twice).len(),
            2
        );
        assert_eq!(todays_form(&app.0, "ast.sql", "app.py", &twice), None);
        // For the one line, today's fingerprint is the one the report gives its finding.
        assert_eq!(
            todays_form(&app.0, "ast.sql", "app.py", &unique).as_deref(),
            Some(found[2].fingerprint.as_str())
        );
    }

    #[test]
    fn an_entry_that_matches_nothing_says_whether_it_was_looked_for() {
        let app = App::new("looked", "x = 1\n");
        let entry = reviewed(
            "tests.name-does-not-match-requirement",
            "v2-0123456789abcdef",
        );
        let said = |looked: Looked| {
            let out = apply_looked(&app, std::slice::from_ref(&entry), Vec::new(), looked);
            assert!(out.set_aside.is_empty());
            assert_eq!(out.not_counted.len(), 1);
            out.not_counted[0].clone()
        };
        let gone = said(Looked::Ran);
        let not_looked = said(Looked::NotThisTime(
            "the app's own tests run only with --run".to_owned(),
        ));
        let unknown = said(Looked::Unknown);
        assert!(gone.contains("no finding matches it any more") && gone.contains("can be removed"));
        for not_gone in [&not_looked, &unknown] {
            assert!(
                !not_gone.contains("no finding matches it any more")
                    && !not_gone.contains("can be removed")
                    && not_gone.contains("not a sign the finding was fixed"),
                "{not_gone}"
            );
        }
        assert!(
            not_looked
                .contains("not looked for this time (the app's own tests run only with --run)")
                && not_looked.contains("keep the entry"),
            "{not_looked}"
        );
        assert!(
            unknown.contains("has no rule `tests.name-does-not-match-requirement`"),
            "{unknown}"
        );
    }

    #[test]
    fn a_second_entry_for_a_finding_already_set_aside_is_not_called_gone() {
        // Two entries for one finding: R11's rule decides (the second adds nothing), and with R3 the
        // second is never told its finding is gone.
        let app = App::new("twice", TWO_QUERIES);
        let found = app.findings("ast.sql", &[3, 7]);
        let e = reviewed("ast.sql", &found[0].fingerprint);
        let out = apply_looked(&app, &[e.clone(), e], found, Looked::Ran);
        assert_eq!(out.set_aside.len(), 1);
        assert_eq!(out.findings.len(), 1);
        assert!(
            out.not_counted[0].contains("an earlier entry already answers for this finding")
                && !out.not_counted[0].contains("no finding matches"),
            "{:?}",
            out.not_counted
        );
    }
}
