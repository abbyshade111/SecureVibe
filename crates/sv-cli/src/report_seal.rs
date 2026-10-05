//! The proof that a report folder is one `sv` wrote (deep review R9, ADR-032).
//!
//! The MCP server offers the reports below its root as resources, "a report sv wrote". It took any
//! folder holding the marker, `.securevibe-report`, as one, and anything can write that marker: the
//! review offered the AI coding tool a forged report that way. H6 of the same review made the walk of
//! the app believe the marker only in a folder holding nothing but the files `sv` writes, which keeps a
//! marker from hiding code, but a forged report is exactly such a folder.
//!
//! So `sv report` and `securevibe_write_report` seal what they wrote: the marker gains a line
//! `seal: v1:<key id>:<mac>`, an HMAC-SHA-256 of each report file's name and SHA-256, under a key of this
//! computer's kept beside the review key (`sv_check::seal::REPORT_KEY_FILE`), outside every app, made
//! the first time a report is written. A folder is offered as `sv`'s only when it holds nothing but
//! `sv`'s files (H6) and its seal holds for the files as they are now, and a file is handed over only
//! when what was read is what was sealed.
//!
//! What it shows and what it cannot, as for the review seal (ADR-026): that `sv` on this computer
//! wrote these files and nothing has changed them since. A report written on another computer, or in
//! a container since gone, cannot be checked here, and is not offered: a made-up seal would look the
//! same. Something running as the person could read the key and forge a seal; what the seal stops is
//! a report shipped in the app's own files, or written by anything that only writes into the app.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use sv_check::seal::{Key, REPORT_KEY_FILE};

/// The files a seal covers, in the order they are sealed: every report file `sv` writes.
pub const SEALED: [&str; 5] = [
    "report.html",
    "compliance.md",
    "security.md",
    "findings.sarif",
    "report.json",
];

/// How the seal's line in the marker starts.
const SEAL_LINE: &str = "seal: ";

/// The largest file sealed or checked. A report of a very large app is a few megabytes.
const MAX_BYTES: u64 = 16 * 1024 * 1024;

/// The largest marker read: a sentence and a seal.
const MAX_MARKER_BYTES: u64 = 4096;

/// What the marker says once the folder is sealed: the sentence it always said, then the seal.
pub fn marker_text(sentence: &str, seal: &str) -> String {
    format!("{sentence}{SEAL_LINE}{seal}\n")
}

fn fields(digests: &BTreeMap<&'static str, String>) -> Vec<String> {
    let mut fields = vec!["report-folder".to_owned()];
    for name in SEALED {
        fields.push(name.to_owned());
        fields.push(digests.get(name).cloned().unwrap_or_default());
    }
    fields
}

/// The SHA-256 of every sealed file in `dir`, each a plain file no larger than any report.
fn digests(dir: &Path) -> Result<BTreeMap<&'static str, String>, String> {
    let mut found = BTreeMap::new();
    for name in SEALED {
        let path = dir.join(name);
        let meta = std::fs::symlink_metadata(&path).map_err(|_| format!("{name} is missing"))?;
        if !meta.is_file() {
            return Err(format!("{name} is a link or a folder, not a report file"));
        }
        if meta.len() > MAX_BYTES {
            return Err(format!("{name} is larger than any report sv writes"));
        }
        let bytes = std::fs::read(&path).map_err(|_| format!("{name} cannot be read"))?;
        found.insert(name, crate::bundle::sha256(&bytes));
    }
    Ok(found)
}

/// Where this computer's report key is, or why there is nowhere for it.
fn key_folder() -> Result<PathBuf, String> {
    Key::folder().ok_or_else(|| {
        "this computer has no folder for sv's keys (neither HOME nor XDG_CONFIG_HOME is set)"
            .to_owned()
    })
}

/// What sealing a report folder came to.
pub struct Sealed {
    /// Where the report key is, when it was made by this run.
    pub made_key: Option<PathBuf>,
}

/// Seals the report `sv` has just written in `dir`, the marker last, while the run still holds the
/// folder. `sentence` is what the marker says above the seal. `Err` says why it could not be sealed,
/// for the caller to say; the report itself stands either way.
pub fn seal(dir: &Path, sentence: &str) -> Result<Sealed, String> {
    let folder = key_folder()?;
    let (key, made) = Key::load_or_make_named(&folder, REPORT_KEY_FILE)?;
    let digests = digests(dir)?;
    let fields = fields(&digests);
    let seal = key.report_seal(&fields.iter().map(String::as_str).collect::<Vec<_>>());
    crate::write_without_following(
        dir,
        sv_scan::ecosystems::REPORT_MARKER,
        marker_text(sentence, &seal).as_bytes(),
    )
    .map_err(|e| format!("{e:#}"))?;
    Ok(Sealed {
        made_key: made.then(|| folder.join(REPORT_KEY_FILE)),
    })
}

/// The SHA-256 of each file of the report in `dir`, when `sv` can show it wrote them on this
/// computer and nothing has changed them since; otherwise why not, as the end of a sentence
/// beginning "sv cannot show it wrote this report:".
pub fn proven(dir: &Path) -> Result<BTreeMap<&'static str, String>, String> {
    let marker = dir.join(sv_scan::ecosystems::REPORT_MARKER);
    let meta = std::fs::symlink_metadata(&marker)
        .map_err(|_| "the folder holds no marker of sv's".to_owned())?;
    if !meta.is_file() || meta.len() > MAX_MARKER_BYTES {
        return Err("its marker is not one sv writes".to_owned());
    }
    // H6: a folder holding anything but what `sv` writes there is not a report folder of `sv`'s.
    if !sv_scan::ecosystems::is_sv_output(dir) {
        return Err("the folder holds files sv does not write in a report folder".to_owned());
    }
    let text = std::fs::read_to_string(&marker)
        .map_err(|_| "its marker is not one sv writes".to_owned())?;
    let seal = text
        .lines()
        .find_map(|line| line.strip_prefix(SEAL_LINE))
        .ok_or_else(|| {
            "its marker holds no seal, so it was written by something other than sv, or by an sv \
             from before reports were sealed"
                .to_owned()
        })?;
    let key = match Key::load_named(&key_folder()?, REPORT_KEY_FILE)? {
        Some(key) => key,
        None => {
            return Err(
                "this computer has no report key to check its seal with, so it was written on \
                 another computer, or not by sv"
                    .to_owned(),
            );
        }
    };
    let digests = digests(dir)?;
    let fields = fields(&digests);
    key.report_seal_holds(seal, &fields.iter().map(String::as_str).collect::<Vec<_>>())?;
    Ok(digests)
}
