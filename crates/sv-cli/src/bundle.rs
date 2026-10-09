//! `sv bundle`: the app, its report and the record of what was checked, in one zip the owner can keep or hand on.
//!
//! Three things decide what this file does, and each came from the backlog entry that asked for it:
//!
//! * **It must never carry a secret.** "The application's files" includes a `.env` for most beginners. So nothing goes
//!   in that the credential scan flagged, that is named like a file that holds credentials or keys, that is a
//!   database, or that the credential scan could not read (a file it did not read is not a file it can vouch for).
//!   Everything left out is listed, with the reason, in the zip itself and on the screen.
//! * **It goes outside the app folder.** A report written inside the app was once read back as the app's own code.
//! * **Nothing here is a dependency.** The zip is written stored (uncompressed), the SHA-256 and the CRC are computed
//!   here, and the file is deterministic: the same folder gives the same bytes, apart from the date in `BUNDLE.json`.
//!
//! What it does not do, and says so: it cannot tell which files hold data about the app's people, so it leaves out
//! the database files it recognizes by name and tells the owner to look before handing the zip on.

use anyhow::{Result, bail};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use sv_check::secrets::SecretScan;

// ------------------------------------------------------------------------------------------------ SHA-256

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// The SHA-256 of `data`, as lowercase hex.
pub fn sha256(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for start in (0..padded.len()).step_by(64) {
        let block = &padded[start..start + 64];
        let mut w = [0u32; 64];
        for (i, slot) in w.iter_mut().take(16).enumerate() {
            let at = i * 4;
            *slot = u32::from_be_bytes([block[at], block[at + 1], block[at + 2], block[at + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, value) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(value);
        }
    }
    h.iter().map(|word| format!("{word:08x}")).collect()
}

// ------------------------------------------------------------------------------------------------------ zip

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A zip archive holding `entries` uncompressed, in the order given. The modified time of every entry is 1 January
/// 1980, the earliest a zip can say, so the same entries always make the same bytes.
pub fn zip(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    if entries.len() > 0xffff {
        bail!(
            "{} files is more than a plain zip can hold (65,535)",
            entries.len()
        );
    }
    // Every name is checked part by part before anything is written: an entry whose name climbs out of
    // the folder it is unpacked into, or starts at the top of the disk, is never put in the archive.
    for (name, _) in entries {
        let ordinary = !name.is_empty()
            && name.split('/').all(|part| {
                !part.is_empty() && part != "." && part != ".." && !part.contains(['\\', '\0'])
            });
        if !ordinary {
            bail!("refusing to put {name:?} in the bundle: it is not a plain path inside it");
        }
    }
    let mut out: Vec<u8> = Vec::new();
    let mut central: Vec<u8> = Vec::new();
    for (name, data) in entries {
        if data.len() as u64 >= 0xffff_ffff || out.len() as u64 >= 0xffff_ffff {
            bail!("the bundle is larger than 4 GB, which a plain zip cannot hold");
        }
        let name_bytes = name.as_bytes();
        let crc = crc32(data);
        let offset = out.len() as u32;
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0x0800u16.to_le_bytes()); // names are UTF-8
        out.extend_from_slice(&0u16.to_le_bytes()); // stored
        out.extend_from_slice(&0u16.to_le_bytes()); // time
        out.extend_from_slice(&0x0021u16.to_le_bytes()); // date: 1980-01-01
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&0x031eu16.to_le_bytes()); // made on Unix, version 3.0
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&0x0800u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes());
        central.extend_from_slice(&0x0021u16.to_le_bytes());
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        central.extend_from_slice(&0u16.to_le_bytes()); // extra
        central.extend_from_slice(&0u16.to_le_bytes()); // comment
        central.extend_from_slice(&0u16.to_le_bytes()); // disk
        central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        central.extend_from_slice(&(0o100644u32 << 16).to_le_bytes()); // a plain file, rw-r--r--
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name_bytes);
    }
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&(MADE_BY_SV.len() as u16).to_le_bytes());
    out.extend_from_slice(MADE_BY_SV.as_bytes());
    Ok(out)
}

/// The comment every bundle ends with, in the archive's own comment field, so `sv` can tell a zip it
/// made from any other file of the same name. Any zip program shows it.
pub const MADE_BY_SV: &str = sv_frameworks::names::BUNDLE_COMMENT;
/// The comment a bundle made before the rename ends with (ADR-062): still `sv`'s own.
const OLD_MADE_BY_SV: &str = sv_frameworks::names::OLD_BUNDLE_COMMENT;

/// Whether the file at `path` is a bundle `sv` made: it ends with the archive's last record and
/// `MADE_BY_SV` as its comment. Only its last few bytes are read. Such a file is replaced by the next
/// bundle; any other is not (the deep review's improvement 7).
pub fn made_by_sv(path: &Path) -> bool {
    [MADE_BY_SV, OLD_MADE_BY_SV]
        .iter()
        .any(|comment| ends_with_comment(path, comment))
}

/// Whether the zip at `path` ends with the archive's last record carrying `comment`.
fn ends_with_comment(path: &Path, comment: &str) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let tail = 22 + comment.len();
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut end = vec![0u8; tail];
    let read = file
        .seek(SeekFrom::End(-(tail as i64)))
        .and_then(|_| file.read_exact(&mut end));
    read.is_ok()
        && end[..4] == 0x0605_4b50u32.to_le_bytes()
        && end[20..22] == (comment.len() as u16).to_le_bytes()
        && &end[22..] == comment.as_bytes()
}

// ------------------------------------------------------------------------------------------------- the plan

/// What goes in and what stays out, decided before anything is written.
#[derive(Debug, Default)]
pub struct Plan {
    /// Paths relative to the app folder, in a stable order.
    pub include: Vec<String>,
    /// Paths relative to the app folder, with the reason each stays out.
    pub left_out: Vec<(String, String)>,
}

/// Files that are safe to include even though the credential scan could not read them as text: images, fonts and
/// documents that people put in an app. Anything else it could not read stays out.
const HARMLESS_BINARY: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "ico", "bmp", "avif", "woff", "woff2", "ttf", "otf",
    "eot", "pdf", "mp3", "mp4", "mov", "webm", "wav", "ogg",
];

const KEY_EXTENSIONS: &[&str] = &[
    "pem", "key", "p12", "pfx", "jks", "keystore", "ppk", "kdbx", "asc", "gpg",
];

const DATA_EXTENSIONS: &[&str] = &[
    "sqlite", "sqlite3", "db", "db3", "mdb", "rdb", "dump", "bak",
];

const CREDENTIAL_NAMES: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".htpasswd",
    ".git-credentials",
    "credentials",
    "credentials.json",
    "secrets.json",
    "secrets.yml",
    "secrets.yaml",
    ".pgpass",
    ".my.cnf",
    ".s3cfg",
    ".boto",
    ".envrc",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
];

/// Files that hold credentials by where they are, not what they are called: Docker's and
/// Kubernetes' own logins, which an app folder sometimes carries a copy of.
const CREDENTIAL_PATHS: &[&str] = &[".docker/config.json", ".kube/config"];

/// Why a file named like this stays out, or `None` when the name alone does not say.
///
/// Until 5 October 2026 an environment file had to be called `.env` or `.env.<something>`, and
/// `prod.env`, `.envrc`, `.pgpass`, Docker's and Kubernetes' logins, and Terraform's variables
/// and state all went into the zip (A6 of the deep review).
fn left_out_by_name(rel: &str) -> Option<&'static str> {
    let name = rel.rsplit('/').next().unwrap_or(rel);
    let lower = name.to_lowercase();
    let extension = lower.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    const SHOWN: &[&str] = &["example", "sample", "template", "dist"];
    // `.env`, `.env.production`, and `prod.env` or `local.env`; never `.env.example` or
    // `example.env`, which are there to show what to fill in.
    let stem = lower.strip_suffix(".env").unwrap_or("");
    // And one with `env` between dots, as `prod.env.local` or `app.env.production` has it, unless a
    // part of its name says it is there to show the form, or it ends in code (the review of
    // 6 October, item 17).
    let parts: Vec<&str> = lower.trim_start_matches('.').split('.').collect();
    const CODE: &[&str] = &[
        "js", "mjs", "cjs", "ts", "tsx", "jsx", "py", "rb", "go", "php", "rs", "java", "kt", "cs",
        "swift", "dart",
    ];
    let env_between = parts.len() > 2
        && parts[1..parts.len() - 1].contains(&"env")
        && !parts.iter().any(|p| SHOWN.contains(p))
        && !CODE.contains(&extension);
    if lower == ".env"
        || (lower.starts_with(".env.") && !SHOWN.contains(&extension))
        || (!stem.is_empty() && !SHOWN.iter().any(|s| stem.trim_start_matches('.') == *s))
        || env_between
    {
        return Some("it is an environment file, which is where an app keeps its secrets");
    }
    let lower_rel = rel.to_lowercase();
    if CREDENTIAL_PATHS
        .iter()
        .any(|p| lower_rel == *p || lower_rel.ends_with(&format!("/{p}")))
    {
        return Some("it is a tool's own login, which holds its credentials");
    }
    // Terraform's variables hold the values passed in, passwords among them, and its state holds
    // every value it created, in plain text. `terraform.tfstate.backup` is state too.
    if extension == "tfvars" || lower.ends_with(".tfvars.json") || lower.contains(".tfstate") {
        return Some(
            "it is Terraform's variables or state, which hold passwords and keys as written",
        );
    }
    if CREDENTIAL_NAMES.contains(&lower.as_str())
        || lower.starts_with("service-account") && extension == "json"
    {
        return Some("its name says it holds credentials");
    }
    if KEY_EXTENSIONS.contains(&extension) {
        return Some("it is a key or certificate store");
    }
    if DATA_EXTENSIONS.contains(&extension) {
        return Some("it is a database or a dump, which may hold data about the app's people");
    }
    None
}

/// Whether `rel` is a Rails-style `database.yml` with a password written into it rather than read
/// from the environment (`<%= ENV[...] %>`). The credential scan does not always see one, and the
/// file is the database's front door.
fn written_out_database_password(app_dir: &Path, rel: &str) -> bool {
    let name = rel.rsplit('/').next().unwrap_or(rel).to_lowercase();
    if name != "database.yml" && name != "database.yaml" {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(app_dir.join(rel)) else {
        return false;
    };
    text.lines().any(|line| {
        let line = line.trim();
        let Some(value) = line.strip_prefix("password:") else {
            return false;
        };
        let value = value
            .split(" #")
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches(['"', '\'']);
        !value.is_empty() && !value.contains("<%") && !value.starts_with('$')
    })
}

/// Decides what a bundle of `app_dir` holds, given what the credential scan found and could not read.
pub fn plan(app_dir: &Path, scan: &SecretScan) -> Plan {
    let mut flagged: BTreeMap<&str, usize> = BTreeMap::new();
    for finding in &scan.findings {
        *flagged.entry(finding.location.file.as_str()).or_default() += 1;
    }
    let unread: BTreeMap<&str, &str> = scan
        .coverage
        .skipped
        .iter()
        .map(|(p, why)| (p.as_str(), why.as_str()))
        .collect();
    // An image, a font, or a `.DS_Store`, known by its contents: not read for credentials either,
    // so held to the same rule as a file that is not text.
    let no_written_text: BTreeMap<&str, &str> = scan
        .coverage
        .no_written_text
        .iter()
        .map(|(p, what)| (p.as_str(), what.as_str()))
        .collect();

    let mut plan = Plan::default();
    let mut files = Vec::new();
    walk(app_dir, app_dir, &mut files, &mut plan);
    files.sort();
    for rel in files {
        let extension = rel
            .rsplit_once('.')
            .map(|(_, e)| e.to_lowercase())
            .unwrap_or_default();
        if let Some(count) = flagged.get(rel.as_str()) {
            plan.left_out.push((
                rel,
                format!(
                    "the credential scan found {count} thing{} that look{} like a secret in it",
                    if *count == 1 { "" } else { "s" },
                    if *count == 1 { "s" } else { "" }
                ),
            ));
        } else if let Some(reason) = left_out_by_name(&rel) {
            plan.left_out.push((rel, reason.to_owned()));
        } else if written_out_database_password(app_dir, &rel) {
            plan.left_out.push((
                rel,
                "it is a database configuration with a password written in it".to_owned(),
            ));
        } else if let Some(what) = no_written_text.get(rel.as_str()) {
            if HARMLESS_BINARY.contains(&extension.as_str()) {
                plan.include.push(rel);
            } else {
                plan.left_out.push((rel, format!("it is {what}, so the credential scan did not read it, and nothing here can say it holds no secret")));
            }
        } else if let Some(why) = unread.get(rel.as_str()) {
            if HARMLESS_BINARY.contains(&extension.as_str()) && *why == "not a text file" {
                plan.include.push(rel);
            } else {
                plan.left_out.push((rel, format!("the credential scan could not read it ({why}), so nothing here can say it holds no secret")));
            }
        } else {
            plan.include.push(rel);
        }
    }
    plan.left_out.sort();
    plan
}

/// The folders the credential scan skips, less the editor folders, which it reads because they can hold a token, and
/// which a bundle therefore leaves out entirely.
fn skipped_folder(dir: &Path) -> Option<&'static str> {
    let name = dir
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    if sv_scan::ecosystems::EDITOR_DIRS.contains(&name.as_ref()) {
        return Some("editor settings can hold a token");
    }
    if sv_scan::ecosystems::skip_dir(dir) {
        return Some("");
    }
    None
}

fn walk(root: &Path, dir: &Path, files: &mut Vec<String>, plan: &mut Plan) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = sv_scan::files::relative(root, &path);
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        // A name with a `\\` in it, or one that is not text, is carried as nothing: an archive's
        // names are read on other systems, where a `\\` separates folders and `..\\` climbs out of the
        // one being unpacked into.
        let name_is_plain = entry
            .file_name()
            .to_str()
            .is_some_and(|n| !n.contains('\\'));
        if !name_is_plain {
            plan.left_out.push((
                rel,
                "its name has a backslash, or characters that are not text, which another system \
                 would read as a path"
                    .to_owned(),
            ));
        } else if meta.file_type().is_symlink() {
            plan.left_out.push((
                rel,
                "it is a link, and a link can lead outside the app folder".to_owned(),
            ));
        } else if meta.is_dir() {
            match skipped_folder(&path) {
                Some("") => {} // installed packages, build output, version control: never part of the app itself
                Some(reason) => plan.left_out.push((format!("{rel}/"), reason.to_owned())),
                None => walk(root, &path, files, plan),
            }
        } else if meta.is_file() {
            files.push(rel);
        } else {
            plan.left_out.push((
                rel,
                "it is not an ordinary file (a named pipe, a socket, or a device), so it was not read"
                    .to_owned(),
            ));
        }
    }
}

// ------------------------------------------------------------------------------------------ the documents

/// `seconds` since 1 January 1970 as `2026-09-27T14:03:09Z`.
pub fn utc_time(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    // Days since 1970-01-01 to a calendar date (Howard Hinnant's civil_from_days).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// What the listing and the README are told about how the bundle was made.
pub struct Made<'a> {
    pub sv_version: &'a str,
    /// The commit `sv` was built from, or `unknown` when it was built outside a checkout.
    pub commit: &'a str,
    pub made_at: &'a str,
    pub command: &'a str,
    pub app_name: &'a str,
    /// What `stackvet.toml` says about the data the app holds.
    pub categories: &'a [String],
}

/// The listing that travels with the zip: which `sv` made it, when, and a SHA-256 for every file, so what was
/// checked can be matched to what is inside.
pub fn listing(made: &Made, files: &[(String, Vec<u8>)], plan: &Plan) -> serde_json::Value {
    serde_json::json!({
        "made-by": format!("sv {}", made.sv_version),
        "commit": made.commit,
        "made-at": made.made_at,
        "command": made.command,
        "app": made.app_name,
        "data-categories-in-securevibe-toml": made.categories,
        "note": "The report describes the app as it stood when this was made. The files under app/ are what the report was made from, less the files listed under left-out. The data categories are the owner's statement: sv cannot tell which files hold that data, and leaves out only the database files it recognizes by name.",
        "files": files.iter().map(|(path, data)| serde_json::json!({"path": path, "bytes": data.len(), "sha256": sha256(data)})).collect::<Vec<_>>(),
        "left-out": plan.left_out.iter().map(|(path, reason)| serde_json::json!({"path": path, "reason": reason})).collect::<Vec<_>>(),
    })
}

/// The page a person reads first, in plain words.
pub fn readme(
    app_name: &str,
    made_at: &str,
    included: usize,
    plan: &Plan,
    categories: &[String],
) -> String {
    let mut text = format!(
        "This is a bundle of {app_name}, made by sv on {made_at}.\n\n\
         app/      the application's own files ({included} of them)\n\
         report/   the report sv wrote about it: report.html to read, compliance.md and security.md,\n\
         \x20         findings.sarif for tools that read it, report.json, and sbom.cdx.json, the list of what it ships\n\
         BUNDLE.json  which sv made this, when, and a SHA-256 for every file, so you can check\n\
         \x20         that what is here is what was checked (on a Mac: shasum -a 256 FILE)\n\n"
    );
    if plan.left_out.is_empty() {
        text.push_str("Nothing was left out.\n\n");
    } else {
        text.push_str(&format!(
            "{} thing{} left out on purpose, so that this zip carries no secret:\n",
            plan.left_out.len(),
            if plan.left_out.len() == 1 {
                " was"
            } else {
                "s were"
            }
        ));
        for (path, reason) in &plan.left_out {
            text.push_str(&format!("  {path}: {reason}\n"));
        }
        text.push('\n');
    }
    if !categories.is_empty() {
        text.push_str(&format!(
            "stackvet.toml says this app holds: {}. Those files are not left out, because sv cannot tell which they are.\n\n",
            categories.join(", ")
        ));
    }
    text.push_str(
        "What sv cannot promise. It looked for credentials in every file it could read as text, and left out any\n\
         file it could not. It cannot tell which files hold data about the app's people: it leaves out the\n\
         database files it recognizes by name, and nothing else. If this app holds real people's information,\n\
         look through app/ before you hand the zip to anyone.\n",
    );
    text
}

/// `path` with every link in the folders on the way to it resolved, including for a file that does not exist yet: the
/// deepest folder that does exist is looked up on disk, and the rest is added back unchanged. The file name itself is
/// never resolved: a link there is the place the bundle would be written through, and resolving it would hide it from
/// the check that refuses it (deep review S4).
pub fn resolve_for_writing(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
            resolve_existing(parent).join(name)
        }
        _ => resolve_existing(path),
    }
}

/// `path` with every link on the way to it resolved, the parts that do not exist yet added back unchanged.
fn resolve_existing(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        match (
            existing.file_name().map(|n| n.to_owned()),
            existing.parent().map(Path::to_path_buf),
        ) {
            (Some(name), Some(parent)) => {
                rest.push(name);
                existing = parent;
            }
            _ => break,
        }
    }
    let mut resolved = sv_frameworks::paths::canonical(&existing).unwrap_or(existing);
    for name in rest.into_iter().rev() {
        resolved.push(name);
    }
    resolved
}

/// A folder name safe to use inside a zip, made from the app's own.
pub fn safe_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches(|c| c == '-' || c == '.').to_owned();
    if trimmed.is_empty() {
        "app".to_owned()
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_name_that_is_not_a_plain_path_inside_the_bundle_is_refused() {
        for name in [
            "app/../outside/key",
            "../key",
            "/etc/hosts",
            "app/./x",
            "app//x",
            "app/a\\b",
            "",
            "app/",
        ] {
            assert!(
                zip(&[(name.to_owned(), b"x".to_vec())]).is_err(),
                "{name:?}"
            );
        }
        assert!(zip(&[("app/src/main.py".to_owned(), b"x".to_vec())]).is_ok());
        assert!(
            zip(&[("app/a:b.txt".to_owned(), b"x".to_vec())]).is_ok(),
            "a colon is an ordinary character"
        );
    }

    #[test]
    fn sha256_matches_the_published_test_vectors() {
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        // Exactly one block of message plus the padding spilling into a second block.
        assert_eq!(
            sha256(&[b'a'; 64]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
        assert_eq!(
            sha256(&[b'a'; 1_000_000]),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn every_secret_file_the_review_named_stays_out_and_its_shown_forms_go_in() {
        // A6 of the deep review: each of these went into the zip.
        for rel in [
            "prod.env",
            "config/local.env",
            ".envrc",
            "deploy/.pgpass",
            ".my.cnf",
            ".s3cfg",
            ".docker/config.json",
            "ops/.docker/config.json",
            ".kube/config",
            "infra/prod.tfvars",
            "infra/secrets.auto.tfvars.json",
            "infra/terraform.tfstate",
            "infra/terraform.tfstate.backup",
            // The review of 6 October, item 17: `env` between dots.
            "prod.env.local",
            "config/app.env.production",
            // And what already stayed out still does.
            ".env",
            ".env.production",
            "id_ed25519",
        ] {
            assert!(
                left_out_by_name(rel).is_some(),
                "{rel} went into the bundle"
            );
        }
        for rel in [
            ".env.example",
            "example.env",
            ".sample.env",
            "template.env",
            "config.json",
            "src/environment.ts",
            "venv/readme.md",
            "kube/deployment.yaml",
            "docker/config.json",
            "main.tf",
            "prod.env.example",
            "src/config.env.ts",
            "env.local.md",
        ] {
            assert_eq!(left_out_by_name(rel), None, "{rel} was left out");
        }
    }

    #[test]
    fn a_database_yml_with_a_password_written_in_it_stays_out() {
        let dir = std::env::temp_dir().join(format!("sv-bundle-dbyml-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("config")).unwrap();
        let check = |text: &str| {
            std::fs::write(dir.join("config/database.yml"), text).unwrap();
            written_out_database_password(&dir, "config/database.yml")
        };
        let pieces = ["s3cret", "Pass", "w0rd"].concat();
        assert!(check(&format!(
            "production:\n  adapter: postgresql\n  password: {pieces}\n"
        )));
        assert!(check(&format!(
            "production:\n  password: \"{pieces}\" # set by hand\n"
        )));
        assert!(!check(
            "production:\n  password: <%= ENV['DB_PASSWORD'] %>\n"
        ));
        assert!(!check("production:\n  password:\n  username: app\n"));
        assert!(!check("production:\n  password: ''\n"));
        assert!(!check("production:\n  adapter: sqlite3\n"));
        // Only that file name.
        std::fs::write(
            dir.join("config/other.yml"),
            format!("password: {pieces}\n"),
        )
        .unwrap();
        assert!(!written_out_database_password(&dir, "config/other.yml"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crc32_matches_the_published_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn the_time_is_written_as_utc() {
        assert_eq!(utc_time(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_time(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_time(1_790_000_000), "2026-09-21T14:13:20Z");
    }

    #[test]
    fn the_same_files_always_make_the_same_zip_and_it_holds_what_it_was_given() {
        let entries = vec![
            ("a/one.txt".to_owned(), b"first".to_vec()),
            ("a/two.txt".to_owned(), Vec::new()),
        ];
        let once = zip(&entries).unwrap();
        assert_eq!(once, zip(&entries).unwrap());
        assert_eq!(&once[..4], b"PK\x03\x04");
        assert!(
            once.windows(4).any(|w| w == b"PK\x05\x06"),
            "no end-of-archive record"
        );
        assert!(once.windows(5).any(|w| w == b"first"));
        assert!(
            zip(&vec![(String::new(), Vec::new()); 65_536]).is_err(),
            "a plain zip cannot hold more than 65,535 files"
        );
    }

    #[test]
    fn a_path_that_does_not_exist_yet_is_resolved_through_the_links_before_it() {
        let dir = std::env::temp_dir().join(format!("sv-resolve-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let real = sv_frameworks::paths::canonical(&dir).unwrap();
        assert_eq!(
            resolve_for_writing(&dir.join("new").join("out.zip")),
            real.join("new").join("out.zip")
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_at_the_file_name_itself_is_left_for_the_writer_to_refuse() {
        let dir = std::env::temp_dir().join(format!("sv-resolve-link-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("precious.txt"), "keep me\n").unwrap();
        std::os::unix::fs::symlink(dir.join("precious.txt"), dir.join("out.zip")).unwrap();
        let real = sv_frameworks::paths::canonical(&dir).unwrap();
        let resolved = resolve_for_writing(&dir.join("out.zip"));
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(resolved, real.join("out.zip"));
    }

    #[test]
    fn a_name_is_made_safe_for_a_zip() {
        assert_eq!(safe_name("My App (v2)"), "My-App--v2");
        assert_eq!(safe_name("../.."), "app");
    }
}
