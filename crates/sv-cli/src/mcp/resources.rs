//! The report folders below the root that are offered as resources, each held to its seal, and the
//! file URIs they are named by.

use super::*;
use sv_frameworks::paths::Canonical;

impl Server {
    /// Every report `sv` has written below the root, each of its files a resource.
    ///
    /// Only folders `sv` can show it wrote are offered (`report_seal::proven`), and only the five
    /// files `sv` writes in them, so nothing else of the person's can be listed or read this way, and
    /// a report anything else wrote is not offered as `sv`'s: a folder holding the marker was enough
    /// until the deep review's R9 offered a forged one. The search does not follow links, goes at
    /// most `REPORT_SEARCH_DEPTH` folders down, and does not enter installed packages, build output,
    /// or version control.
    pub(super) fn resources(&self) -> Vec<Value> {
        let mut folders = Vec::new();
        report_folders(&self.root, 0, &mut folders);
        folders.sort();
        let mut resources = Vec::new();
        for folder in folders {
            if crate::report_seal::proven(&folder).is_err() {
                continue;
            }
            // Its parts joined by `/` on every system, so the name reads the same on Windows,
            // where the folder's own form has `\` (backlog 0120).
            let shown = folder
                .strip_prefix(&self.root)
                .unwrap_or(&folder)
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let shown = if shown.is_empty() {
                ".".to_owned()
            } else {
                shown
            };
            for ReportFile { name, mime, .. } in &REPORT_FILES {
                let path = folder.join(name);
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                // The URI has to say where the file is exactly; a name that cannot be written in
                // one is left out rather than offered under a name that reads something else.
                let (true, Some(uri)) = (meta.is_file(), file_uri(&path)) else {
                    continue;
                };
                resources.push(json!({
                    "uri": uri,
                    "name": format!("{}/{name}", sv_report::one_line(&shown)),
                    "description": format!(
                        "{} A report sv wrote on this computer, sealed when it was written and \
                         unchanged since; it describes the app as it was when written, not \
                         necessarily as it is now. {REPORT_QUOTES_THE_APP} {}",
                        report_file_description(name),
                        if fenced_when_read(name) {
                            "Read, it comes back whole between <app-text-…> tags named for that \
                             reading, with what they mean said first."
                        } else {
                            "Read, it comes back exactly as written, for a program to parse, \
                             with no tags; the app's text is inside it all the same."
                        }
                    ),
                    "mimeType": mime,
                    "size": meta.len(),
                }));
            }
        }
        resources
    }

    /// One file of a report, by the URI `resources/list` gave for it.
    ///
    /// The same limits as the list, checked again here rather than trusted, since a URI can be
    /// written by hand: below the root, in a folder `sv` can show it wrote, one of its five names,
    /// and not a link. The file opened is held to the one that was looked at, so a link put in its
    /// place in between is not read, and what was read is held to what was sealed, so a file changed
    /// in between is not handed over either.
    pub(super) fn read_resource(&self, params: &Value) -> Result<Value, Unreadable> {
        let Some(uri) = params.get("uri").and_then(Value::as_str) else {
            return Err(Unreadable::Malformed(
                "resources/read needs a uri, as resources/list gives".to_owned(),
            ));
        };
        let not_found = |why: &str| Unreadable::NotFound(format!("{why}: {uri}"));
        let path = path_from_uri(uri).ok_or_else(|| {
            Unreadable::Malformed(format!("not a file:// URI of an absolute path: {uri}"))
        })?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let Some(ReportFile { name, mime, .. }) = REPORT_FILES.iter().find(|f| f.name == name)
        else {
            return Err(not_found("only the files of a report sv wrote are offered"));
        };
        let folder = path
            .parent()
            .and_then(|p| p.canonical().ok())
            .ok_or_else(|| not_found("no such folder"))?;
        if !folder.starts_with(&self.root) {
            return Err(not_found(
                "that is outside the folder this server was started for",
            ));
        }
        if !is_report_folder(&folder) {
            return Err(not_found("that folder does not hold a report sv wrote"));
        }
        let sealed = crate::report_seal::proven(&folder).map_err(|why| {
            not_found(&format!(
                "sv cannot show it wrote the report in that folder ({why}), so it is not offered \
                 as one. Call stackvet_check for what sv finds now"
            ))
        })?;
        let path = folder.join(name);
        let looked = std::fs::symlink_metadata(&path).map_err(|_| not_found("no such file"))?;
        if !looked.is_file() {
            return Err(not_found("that is a link or a folder, not a report file"));
        }
        if looked.len() > MAX_RESOURCE_BYTES {
            return Err(not_found("that file is larger than any report sv writes"));
        }
        let mut file = std::fs::File::open(&path).map_err(|_| not_found("it cannot be opened"))?;
        let opened = file
            .metadata()
            .map_err(|_| not_found("it cannot be opened"))?;
        if !same_file(&looked, &opened) {
            return Err(not_found("the file changed while it was being opened"));
        }
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut file, MAX_RESOURCE_BYTES + 1),
            &mut bytes,
        )
        .map_err(|_| not_found("it cannot be read"))?;
        // It may have grown since it was looked at.
        if bytes.len() as u64 > MAX_RESOURCE_BYTES {
            return Err(not_found("that file is larger than any report sv writes"));
        }
        if sealed.get(name).map(String::as_str) != Some(crate::bundle::sha256(&bytes).as_str()) {
            return Err(not_found(
                "that file changed after its seal was checked, so it is not what sv wrote",
            ));
        }
        let text = String::from_utf8(bytes)
            .map_err(|_| not_found("it is not text, so sv did not write it"))?;
        // Read back, a report is the app's text as much as a tool's result is, and is fenced as one
        // is; the files a program parses are handed over as written (ADR-066, Later, 9 October 2026).
        let text = if fenced_when_read(name) {
            sv_report::fence::fenced_block(&text)
        } else {
            text
        };
        Ok(json!({
            "contents": [{
                "uri": file_uri(&path).unwrap_or_else(|| uri.to_owned()),
                "mimeType": mime,
                "text": text,
            }],
        }))
    }
}

/// Why a resource was not read: the request was malformed, or there is no such report file.
pub(super) enum Unreadable {
    Malformed(String),
    NotFound(String),
}

/// Whether `sv` marked this folder as one of its reports: the marker is a file, not a link to one.
pub(super) fn is_report_folder(dir: &Path) -> bool {
    sv_scan::ecosystems::report_marker_in(dir).is_some()
}

/// The report folders at or below `dir`, not following links. A report folder is not looked into
/// further; installed packages, build output, and version control are not entered.
pub(super) fn report_folders(dir: &Path, depth: usize, found: &mut Vec<PathBuf>) {
    if found.len() >= MAX_REPORT_FOLDERS {
        return;
    }
    if is_report_folder(dir) {
        found.push(dir.to_path_buf());
        return;
    }
    if depth >= REPORT_SEARCH_DEPTH || (depth > 0 && sv_scan::ecosystems::skip_dir(dir)) {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut below: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    below.sort();
    for sub in below {
        report_folders(&sub, depth + 1, found);
    }
}

/// Whether a report file comes back between tags when read: the page and the two Markdown files,
/// which a model reads, and not the JSON and SARIF, which a program parses and tags would break.
pub(super) fn fenced_when_read(name: &str) -> bool {
    name.ends_with(".md") || name.ends_with(".html")
}

/// What each report file is, for a person or a model choosing which to open.
pub(super) fn report_file_description(name: &str) -> &'static str {
    match name {
        "report.html" => "The report for a person to read.",
        "compliance.md" => "Each requirement and what was found for it.",
        "security.md" => "The findings, worst first.",
        "findings.sarif" => "The findings in SARIF, for code-scanning tools.",
        _ => "The whole report, for a program to read.",
    }
}

/// Bytes that stand for themselves in a URI's path; every other byte is written as `%XX`.
pub(super) fn plain_in_uri(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte)
}

/// `file://` and the absolute path, with anything that is not plain written as `%XX`. None for a
/// path that is not text, which a URI here cannot name. On Windows the path is written the way
/// RFC 8089 and every AI coding tool there reads it: `C:\a\b` as `file:///C:/a/b`, and a network
/// share `\\server\share\a` as `file://server/share/a` (backlog 0120).
pub(super) fn file_uri(path: &Path) -> Option<String> {
    file_uri_of(path.to_str()?, cfg!(windows))
}

/// The absolute path a `file://` URI names, or None if it is not one.
pub(super) fn path_from_uri(uri: &str) -> Option<PathBuf> {
    let text = path_text_from_uri(uri, cfg!(windows))?;
    let path = PathBuf::from(text);
    path.is_absolute().then_some(path)
}

/// `file_uri`, for either system, so the Windows form is tested on every one.
pub(super) fn file_uri_of(text: &str, windows: bool) -> Option<String> {
    let (mut uri, rest) = if !windows {
        (String::from("file://"), text.to_owned())
    } else if let Some(share) = text.strip_prefix(r"\\") {
        (String::from("file://"), share.replace('\\', "/"))
    } else {
        let drive = text.as_bytes();
        if drive.len() < 3 || !drive[0].is_ascii_alphabetic() || &drive[1..3] != b":\\" {
            return None;
        }
        (
            format!("file:///{}:", drive[0] as char),
            text[2..].replace('\\', "/"),
        )
    };
    for byte in rest.bytes() {
        if plain_in_uri(byte) {
            uri.push(byte as char);
        } else {
            uri.push_str(&format!("%{byte:02X}"));
        }
    }
    Some(uri)
}

/// The path text a `file://` URI names, for either system, or None if it is not one: on Windows
/// `file:///C:/a/b` is `C:\a\b` and `file://server/share/a` is `\\server\share\a`.
pub(super) fn path_text_from_uri(uri: &str, windows: bool) -> Option<String> {
    let rest = uri.strip_prefix("file://")?;
    let mut bytes = Vec::with_capacity(rest.len());
    let mut iter = rest.bytes();
    while let Some(byte) = iter.next() {
        if byte == b'%' {
            let high = (iter.next()? as char).to_digit(16)?;
            let low = (iter.next()? as char).to_digit(16)?;
            bytes.push((high * 16 + low) as u8);
        } else {
            bytes.push(byte);
        }
    }
    let text = String::from_utf8(bytes).ok()?;
    if !windows {
        return Some(text);
    }
    // A backslash written into the URI would be a separator once turned around, naming another
    // place than the one written; none of ours holds one, so none is read.
    if text.contains('\\') {
        return None;
    }
    let drive = text.as_bytes();
    if drive.len() >= 4
        && drive[0] == b'/'
        && drive[1].is_ascii_alphabetic()
        && drive[2] == b':'
        && drive[3] == b'/'
    {
        Some(text[1..].replace('/', "\\"))
    } else if !text.is_empty() && !text.starts_with('/') {
        Some(format!(r"\\{}", text.replace('/', "\\")))
    } else {
        None
    }
}

/// Whether two looks at a path saw the same file.
#[cfg(unix)]
pub(super) fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
pub(super) fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.len() == b.len() && b.is_file()
}
