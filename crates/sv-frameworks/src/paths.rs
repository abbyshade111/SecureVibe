//! A file's real place, written the way people and Docker read it (backlog 0120).
//!
//! On Windows the standard library gives a real place in the long form, `\\?\C:\Users\me\app`.
//! Windows itself reads that form; Docker does not (`docker run -v \\?\C:\...:/app` is refused as an
//! "invalid spec"), and in a report or a settings file it is a puzzle to anybody who has not met it.
//! Every real place `sv` works out goes through `canonical`, which gives the short form, `C:\Users\me\app`,
//! wherever that names the same place. On macOS and Linux it is exactly `std::fs::canonicalize`.

use std::path::{Path, PathBuf};

/// The real place of `path`: links followed, `..` and `.` gone, and on Windows without the `\\?\`
/// prefix wherever the short form names the same place.
pub fn canonical(path: impl AsRef<Path>) -> std::io::Result<PathBuf> {
    let real = std::fs::canonicalize(path)?;
    if cfg!(windows)
        && let Some(short) = real.to_str().and_then(short_form)
    {
        return Ok(PathBuf::from(short));
    }
    Ok(real)
}

/// The same as `canonical`, called as a method: `folder.canonical()`.
pub trait Canonical {
    fn canonical(&self) -> std::io::Result<PathBuf>;
}

impl Canonical for Path {
    fn canonical(&self) -> std::io::Result<PathBuf> {
        canonical(self)
    }
}

/// Windows's longest path in the short form, counting the end: past it only the long form reaches.
const SHORT_LIMIT: usize = 260;

/// The short form of a Windows long-form path, or `None` where there is none that names the same
/// place: a drive path (`\\?\C:\a` to `C:\a`) or a network share (`\\?\UNC\server\share` to
/// `\\server\share`), short enough, and with no part Windows would read differently once the prefix
/// is gone (`/`, a name that ends in a dot or a space, or a device name such as `CON` or `NUL`).
/// Pure, so it is tested on every system.
pub fn short_form(long: &str) -> Option<String> {
    let short = if let Some(rest) = long.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        let rest = long.strip_prefix(r"\\?\")?;
        let drive = rest.as_bytes();
        if drive.len() < 3
            || !drive[0].is_ascii_alphabetic()
            || drive[1] != b':'
            || drive[2] != b'\\'
        {
            return None;
        }
        rest.to_owned()
    };
    if short.len() >= SHORT_LIMIT || short.contains('/') {
        return None;
    }
    let parts = short.trim_start_matches('\\').split('\\').skip(1);
    for part in parts.filter(|p| !p.is_empty()) {
        if part.ends_with('.') || part.ends_with(' ') || device(part) {
            return None;
        }
    }
    Some(short)
}

/// Whether Windows reads `part` as a device rather than a file: `CON`, `PRN`, `AUX`, `NUL`, `COM1`
/// to `COM9`, and `LPT1` to `LPT9`, in any case and with any extension.
fn device(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or(part)
        .trim_end()
        .to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

#[cfg(test)]
mod tests;
