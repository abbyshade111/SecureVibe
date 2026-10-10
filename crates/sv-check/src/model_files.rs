//! C4.1.2, read from the files: model files in the app's folder stored in a format that can run code
//! when it is loaded.
//!
//! C4.1.2 asks that loading a model allows only formats that cannot run code while being read.
//! `ast.model-loaded-with-pickle` reads the loading calls; this reads the files themselves, by their
//! own bytes rather than by name, since `.bin` and `.pt` hold many things. Three kinds count, each
//! read from its library's source on 30 September 2026:
//!
//! - a Python pickle, which opens with the `PROTO` opcode (`0x80`) and a protocol from 2 to 5, or, in
//!   protocols 0 and 1, which have no opening opcode, reads as a pickle from its first opcode to the
//!   `STOP` that ends the file (`walks_as_pickle`);
//! - a PyTorch file, which since PyTorch 1.6 is a zip holding a `data.pkl` record
//!   (`torch/serialization.py` in 2.14, `write_record("data.pkl", ...)`);
//! - a `.joblib` file that opens with one of the prefixes joblib writes for its compressors
//!   (`joblib/compressor.py`), since `joblib.load` always unpickles what it decompresses.
//!
//! Files are looked at by name first: those named like a model file are read as above. Every other file
//! that is not code is opened for its first two bytes only, and one that opens as a protocol 2 to 5
//! pickle is walked to its end too, so a pickle saved as `cache.dat` is found without every file in
//! the app being read through.
//!
//! Only ever a finding. PyTorch 2.6 and later load with `weights_only` on unless told otherwise,
//! which refuses the code a pickle can carry, and the finding says so; `pickle` and `joblib` refuse
//! nothing. A Git LFS pointer is named but not judged: the file it stands for is not in the folder.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use crate::verified::Verified;
use std::io::{Read, Seek, SeekFrom};
use sv_scan::files::Listing;

pub const PICKLE_MODEL: &str = "config.model-file-can-run-code";

/// Extensions model files are saved under by the libraries that write pickles.
const MODEL_EXTENSIONS: &[&str] = &["pt", "pth", "ckpt", "bin", "pkl", "pickle", "joblib"];

/// What joblib writes first for each compressor (`joblib/compressor.py`, 1.5).
const JOBLIB_PREFIXES: &[&[u8]] = &[
    b"ZF",
    b"\x78",
    b"\x1f\x8b",
    b"BZ",
    b"\xfd\x37\x7a\x58\x5a",
    b"\x5d\x00",
    b"\x04\x22\x4d\x18",
];

/// How far from the end a zip's list of names is looked for. The list is at the end, and a model
/// zip holds a handful of names, so this is far more than it needs.
const TAIL: u64 = 1024 * 1024;

/// How large a file is walked opcode by opcode. A larger one opening as a pickle is judged by that
/// and by its last byte; a larger one under a model file's name that does not open as one is counted
/// as not read whole.
const MAX_WALK: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Pickle,
    /// A protocol 0 or 1 pickle, which has no opening opcode.
    OldPickle,
    /// A protocol 2 to 5 pickle under a name that is not a model file's.
    PickleElsewhere,
    Torch,
    Joblib,
    LfsPointer,
    /// Under a model file's name, larger than `MAX_WALK`, and not opening as a pickle.
    NotReadWhole,
    Other,
}

/// Whether a file's first bytes are the `PROTO` opcode with a protocol from 2 to 5.
fn opens_as_pickle(head: &[u8]) -> bool {
    head.len() >= 2 && head[0] == 0x80 && (2..=5).contains(&head[1])
}

/// What a file holds: `extension` is the file's when it is named like a model file, `None` for any
/// other file, which counts only as a protocol 2 to 5 pickle read through to its end.
fn kind_of(path: &std::path::Path, extension: Option<&str>) -> std::io::Result<Kind> {
    let mut file = std::fs::File::open(path)?;
    let mut head = [0u8; 64];
    let read = file.read(&mut head)?;
    let head = &head[..read];
    let length = file.metadata()?.len();
    let Some(extension) = extension else {
        if !opens_as_pickle(head) {
            return Ok(Kind::Other);
        }
        let whole = if length <= MAX_WALK {
            walks_as_pickle(&std::fs::read(path)?, head[1])
        } else {
            // Too large to walk: the last byte must be the `STOP` a pickle ends with.
            file.seek(SeekFrom::End(-1))?;
            let mut last = [0u8; 1];
            file.read_exact(&mut last)?;
            last[0] == STOP
        };
        return Ok(if whole {
            Kind::PickleElsewhere
        } else {
            Kind::Other
        });
    };
    if opens_as_pickle(head) {
        return Ok(Kind::Pickle);
    }
    if head.starts_with(b"version https://git-lfs") {
        return Ok(Kind::LfsPointer);
    }
    if head.starts_with(b"PK\x03\x04") {
        file.seek(SeekFrom::Start(length.saturating_sub(TAIL)))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        let holds_pickle = tail.windows(b"data.pkl".len()).any(|w| w == b"data.pkl");
        return Ok(if holds_pickle {
            Kind::Torch
        } else {
            Kind::Other
        });
    }
    if extension == "joblib" && JOBLIB_PREFIXES.iter().any(|p| head.starts_with(p)) {
        return Ok(Kind::Joblib);
    }
    if length > MAX_WALK {
        return Ok(Kind::NotReadWhole);
    }
    Ok(if walks_as_pickle(&std::fs::read(path)?, 1) {
        Kind::OldPickle
    } else {
        Kind::Other
    })
}

/// The opcode that ends a pickle.
const STOP: u8 = b'.';

/// What follows an opcode, as `pickletools` (Python 3.13) describes each.
#[derive(Clone, Copy)]
enum Arg {
    None,
    /// A fixed number of bytes.
    Fixed(usize),
    /// A length in this many little-endian bytes, then that many bytes.
    Counted(usize),
    /// A line ending in `\n`, of this kind.
    Line(LineKind),
    /// Two lines: a module and a name.
    TwoNames,
}

#[derive(Clone, Copy)]
enum LineKind {
    /// `INT`, `GET`, `PUT`: an integer (`01` and `00` are `True` and `False`).
    Integer,
    /// `LONG`: an integer, with or without an `L` after it.
    Long,
    /// `FLOAT`: a number as `repr` writes it.
    Float,
    /// `STRING`: a quoted string.
    Quoted,
    /// `UNICODE` and `PERSID`: any text.
    Text,
}

/// The protocol each opcode came in with, and what follows it; `None` for a byte that is no opcode.
fn opcode(op: u8) -> Option<(u8, Arg)> {
    use Arg::*;
    use LineKind::*;
    Some(match op {
        b'(' | b'.' | b'0' | b'2' | b'N' | b'R' | b'a' | b'b' | b'd' | b'l' | b's' | b't' => {
            (0, None)
        }
        b'F' => (0, Line(Float)),
        b'I' | b'g' | b'p' => (0, Line(Integer)),
        b'L' => (0, Line(Long)),
        b'S' => (0, Line(Quoted)),
        b'V' | b'P' => (0, Line(Text)),
        b'c' | b'i' => (0, TwoNames),
        b'1' | b'Q' | b'e' | b'o' | b'u' | b'}' | b']' | b')' => (1, None),
        b'J' => (1, Fixed(4)),
        b'K' | b'h' | b'q' => (1, Fixed(1)),
        b'M' => (1, Fixed(2)),
        b'j' | b'r' => (1, Fixed(4)),
        b'G' => (1, Fixed(8)),
        b'T' | b'X' => (1, Counted(4)),
        b'U' => (1, Counted(1)),
        0x80 => (2, Fixed(1)),
        0x81 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 => (2, None),
        0x82 => (2, Fixed(1)),
        0x83 => (2, Fixed(2)),
        0x84 => (2, Fixed(4)),
        0x8a => (2, Counted(1)),
        0x8b => (2, Counted(4)),
        b'B' => (3, Counted(4)),
        b'C' => (3, Counted(1)),
        0x8c => (4, Counted(1)),
        0x8d | 0x8e => (4, Counted(8)),
        0x8f..=0x94 => (4, None),
        0x95 => (4, Fixed(8)),
        0x96 => (5, Counted(8)),
        0x97 | 0x98 => (5, None),
        _ => return Option::None,
    })
}

/// Whether `bytes` read as one pickle of at most protocol `highest`: every byte an opcode or its
/// argument, each argument well formed, and a `STOP` after at least one other opcode as the very
/// last byte. A file that is anything else almost never survives this, which is what lets an old
/// pickle, with no opening opcode to know it by, be told from text that happens to start with `(`.
fn walks_as_pickle(bytes: &[u8], highest: u8) -> bool {
    let mut at = 0;
    let mut opcodes = 0;
    while at < bytes.len() {
        let op = bytes[at];
        at += 1;
        opcodes += 1;
        let Some((protocol, arg)) = opcode(op) else {
            return false;
        };
        if protocol > highest {
            return false;
        }
        if op == 0x80 && bytes.get(at).is_none_or(|p| *p > highest) {
            return false;
        }
        let next = match arg {
            Arg::None => Some(at),
            Arg::Fixed(n) => at.checked_add(n),
            Arg::Counted(n) => bytes.get(at..at + n).and_then(|len| {
                let mut value: u64 = 0;
                for (i, b) in len.iter().enumerate() {
                    value |= u64::from(*b) << (8 * i);
                }
                // `BINSTRING`'s length is signed; a negative one is no pickle.
                if op == b'T' && value > i32::MAX as u64 {
                    return None;
                }
                (at + n).checked_add(usize::try_from(value).ok()?)
            }),
            Arg::Line(kind) => line(bytes, at)
                .filter(|(text, _)| line_fits(kind, text))
                .map(|(_, next)| next),
            Arg::TwoNames => line(bytes, at)
                .filter(|(module, _)| is_name(module))
                .and_then(|(_, next)| line(bytes, next))
                .filter(|(name, _)| is_name(name))
                .map(|(_, next)| next),
        };
        match next {
            Some(next) if next <= bytes.len() => at = next,
            _ => return false,
        }
        if op == STOP {
            return at == bytes.len() && opcodes > 1;
        }
    }
    false
}

/// The line starting at `at`, without its `\n`, and where the next byte is.
fn line(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let end = bytes.get(at..)?.iter().position(|b| *b == b'\n')? + at;
    Some((&bytes[at..end], end + 1))
}

fn line_fits(kind: LineKind, text: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(text) else {
        // `UNICODE` is raw-unicode-escape text, which can hold any byte of Latin-1.
        return matches!(kind, LineKind::Text);
    };
    let digits = |t: &str| {
        let t = t.strip_prefix('-').unwrap_or(t);
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())
    };
    match kind {
        LineKind::Integer => digits(text),
        LineKind::Long => digits(text.strip_suffix('L').unwrap_or(text)),
        LineKind::Float => text.parse::<f64>().is_ok(),
        LineKind::Quoted => {
            text.len() >= 2
                && ((text.starts_with('\'') && text.ends_with('\''))
                    || (text.starts_with('"') && text.ends_with('"')))
        }
        LineKind::Text => true,
    }
}

/// A module or attribute name as `GLOBAL` and `INST` write it: dotted words, nothing else.
fn is_name(text: &[u8]) -> bool {
    !text.is_empty()
        && text
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'.')
}

pub fn check(listing: &Listing, report: &mut ConfigReport) {
    let mut found: Vec<(String, Kind)> = Vec::new();
    let mut pointers = Vec::new();
    let mut not_whole = Vec::new();
    let mut looked = 0;
    let mut others = 0;
    for entry in listing.app_files() {
        let model = entry
            .extension
            .as_deref()
            .filter(|e| MODEL_EXTENSIONS.contains(e));
        if model.is_some() {
            looked += 1;
        } else if entry.language.is_none() {
            others += 1;
        } else {
            continue;
        }
        match kind_of(&entry.path, model) {
            Ok(Kind::LfsPointer) => pointers.push(entry.relative.clone()),
            Ok(Kind::NotReadWhole) => not_whole.push(entry.relative.clone()),
            Ok(Kind::Other) | Err(_) => {}
            Ok(kind) => found.push((entry.relative.clone(), kind)),
        }
    }
    let pointer_note = if pointers.is_empty() {
        String::new()
    } else {
        match pointers.len() {
            1 => "; 1 is a Git LFS pointer, whose file is not in the folder and was not judged"
                .into(),
            n => format!(
                "; {n} are Git LFS pointers, whose files are not in the folder and were not judged"
            ),
        }
    };
    let pointer_note = match not_whole.len() {
        0 => pointer_note,
        n => format!(
            "{pointer_note}; {n} larger than {} MB that do not open as a pickle were not read whole, \
             so an old (protocol 0 or 1) pickle among them would not be seen: {}",
            MAX_WALK / (1024 * 1024),
            not_whole
                .iter()
                .take(5)
                .map(|f| format!("`{f}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    };
    let Some((first, _)) = found.first() else {
        report.passed.push(Verified::new(
            PICKLE_MODEL,
            &[],
            format!(
                "{looked} file(s) named like a model file, none holding a pickle{pointer_note}; {others} \
                 other file(s) that are not code, none opening as a pickle; a model downloaded when the \
                 app runs is not seen"
            ),
        ));
        return;
    };
    let named: Vec<String> = found
        .iter()
        .take(10)
        .map(|(file, kind)| {
            format!(
                "`{file}` ({})",
                match kind {
                    Kind::Torch => "a PyTorch file, which holds a pickle",
                    Kind::Joblib => "a compressed joblib file, which is a pickle inside",
                    Kind::OldPickle => "a Python pickle in the old protocol 0 or 1 form",
                    Kind::PickleElsewhere => {
                        "a Python pickle, under a name that is not a model file's"
                    }
                    _ => "a Python pickle",
                }
            )
        })
        .collect();
    report.findings.push(crate::finding::found(Finding {
        evidence: Vec::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "config.model-file-can-run-code".into(),
        title: "A model file in the app is stored in a format that can run code when loaded".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        location: Location {
            file: first.clone(),
            line: 1,
        },
        secret: None,
        requirement_ids: vec!["C4.1.2".into()],
        cwe: vec!["CWE-502".into()],
        description: format!(
            "{} of the app's files {} stored as Python pickles: {}{}{pointer_note}.",
            found.len(),
            if found.len() == 1 { "is" } else { "are" },
            named.join(", "),
            if found.len() > named.len() {
                format!(", and {} more", found.len() - named.len())
            } else {
                String::new()
            }
        ),
        impact: "A pickle can carry instructions that run the moment it is loaded, so whoever can \
                 change the file, or swap it for another, can run code on the server. PyTorch 2.6 and \
                 later refuse that by default when loading; `pickle.load` and `joblib.load` do not."
            .into(),
        fix: "Save and load model weights as `safetensors` (or ONNX or GGUF, which hold no code). If a \
              PyTorch file has to stay, load it with `torch.load(path, weights_only=True)`, and never \
              load a pickle from anywhere you do not control."
            .into(),
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-models-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(dir: &std::path::Path) -> ConfigReport {
        let mut report = ConfigReport::default();
        check(&Listing::of(dir), &mut report);
        report
    }

    fn found(report: &ConfigReport) -> Option<&Finding> {
        report.findings.iter().find(|f| f.rule_id == PICKLE_MODEL)
    }

    /// `pickle.dumps({'w': [1, 2]}, protocol=4)`, as Python 3 writes it.
    const PICKLE: &[u8] = &[
        128, 4, 149, 16, 0, 0, 0, 0, 0, 0, 0, 125, 148, 140, 1, 119, 148, 93, 148, 40, 75, 1, 75,
        2, 101, 115, 46,
    ];
    // Both written by Python's `zipfile`, stored: the first laid out as `torch.save` writes
    // (`archive/data.pkl`, `archive/.format_version`, `archive/data/0`), the second a zip of
    // something else.
    const TORCH_ZIP: &[u8] = &[
        80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 244, 225, 175, 86, 24, 0, 0, 0, 24, 0, 0,
        0, 16, 0, 0, 0, 97, 114, 99, 104, 105, 118, 101, 47, 100, 97, 116, 97, 46, 112, 107, 108,
        128, 2, 125, 113, 0, 88, 1, 0, 0, 0, 119, 113, 1, 93, 113, 2, 40, 75, 1, 75, 2, 101, 115,
        46, 80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 183, 239, 220, 131, 1, 0, 0, 0, 1, 0,
        0, 0, 23, 0, 0, 0, 97, 114, 99, 104, 105, 118, 101, 47, 46, 102, 111, 114, 109, 97, 116,
        95, 118, 101, 114, 115, 105, 111, 110, 49, 80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 221, 11, 62,
        93, 105, 223, 34, 101, 8, 0, 0, 0, 8, 0, 0, 0, 14, 0, 0, 0, 97, 114, 99, 104, 105, 118,
        101, 47, 100, 97, 116, 97, 47, 48, 0, 0, 0, 0, 0, 0, 0, 0, 80, 75, 1, 2, 20, 3, 20, 0, 0,
        0, 0, 0, 221, 11, 62, 93, 244, 225, 175, 86, 24, 0, 0, 0, 24, 0, 0, 0, 16, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 128, 1, 0, 0, 0, 0, 97, 114, 99, 104, 105, 118, 101, 47, 100, 97, 116,
        97, 46, 112, 107, 108, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 183, 239,
        220, 131, 1, 0, 0, 0, 1, 0, 0, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 70, 0, 0, 0,
        97, 114, 99, 104, 105, 118, 101, 47, 46, 102, 111, 114, 109, 97, 116, 95, 118, 101, 114,
        115, 105, 111, 110, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 105, 223, 34,
        101, 8, 0, 0, 0, 8, 0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 124, 0, 0, 0, 97,
        114, 99, 104, 105, 118, 101, 47, 100, 97, 116, 97, 47, 48, 80, 75, 5, 6, 0, 0, 0, 0, 3, 0,
        3, 0, 191, 0, 0, 0, 176, 0, 0, 0, 0, 0,
    ];
    const OTHER_ZIP: &[u8] = &[
        80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 84, 13, 100, 23, 2, 0, 0, 0, 2, 0, 0, 0,
        16, 0, 0, 0, 109, 111, 100, 101, 108, 47, 109, 111, 100, 101, 108, 46, 111, 110, 110, 120,
        8, 7, 80, 75, 3, 4, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 67, 191, 166, 163, 2, 0, 0, 0, 2,
        0, 0, 0, 17, 0, 0, 0, 109, 111, 100, 101, 108, 47, 99, 111, 110, 102, 105, 103, 46, 106,
        115, 111, 110, 123, 125, 80, 75, 1, 2, 20, 3, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 84, 13,
        100, 23, 2, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 0, 0, 0, 0,
        109, 111, 100, 101, 108, 47, 109, 111, 100, 101, 108, 46, 111, 110, 110, 120, 80, 75, 1, 2,
        20, 3, 20, 0, 0, 0, 0, 0, 221, 11, 62, 93, 67, 191, 166, 163, 2, 0, 0, 0, 2, 0, 0, 0, 17,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 1, 48, 0, 0, 0, 109, 111, 100, 101, 108, 47, 99, 111,
        110, 102, 105, 103, 46, 106, 115, 111, 110, 80, 75, 5, 6, 0, 0, 0, 0, 2, 0, 2, 0, 125, 0,
        0, 0, 97, 0, 0, 0, 0, 0,
    ];

    #[test]
    fn each_kind_of_pickle_is_found_by_its_bytes() {
        for (file, bytes, words) in [
            ("model.pkl", PICKLE, "a Python pickle"),
            ("weights/model.pt", TORCH_ZIP, "a PyTorch file"),
            ("pytorch_model.bin", TORCH_ZIP, "a PyTorch file"),
            (
                "clf.joblib",
                &b"\x1f\x8b\x08\x00compressed"[..],
                "a compressed joblib file",
            ),
            ("clf.joblib", PICKLE, "a Python pickle"),
        ] {
            let dir = scratch("found");
            let path = dir.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, bytes).unwrap();
            let report = run(&dir);
            let finding = found(&report).unwrap_or_else(|| panic!("{file}: {report:?}"));
            assert_eq!(finding.requirement_ids, vec!["C4.1.2"]);
            assert_eq!(finding.location.file, file);
            assert!(
                finding.description.contains(words),
                "{file}: {}",
                finding.description
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn a_file_named_like_a_model_that_holds_no_pickle_is_not_reported() {
        // A zip of something else, safetensors (a length, then JSON), a gzip that is not a joblib
        // file, text, and a Git LFS pointer, which is named in what was looked at.
        let dir = scratch("clean");
        fs::write(dir.join("model.bin"), OTHER_ZIP).unwrap();
        fs::write(
            dir.join("model.pt"),
            b"\x10\x00\x00\x00\x00\x00\x00\x00{\"w\":{}}",
        )
        .unwrap();
        fs::write(dir.join("data.pkl"), b"\x1f\x8b\x08\x00not joblib").unwrap();
        fs::write(dir.join("notes.bin"), b"plain text").unwrap();
        fs::write(
            dir.join("big.ckpt"),
            "version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 1\n",
        )
        .unwrap();
        let report = run(&dir);
        assert!(found(&report).is_none(), "{report:?}");
        let passed = report
            .passed
            .iter()
            .find(|p| p.check_id == PICKLE_MODEL)
            .expect("a clean look is recorded");
        assert!(
            passed.requirement_ids.is_empty(),
            "finding nothing credits nothing"
        );
        assert!(
            passed.scope.starts_with("5 file(s)")
                && passed.scope.contains("1 is a Git LFS pointer"),
            "{}",
            passed.scope
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// `pickle.dumps(obj, protocol=0)` and `protocol=1` in Python 3.11, where `obj` is
    /// `{'w': [1, 2.5, 'x'], 'm': OrderedDict(a=1), 'b': True, 'n': None, 'big': 2**70}`: a list, a
    /// float, text, a class named by module (the opcode a malicious pickle uses), `True`, `None`, and a
    /// long integer.
    const PICKLE_0: &[u8] =
        b"(dp0\nVw\np1\n(lp2\nI1\naF2.5\naVx\np3\nasVm\np4\nccollections\nOrderedDict\np5\n\
(tRp6\nVa\np7\nI1\nssVb\np8\nI01\nsVn\np9\nNsVbig\np10\nL1180591620717411303424L\ns.";
    const PICKLE_1: &[u8] = &[
        125, 113, 0, 40, 88, 1, 0, 0, 0, 119, 113, 1, 93, 113, 2, 40, 75, 1, 71, 64, 4, 0, 0, 0, 0,
        0, 0, 88, 1, 0, 0, 0, 120, 113, 3, 101, 88, 1, 0, 0, 0, 109, 113, 4, 99, 99, 111, 108, 108,
        101, 99, 116, 105, 111, 110, 115, 10, 79, 114, 100, 101, 114, 101, 100, 68, 105, 99, 116,
        10, 113, 5, 41, 82, 113, 6, 88, 1, 0, 0, 0, 97, 113, 7, 75, 1, 115, 88, 1, 0, 0, 0, 98,
        113, 8, 73, 48, 49, 10, 88, 1, 0, 0, 0, 110, 113, 9, 78, 88, 3, 0, 0, 0, 98, 105, 103, 113,
        10, 76, 49, 49, 56, 48, 53, 57, 49, 54, 50, 48, 55, 49, 55, 52, 49, 49, 51, 48, 51, 52, 50,
        52, 76, 10, 117, 46,
    ];
    /// The same object with `protocol=2`, which opens with `PROTO`.
    const PICKLE_2: &[u8] = &[
        128, 2, 125, 113, 0, 40, 88, 1, 0, 0, 0, 119, 113, 1, 93, 113, 2, 40, 75, 1, 71, 64, 4, 0,
        0, 0, 0, 0, 0, 88, 1, 0, 0, 0, 120, 113, 3, 101, 88, 1, 0, 0, 0, 109, 113, 4, 99, 99, 111,
        108, 108, 101, 99, 116, 105, 111, 110, 115, 10, 79, 114, 100, 101, 114, 101, 100, 68, 105,
        99, 116, 10, 113, 5, 41, 82, 113, 6, 88, 1, 0, 0, 0, 97, 113, 7, 75, 1, 115, 88, 1, 0, 0,
        0, 98, 113, 8, 136, 88, 1, 0, 0, 0, 110, 113, 9, 78, 88, 3, 0, 0, 0, 98, 105, 103, 113, 10,
        138, 9, 0, 0, 0, 0, 0, 0, 0, 0, 64, 117, 46,
    ];

    fn one(name: &str, bytes: &[u8]) -> ConfigReport {
        let dir = scratch(&format!("one-{}", name.replace('/', "_")));
        let path = dir.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        let report = run(&dir);
        fs::remove_dir_all(&dir).ok();
        report
    }

    #[test]
    fn an_old_pickle_under_a_model_file_s_name_is_found() {
        // Protocols 0 and 1 have no opening opcode, so a `.pkl` holding one read as "no pickle".
        for (file, bytes) in [
            ("model.pkl", PICKLE_0),
            ("model.pickle", PICKLE_1),
            ("weights.bin", PICKLE_0),
            ("none.pkl", &b"N."[..]),
            // The shape of a pickle written to run a command when loaded, here a harmless one:
            // `os.system` named by `GLOBAL`, a quoted string, and `REDUCE` to call it. Never loaded.
            ("model.pkl", b"cos\nsystem\n(S'true'\ntR."),
        ] {
            let report = one(file, bytes);
            let finding = found(&report).unwrap_or_else(|| panic!("{file}: {report:?}"));
            assert!(
                finding.description.contains("the old protocol 0 or 1 form"),
                "{file}: {}",
                finding.description
            );
        }
    }

    #[test]
    fn text_that_starts_like_an_old_pickle_is_not_one() {
        // Each opens with a byte that is an opcode, and fails somewhere a pickle could not.
        for (file, bytes) in [
            (
                "notes.pkl",
                &b"(see the README for how this was trained)."[..],
            ),
            ("list.bin", b"]"),
            ("int.pkl", b"I12x\n."),
            ("open.pkl", b"(dp0\nVw\np1\n"),
            ("after.pkl", b"N.N."),
            ("stop.pkl", b"."),
            ("global.pkl", b"cos system\nsystem\n."),
            ("new.pkl", &PICKLE_2[2..]),
        ] {
            let report = one(file, bytes);
            assert!(found(&report).is_none(), "{file}: {report:?}");
        }
    }

    #[test]
    fn a_pickle_under_any_name_is_found_when_it_reads_through_to_its_end() {
        // Every file that is not code is opened for two bytes, and one opening as a protocol 2 to 5
        // pickle is walked to its `STOP`.
        for (file, bytes) in [
            ("cache.dat", PICKLE),
            ("state", PICKLE_2),
            ("data/features.npy.cache", PICKLE_2),
        ] {
            let report = one(file, bytes);
            let finding = found(&report).unwrap_or_else(|| panic!("{file}: {report:?}"));
            assert_eq!(finding.location.file, file);
            assert!(
                finding
                    .description
                    .contains("under a name that is not a model file's"),
                "{file}: {}",
                finding.description
            );
        }
    }

    #[test]
    fn under_another_name_only_a_whole_new_pickle_counts() {
        // Bytes that open like a pickle and then are not one; an old pickle, which has nothing to
        // know it by, under a name that is not a model file's; and a pickle inside code, which is
        // the code rules' to read.
        let mut cut = PICKLE_2.to_vec();
        cut.pop();
        let mut longer = PICKLE_2.to_vec();
        longer.extend_from_slice(b"more");
        for (file, bytes) in [
            ("cut.dat", &cut[..]),
            ("longer.dat", &longer[..]),
            ("noise.dat", &b"\x80\x02\xff\xfe."[..]),
            ("old.dat", PICKLE_0),
            ("loader.py", PICKLE_2),
        ] {
            let report = one(file, bytes);
            assert!(found(&report).is_none(), "{file}: {report:?}");
        }
        // What the clean record says it looked at.
        let report = one("old.dat", PICKLE_0);
        let passed = report
            .passed
            .iter()
            .find(|p| p.check_id == PICKLE_MODEL)
            .expect("a clean look is recorded");
        assert!(
            passed.scope.contains("1 other file(s) that are not code"),
            "{}",
            passed.scope
        );
    }

    #[test]
    fn every_kind_of_pickle_python_writes_walks_through() {
        // The walker on its own, against each protocol's own output, and with the protocol held to
        // what the opening says.
        assert!(walks_as_pickle(PICKLE_0, 1));
        assert!(walks_as_pickle(PICKLE_1, 1));
        assert!(walks_as_pickle(PICKLE_2, 2));
        assert!(walks_as_pickle(PICKLE, 4));
        assert!(
            !walks_as_pickle(PICKLE, 2),
            "a protocol 4 opcode in a protocol 2 pickle"
        );
        assert!(
            !walks_as_pickle(PICKLE_2, 1),
            "PROTO is not a protocol 1 opcode"
        );
        assert!(
            !walks_as_pickle(b"\x80\x02\x80\x05N.", 2),
            "a later PROTO claiming more than the opening"
        );
    }
}
