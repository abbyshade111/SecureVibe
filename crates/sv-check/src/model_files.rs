//! C4.1.2, read from the files: model files in the app's folder stored in a format that can run code
//! when it is loaded.
//!
//! C4.1.2 asks that loading a model allows only formats that cannot run code while being read.
//! `ast.model-loaded-with-pickle` reads the loading calls; this reads the files themselves, by their
//! own bytes rather than by name, since `.bin` and `.pt` hold many things. Three kinds count, each
//! read from its library's source on 30 September 2026:
//!
//! - a Python pickle, which opens with the `PROTO` opcode (`0x80`) and a protocol from 2 to 5;
//! - a PyTorch file, which since PyTorch 1.6 is a zip holding a `data.pkl` record
//!   (`torch/serialization.py` in 2.14, `write_record("data.pkl", ...)`);
//! - a `.joblib` file that opens with one of the prefixes joblib writes for its compressors
//!   (`joblib/compressor.py`), since `joblib.load` always unpickles what it decompresses.
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

#[derive(Debug, PartialEq, Eq)]
enum Kind {
    Pickle,
    Torch,
    Joblib,
    LfsPointer,
    Other,
}

fn kind_of(path: &std::path::Path, extension: &str) -> std::io::Result<Kind> {
    let mut file = std::fs::File::open(path)?;
    let mut head = [0u8; 64];
    let read = file.read(&mut head)?;
    let head = &head[..read];
    if head.len() >= 2 && head[0] == 0x80 && (2..=5).contains(&head[1]) {
        return Ok(Kind::Pickle);
    }
    if head.starts_with(b"version https://git-lfs") {
        return Ok(Kind::LfsPointer);
    }
    if head.starts_with(b"PK\x03\x04") {
        let length = file.metadata()?.len();
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
    Ok(Kind::Other)
}

pub fn check(listing: &Listing, report: &mut ConfigReport) {
    let mut found: Vec<(String, Kind)> = Vec::new();
    let mut pointers = Vec::new();
    let mut looked = 0;
    for entry in listing.app_files() {
        let Some(extension) = entry.extension.as_deref() else {
            continue;
        };
        if !MODEL_EXTENSIONS.contains(&extension) {
            continue;
        }
        looked += 1;
        match kind_of(&entry.path, extension) {
            Ok(Kind::LfsPointer) => pointers.push(entry.relative.clone()),
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
    let Some((first, _)) = found.first() else {
        report.passed.push(Verified::new(
            PICKLE_MODEL,
            &[],
            format!(
                "{looked} file(s) named like a model file, none holding a pickle{pointer_note}; a model \
                 downloaded when the app runs is not seen"
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
                    _ => "a Python pickle",
                }
            )
        })
        .collect();
    report.findings.push(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
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
            "{} of the app's model files {} stored as Python pickles: {}{}{pointer_note}.",
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
    });
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

    #[test]
    fn a_pickle_under_a_name_that_is_not_a_model_s_is_not_looked_at() {
        // The extensions are the guard against reading every file in the app; a pickle saved as
        // `.dat` is not seen, which the clean record says by counting what was looked at.
        let dir = scratch("other-name");
        fs::write(dir.join("cache.dat"), PICKLE).unwrap();
        let report = run(&dir);
        assert!(found(&report).is_none(), "{report:?}");
        fs::remove_dir_all(&dir).ok();
    }
}
