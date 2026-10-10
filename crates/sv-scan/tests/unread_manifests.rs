//! A package list `sv` finds and cannot read (backlog 0226, part 1, item 11).
//!
//! What it names is not read, so a technology `sv` knows only by its package reads as not used. That
//! answer counting for nothing would change what counts as evidence, which is the owner's (part 3,
//! item H); what is built here is the fixture that shows the wrong answer reaching the scan, and the
//! list of unread files the report names beside it.

use std::path::PathBuf;
use sv_frameworks::Condition;
use sv_scan::{ScanReport, Signatures, scan};

fn data(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(file)
}

fn scan_files(name: &str, files: &[(&str, &[u8])]) -> ScanReport {
    let dir = std::env::temp_dir().join(format!("sv-unread-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    for (path, contents) in files {
        let path = dir.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }
    let sigs = Signatures::load_all(&[
        &data("tech-signatures.json"),
        &data("claim-corroborators.json"),
    ])
    .expect("signatures load");
    let report = scan(&dir, &sigs).expect("scan");
    std::fs::remove_dir_all(&dir).ok();
    report
}

fn memcache(report: &ScanReport) -> Option<bool> {
    report
        .answers
        .iter()
        .find(|a| a.condition == Condition::Memcache)
        .and_then(|a| a.value)
}

const CODE: &[u8] = b"console.log('hello');\n";
// A lockfile, so npm is pinned: without one, an absent package is no evidence already, and the
// answer is "can't tell" whatever the package list says.
const LOCK: &[u8] = b"{ \"name\": \"x\", \"lockfileVersion\": 3, \"packages\": { \"\": { \"name\": \"x\" }, \"node_modules/memjs\": { \"version\": \"1.3.2\" } } }\n";
const READS: &[u8] = b"{ \"name\": \"x\", \"dependencies\": { \"memjs\": \"1.3.2\" } }\n";
// The same file with one stray comma, as a hand edit leaves it.
const DOES_NOT: &[u8] = b"{ \"name\": \"x\", \"dependencies\": { \"memjs\": \"1.3.2\", } }\n";

#[test]
fn a_package_json_that_does_not_parse_turns_a_used_library_into_not_used_and_is_named() {
    let read = scan_files(
        "reads",
        &[
            ("package.json", READS),
            ("package-lock.json", LOCK),
            ("index.js", CODE),
        ],
    );
    let unread = scan_files(
        "does-not",
        &[
            ("package.json", DOES_NOT),
            ("package-lock.json", LOCK),
            ("index.js", CODE),
        ],
    );
    // The setup: with the lockfile, npm is pinned in both.
    assert!(
        read.unpinned.is_empty() && unread.unpinned.is_empty(),
        "{:?}",
        unread.unpinned
    );
    // The control: read, the package is seen, and the scan says memcache is used.
    assert_eq!(memcache(&read), Some(true), "{:?}", read.declared);
    assert!(
        read.unread_manifests.is_empty(),
        "{:?}",
        read.unread_manifests
    );
    // Not read, the same app reads as not using it: the wrong answer this item is about. Whether that
    // answer should count for nothing is the owner's (backlog 0226, part 3, item H).
    let why = unread
        .answers
        .iter()
        .find(|a| a.condition == Condition::Memcache)
        .map(|a| format!("{:?}", a.evidence));
    assert_eq!(memcache(&unread), Some(false), "{why:?}");
    // What is built here: the file is named, with why.
    assert_eq!(
        unread.unread_manifests.len(),
        1,
        "{:?}",
        unread.unread_manifests
    );
    let named = &unread.unread_manifests[0];
    assert_eq!(named.manifest, "package.json");
    assert!(named.why.contains("not valid JSON"), "{}", named.why);
}

#[test]
fn each_way_a_package_list_can_fail_is_named_and_a_good_one_is_not() {
    let report = scan_files(
        "each",
        &[
            ("web/package.json", b"{ not json"),
            ("php/composer.json", b"[1, 2"),
            ("py/Pipfile", b"[packages\nrequests = \"*\"\n"),
            ("bin/package.json", &[0xff, 0xfe, 0x00, 0x7b]),
            // A good one beside them, and a format read line by line, which cannot fail to parse.
            ("ok/package.json", READS),
            ("go/go.mod", b"module x\n\nrequire (\n"),
            ("index.js", CODE),
        ],
    );
    let named: Vec<(&str, &str)> = report
        .unread_manifests
        .iter()
        .map(|u| (u.manifest.as_str(), u.why.as_str()))
        .collect();
    let has =
        |manifest: &str, why: &str| named.iter().any(|(m, w)| *m == manifest && w.contains(why));
    assert!(has("web/package.json", "not valid JSON"), "{named:?}");
    assert!(has("php/composer.json", "not valid JSON"), "{named:?}");
    assert!(has("py/Pipfile", "not valid TOML"), "{named:?}");
    assert!(
        has("bin/package.json", "could not be read as text"),
        "{named:?}"
    );
    assert_eq!(named.len(), 4, "only the four that fail: {named:?}");
}

#[test]
fn a_version_catalog_that_does_not_parse_is_named_among_the_unread() {
    // Backlog 226, part 2, item 20.
    let report = scan_files(
        "catalog",
        &[
            (
                "build.gradle",
                b"dependencies {\n  implementation libs.okhttp\n}\n",
            ),
            ("gradle/libs.versions.toml", b"[libraries\nokhttp = \"x\"\n"),
        ],
    );
    let unread: Vec<(&str, &str)> = report
        .unread_manifests
        .iter()
        .map(|u| (u.manifest.as_str(), u.why.as_str()))
        .collect();
    assert_eq!(
        unread,
        [("gradle/libs.versions.toml", "it is not valid TOML")]
    );
}
