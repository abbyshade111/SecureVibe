//! `sv bundle`, end to end through the binary: the app, its report and a record of what was checked, in one zip that
//! must never carry a secret.
//!
//! The property that matters is negative, so the setup is asserted first: the credential the test plants is one the
//! credential scan really finds, and it really is on disk. A bundle that leaves out a secret nobody could find would
//! prove nothing, and neither would one made from an app that never had one.
//!
//! The key is built from pieces at run time so this file holds none (GitHub's push protection refuses a key-shaped
//! literal, and the alternative is teaching the reflex this scanner exists to end).

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SV: &str = env!("CARGO_BIN_EXE_sv");

fn planted_key() -> String {
    ["sk", "ant", "api03", "Zp8Kd3Wq1Ls6Vn0Rt4Yb9Xm2Qc"].join("-")
}

const ENV_VALUE: &str = "value-that-lives-only-in-the-env-file-7731";
const PEM_BODY: &str = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC-private-body";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-bundle-test-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A small app with one file of every kind a bundle has to decide about.
fn app(root: &Path) -> PathBuf {
    let dir = root.join("notes app");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(dir.join("static")).unwrap();
    std::fs::create_dir_all(dir.join("keys")).unwrap();
    std::fs::create_dir_all(dir.join("data")).unwrap();
    std::fs::create_dir_all(dir.join(".vscode")).unwrap();
    std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
    let manifest = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/tested-notes/securevibe.toml"),
    )
    .unwrap();
    std::fs::write(dir.join("securevibe.toml"), manifest).unwrap();
    std::fs::write(dir.join("src/main.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("src/config.py"),
        format!("API_KEY = \"{}\"\n", planted_key()),
    )
    .unwrap();
    std::fs::write(dir.join(".env"), format!("SECRET_KEY={ENV_VALUE}\n")).unwrap();
    std::fs::write(dir.join(".env.example"), "SECRET_KEY=generate-one\n").unwrap();
    std::fs::write(
        dir.join("keys/server.pem"),
        format!("-----BEGIN PRIVATE KEY-----\n{PEM_BODY}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();
    std::fs::write(
        dir.join("data/app.sqlite"),
        b"SQLite format 3\0rows about people",
    )
    .unwrap();
    std::fs::write(
        dir.join("static/logo.png"),
        [0x89u8, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe],
    )
    .unwrap();
    std::fs::write(dir.join("blob.bin"), [0xffu8, 0xfe, 0x00, 0x80]).unwrap();
    std::fs::write(dir.join("big.txt"), vec![b'x'; 3 * 1024 * 1024]).unwrap();
    std::fs::write(
        dir.join(".vscode/settings.json"),
        "{\"token\": \"in-the-editor\"}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("node_modules/pkg/index.js"),
        "module.exports = 1;\n",
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("/etc/hosts", dir.join("outside-link")).unwrap();
    dir
}

fn sv(args: &[&str]) -> Output {
    Command::new(SV).args(args).output().unwrap()
}

/// Reads the zip with Python's own zipfile, which is the second opinion on a zip written by hand: it checks every
/// entry's CRC, then prints each entry's name, bytes and SHA-256.
fn read_zip(zip: &Path) -> (Vec<(String, Vec<u8>)>, Option<String>) {
    let script = r#"
import sys, zipfile, hashlib, json, base64
z = zipfile.ZipFile(sys.argv[1])
bad = z.testzip()
print(json.dumps({"bad": bad, "entries": [[i.filename, base64.b64encode(z.read(i)).decode()] for i in z.infolist()]}))
"#;
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .arg(zip)
        .output()
        .expect("python3 is needed to read the zip back");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value: Value = serde_json::from_slice(&out.stdout).unwrap();
    let entries = value["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let name = e[0].as_str().unwrap().to_owned();
            let data = decode_base64(e[1].as_str().unwrap());
            (name, data)
        })
        .collect();
    (entries, value["bad"].as_str().map(str::to_owned))
}

fn decode_base64(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes().filter(|c| *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[test]
fn the_setup_is_real_the_scan_finds_the_planted_key_and_it_is_on_disk() {
    let root = scratch("setup");
    let dir = app(&root);
    assert!(
        std::fs::read_to_string(dir.join("src/config.py"))
            .unwrap()
            .contains(&planted_key())
    );
    assert!(
        std::fs::read_to_string(dir.join(".env"))
            .unwrap()
            .contains(ENV_VALUE)
    );
    let out = sv(&["check", dir.to_str().unwrap()]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("src/config.py"),
        "the credential scan did not find the planted key:\n{text}"
    );
}

#[test]
fn a_bundle_carries_the_app_and_the_report_and_no_secret() {
    let root = scratch("bundle");
    let dir = app(&root);
    let zip = root.join("out").join("notes.zip");
    let out = sv(&[
        "bundle",
        dir.to_str().unwrap(),
        "--out",
        zip.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let (entries, bad) = read_zip(&zip);
    assert_eq!(bad, None, "an entry's CRC does not match");
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();

    // What must be there.
    for wanted in [
        "notes-app/app/src/main.py",
        "notes-app/app/securevibe.toml",
        "notes-app/app/.env.example",
        "notes-app/app/static/logo.png",
        "notes-app/report/report.html",
        "notes-app/report/compliance.md",
        "notes-app/report/security.md",
        "notes-app/report/findings.sarif",
        "notes-app/report/report.json",
        "notes-app/report/sbom.cdx.json",
        "notes-app/BUNDLE.json",
        "notes-app/README.txt",
    ] {
        assert!(
            names.contains(&wanted),
            "{wanted} is not in the bundle: {names:?}"
        );
    }

    // What must not: by name, and by what is inside anything at all, the report included.
    for forbidden in [
        "app/.env",
        "server.pem",
        "app.sqlite",
        "src/config.py",
        "blob.bin",
        "big.txt",
        ".vscode",
        "node_modules",
        "outside-link",
    ] {
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with(forbidden) || n.contains(&format!("/{forbidden}/"))),
            "{forbidden} is in the bundle: {names:?}"
        );
    }
    for (name, data) in &entries {
        assert!(
            !contains(data, &planted_key()),
            "the planted key is in {name}"
        );
        assert!(
            !contains(data, ENV_VALUE),
            "the environment file's value is in {name}"
        );
        assert!(!contains(data, PEM_BODY), "the private key is in {name}");
        assert!(
            !contains(data, "rows about people"),
            "the database is in {name}"
        );
        assert!(
            !contains(data, "in-the-editor"),
            "the editor's token is in {name}"
        );
    }

    // The listing: a SHA-256 for every other file, and a reason for everything left out.
    let listing: Value = serde_json::from_slice(
        &entries
            .iter()
            .find(|(n, _)| n.ends_with("BUNDLE.json"))
            .unwrap()
            .1,
    )
    .unwrap();
    let files = listing["files"].as_array().unwrap();
    assert!(files.len() >= 10);
    for file in files {
        let path = file["path"].as_str().unwrap();
        let entry = entries
            .iter()
            .find(|(n, _)| n == path)
            .unwrap_or_else(|| panic!("{path} is listed but not in the zip"));
        assert_eq!(
            file["bytes"].as_u64().unwrap() as usize,
            entry.1.len(),
            "{path}"
        );
        let check = Command::new("python3")
            .args([
                "-c",
                "import sys,hashlib;print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())",
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child.stdin.take().unwrap().write_all(&entry.1)?;
                child.wait_with_output()
            })
            .unwrap();
        assert_eq!(
            file["sha256"].as_str().unwrap(),
            String::from_utf8_lossy(&check.stdout).trim(),
            "the SHA-256 of {path} is not the file's"
        );
    }
    let left_out: Vec<(&str, &str)> = listing["left-out"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| (l["path"].as_str().unwrap(), l["reason"].as_str().unwrap()))
        .collect();
    for path in [
        ".env",
        "keys/server.pem",
        "data/app.sqlite",
        "src/config.py",
        "blob.bin",
        "big.txt",
        ".vscode/",
        "outside-link",
    ] {
        let (_, reason) = left_out
            .iter()
            .find(|(p, _)| *p == path)
            .unwrap_or_else(|| panic!("{path} is not listed as left out: {left_out:?}"));
        assert!(!reason.is_empty());
    }
    // The person is told the same on screen, and told what sv cannot promise.
    assert!(stdout.contains("Left out on purpose"), "{stdout}");
    assert!(
        stdout.contains("cannot tell which files hold data about your app's people"),
        "{stdout}"
    );
    // And the reason for the key is the credential scan's, not a guess from the name.
    assert!(
        left_out
            .iter()
            .any(|(p, r)| *p == "src/config.py" && r.contains("credential scan found")),
        "{left_out:?}"
    );
}

#[test]
fn the_bundle_will_not_be_written_inside_the_app() {
    let root = scratch("inside");
    let dir = app(&root);
    let inside = dir.join("bundle.zip");
    let out = sv(&[
        "bundle",
        dir.to_str().unwrap(),
        "--out",
        inside.to_str().unwrap(),
    ]);
    assert!(!out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("inside the app folder"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!inside.exists());
}

#[test]
fn with_no_place_given_the_bundle_goes_beside_the_app_not_in_it() {
    let root = scratch("beside");
    let dir = app(&root);
    let out = sv(&["bundle", dir.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(root.join("notes-app-securevibe-bundle.zip").is_file());
    assert!(!dir.join("notes-app-securevibe-bundle.zip").exists());
}

#[test]
fn an_app_with_nothing_to_leave_out_says_so() {
    let root = scratch("clean");
    let dir = root.join("tidy");
    std::fs::create_dir_all(&dir).unwrap();
    let manifest = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/tested-notes/securevibe.toml"),
    )
    .unwrap();
    std::fs::write(dir.join("securevibe.toml"), manifest).unwrap();
    std::fs::write(dir.join("main.py"), "print('hi')\n").unwrap();
    let zip = root.join("tidy.zip");
    let out = sv(&[
        "bundle",
        dir.to_str().unwrap(),
        "--out",
        zip.to_str().unwrap(),
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{stdout}{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("Nothing was left out."), "{stdout}");
    let (entries, bad) = read_zip(&zip);
    assert_eq!(bad, None);
    let readme = String::from_utf8_lossy(
        &entries
            .iter()
            .find(|(n, _)| n.ends_with("README.txt"))
            .unwrap()
            .1,
    )
    .into_owned();
    assert!(readme.contains("Nothing was left out."));
}
