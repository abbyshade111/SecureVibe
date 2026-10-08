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
    // A6: a database configuration with a weak password written in it, which the credential scan
    // does not flag, and a Kubernetes login copied into the app.
    std::fs::create_dir_all(dir.join("config")).unwrap();
    std::fs::write(
        dir.join("config/database.yml"),
        "production:\n  adapter: postgresql\n  password: rails123\n",
    )
    .unwrap();
    std::fs::create_dir_all(dir.join(".kube")).unwrap();
    std::fs::write(dir.join(".kube/config"), "users:\n- name: admin\n").unwrap();
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
    // A Finder settings file: known by its contents since H22, and still not something a bundle
    // carries, since nothing read it and its name says nothing harmless.
    std::fs::write(
        dir.join(".DS_Store"),
        b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00",
    )
    .unwrap();
    std::fs::write(dir.join("big.txt"), vec![b'x'; 3 * 1024 * 1024]).unwrap();
    // Over 2 MB with a key past the 2 MB mark: read in pieces since 28 September 2026, so the scan
    // finds the key and the file stays out as one holding a credential.
    let mut big_with_key = "a line of generated data\n".repeat(120_000);
    big_with_key.push_str(&format!("key = {}\n", planted_key()));
    std::fs::write(dir.join("big-with-key.txt"), big_with_key).unwrap();
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

/// A bundle of the test app, read back: its entries, its listing, and what `sv` printed.
struct Made {
    entries: Vec<(String, Vec<u8>)>,
    listing: Value,
    stdout: String,
}

impl Made {
    fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|(n, _)| n.as_str()).collect()
    }
    fn has(&self, ends_with: &str) -> bool {
        self.names().iter().any(|n| n.ends_with(ends_with))
    }
    fn left_out(&self, path: &str) -> Option<String> {
        self.listing["left-out"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["path"] == path)
            .map(|l| l["reason"].as_str().unwrap().to_owned())
    }
}

fn make(name: &str) -> Made {
    let root = scratch(name);
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
    let listing: Value = serde_json::from_slice(
        &entries
            .iter()
            .find(|(n, _)| n.ends_with("BUNDLE.json"))
            .unwrap()
            .1,
    )
    .unwrap();
    Made {
        entries,
        listing,
        stdout,
    }
}

#[test]
fn the_bundle_holds_the_app_the_report_the_bill_of_materials_and_the_listing() {
    let made = make("holds");
    for wanted in [
        "notes-app/app/src/main.py",
        "notes-app/app/securevibe.toml",
        "notes-app/app/.env.example",
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
            made.names().contains(&wanted),
            "{wanted} is not in the bundle: {:?}",
            made.names()
        );
    }
}

#[test]
fn a_file_the_credential_scan_flagged_stays_out_whatever_it_is_called() {
    let made = make("flagged");
    assert!(
        !made.has("src/config.py"),
        "the file holding the planted key is in the bundle"
    );
    assert!(
        made.left_out("src/config.py")
            .is_some_and(|r| r.contains("credential scan found")),
        "{:?}",
        made.left_out("src/config.py")
    );
    for (name, data) in &made.entries {
        assert!(
            !contains(data, &planted_key()),
            "the planted key is in {name}"
        );
    }
}

#[test]
fn files_named_like_secrets_keys_and_databases_stay_out() {
    let made = make("named");
    // The database configuration stays out for its password, not because the scan flagged it:
    // that is the path that was missing.
    let why = made.left_out("config/database.yml").unwrap_or_default();
    assert!(why.contains("database configuration"), "{why}");
    for (path, secret) in [
        (".env", ENV_VALUE),
        ("keys/server.pem", PEM_BODY),
        ("data/app.sqlite", "rows about people"),
        ("config/database.yml", "rails123"),
        (".kube/config", "name: admin"),
    ] {
        assert!(!made.has(&format!("app/{path}")), "{path} is in the bundle");
        assert!(
            made.left_out(path).is_some(),
            "{path} is not listed as left out"
        );
        for (name, data) in &made.entries {
            assert!(!contains(data, secret), "what {path} holds is in {name}");
        }
    }
}

#[test]
fn a_file_the_scan_could_not_read_stays_out_unless_it_is_a_plain_image_or_font_and_a_large_one_is_read()
 {
    let made = make("unread");
    assert!(
        !made.has("app/blob.bin")
            && made
                .left_out("blob.bin")
                .is_some_and(|r| r.contains("could not read it"))
    );
    // A file over 2 MB is read in pieces now, so the scan can vouch for it: a clean one goes in, and
    // one with a key past the 2 MB mark stays out as holding a credential, never as unread.
    assert!(
        made.has("app/big.txt"),
        "a large file the scan read clean is left out"
    );
    assert!(
        !made.has("app/big-with-key.txt")
            && made
                .left_out("big-with-key.txt")
                .is_some_and(|r| r.contains("credential scan found")),
        "{:?}",
        made.left_out("big-with-key.txt")
    );
    for (name, data) in &made.entries {
        assert!(
            !contains(data, &planted_key()),
            "the planted key is in {name}"
        );
    }
    assert!(
        made.has("app/static/logo.png"),
        "a plain image is left out too"
    );
    assert!(
        !made.has("app/.DS_Store")
            && made
                .left_out(".DS_Store")
                .is_some_and(|r| r.contains("Finder settings file")),
        "{:?}",
        made.left_out(".DS_Store")
    );
}

#[test]
fn links_and_editor_folders_stay_out() {
    let made = make("links");
    assert!(
        !made.has("outside-link")
            && made
                .left_out("outside-link")
                .is_some_and(|r| r.contains("link"))
    );
    assert!(
        !made.names().iter().any(|n| n.contains(".vscode")) && made.left_out(".vscode/").is_some()
    );
    for (name, data) in &made.entries {
        assert!(
            !contains(data, "in-the-editor"),
            "the editor's token is in {name}"
        );
    }
    assert!(
        !made.names().iter().any(|n| n.contains("node_modules")),
        "installed packages are in the bundle"
    );
}

#[test]
fn every_file_has_the_sha256_the_listing_says_and_the_person_is_told_what_was_left_out() {
    let made = make("listing");
    let files = made.listing["files"].as_array().unwrap();
    assert!(files.len() >= 10);
    for file in files {
        let path = file["path"].as_str().unwrap();
        let entry = made
            .entries
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
    assert!(
        made.stdout.contains("Left out on purpose"),
        "{}",
        made.stdout
    );
    assert!(
        made.stdout
            .contains("cannot tell which files hold data about your app's people"),
        "{}",
        made.stdout
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

#[test]
fn the_listing_names_the_commit_sv_was_built_from() {
    let made = make("commit");
    let commit = made.listing["commit"].as_str().unwrap();
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output();
    match head {
        Ok(out) if out.status.success() => assert_eq!(
            commit,
            String::from_utf8_lossy(&out.stdout).trim(),
            "the listing names another commit than the checkout this was built from"
        ),
        _ => assert!(commit == "unknown" || commit.len() == 40, "{commit}"),
    }
    assert_eq!(
        made.listing["made-by"],
        format!("sv {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn the_data_the_owner_says_the_app_holds_is_named_and_not_pretended_away() {
    let root = scratch("categories");
    let dir = app(&root);
    let manifest = std::fs::read_to_string(dir.join("securevibe.toml")).unwrap();
    assert!(
        !manifest.contains("[data]"),
        "the example grew a [data] section; merge rather than append"
    );
    std::fs::write(
        dir.join("securevibe.toml"),
        format!("{manifest}\n[data]\ncategories = [\"health\"]\n"),
    )
    .unwrap();
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
    assert!(
        stdout.contains("securevibe.toml says this app holds: health"),
        "{stdout}"
    );
    let (entries, bad) = read_zip(&zip);
    assert_eq!(bad, None);
    let listing: Value = serde_json::from_slice(
        &entries
            .iter()
            .find(|(n, _)| n.ends_with("BUNDLE.json"))
            .unwrap()
            .1,
    )
    .unwrap();
    assert_eq!(
        listing["data-categories-in-securevibe-toml"],
        serde_json::json!(["health"])
    );
    let readme = String::from_utf8_lossy(
        &entries
            .iter()
            .find(|(n, _)| n.ends_with("README.txt"))
            .unwrap()
            .1,
    )
    .into_owned();
    assert!(
        readme.contains("says this app holds: health") && readme.contains("not left out"),
        "{readme}"
    );
    // And the honest half: nothing is left out on the strength of a category, since sv cannot tell which files.
    assert!(entries.iter().any(|(n, _)| n.ends_with("app/src/main.py")));
}

/// The deep review of 4 October 2026, S1: on macOS and Linux a `\` is an ordinary character in a file name, and
/// turning it into `/` made `..\outside\deploy_key.txt` name a file outside the app, which the bundle read and
/// zipped, under an entry name that climbs out of the folder it is unpacked into.
#[cfg(unix)]
#[test]
fn a_backslash_in_a_file_name_never_reaches_outside_the_app() {
    let root = scratch("backslash");
    let dir = root.join("app");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::create_dir_all(root.join("outside")).unwrap();
    let outside = "text-that-lives-outside-the-app-4417";
    std::fs::write(root.join("outside/deploy_key.txt"), outside).unwrap();
    std::fs::copy(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/tested-notes/securevibe.toml"),
        dir.join("securevibe.toml"),
    )
    .unwrap();
    std::fs::write(dir.join("src/main.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("..\\outside\\deploy_key.txt"),
        "the odd name's own text\n",
    )
    .unwrap();
    // The setup is real: the odd name is one file inside the app, and the outside file is there to be reached.
    assert!(dir.join("..\\outside\\deploy_key.txt").is_file());
    assert!(dir.join("../outside/deploy_key.txt").is_file());

    let zip = root.join("out.zip");
    let out = sv(&[
        "bundle",
        dir.to_str().unwrap(),
        "--out",
        zip.to_str().unwrap(),
    ]);
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let (entries, bad) = read_zip(&zip);
    std::fs::remove_dir_all(&root).ok();
    assert_eq!(bad, None);
    assert!(
        entries.iter().any(|(n, _)| n.ends_with("app/src/main.py")),
        "the app's ordinary file is carried"
    );
    for (name, data) in &entries {
        assert!(
            !contains(data, outside),
            "{name} carries the outside file's text"
        );
        assert!(
            !name.split('/').any(|p| p == ".." || p.contains('\\')),
            "{name} is not a plain path inside the bundle"
        );
    }
    let listing = &entries
        .iter()
        .find(|(n, _)| n.ends_with("BUNDLE.json"))
        .unwrap()
        .1;
    let listing = String::from_utf8_lossy(listing);
    assert!(
        listing.contains("backslash"),
        "the odd name is listed as left out: {listing}"
    );
}

#[test]
fn a_bundle_replaces_only_a_zip_sv_made() {
    // The deep review's improvement 7: `sv bundle` wrote over whatever file had the bundle's name.
    let root = scratch("replace");
    let dir = app(&root);
    let zip = root.join("notes-app-securevibe-bundle.zip");
    let bundle = || sv(&["bundle", dir.to_str().unwrap()]);
    let first = bundle();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    // The archive says who made it, in the comment any zip program shows, and is still a zip.
    let comment = Command::new("python3")
        .arg("-c")
        .arg("import sys, zipfile; print(zipfile.ZipFile(sys.argv[1]).comment.decode())")
        .arg(&zip)
        .output()
        .expect("python3 is needed to read the zip back");
    assert!(
        String::from_utf8_lossy(&comment.stdout).starts_with("Made by StackVet (sv bundle)"),
        "{}{}",
        String::from_utf8_lossy(&comment.stdout),
        String::from_utf8_lossy(&comment.stderr)
    );
    // Run again, it replaces its own.
    let again = bundle();
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );

    // A file of the owner's at that name, a zip or not, is left as it is.
    for (what, bytes) in [
        ("a document", b"the owner's own notes\n".to_vec()),
        (
            "another zip",
            b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec(),
        ),
    ] {
        std::fs::write(&zip, &bytes).unwrap();
        let refused = bundle();
        let said = String::from_utf8_lossy(&refused.stderr).into_owned();
        assert!(!refused.status.success(), "{what}: written over");
        assert!(said.contains("is not a bundle sv made"), "{what}: {said}");
        assert_eq!(std::fs::read(&zip).unwrap(), bytes, "{what} was changed");
    }
    std::fs::remove_dir_all(&root).ok();
}
