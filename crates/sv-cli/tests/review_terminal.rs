//! `sv review` end to end (deep review R1): it runs only in a terminal, what it records counts in
//! the report of the app it was recorded in, on the computer whose list of trusted keys names its
//! key and on any computer given that list (ADR-043), and the report says why anywhere else.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const LINE: &str = "return redirect(request.args.get(\"next\"))";
const WHY: &str = "The next= value is looked up in a fixed list of our own paths first.";
const HEAD: &str =
    "manifest-version = 1\n[app]\nname = \"Reviewed\"\n[stack]\nlanguages = [\"python\"]\n";

/// Runs `sv` with stdin, stdout and stderr on a pseudo-terminal, typing `typed`.
const PTY: &str = r#"
import os, pty, select, subprocess, sys
typed = sys.argv[1]
main, child = pty.openpty()
p = subprocess.Popen(sys.argv[2:], stdin=child, stdout=child, stderr=child, close_fds=True)
os.close(child)
os.write(main, typed.encode())
out = b""
while True:
    ready, _, _ = select.select([main], [], [], 20)
    if not ready:
        break
    try:
        data = os.read(main, 4096)
    except OSError:
        break
    if not data:
        break
    out += data
sys.stdout.write(out.decode(errors="replace"))
sys.exit(p.wait())
"#;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn scratch(name: &str) -> Scratch {
    let dir = std::env::temp_dir().join(format!("sv-review-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(
        dir.join("app").join("app.py"),
        format!(
            "from flask import Flask, redirect, request\napp = Flask(__name__)\n\n@app.route(\"/go\")\ndef go():\n    {LINE}\n"
        ),
    )
    .unwrap();
    Scratch(dir)
}

fn sv(config: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sv"));
    c.env("XDG_CONFIG_HOME", config)
        .env_remove("RUST_BACKTRACE")
        .env_remove(sv_check::signed::TRUSTED_VARIABLE);
    c
}

fn report(app: &Path, config: &Path) -> String {
    report_given(app, config, None)
}

/// The report, on a computer given `list` as SV_TRUSTED_SEALS when there is one.
fn report_given(app: &Path, config: &Path, list: Option<&str>) -> String {
    let out_dir = app.join("report");
    let mut sv = sv(config);
    if let Some(list) = list {
        sv.env(sv_check::signed::TRUSTED_VARIABLE, list);
    }
    let run = sv
        .arg("report")
        .arg(app)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    std::fs::read_to_string(out_dir.join("security.md")).unwrap()
}

fn proposal(app: &Path) -> String {
    let fingerprint = sv_check::review::named("ast.open-redirect", "app.py", LINE);
    let manifest = format!(
        "{HEAD}\n[[finding-review]]\nrule = \"ast.open-redirect\"\nfile = \"app.py\"\n\
         fingerprint = \"{fingerprint}\"\nverdict = \"false-alarm\"\nwhy = \"{WHY}\"\n\
         by = \"owner\"\non = \"2026-10-01\"\n"
    );
    std::fs::write(app.join("stackvet.toml"), &manifest).unwrap();
    manifest
}

#[test]
fn it_refuses_to_run_when_not_in_a_terminal() {
    let s = scratch("piped");
    let app = s.0.join("app");
    let manifest = proposal(&app);
    let config = s.0.join("config");
    let run = sv(&config)
        .arg("review")
        .arg(&app)
        .stdin(Stdio::piped())
        .output()
        .expect("sv runs");
    assert!(!run.status.success());
    assert!(
        String::from_utf8_lossy(&run.stderr).contains("runs only in a terminal you are typing in"),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(app.join("stackvet.toml")).unwrap(),
        manifest
    );
    assert!(!config.exists(), "no key is made by a refused run");
}

#[test]
fn what_a_person_records_counts_and_the_report_says_where_its_seal_was_checked() {
    let s = scratch("pty");
    let app = s.0.join("app");
    proposal(&app);
    let config = s.0.join("config");

    // `by = "owner"` written into the file is a proposal: the finding still counts.
    let before = report(&app, &config);
    assert!(
        before.contains("not recorded through `sv review`"),
        "{before}"
    );
    assert!(!before.contains("## Set aside in stackvet.toml\n\nFound"));

    let run = Command::new("python3")
        .arg("-c")
        .arg(PTY)
        // No passphrase on the key it makes, then the owner's name.
        .arg("none\nowner\n")
        .arg(env!("CARGO_BIN_EXE_sv"))
        .arg("review")
        .arg(&app)
        .env("XDG_CONFIG_HOME", &config)
        .env_remove(sv_check::signed::TRUSTED_VARIABLE)
        .output()
        .expect("python3 runs");
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "{said}");
    assert!(said.contains(&format!("Line 6: {LINE}")), "{said}");
    assert!(said.contains("Recorded 1 of 1"), "{said}");
    // The proposal named its line with the fingerprint used before 5 October 2026; what was
    // recorded names it with today's, the one the report gives the finding (deep review A2).
    let recorded = std::fs::read_to_string(app.join("stackvet.toml")).unwrap();
    let earlier = sv_check::review::named("ast.open-redirect", "app.py", LINE);
    let todays = sv_check::review::todays_form(&app, "ast.open-redirect", "app.py", &earlier)
        .expect("the earlier fingerprint names one line");
    assert!(
        !recorded.contains(&earlier) && recorded.contains(&format!("fingerprint = \"{todays}\"")),
        "{recorded}"
    );
    let keys = config.join(sv_frameworks::names::CONFIG_DIR);
    assert!(
        keys.join(sv_check::signed::SIGNING_KEY_FILE).is_file(),
        "the setup: a signing key was made"
    );
    assert!(
        !keys.join(sv_check::seal::KEY_FILE).exists(),
        "no review key is made any more"
    );
    let list = std::fs::read_to_string(keys.join(sv_check::signed::TRUSTED_FILE)).unwrap();
    // `sv review` showed the line to give CI: the public half, and its fingerprint.
    assert!(said.contains(list.trim()), "{said}");
    assert!(said.contains("SHA256:"), "{said}");

    // On this computer the signature is checked against its own list.
    let here = report(&app, &config);
    assert!(
        here.contains("Recorded through `sv review` and signed with key SHA256:"),
        "{here}"
    );
    // The key was made with no passphrase, and the entry says so (ADR-043, Later, 9 October 2026).
    assert!(
        here.contains(
            "which this computer's list of trusted keys trusts for this app (a key on this \
             computer with no passphrase, so anything that can run as you, your AI coding tool \
             included, could have signed it): the owner set it aside"
        ),
        "{here}"
    );
    // Where there is no list, it does not count: the seal cannot be checked, and a made-up one
    // would look the same. The report says what to do (item 8 of the review of 1 to 4 October).
    let none = report(&app, &s.0.join("no-key"));
    assert!(none.contains("no list of trusted keys"), "{none}");
    assert!(
        none.contains("set SV_TRUSTED_SEALS to the line `sv review` showed you"),
        "{none}"
    );
    assert!(!none.contains("set it aside as a false alarm on"), "{none}");
    // Given the list, as CI is, with no key and the app in another folder: it counts, and the
    // report says where the list came from (ADR-043).
    let ci_app = s.0.join("ci");
    std::fs::create_dir_all(&ci_app).unwrap();
    for file in ["app.py", "stackvet.toml"] {
        std::fs::copy(app.join(file), ci_app.join(file)).unwrap();
    }
    let ci = report_given(&ci_app, &s.0.join("no-key"), Some(&list));
    assert!(
        ci.contains(
            "which the list of trusted keys in SV_TRUSTED_SEALS trusts for this app (a key that is \
             not on this computer, so whether it has a passphrase cannot be told here): the owner \
             set it aside"
        ),
        "{ci}"
    );
    // Copied into another app's folder on this computer, it does not count there (item 11), and
    // still counts where it was recorded.
    let copy = s.0.join("copy");
    std::fs::create_dir_all(&copy).unwrap();
    for file in ["app.py", "stackvet.toml"] {
        std::fs::copy(app.join(file), copy.join(file)).unwrap();
    }
    let copied = report(&copy, &config);
    assert!(copied.contains("for an app in another folder"), "{copied}");
    assert!(
        !copied.contains("set it aside as a false alarm on"),
        "{copied}"
    );
    assert!(
        report(&app, &config).contains("Recorded through `sv review` and signed with key"),
        "the setup: it still counts in its own app"
    );
    // Given a list that trusts the key for another app only: a proposal, and it says so.
    let another = sv_check::seal::App::of(&s.0.join("no-key").join("..")).unwrap();
    let mine = sv_check::seal::App::of(&app).unwrap();
    assert_ne!(another.id(), mine.id());
    let for_another = report_given(
        &ci_app,
        &s.0.join("no-key"),
        Some(&list.replace(mine.id(), another.id())),
    );
    assert!(
        for_another.contains("trusts for another app only"),
        "{for_another}"
    );
    assert!(!for_another.contains("set it aside as a false alarm on"));
    // On a computer whose list trusts another key for this app, it is a proposal: anyone can make
    // a key and sign with it.
    let other = s.0.join("other").join(sv_frameworks::names::CONFIG_DIR);
    let theirs = sv_check::signed::SigningKey::make_in(&other, None).unwrap();
    sv_check::signed::trust_here(&other, &theirs, &sv_check::seal::App::of(&app).unwrap()).unwrap();
    let elsewhere = report(&app, &s.0.join("other"));
    assert!(elsewhere.contains("does not name"), "{elsewhere}");
    assert!(!elsewhere.contains("set it aside as a false alarm on"));
    // A word of the reason changed after it was recorded: a proposal again.
    let manifest = std::fs::read_to_string(app.join("stackvet.toml")).unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        manifest.replace("own paths first", "own paths"),
    )
    .unwrap();
    let edited = report(&app, &config);
    assert!(edited.contains("does not match what it says"), "{edited}");
}

/// `sv review` on `app`, typing `typed` at its terminal.
fn review_typing(typed: &str, app: &Path, config: &Path) -> std::process::Output {
    Command::new("python3")
        .arg("-c")
        .arg(PTY)
        .arg(typed)
        .arg(env!("CARGO_BIN_EXE_sv"))
        .arg("review")
        .arg(app)
        .env("XDG_CONFIG_HOME", config)
        .env_remove(sv_check::signed::TRUSTED_VARIABLE)
        .output()
        .expect("python3 runs")
}

/// A link planted in the app at a name `sv review` writes is refused before anything is asked,
/// and the file it points at is left as it was: the rule `sv notes` and `sv rules` follow (deep
/// review S3), which `sv review` did not until the review of 8 October 2026 (its item 3).
#[cfg(unix)]
#[test]
fn a_link_at_a_file_it_writes_is_refused_before_anything_is_asked() {
    let s = scratch("links");
    let app = s.0.join("app");
    let config = s.0.join("config");
    let no_staging_left = |app: &Path| {
        let left: Vec<String> = std::fs::read_dir(app)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".sv-"))
            .collect();
        assert!(left.is_empty(), "staging files left behind: {left:?}");
    };

    // The manifest held outside the app and linked from inside it. The link is real: it reads
    // as the manifest.
    let manifest = proposal(&app);
    let precious = s.0.join("precious.toml");
    std::fs::write(&precious, &manifest).unwrap();
    std::fs::remove_file(app.join("stackvet.toml")).unwrap();
    std::os::unix::fs::symlink(&precious, app.join("stackvet.toml")).unwrap();
    assert_eq!(
        std::fs::read_to_string(app.join("stackvet.toml")).unwrap(),
        manifest,
        "the setup: the link reads as the manifest"
    );
    let run = review_typing("none\nowner\n", &app, &config);
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(!run.status.success(), "it went through: {said}");
    assert!(said.contains("is a link to somewhere else"), "{said}");
    assert_eq!(
        std::fs::read_to_string(&precious).unwrap(),
        manifest,
        "the file the link points at was written over"
    );
    assert!(
        std::fs::symlink_metadata(app.join("stackvet.toml"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the link was removed rather than refused"
    );
    assert!(!config.exists(), "nothing was asked: no key was made");
    no_staging_left(&app);

    // The notes file, with the manifest real again.
    std::fs::remove_file(app.join("stackvet.toml")).unwrap();
    proposal(&app);
    let notes = s.0.join("precious-notes.md");
    std::fs::write(&notes, "keep me\n").unwrap();
    std::os::unix::fs::symlink(&notes, app.join("security-notes.md")).unwrap();
    assert_eq!(
        std::fs::read_to_string(app.join("security-notes.md")).unwrap(),
        "keep me\n",
        "the setup: the link reads as the notes file"
    );
    let run = review_typing("none\nowner\n", &app, &config);
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(!run.status.success(), "it went through: {said}");
    assert!(said.contains("is a link to somewhere else"), "{said}");
    assert_eq!(std::fs::read_to_string(&notes).unwrap(), "keep me\n");
    assert!(
        std::fs::symlink_metadata(app.join("security-notes.md"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(!config.exists(), "nothing was asked: no key was made");
    no_staging_left(&app);

    // Without the links, it records as it always did, leaving no staging file behind.
    std::fs::remove_file(app.join("security-notes.md")).unwrap();
    let run = review_typing("none\nowner\n", &app, &config);
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "{said}");
    assert!(said.contains("Recorded 1 of 1"), "{said}");
    no_staging_left(&app);
}
