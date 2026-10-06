//! `sv review` end to end (deep review R1): it runs only in a terminal, what it records counts in
//! the report of the app it was recorded in, on the computer that holds the key, and the report
//! says why anywhere else.

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
        .env_remove("RUST_BACKTRACE");
    c
}

fn report(app: &Path, config: &Path) -> String {
    let out_dir = app.join("report");
    let run = sv(config)
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
    std::fs::write(app.join("securevibe.toml"), &manifest).unwrap();
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
        std::fs::read_to_string(app.join("securevibe.toml")).unwrap(),
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
    assert!(!before.contains("## Set aside in securevibe.toml\n\nFound"));

    let run = Command::new("python3")
        .arg("-c")
        .arg(PTY)
        .arg("owner\n")
        .arg(env!("CARGO_BIN_EXE_sv"))
        .arg("review")
        .arg(&app)
        .env("XDG_CONFIG_HOME", &config)
        .output()
        .expect("python3 runs");
    let said = String::from_utf8_lossy(&run.stdout);
    assert!(run.status.success(), "{said}");
    assert!(said.contains(&format!("Line 6: {LINE}")), "{said}");
    assert!(said.contains("Recorded 1 of 1"), "{said}");
    // The proposal named its line with the fingerprint used before 5 October 2026; what was
    // recorded names it with today's, the one the report gives the finding (deep review A2).
    let recorded = std::fs::read_to_string(app.join("securevibe.toml")).unwrap();
    let earlier = sv_check::review::named("ast.open-redirect", "app.py", LINE);
    let todays = sv_check::review::todays_form(&app, "ast.open-redirect", "app.py", &earlier)
        .expect("the earlier fingerprint names one line");
    assert!(
        !recorded.contains(&earlier) && recorded.contains(&format!("fingerprint = \"{todays}\"")),
        "{recorded}"
    );
    assert!(
        config.join("securevibe").join("review-key").is_file(),
        "the setup: a key was made"
    );

    // On this computer the seal is checked.
    let here = report(&app, &config);
    assert!(
        here.contains("Recorded through `sv review` on this computer: the owner set it aside"),
        "{here}"
    );
    // Where there is no key, it does not count: the seal cannot be checked, and a made-up one
    // would look the same. The report says what to do (item 8 of the review of 1 to 4 October).
    let none = report(&app, &s.0.join("no-key"));
    assert!(none.contains("cannot check"), "{none}");
    assert!(
        none.contains("run `sv review` once on this computer"),
        "{none}"
    );
    assert!(!none.contains("set it aside as a false alarm on"), "{none}");
    // Copied into another app's folder on this computer, it does not count there (item 11), and
    // still counts where it was recorded.
    let copy = s.0.join("copy");
    std::fs::create_dir_all(&copy).unwrap();
    for file in ["app.py", "securevibe.toml"] {
        std::fs::copy(app.join(file), copy.join(file)).unwrap();
    }
    let copied = report(&copy, &config);
    assert!(copied.contains("for an app in another folder"), "{copied}");
    assert!(
        !copied.contains("set it aside as a false alarm on"),
        "{copied}"
    );
    assert!(
        report(&app, &config).contains("Recorded through `sv review` on this computer"),
        "the setup: it still counts in its own app"
    );
    // On a computer with another key, it is a proposal: a made-up seal would look the same.
    let other = s.0.join("other");
    sv_check::seal::Key::load_or_make_in(&other.join("securevibe")).unwrap();
    let elsewhere = report(&app, &other);
    assert!(elsewhere.contains("not this computer's"), "{elsewhere}");
    assert!(!elsewhere.contains("set it aside as a false alarm on"));
    // A word of the reason changed after it was recorded: a proposal again.
    let manifest = std::fs::read_to_string(app.join("securevibe.toml")).unwrap();
    std::fs::write(
        app.join("securevibe.toml"),
        manifest.replace("own paths first", "own paths"),
    )
    .unwrap();
    let edited = report(&app, &config);
    assert!(edited.contains("does not match what it says"), "{edited}");
}
