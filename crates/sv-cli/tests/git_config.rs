//! `sv check` on an app whose own repository names a program for git to run (ADR-032). The
//! committed-secrets check asks git which files are tracked, and git reads the repository's config,
//! which the app's author wrote. Found and reproduced on 5 October 2026: `core.fsmonitor` ran.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) {
    let ok = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(ok, "git {args:?} failed in the test's setup");
}

#[test]
fn checking_an_app_runs_no_program_its_repository_names() {
    if Command::new("git").arg("--version").output().is_err() {
        println!("no git here; this needs it");
        return;
    }
    let root = std::env::temp_dir().join(format!("sv-git-config-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    // The mark is outside the app, where a program would reach on the owner's computer.
    let mark = root.join("ran");
    std::fs::write(
        app.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Planted\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    std::fs::write(app.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(app.join(".gitignore"), ".env\n").unwrap();
    git(&app, &["init", "-q"]);
    git(&app, &["add", "-A"]);
    git(
        &app,
        &[
            "-c",
            "user.email=t@t",
            "-c",
            "user.name=t",
            "commit",
            "-qm",
            "one",
        ],
    );
    git(
        &app,
        &[
            "config",
            "core.fsmonitor",
            &format!("touch '{}'; false", mark.display()),
        ],
    );

    // The control: plain git in that folder runs it, so the app is the attack it should be.
    git(&app, &["ls-files"]);
    assert!(
        mark.exists(),
        "plain git did not run the planted program, so this proves nothing"
    );
    std::fs::remove_file(&mark).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("check")
        .arg(&app)
        .output()
        .expect("sv runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let ran = mark.exists();
    std::fs::remove_dir_all(&root).ok();
    assert!(
        !ran,
        "sv check ran the program the app's repository named:\n{text}"
    );
    // And the check still asked git: it says nothing about not being a repository.
    assert!(!text.contains("is not a git repository"), "{text}");
}
