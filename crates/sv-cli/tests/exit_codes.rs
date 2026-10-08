//! What `sv check`, `sv report` and `sv audit` exit with, through the binary, each code reached on
//! purpose (the deep review of 4 October 2026, R6; DESIGN, "Exit codes for CI"):
//! 0 finished; 1 needs attention (audit's known vulnerability, or `--fail-on attention`); 2 not
//! assessed (a check could not run, or no file of the app was read; more with `--fail-on
//! not-assessed`); 3 `sv` itself failed. Before, `sv check` and `sv report` exited 0 whatever
//! happened, and every error exited 1, the code `sv audit` uses for a known vulnerability.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `sv` with `args`: its exit status and everything it printed.
fn sv(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .env_remove("SV_ADVISORY_DIR")
        .output()
        .expect("sv runs");
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

fn s(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// A fresh folder for one test.
fn root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("sv-exit-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(&root).unwrap();
    root
}

const MANIFEST: &str = "manifest-version = 1\n[app]\nname = \"Exit codes\"\naudience = \"customers\"\n\
                        deployment = \"internet\"\n[stack]\nlanguages = [\"python\"]\n";

/// A small Python app sv reads all of: one low-severity finding (no security.txt), nothing it
/// could not read. `extra` adds a file.
fn app(root: &Path, extra: &[(&str, &str)]) -> PathBuf {
    let app = root.join("app");
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(app.join("securevibe.toml"), MANIFEST).unwrap();
    std::fs::write(app.join("app.py"), "def hello():\n    return 'hello'\n").unwrap();
    for (name, text) in extra {
        std::fs::write(app.join(name), text).unwrap();
    }
    app
}

/// Code two rules grade high: a shell command and code built at run time.
const HIGH_FINDINGS: &str =
    "import os\n\ndef run(cmd):\n    os.system(cmd)\n\ndef calc(expr):\n    return eval(expr)\n";

#[test]
fn check_exits_0_when_it_read_everything_however_many_findings() {
    let root = root("check0");
    let app = app(&root, &[("tool.py", HIGH_FINDINGS)]);
    let (code, said) = sv(&["check", s(&app)]);
    std::fs::remove_dir_all(&root).ok();
    // The setup: it read the files, and the high findings are there.
    assert!(said.contains("Read 3 files"), "{said}");
    assert!(said.contains("[high]"), "{said}");
    assert_eq!(
        code,
        Some(0),
        "findings alone do not fail without --fail-on: {said}"
    );
    assert!(!said.contains("Exit status"), "{said}");
}

#[test]
fn check_exits_1_with_fail_on_attention_at_or_above_the_bar_only() {
    let root = root("check1");
    let plain = app(&root, &[]);
    let (low_any, low_said) = sv(&["check", s(&plain), "--fail-on", "attention"]);
    let (low_high, _) = sv(&["check", s(&plain), "--fail-on", "attention:high"]);
    std::fs::write(plain.join("tool.py"), HIGH_FINDINGS).unwrap();
    let (high, said) = sv(&["check", "--fail-on", "attention:high", s(&plain)]);
    let (any, _) = sv(&["check", s(&plain), "--fail-on", "any"]);
    std::fs::remove_dir_all(&root).ok();

    // Only a low finding: attention (low and worse) fails, attention:high does not.
    assert!(
        low_said.contains("[low]") && !low_said.contains("[high]"),
        "{low_said}"
    );
    assert_eq!(low_any, Some(1), "{low_said}");
    assert!(
        low_said.contains("Exit status 1 (something needs attention)"),
        "{low_said}"
    );
    assert_eq!(low_high, Some(0));
    assert_eq!(high, Some(1), "{said}");
    assert!(said.contains("finding(s) at high or worse"), "{said}");
    assert_eq!(any, Some(1));
}

#[test]
fn check_exits_2_when_a_check_could_not_run_or_nothing_was_read() {
    let root = root("check2");
    // A language nothing reads.
    let objc = app(
        &root.join("objc"),
        &[("view.m", "int main(void) { return 0; }\n")],
    );
    let (objc_code, objc_said) = sv(&["check", s(&objc)]);
    // A Python file the parser cannot make sense of.
    let broken = app(
        &root.join("broken"),
        &[("broken.py", "def (:\n  return ]]\n")],
    );
    let (broken_code, broken_said) = sv(&["check", s(&broken)]);
    // A folder holding nothing but securevibe.toml, and one holding nothing.
    let only = root.join("only");
    std::fs::create_dir_all(&only).unwrap();
    std::fs::write(only.join("securevibe.toml"), MANIFEST).unwrap();
    let (only_code, only_said) = sv(&["check", s(&only)]);
    let empty = root.join("empty");
    std::fs::create_dir_all(&empty).unwrap();
    let (empty_code, empty_said) = sv(&["check", s(&empty)]);
    // An image is read and is not text: not a gap, or every web app would exit 2.
    let image = app(&root.join("image"), &[]);
    std::fs::write(
        image.join("logo.png"),
        [0x89, b'P', b'N', b'G', 0xff, 0xfe, 0x00],
    )
    .unwrap();
    let (image_code, image_said) = sv(&["check", s(&image)]);
    // With --fail-on attention, a finding still outranks not assessed.
    let (both, _) = sv(&["check", s(&objc), "--fail-on", "attention"]);
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(objc_code, Some(2), "{objc_said}");
    assert!(objc_said.contains("nothing here reads objc"), "{objc_said}");
    assert_eq!(broken_code, Some(2), "{broken_said}");
    assert!(
        broken_said.contains("the parser could not make sense of, such as broken.py"),
        "{broken_said}"
    );
    assert_eq!(only_code, Some(2), "{only_said}");
    assert!(
        only_said.contains("no file of the app was read"),
        "{only_said}"
    );
    assert_eq!(empty_code, Some(2), "{empty_said}");
    assert!(
        image_said.contains("logo.png"),
        "the setup: the image is listed: {image_said}"
    );
    assert_eq!(image_code, Some(0), "{image_said}");
    assert_eq!(both, Some(1));
}

#[cfg(unix)]
#[test]
fn check_exits_2_for_a_file_it_could_not_open_and_a_link_only_with_fail_on_not_assessed() {
    use std::os::unix::fs::PermissionsExt;
    let root = root("check2-unix");
    let locked = app(&root.join("locked"), &[("secret.py", "KEY = 1\n")]);
    std::fs::set_permissions(
        locked.join("secret.py"),
        std::fs::Permissions::from_mode(0o000),
    )
    .unwrap();
    // The setup: as root every file opens, and there is nothing to test.
    let really_locked = std::fs::read(locked.join("secret.py")).is_err();
    let (locked_code, locked_said) = sv(&["check", s(&locked)]);
    std::fs::set_permissions(
        locked.join("secret.py"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();

    let linked = app(&root.join("linked"), &[]);
    std::os::unix::fs::symlink(linked.join("app.py"), linked.join("alias.py")).unwrap();
    let (link_code, link_said) = sv(&["check", s(&linked)]);
    let (strict, strict_said) = sv(&["check", s(&linked), "--fail-on", "not-assessed"]);
    std::fs::remove_dir_all(&root).ok();

    // Printed whichever branch was taken, so a run as root says the case went untested.
    if really_locked {
        assert_eq!(locked_code, Some(2), "{locked_said}");
        assert!(
            locked_said.contains("could not be read, such as secret.py"),
            "{locked_said}"
        );
    } else {
        eprintln!(
            "running as a user who can open any file: the unreadable-file case was not tested"
        );
    }
    assert!(
        link_said.contains("alias.py"),
        "the setup: the link is listed: {link_said}"
    );
    assert_eq!(link_code, Some(0), "{link_said}");
    assert_eq!(strict, Some(2), "{strict_said}");
    assert!(
        strict_said.contains("symbolic link(s) were not followed"),
        "{strict_said}"
    );
}

#[test]
fn check_exits_3_when_sv_itself_fails() {
    let root = root("check3");
    let (missing, said) = sv(&["check", s(&root.join("not-there"))]);
    assert_eq!(missing, Some(3), "{said}");
    assert!(said.contains("is not a folder"), "{said}");
    let (wrong, said) = sv(&["check", s(&root), "--fail-on", "findings"]);
    assert_eq!(wrong, Some(3), "{said}");
    assert!(said.contains("--fail-on findings"), "{said}");
    let (unknown, said) = sv(&["check", "--nonsense"]);
    assert_eq!(unknown, Some(3), "{said}");
    std::fs::remove_dir_all(&root).ok();
}

#[test]
fn check_reads_securevibe_toml_when_it_is_there_and_stops_on_one_it_cannot_read() {
    // Gap analysis 5.1: a broken securevibe.toml finished with 0 at a terminal, while `sv report`
    // and securevibe_check refused it. Both of the gap analysis's own examples: bad syntax, and a
    // section misspelt.
    let root = root("check-manifest");
    let app = app(&root, &[("tool.py", "x = 1\n")]);
    let (good, good_said) = sv(&["check", s(&app)]);
    std::fs::remove_file(app.join("securevibe.toml")).unwrap();
    let (none, none_said) = sv(&["check", s(&app)]);
    std::fs::write(app.join("securevibe.toml"), "auth = = true\n").unwrap();
    let (syntax, syntax_said) = sv(&["check", s(&app)]);
    std::fs::write(
        app.join("securevibe.toml"),
        format!("{MANIFEST}\n[capabilitys]\nauth = true\n"),
    )
    .unwrap();
    let (misspelt, misspelt_said) = sv(&["check", s(&app)]);
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(good, Some(0), "{good_said}");
    assert_eq!(
        none,
        Some(0),
        "no securevibe.toml is fine here: {none_said}"
    );
    for (code, said) in [(syntax, &syntax_said), (misspelt, &misspelt_said)] {
        assert_eq!(code, Some(3), "{said}");
        assert!(said.contains("securevibe.toml"), "{said}");
        assert!(!said.contains("Read 1 file"), "the scan ran anyway: {said}");
    }
}

#[test]
fn report_exits_0_1_and_2_as_check_does() {
    let root = root("report");
    let app = app(&root, &[("tool.py", HIGH_FINDINGS)]);
    let out = |n: &str| root.join(format!("out-{n}"));
    let (clean, clean_said) = sv(&["report", s(&app), "--out", s(&out("0"))]);
    let (found, found_said) = sv(&[
        "report",
        s(&app),
        "--out",
        s(&out("1")),
        "--fail-on",
        "attention:high",
    ]);
    let (below, _) = sv(&[
        "report",
        s(&app),
        "--out",
        s(&out("1b")),
        "--fail-on",
        "attention:critical",
    ]);
    // --run asked for, and securevibe.toml says nothing of how to start the app.
    let (not_started, not_started_said) =
        sv(&["report", s(&app), "--out", s(&out("run")), "--run"]);
    std::fs::write(app.join("view.m"), "int main(void) { return 0; }\n").unwrap();
    let (unread, unread_said) = sv(&["report", s(&app), "--out", s(&out("2"))]);
    let wrote = out("0").join("report.json").is_file();
    std::fs::remove_dir_all(&root).ok();

    assert!(wrote, "the setup: the report was written: {clean_said}");
    assert_eq!(clean, Some(0), "{clean_said}");
    assert_eq!(found, Some(1), "{found_said}");
    assert!(
        found_said.contains("finding(s) at high or worse"),
        "{found_said}"
    );
    assert_eq!(below, Some(0));
    assert_eq!(not_started, Some(2), "{not_started_said}");
    assert!(
        not_started_said.contains("--run was given and the app could not be started"),
        "{not_started_said}"
    );
    assert_eq!(unread, Some(2), "{unread_said}");
    assert!(
        unread_said.contains("nothing here reads objc"),
        "{unread_said}"
    );
}

#[test]
fn report_exits_3_with_no_manifest_a_broken_one_or_no_folder() {
    let root = root("report3");
    let bare = root.join("bare");
    std::fs::create_dir_all(&bare).unwrap();
    std::fs::write(bare.join("app.py"), "x = 1\n").unwrap();
    let (none, none_said) = sv(&["report", s(&bare), "--out", s(&root.join("o1"))]);
    std::fs::write(bare.join("securevibe.toml"), "manifest-version = [\n").unwrap();
    let (broken, broken_said) = sv(&["report", s(&bare), "--out", s(&root.join("o2"))]);
    let (missing, missing_said) = sv(&["report", s(&root.join("not-there"))]);
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(none, Some(3), "{none_said}");
    assert!(none_said.contains("no securevibe.toml"), "{none_said}");
    assert_eq!(broken, Some(3), "{broken_said}");
    assert!(
        broken_said.starts_with("Error:") || broken_said.contains("\nError:"),
        "{broken_said}"
    );
    assert_eq!(missing, Some(3), "{missing_said}");
}

/// An npm app using `packages`, and an advisory database about npm with one record, for qs.
fn npm_app(root: &Path, packages: &[(&str, &str)], manifest: &str) -> (PathBuf, PathBuf) {
    let (dir, osv) = (root.join("app"), root.join("osv"));
    std::fs::create_dir_all(&dir).unwrap();
    let deps: Vec<String> = packages
        .iter()
        .map(|(n, v)| format!("\"{n}\":\"{v}\""))
        .collect();
    let locked: Vec<String> = packages
        .iter()
        .map(|(n, v)| format!("\"node_modules/{n}\":{{\"version\":\"{v}\"}}"))
        .collect();
    std::fs::write(
        dir.join("package.json"),
        format!(
            r#"{{"name":"demo","version":"1.0.0","dependencies":{{{}}}}}"#,
            deps.join(",")
        ),
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        format!(
            r#"{{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"name":"demo","version":"1.0.0"}},{}}}}}"#,
            locked.join(",")
        ),
    )
    .unwrap();
    std::fs::write(dir.join("securevibe.toml"), manifest).unwrap();
    std::fs::create_dir_all(&osv).unwrap();
    std::fs::write(
        osv.join("GHSA-qs.json"),
        r#"{"id":"GHSA-qs","summary":"A vulnerability.","published":"2020-07-15T00:00:00Z",
            "affected":[{"package":{"ecosystem":"npm","name":"qs"},
            "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"99"}]}]}]}"#,
    )
    .unwrap();
    (dir, osv)
}

const NPM: &str =
    "manifest-version = 1\n[app]\nname = \"Audited\"\n[stack]\nlanguages = [\"javascript\"]\n";

#[test]
fn audit_keeps_0_1_and_2_and_its_errors_are_now_3() {
    let root = root("audit");
    let (dir, osv) = npm_app(&root, &[("express", "4.21.2")], NPM);
    let (clean, clean_said) = sv(&["audit", s(&dir), "--advisories", s(&osv)]);
    let (no_database, no_database_said) = sv(&["audit", s(&dir)]);
    let (dir2, osv2) = npm_app(&root.join("vulnerable"), &[("qs", "6.5.0")], NPM);
    let (found, found_said) = sv(&["audit", s(&dir2), "--advisories", s(&osv2)]);
    // What `sv` itself could not get past, which used to be 1 and read as a vulnerability.
    std::fs::write(dir.join("securevibe.toml"), "manifest-version = [\n").unwrap();
    let (bad_manifest, bad_manifest_said) = sv(&["audit", s(&dir), "--advisories", s(&osv)]);
    let (missing, missing_said) = sv(&["audit", s(&root.join("not-there"))]);
    let (no_such_database, no_such_said) =
        sv(&["audit", s(&dir2), "--advisories", s(&root.join("nowhere"))]);
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(clean, Some(0), "{clean_said}");
    assert_eq!(no_database, Some(2), "{no_database_said}");
    // Not assessed says where the list it needs is, for this app's own kind of package.
    assert!(
        no_database_said
            .contains("npm: https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip"),
        "{no_database_said}"
    );
    assert!(found_said.contains("qs 6.5.0"), "{found_said}");
    assert_eq!(found, Some(1), "{found_said}");
    assert_eq!(bad_manifest, Some(3), "{bad_manifest_said}");
    assert_eq!(missing, Some(3), "{missing_said}");
    assert!(missing_said.contains("is not a folder"), "{missing_said}");
    // Before, this was 1, the code for a known vulnerability.
    assert_eq!(no_such_database, Some(3), "{no_such_said}");
    assert!(
        no_such_said.contains("reading the advisory database"),
        "{no_such_said}"
    );
}

#[test]
fn the_help_says_what_each_status_means() {
    for command in ["check", "report", "audit", "run"] {
        let (code, said) = sv(&[command, "--help"]);
        assert_eq!(code, Some(0), "{said}");
        assert!(
            said.contains("exit status: 0"),
            "sv {command} --help: {said}"
        );
        assert!(
            said.contains("3 sv itself failed"),
            "sv {command} --help: {said}"
        );
    }
    let (_, said) = sv(&["--help"]);
    assert!(said.contains("EXIT STATUS:"), "{said}");
}
