//! gosec, run through `sv`, runs no C compiler, downloads none of the app's modules, says which
//! files it read, and is not run over an app that holds a link (the review of 8 October 2026,
//! item 3). Each guard has a control that runs gosec bare, the way the entry ran it before, and
//! shows the thing happening.
//!
//! Needs the real gosec: without it on `PATH` this says so and checks nothing. Run here on 8
//! October 2026 with gosec 2.22.9 and Go 1.24.7. The one test in this file changes the process's
//! environment (`PATH`, and where Go keeps modules), which is why it has a file of its own.

// Unix only: its stand-in `gcc` is a shell script, and it makes symbolic links (backlog 0120).
#![cfg(unix)]

mod scratch;

use scratch::Scratch;
use std::path::{Path, PathBuf};
use std::process::Command;
use sv_check::adapters::{self, Adapters, Outcome};
use sv_check::secrets::SecretRules;

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn secret_rules() -> SecretRules {
    SecretRules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"))
        .unwrap()
}

/// A Go module at `dir` with the given files.
fn module(dir: &Path, name: &str, files: &[(&str, &str)]) -> PathBuf {
    let app = dir.join(name);
    std::fs::create_dir_all(&app).unwrap();
    std::fs::write(
        app.join("go.mod"),
        format!("module example.com/{name}\n\ngo 1.22\n"),
    )
    .unwrap();
    for (file, text) in files {
        std::fs::write(app.join(file), text).unwrap();
    }
    app
}

/// gosec run bare in `app`, as the entry ran it before 8 October 2026: the owner's `PATH`, no
/// `GOPROXY` or `CGO_ENABLED`, writing its report to `out`.
fn bare(app: &Path, out: &Path, modcache: &Path, gocache: &Path) -> Option<i32> {
    Command::new("gosec")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", std::env::var_os("HOME").unwrap_or_default())
        .env("GOTOOLCHAIN", "local")
        .env("GOMODCACHE", modcache)
        .env("GOCACHE", gocache)
        .args(["-fmt", "sarif", "-out"])
        .arg(out)
        .args(["-tests", "-track-suppressions", "./..."])
        .current_dir(app)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()
        .and_then(|s| s.code())
}

/// The files a SARIF report's results point at.
fn reported_files(sarif: &Path) -> Vec<String> {
    let Ok(text) = std::fs::read_to_string(sarif) else {
        return Vec::new();
    };
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let mut files: Vec<String> = v["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    files.sort();
    files.dedup();
    files
}

/// How many module archives a module cache holds: what a download leaves behind. With downloads
/// off, Go still writes a lock file where the module would go, which is not one.
fn archives(cache: &Path) -> usize {
    fn walk(dir: &Path, count: &mut usize) {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, count);
            } else if path.extension().is_some_and(|e| e == "zip") {
                *count += 1;
            }
        }
    }
    let mut count = 0;
    walk(cache, &mut count);
    count
}

#[test]
fn gosec_runs_no_c_compiler_downloads_nothing_says_what_it_read_and_follows_no_link() {
    let adapters = Adapters::load(&real_adapters()).unwrap();
    let gosec = adapters
        .all()
        .iter()
        .find(|a| a.id == "gosec")
        .unwrap()
        .clone();
    if !adapters::is_installed(&gosec) {
        println!("gosec is not installed here; the real run is skipped");
        return;
    }
    let dir = Scratch::new("gosec-fence");
    // A `gcc` that leaves a mark, first on the PATH for everything below, bare and through `sv`
    // (which passes `PATH` on). Go's cgo starts `gcc` by that name.
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let mark = dir.join("gcc-ran");
    std::fs::write(
        bin.join("gcc"),
        format!("#!/bin/sh\necho ran >> '{}'\nexit 1\n", mark.display()),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(bin.join("gcc"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::var("PATH").unwrap();
    let modcache = dir.join("modcache");
    let gocache = dir.join("gocache");
    // The one test in this binary, so the process environment is its own to set.
    unsafe {
        std::env::set_var("PATH", format!("{}:{path}", bin.display()));
        std::env::set_var("GOMODCACHE", &modcache);
        std::env::set_var("GOCACHE", &gocache);
    }

    // 1. The C compiler. A file that uses cgo beside a plain one.
    let cgo = module(
        &dir,
        "cgo",
        &[
            (
                "native.go",
                "package main\n\n/*\n#include <stdlib.h>\n*/\nimport \"C\"\n\nfunc native() { _ = C.rand() }\n",
            ),
            (
                "main.go",
                "package main\n\nimport \"crypto/md5\"\n\nfunc main() { _ = md5.New() }\n",
            ),
        ],
    );
    bare(&cgo, &dir.join("cgo-bare.sarif"), &modcache, &gocache);
    assert!(
        mark.exists(),
        "the control: gosec run bare over a cgo file starts the C compiler"
    );
    std::fs::remove_file(&mark).unwrap();
    let outcome = adapters::run_one(&gosec, &cgo, &dir.join("cgo.sarif"), &secret_rules());
    assert!(
        !mark.exists(),
        "through `sv`, the C compiler is never started"
    );
    let Outcome::Ran {
        findings,
        looked_away,
        ..
    } = &outcome
    else {
        panic!("{outcome:?}");
    };
    assert!(
        findings.iter().any(|f| f.rule_id == "gosec.G401"),
        "the plain file is still read: {findings:?}"
    );
    assert!(
        looked_away
            .iter()
            .any(|r| r.contains("does not say it read 1 of the 2 go files")
                && r.contains("`native.go`")),
        "the cgo file, left out of the build, is said to be unread: {looked_away:?}"
    );

    // 2. The modules. An app depending on a module that is not in the (empty) module cache.
    let deps = module(
        &dir,
        "deps",
        &[
            (
                "main.go",
                "package main\n\nimport (\n\t\"crypto/md5\"\n\t\"fmt\"\n\n\t\"golang.org/x/text/cases\"\n\t\"golang.org/x/text/language\"\n)\n\nfunc main() {\n\tfmt.Println(cases.Title(language.English).String(\"hello\"), md5.New())\n}\n",
            ),
            (
                "go.sum",
                "golang.org/x/text v0.3.8 h1:nAL+RVCQ9uMn3vJZbV+MRnydTJFPf8qqY42YiA6MrqY=\ngolang.org/x/text v0.3.8/go.mod h1:E6s5w1FMmriuDzIBO73fBruAKo1PCIq6d2Q6DHfQ8WQ=\n",
            ),
        ],
    );
    std::fs::write(
        deps.join("go.mod"),
        "module example.com/deps\n\ngo 1.22\n\nrequire golang.org/x/text v0.3.8\n",
    )
    .unwrap();
    std::fs::remove_dir_all(&modcache).ok();
    bare(&deps, &dir.join("deps-bare.sarif"), &modcache, &gocache);
    let downloaded = archives(&modcache) > 0;
    if !downloaded {
        println!("the download control could not be shown here (no way to the module proxy)");
    }
    std::fs::remove_dir_all(&modcache).ok();
    let outcome = adapters::run_one(&gosec, &deps, &dir.join("deps.sarif"), &secret_rules());
    assert_eq!(
        archives(&modcache),
        0,
        "through `sv`, nothing is downloaded"
    );
    let Outcome::Ran {
        findings,
        looked_away,
        ..
    } = &outcome
    else {
        panic!("{outcome:?}");
    };
    assert!(
        findings.iter().any(|f| f.rule_id == "gosec.G401"),
        "its rules still read the code: {findings:?}"
    );
    assert!(
        looked_away
            .iter()
            .any(|r| r.contains("deeper analyzers") && r.contains("go mod download")),
        "and the analyzers that could not run are said: {looked_away:?}"
    );

    // 3. The link. A linked `.go` file pointing outside the app.
    let outside = dir.join("outside.go");
    std::fs::write(
        &outside,
        "package main\n\nimport \"crypto/sha1\"\n\nfunc outside() { _ = sha1.New() }\n",
    )
    .unwrap();
    let linked = module(
        &dir,
        "linked",
        &[("main.go", "package main\n\nfunc main() {}\n")],
    );
    std::os::unix::fs::symlink(&outside, linked.join("linked.go")).unwrap();
    let bare_report = dir.join("linked-bare.sarif");
    bare(&linked, &bare_report, &modcache, &gocache);
    assert_eq!(
        reported_files(&bare_report),
        ["linked.go"],
        "the control: gosec run bare reads through the link and reports the file outside"
    );
    let outcome = adapters::run_one(&gosec, &linked, &dir.join("linked.sarif"), &secret_rules());
    let Outcome::NotRun { why } = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(
        why.contains("follows a link") && why.contains("`linked.go`"),
        "{why}"
    );
    unsafe {
        std::env::set_var("PATH", path);
        std::env::remove_var("GOMODCACHE");
        std::env::remove_var("GOCACHE");
    }
}
