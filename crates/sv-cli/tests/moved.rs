//! A copy of `sv` moved out of its build folder, with its data beside it (ADR-036).
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// A scratch folder of this test's own.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-moved-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

fn repository_data() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .canonicalize()
        .unwrap()
}

fn data_line(program: &Path, env: Option<&Path>) -> String {
    let mut command = Command::new(program);
    command.arg("--version").env_remove("SV_DATA_DIR");
    if let Some(dir) = env {
        command.env("SV_DATA_DIR", dir);
    }
    let out = command.output().unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("data: ").map(str::to_owned))
        .unwrap_or_else(|| panic!("no data line: {out:?}"))
}

#[test]
fn a_copy_of_sv_reads_the_data_beside_it_and_checks_an_app_with_it() {
    // An install: the program in a folder of its own with its data, reached through a link from
    // somewhere else, as `~/.local/bin/sv` reaches `~/.local/share/securevibe/sv`.
    let root = scratch("installed");
    let home = root.join("share/securevibe");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::copy(env!("CARGO_BIN_EXE_sv"), home.join("sv")).unwrap();
    copy_tree(&repository_data(), &home.join("data"));
    std::fs::create_dir_all(root.join("bin")).unwrap();
    std::os::unix::fs::symlink(home.join("sv"), root.join("bin/sv")).unwrap();
    let linked = root.join("bin/sv");

    let said = data_line(&linked, None);
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/flask-booking");
    let checked = Command::new(&linked)
        .args(["check"])
        .arg(&app)
        .env_remove("SV_DATA_DIR")
        .output()
        .unwrap();
    // And `SV_DATA_DIR` still comes first.
    let chosen = data_line(&linked, Some(&repository_data()));
    std::fs::remove_dir_all(&root).ok();

    assert_eq!(
        Path::new(&said),
        home.join("data")
            .canonicalize()
            .unwrap_or(home.join("data")),
        "the copy read some other data"
    );
    assert!(
        checked.status.code().is_some_and(|c| c < 3),
        "the copy could not check an app: {}",
        String::from_utf8_lossy(&checked.stderr)
    );
    assert_eq!(Path::new(&chosen), repository_data());
}

#[test]
fn a_wrong_sv_data_dir_is_named_and_stops_a_check() {
    let root = scratch("wrong");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["check"])
        .arg(&root)
        .env("SV_DATA_DIR", root.join("nothing-here"))
        .output()
        .unwrap();
    std::fs::remove_dir_all(&root).ok();
    let said = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{said}");
    assert!(
        said.contains("SV_DATA_DIR") && said.contains("nothing-here"),
        "{said}"
    );
}

#[test]
fn nothing_but_the_data_finder_reads_from_the_build_folder_at_run_time() {
    // Every `env!("CARGO_MANIFEST_DIR")` outside a test module would be a file read from the build
    // folder whatever `SV_DATA_DIR` or the program's place says, which is the fault this fixed. The
    // test modules and `crates/sv-frameworks/src/data.rs` itself may name it.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut found = Vec::new();
    let mut stack = vec![crates.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                // Only each crate's `src`: `tests/` and `build.rs` run where the source is.
                if dir == crates
                    || name == "src"
                    || dir.components().any(|c| c.as_os_str() == "src")
                {
                    stack.push(path);
                }
                continue;
            }
            if !path.extension().is_some_and(|e| e == "rs")
                || path.ends_with("sv-frameworks/src/data.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Each top-level `#[cfg(test)] mod … {` (or `#[cfg(all(test, …))]`) is skipped to its closing `}` at the margin: one
            // followed by the end of the file or by another item, not by more of a string that
            // happens to hold a `}` line.
            let lines: Vec<&str> = text.lines().collect();
            let item_follows = |n: usize| {
                lines[n + 1..]
                    .iter()
                    .find(|l| !l.trim().is_empty())
                    .is_none_or(|next| {
                        [
                            "#[",
                            "#!",
                            "//",
                            "pub",
                            "fn ",
                            "mod ",
                            "use ",
                            "const ",
                            "static ",
                            "struct ",
                            "enum ",
                            "impl",
                            "type ",
                            "macro_rules!",
                        ]
                        .iter()
                        .any(|start| next.starts_with(start))
                    })
            };
            let mut in_test = false;
            for (n, line) in lines.iter().enumerate() {
                if !in_test
                    && line.starts_with("#[cfg(")
                    && line.contains("test")
                    && lines
                        .get(n + 1)
                        .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
                {
                    in_test = true;
                } else if in_test && *line == "}" && item_follows(n) {
                    in_test = false;
                } else if !in_test && line.contains("env!(\"CARGO_MANIFEST_DIR\")") {
                    found.push(format!("{}:{}", path.display(), n + 1));
                }
            }
        }
    }
    assert!(found.len() < 1000, "the walk went somewhere it should not");
    assert!(
        found.is_empty(),
        "read from the build folder at run time: {found:#?}"
    );
}

#[test]
fn the_install_script_puts_sv_and_its_data_in_a_folder_of_their_own() {
    // `tools/install.sh`, with the program already built (`SV_BINARY`) and a folder of the test's own
    // in place of `~/.local` (`SV_PREFIX`).
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/install.sh");
    let root = scratch("script");
    let install = || {
        Command::new("sh")
            .arg(&script)
            .env("SV_PREFIX", &root)
            .env("SV_BINARY", env!("CARGO_BIN_EXE_sv"))
            .env_remove("SV_DATA_DIR")
            .output()
            .unwrap()
    };
    let first = install();
    let home = root.join("share/securevibe");
    let said = data_line(&root.join("bin/sv"), None);
    // Again, as after pulling a newer sv: the same link, and the data replaced whole.
    std::fs::write(home.join("data/left-over.json"), "{}").unwrap();
    let again = install();
    let left_over = home.join("data/left-over.json").exists();
    // A file at bin/sv that the installer did not put there is left alone.
    std::fs::remove_file(root.join("bin/sv")).unwrap();
    std::fs::write(root.join("bin/sv"), "the owner's own").unwrap();
    let refused = install();
    let kept = std::fs::read_to_string(root.join("bin/sv")).unwrap_or_default();
    std::fs::remove_dir_all(&root).ok();

    assert!(first.status.success(), "{first:?}");
    assert_eq!(
        Path::new(&said),
        home.join("data")
            .canonicalize()
            .unwrap_or(home.join("data"))
    );
    assert!(again.status.success(), "{again:?}");
    assert!(!left_over, "an older install's data was kept");
    assert!(!refused.status.success(), "{refused:?}");
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("is not this installer's link"),
        "{refused:?}"
    );
    assert_eq!(kept, "the owner's own");
}
