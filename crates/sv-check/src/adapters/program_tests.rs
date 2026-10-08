//! The tests of `adapters.rs` that were `mod program_tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;
use std::os::unix::fs::PermissionsExt;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-program-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    dir
}

fn program(dir: &Path, relative: &str) -> PathBuf {
    let path = dir.join(relative);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

fn path_of(entries: &[&Path]) -> std::ffi::OsString {
    std::env::join_paths(entries).unwrap()
}

#[test]
fn a_program_is_found_through_path_outside_the_app_and_refused_inside_it() {
    let dir = scratch("where");
    let app = dir.join("app");
    let outside = program(&dir, "bin/tool");
    let inside = program(&dir, "app/.venv/bin/tool");
    let real_outside = outside.canonicalize().unwrap();
    let real_inside = inside.canonicalize().unwrap();
    // Outside first: found there.
    assert_eq!(
        located(
            "tool",
            &app,
            Some(&path_of(&[&dir.join("bin"), &app.join(".venv/bin")]))
        ),
        Located::At(real_outside.clone())
    );
    // The virtual environment first, as `source .venv/bin/activate` leaves PATH: refused.
    assert_eq!(
        located(
            "tool",
            &app,
            Some(&path_of(&[&app.join(".venv/bin"), &dir.join("bin")]))
        ),
        Located::InsideApp(real_inside.clone())
    );
    // A link outside the app to a program inside it is inside it.
    let linked = dir.join("linked");
    std::fs::create_dir_all(&linked).unwrap();
    std::os::unix::fs::symlink(&inside, linked.join("tool")).unwrap();
    assert_eq!(
        located("tool", &app, Some(&path_of(&[&linked]))),
        Located::InsideApp(real_inside.clone())
    );
    // A path rather than a name is judged the same way.
    assert_eq!(
        located(inside.to_str().unwrap(), &app, None),
        Located::InsideApp(real_inside)
    );
    assert_eq!(
        located(outside.to_str().unwrap(), &app, None),
        Located::At(real_outside)
    );
    // Nowhere: not on PATH, or there but not runnable.
    assert_eq!(
        located("tool", &app, Some(&path_of(&[&linked.join("no")]))),
        Located::Nowhere
    );
    assert_eq!(located("tool", &app, None), Located::Nowhere);
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        located("tool", &app, Some(&path_of(&[&dir.join("bin")]))),
        Located::Nowhere
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_relative_path_entry_is_never_used_and_is_named_when_it_is_the_only_way() {
    let dir = scratch("relative");
    let app = dir.join("app");
    program(&dir, "app/tool");
    let outside = program(&dir, "bin/tool");
    // `.` names the app's own folder once the tool is started there.
    assert_eq!(
        located("tool", &app, Some(std::ffi::OsStr::new("."))),
        Located::OnlyRelative(".".to_owned())
    );
    // An empty entry (`:bin:`) is `.` too.
    let mut with_empty = std::ffi::OsString::new();
    with_empty.push("");
    with_empty.push(":");
    with_empty.push(dir.join("nowhere"));
    assert_eq!(
        located("tool", &app, Some(&with_empty)),
        Located::OnlyRelative(".".to_owned())
    );
    // With an absolute entry that has it, the relative one is skipped and the absolute one
    // used, whatever the order.
    let mut both = std::ffi::OsString::new();
    both.push(".:");
    both.push(dir.join("bin"));
    assert_eq!(
        located("tool", &app, Some(&both)),
        Located::At(outside.canonicalize().unwrap())
    );
    // A relative entry naming nothing is simply nowhere.
    std::fs::remove_file(app.join("tool")).unwrap();
    assert_eq!(
        located("tool", &app, Some(std::ffi::OsStr::new("."))),
        Located::Nowhere
    );
    std::fs::remove_dir_all(&dir).ok();
}
