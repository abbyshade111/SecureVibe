//! The holder file beside the lock (backlog 0120, ADR-041, Later): another run names the run
//! holding the folder from it, which on Windows it cannot read from the locked file, and a run knows
//! its own lock by it where the system cannot tell one file from another.

use super::*;

fn folder(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-lock-holder-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn the_holder_file_names_the_run_while_it_holds_the_folder_and_goes_with_it() {
    let dir = folder("named");
    let held = take(&dir, "sv report --run", "give --out").unwrap();
    let holder = std::fs::read_to_string(dir.join(HOLDER_NAME)).expect("written while held");
    assert!(
        holder.contains(&format!("\"process\": {}", std::process::id())),
        "{holder}"
    );
    assert!(holder.contains("`sv report --run`") || holder.contains("sv report --run"));
    drop(held);
    assert!(!dir.join(HOLDER_NAME).exists(), "removed with the lock");
    assert!(!dir.join(LOCK_NAME).exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_second_run_names_the_first_from_the_holder_file_alone() {
    // What Windows does to the second run, played here: the locked file reads as nothing to it.
    let dir = folder("unreadable");
    let first = take(&dir, "sv report --run --tools", "give --out").unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join(LOCK_NAME))
        .unwrap()
        .set_len(0)
        .unwrap();
    let second = take(&dir, "sv report", "give --out")
        .err()
        .expect("the folder is held")
        .to_string();
    assert!(second.contains("`sv report --run --tools`"), "{second}");
    assert!(
        second.contains(&format!("(process {})", std::process::id())),
        "{second}"
    );
    drop(first);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_lock_from_before_the_holder_file_is_still_named_when_taken_over() {
    // An `sv` from before this wrote its record into the lock file alone.
    let dir = folder("old");
    std::fs::write(
        dir.join(LOCK_NAME),
        r#"{"command": "sv report", "process": 4242, "started": "2026-10-01T09:00:00Z"}"#,
    )
    .unwrap();
    let held = take(&dir, "sv report", "give --out").unwrap();
    assert_eq!(held.notes.len(), 1, "{:?}", held.notes);
    assert!(held.notes[0].contains("(process 4242)"), "{:?}", held.notes);
    drop(held);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_holder_file_that_is_a_link_is_refused_and_its_target_left_alone() {
    let dir = folder("link");
    std::fs::write(dir.join("theirs"), "theirs").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(dir.join("theirs"), dir.join(HOLDER_NAME)).unwrap();
        let refused = take(&dir, "sv report", "give --out")
            .err()
            .expect("a link is refused")
            .to_string();
        assert!(refused.contains("not a plain file"), "{refused}");
        assert_eq!(
            std::fs::read_to_string(dir.join("theirs")).unwrap(),
            "theirs"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn outside_unix_a_run_knows_its_lock_by_the_record_it_wrote() {
    let record = "{\n  \"process\": 7\n}\n";
    assert!(holds_record(Some(record), record));
    // Another run's record, an emptied file, or none at all: not this run's.
    assert!(!holds_record(Some("{\n  \"process\": 8\n}\n"), record));
    assert!(!holds_record(Some(""), record));
    assert!(!holds_record(None, record));
}

#[test]
fn ctrl_c_removes_the_holder_file_only_with_this_runs_lock() {
    let dir = folder("ctrl-c");
    let held = take(&dir, "sv report", "give --out").unwrap();
    let mine = live()
        .iter()
        .find(|(lock, _, _)| *lock == dir.join(LOCK_NAME))
        .and_then(|(_, _, mine)| mine.clone())
        .expect("this run's lock is known");
    // Another run's lock and holder in their place: neither is removed.
    std::mem::forget(held);
    live().retain(|(lock, _, _)| *lock != dir.join(LOCK_NAME));
    std::fs::rename(dir.join(LOCK_NAME), dir.join("moved-aside")).unwrap();
    std::fs::write(dir.join(LOCK_NAME), "{}").unwrap();
    std::fs::write(dir.join(HOLDER_NAME), "{\"process\": 1}\n").unwrap();
    let_go_of(vec![(dir.join(LOCK_NAME), Undo::default(), Some(mine))]);
    assert!(dir.join(LOCK_NAME).exists(), "another run's lock is left");
    assert!(dir.join(HOLDER_NAME).exists(), "and its holder file");
    std::fs::remove_dir_all(&dir).ok();
}
