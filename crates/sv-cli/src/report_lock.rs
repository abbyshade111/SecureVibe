//! One run at a time in a report folder, and no older report replacing a newer one.
//!
//! On family-hub (3 October 2026) the owner and their AI coding tool each ran `sv report --run
//! --tools` on the app at about the same time. Both wrote `<app>/securevibe-report`; the AI tool's
//! run succeeded, and the owner's finished two minutes later with a failure and replaced the good
//! report with the failed one, with nothing anywhere to say so (BACKLOG, "What the owner hit
//! building family-hub", item 2). Three things here:
//!
//! - **A lock in the folder** (`LOCK_NAME`), taken before the run starts and let go when it ends. A
//!   second run refuses at once, naming the run that holds the folder: its command, process number,
//!   and when it started. It refuses rather than waits: a run takes minutes, and a command that sits
//!   silent for minutes because of another nobody remembers starting looks stuck.
//! - **A lock a killed run left behind does not block.** The lock is the operating system's own
//!   (`File::try_lock`), which it lets go when the process ends however it ends, `kill -9`
//!   included, so whether the holder is still running is the operating system's answer rather than a
//!   guess from a process number, which can be reused or belong to another machine or container. The
//!   lock file still says who held it, so the next run says that run stopped before it finished.
//! - **A record in `report.json`** (`sv_report::RunRecord`) of when the run started and the hash of
//!   the `stackvet.toml` it read. Before writing, a run reads the report it would replace; if that
//!   one came from a run that started later, it keeps the newer report and says so. With the lock
//!   this happens only where the lock could not hold: a disk without locks, or a run of an `sv` from
//!   before this.

use anyhow::{Context, Result, bail};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The lock's name in the report folder, from the one list of the folder's names.
pub const LOCK_NAME: &str = sv_scan::ecosystems::REPORT_LOCK;

/// The record of a run that started at `started` and read `manifest` as its `stackvet.toml`.
pub fn run_record(started: SystemTime, manifest: &[u8]) -> sv_report::RunRecord {
    let ms = millis(started);
    sv_report::RunRecord {
        started: crate::bundle::utc_time(ms / 1000),
        started_unix_ms: ms,
        securevibe_toml_sha256: crate::bundle::sha256(manifest),
    }
}

fn millis(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// A report folder this run holds. Dropping it lets the folder go and removes the lock file, and,
/// unless `written` was called, takes away what taking the folder added (`undo_unless_written`).
pub struct Held {
    /// `None` where the disk would not lock, in which case `notes` says so.
    file: Option<File>,
    path: PathBuf,
    /// What the person should be told about taking the folder: a run before this one that stopped
    /// without finishing, or a disk that cannot lock. Said by the caller, since the MCP server must
    /// not print.
    pub notes: Vec<String>,
}

/// What a run that ends without a report takes away: the marker it wrote, and the folder it made,
/// if nothing else is in it. A run stopped with Ctrl-C, or one that failed, wrote no report, and
/// the folder is left as it was before (`interrupt.rs` holds this for Ctrl-C).
#[derive(Default)]
struct Undo {
    marker: Option<PathBuf>,
    folder: Option<PathBuf>,
}

impl Undo {
    fn apply(&self) {
        if let Some(marker) = &self.marker {
            let _ = std::fs::remove_file(marker);
        }
        if let Some(folder) = &self.folder {
            // Only an empty folder goes; anything else in it is left.
            let _ = std::fs::remove_dir(folder);
        }
    }
}

/// The folders this process holds, by their lock's path, with what to undo for each. Kept so that
/// `let_go_of_all` can let them go on the way out of a run stopped with Ctrl-C, which leaves through
/// `std::process::exit`, where nothing is dropped.
static LIVE: std::sync::Mutex<Vec<Live>> = std::sync::Mutex::new(Vec::new());

/// A folder this process holds: its lock's path, what to undo, and the lock file as this run
/// opened and locked it, when the disk could lock it.
type Live = (PathBuf, Undo, Option<Metadata>);

fn live() -> std::sync::MutexGuard<'static, Vec<Live>> {
    LIVE.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl Held {
    /// What to take away if the run ends without a report: `marker`, a file taking the folder
    /// wrote, and `folder`, if taking it made the folder.
    pub fn undo_unless_written(&self, marker: Option<PathBuf>, folder: Option<PathBuf>) {
        if let Some(entry) = live().iter_mut().find(|(lock, _, _)| *lock == self.path) {
            entry.1 = Undo { marker, folder };
        }
    }

    /// The report is written: what taking the folder added stays.
    pub fn written(&self) {
        self.undo_unless_written(None, None);
    }
}

/// Lets go of every folder this process holds, removing their locks and undoing what taking them
/// added. For a run leaving through `std::process::exit`.
pub fn let_go_of_all() {
    let_go_of(live().drain(..).collect());
}

/// Lets go of these folders. A lock is removed only when its name is still the file this run locked,
/// as `Drop` does: where the disk could not lock, or another run has since put its own lock there,
/// the file is another run's, and removing it on Ctrl-C would leave that run's folder open to a
/// third (item 24 of the review of 1 to 4 October).
fn let_go_of(held: Vec<Live>) {
    for (lock, undo, opened) in held {
        if let (Some(opened), Ok(on_disk)) = (opened, std::fs::symlink_metadata(&lock))
            && same_file(&on_disk, &opened)
        {
            let _ = std::fs::remove_file(&lock);
        }
        undo.apply();
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let undo = {
            let mut live = live();
            live.iter()
                .position(|(lock, _, _)| *lock == self.path)
                .map(|at| live.remove(at).1)
                .unwrap_or_default()
        };
        if let Some(file) = self.file.take() {
            // Removed while still locked, and only if the name is still this file, so a run that
            // opened the old file and is waiting to lock it finds, once it has, that the name is
            // gone, and starts again with a new one (`take`).
            if let (Ok(on_disk), Ok(opened)) =
                (std::fs::symlink_metadata(&self.path), file.metadata())
                && same_file(&on_disk, &opened)
            {
                let _ = std::fs::remove_file(&self.path);
            }
            drop(file);
        }
        undo.apply();
    }
}

fn held(file: Option<File>, path: PathBuf, notes: Vec<String>) -> Held {
    let opened = file.as_ref().and_then(|f| f.metadata().ok());
    live().push((path.clone(), Undo::default(), opened));
    Held { file, path, notes }
}

/// Takes `out_dir` for this run, or says which run holds it.
///
/// `command` is what this run is, as another run would be told it (`sv report --run`). `elsewhere`
/// finishes the sentence "wait for it to finish, or ..." in the words of whoever is asking: `--out`
/// for the command, `out` for the MCP server. The folder exists, is not a link, and is `sv`'s own;
/// the caller has checked.
pub fn take(out_dir: &Path, command: &str, elsewhere: &str) -> Result<Held> {
    let path = out_dir.join(LOCK_NAME);
    // A few times round: each turn ends only because another run let the folder go between this one
    // opening the lock file and locking it.
    for _ in 0..8 {
        let mut file = open(&path)?;
        match file.try_lock() {
            Ok(()) => {
                let (Ok(on_disk), Ok(opened)) = (std::fs::symlink_metadata(&path), file.metadata())
                else {
                    continue;
                };
                if !same_file(&on_disk, &opened) {
                    // The run that held it removed the name after this one opened it.
                    continue;
                }
                let before = read_holder(&mut file);
                let mine = serde_json::json!({
                    "command": command,
                    "process": std::process::id(),
                    "started": crate::bundle::utc_time(millis(SystemTime::now()) / 1000),
                    "started_unix_ms": millis(SystemTime::now()),
                });
                file.set_len(0)
                    .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
                    .and_then(|()| file.write_all(format!("{mine:#}\n").as_bytes()))
                    .and_then(|()| file.sync_all())
                    .with_context(|| format!("{} could not be written", path.display()))?;
                let mut notes = Vec::new();
                if let Some(before) = before {
                    notes.push(format!(
                        "An earlier run, {}, stopped before it finished and left its lock in {}. \
                         Nothing is running there now (the computer lets go of a lock when the run \
                         that held it ends), so this run took the folder over. A report that run \
                         left there may be part-written; this run's replaces it.",
                        describe(&before),
                        out_dir.display()
                    ));
                }
                return Ok(held(Some(file), path, notes));
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                let holder = read_holder(&mut file);
                bail!(
                    "Another sv run is writing its report to {}: {}. sv does not write a report \
                     there at the same time, because the run that finished last would replace the \
                     other's report, even a failed run replacing a good one. Wait for that run to \
                     finish and run this again, or {elsewhere}.",
                    out_dir.display(),
                    holder.map_or_else(
                        || "it has not yet said which run it is".to_owned(),
                        |h| describe(&h)
                    )
                );
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Ok(held(
                    None,
                    path,
                    vec![format!(
                        "The disk {} is on would not lock the folder ({e}), so nothing kept another \
                         run from writing there at the same time. The report records when this run \
                         started, and a run does not replace a report from a run that started after it.",
                        out_dir.display()
                    )],
                ));
            }
        }
    }
    bail!(
        "{} kept being taken and let go by other runs, so this run did not write its report there. \
         Run it again, or {elsewhere}.",
        out_dir.display()
    )
}

/// Opens the lock file, making it if it is not there, never through a link.
fn open(path: &Path) -> Result<File> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(file) => return Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("{} could not be made", path.display())),
    }
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("{} could not be read", path.display()))?;
    anyhow::ensure!(
        meta.is_file(),
        "{} is not a plain file (it is a link, or a folder), so sv does not use it. Remove it, \
         and run again.",
        path.display()
    );
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .with_context(|| format!("{} could not be opened", path.display()))
}

/// Who wrote the lock, if anyone did. An empty file, or one that does not read, is nobody yet.
fn read_holder(file: &mut File) -> Option<serde_json::Value> {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0)).ok()?;
    file.take(64 * 1024).read_to_string(&mut text).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value.is_object().then_some(value)
}

/// `` `sv report --run` (process 4321), which started at 2026-10-04T18:55:02Z, 3 minutes ago ``.
fn describe(holder: &serde_json::Value) -> String {
    let command = holder["command"].as_str().unwrap_or("an sv run");
    let process = holder["process"]
        .as_u64()
        .map_or_else(String::new, |p| format!(" (process {p})"));
    let started = holder["started"].as_str().map_or_else(String::new, |s| {
        let ago = holder["started_unix_ms"]
            .as_u64()
            .and_then(|then| millis(SystemTime::now()).checked_sub(then))
            .map_or_else(String::new, |ms| format!(", {}", ago(ms / 1000)));
        format!(", which started at {s}{ago}")
    });
    format!("`{command}`{process}{started}")
}

fn ago(seconds: u64) -> String {
    match seconds {
        0..60 => "less than a minute ago".to_owned(),
        60..120 => "a minute ago".to_owned(),
        _ if seconds < 2 * 3600 => format!("{} minutes ago", seconds / 60),
        _ => format!("{} hours ago", seconds / 3600),
    }
}

#[cfg(unix)]
fn same_file(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino() && a.file_type().is_file()
}

#[cfg(not(unix))]
fn same_file(a: &Metadata, _b: &Metadata) -> bool {
    a.file_type().is_file()
}

/// How far ahead of this computer's clock a report's start may be and still be believed: clocks
/// on one computer agree to well within this, and a run cannot have started in the future.
const CLOCK_SKEW_MS: u64 = 60_000;

/// Refuses to replace a report in `out_dir` that came from a run that started after this one.
///
/// A report without a record, or that does not read, is replaced as before: there is nothing to say
/// it is newer. Nor is one whose run would have started in the future, by this computer's clock: no
/// run did, and believing it kept every later run from writing its report there, for good (item 9
/// of the review of 1 to 4 October).
pub fn refuse_older(report: &sv_report::Report, out_dir: &Path, elsewhere: &str) -> Result<()> {
    let Some(mine) = &report.run_record else {
        return Ok(());
    };
    refuse_older_than(mine, millis(SystemTime::now()), out_dir, elsewhere)
}

/// `refuse_older` for a run with this record, at `now_ms` by this computer's clock.
fn refuse_older_than(
    mine: &sv_report::RunRecord,
    now_ms: u64,
    out_dir: &Path,
    elsewhere: &str,
) -> Result<()> {
    let path = out_dir.join("report.json");
    // A link is refused when the report is written; it is not followed to read one either.
    let Ok(meta) = std::fs::symlink_metadata(&path) else {
        return Ok(());
    };
    if !meta.is_file() {
        return Ok(());
    }
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let Ok(there) = serde_json::from_str::<serde_json::Value>(&text) else {
        return Ok(());
    };
    let record = &there["run_record"];
    let Some(their_start) = record["started_unix_ms"].as_u64() else {
        return Ok(());
    };
    if their_start <= mine.started_unix_ms || their_start > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Ok(());
    }
    let same_file = match record["securevibe_toml_sha256"].as_str() {
        Some(theirs) if theirs == mine.securevibe_toml_sha256 => {
            "Both runs read the same stackvet.toml."
        }
        Some(_) => {
            "The two runs read different versions of stackvet.toml, so the one there is of the \
             newer file."
        }
        None => "",
    };
    bail!(
        "{} already holds a report from a run that started at {}, after this one (which started at \
         {}). This run's report is the older of the two, so sv kept the newer one and did not write \
         this run's. {same_file} Run again for a fresh report, or {elsewhere}.",
        out_dir.display(),
        record["started"].as_str().unwrap_or("a later time"),
        mine.started,
    )
}

/// What to say when `stackvet.toml` changed while the run was going, if it did: the report is of
/// the file as it was when the run started, and a person reading it beside the file should know. A
/// sentence for the terminal, and the same as a gap for the report.
pub fn manifest_changed(
    report: &sv_report::Report,
    app_dir: &Path,
) -> Option<(String, sv_report::Gap)> {
    let mine = report.run_record.as_ref()?;
    let now = std::fs::read(sv_manifest::locate(app_dir).ok()??.path).ok()?;
    if crate::bundle::sha256(&now) == mine.securevibe_toml_sha256 {
        return None;
    }
    let changed = format!(
        "changed while this check ran, so this report is of the file as it was when the run \
         started ({}), not as it is now. Run the check again to check the file as it is",
        mine.started
    );
    Some((
        format!("Note: stackvet.toml {changed}."),
        sv_report::Gap {
            what: "stackvet.toml as it is now".to_owned(),
            why: format!("it {changed}"),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-lock-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_second_take_is_refused_and_names_the_first() {
        let dir = folder("second");
        let first = take(&dir, "sv report --run --tools", "give --out").unwrap();
        assert!(first.notes.is_empty(), "{:?}", first.notes);
        assert!(dir.join(LOCK_NAME).is_file(), "the lock is there to find");
        // A second open of the file is a second lock to the operating system, in this process as
        // in another.
        let second = take(&dir, "sv report", "give --out")
            .err()
            .expect("the folder is held")
            .to_string();
        assert!(second.contains("Another sv run"), "{second}");
        assert!(second.contains("`sv report --run --tools`"), "{second}");
        assert!(
            second.contains(&format!("(process {})", std::process::id())),
            "{second}"
        );
        assert!(second.contains("give --out"), "{second}");
        drop(first);
        assert!(!dir.join(LOCK_NAME).exists(), "let go, and removed");
        let third = take(&dir, "sv report", "give --out").expect("free again");
        assert!(third.notes.is_empty(), "{:?}", third.notes);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lock_left_by_a_run_that_ended_does_not_block_and_is_said() {
        let dir = folder("stale");
        // What a killed run leaves: its record, and no lock held on it.
        std::fs::write(
            dir.join(LOCK_NAME),
            r#"{"command": "sv report --run", "process": 99999, "started": "2026-10-03T18:53:00Z", "started_unix_ms": 1790967180000}"#,
        )
        .unwrap();
        let held = take(&dir, "sv report", "give --out").expect("not held by anyone");
        assert_eq!(held.notes.len(), 1, "{:?}", held.notes);
        let note = &held.notes[0];
        assert!(note.contains("stopped before it finished"), "{note}");
        assert!(note.contains("`sv report --run` (process 99999)"), "{note}");
        assert!(note.contains("2026-10-03T18:53:00Z"), "{note}");
        let now = std::fs::read_to_string(dir.join(LOCK_NAME)).unwrap();
        assert!(
            now.contains(&format!("\"process\": {}", std::process::id())),
            "{now}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_link_where_the_lock_goes_is_refused() {
        let dir = folder("link");
        std::fs::write(dir.join("elsewhere"), "theirs").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere"), dir.join(LOCK_NAME)).unwrap();
        let refused = take(&dir, "sv report", "give --out")
            .err()
            .expect("a link is refused")
            .to_string();
        assert!(refused.contains("not a plain file"), "{refused}");
        assert_eq!(
            std::fs::read_to_string(dir.join("elsewhere")).unwrap(),
            "theirs"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_report_from_a_later_run_is_kept_and_one_from_the_future_is_not() {
        let dir = folder("future");
        let now = 1_791_053_580_000;
        let mine = sv_report::RunRecord {
            started: "2026-10-03T18:52:00Z".into(),
            started_unix_ms: now - 60_000,
            securevibe_toml_sha256: "a".repeat(64),
        };
        let there = |start: u64| {
            std::fs::write(
                dir.join("report.json"),
                serde_json::json!({ "run_record": {
                    "started": "then", "started_unix_ms": start,
                    "securevibe_toml_sha256": "a".repeat(64),
                }})
                .to_string(),
            )
            .unwrap();
            refuse_older_than(&mine, now, &dir, "give --out")
        };
        // A run that started after this one and before now: the report there is the newer, kept.
        let kept = there(now - 30_000).expect_err("refused").to_string();
        assert!(kept.contains("kept the newer one"), "{kept}");
        // Within a minute of now still counts, for clocks that read a little apart.
        assert!(there(now + 30_000).is_err());
        // From the future, by this computer's clock: no run started then, so it is replaced, and
        // a report that says so cannot hold the folder for good.
        assert!(there(now + 86_400_000).is_ok());
        assert!(there(u64::MAX).is_ok());
        // An earlier one is replaced, as always.
        assert!(there(now - 120_000).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ctrl_c_removes_only_the_lock_this_run_holds() {
        let dir = folder("ctrl-c");
        let lock = dir.join(LOCK_NAME);
        let make = || {
            std::fs::write(&lock, "{}").unwrap();
            std::fs::metadata(&lock).unwrap()
        };
        // Its own, still in place: removed.
        let mine = make();
        let_go_of(vec![(lock.clone(), Undo::default(), Some(mine))]);
        assert!(!lock.exists(), "its own lock is removed");
        // A disk that could not lock: the file is not known to be this run's, and is left.
        make();
        let_go_of(vec![(lock.clone(), Undo::default(), None)]);
        assert!(lock.exists(), "a lock this run never held is left");
        // Its own was removed and another run made one in its place: left.
        // Moved aside rather than removed, so the new file cannot reuse its place on the disk.
        let old = std::fs::metadata(&lock).unwrap();
        std::fs::rename(&lock, dir.join("moved-aside")).unwrap();
        make();
        let_go_of(vec![(lock.clone(), Undo::default(), Some(old))]);
        assert!(lock.exists(), "another run's lock is left");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_record_holds_the_start_and_the_hash() {
        let at = UNIX_EPOCH + std::time::Duration::from_millis(1_791_053_580_250);
        let record = run_record(at, b"abc");
        assert_eq!(record.started, "2026-10-03T18:53:00Z");
        assert_eq!(record.started_unix_ms, 1_791_053_580_250);
        assert_eq!(
            record.securevibe_toml_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
