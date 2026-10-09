//! History: a small record of each `sv report` run, kept only once the person turns it on (ADR-057).
//!
//! Kept outside every app's folder, because an app's folder is often a public git repository, and a
//! dated list of an app's weaknesses committed there is a gift to anybody looking for one; in
//! `$XDG_DATA_HOME/stackvet/history`, or `~/.local/share/stackvet/history`, readable only by the
//! person. Switched on by a file of the person's own, `keep-history` in the folder `sv` keeps its
//! review key in, never by `stackvet.toml`, which the AI coding tool writes. A record holds what
//! `sv_report::dashboard::Run` holds and nothing else; at most `KEEP` are kept for each app.
//!
//! History is a convenience for the person and never evidence: the reports never read it, and no
//! requirement is credited from it. An AI coding tool runs as the same person and could rewrite it.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use sv_report::dashboard::Run;

/// How many runs are kept for each app; the oldest go first.
pub const KEEP: usize = 100;

/// The file whose presence turns history on.
const SWITCH: &str = "keep-history";

/// Where the switch lives: the folder `sv` keeps the review key in.
fn settings() -> Option<PathBuf> {
    sv_check::seal::Key::folder()
}

/// Where history is kept: `$XDG_DATA_HOME/stackvet/history`, or `~/.local/share/stackvet/history`.
pub fn folder() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|home| home.join(".local/share"))
        })
        .map(|data| {
            // The old folder is used while only it exists (ADR-062), as the config folder is:
            // nothing moves what was kept.
            let new = data.join(sv_frameworks::names::CONFIG_DIR).join("history");
            let old = data
                .join(sv_frameworks::names::OLD_CONFIG_DIR)
                .join("history");
            if !new.is_dir() && old.is_dir() {
                old
            } else {
                new
            }
        })
}

/// Whether the person has turned history on.
pub fn is_on() -> bool {
    settings().is_some_and(|s| {
        std::fs::symlink_metadata(s.join(SWITCH)).is_ok_and(|m| m.file_type().is_file())
    })
}

/// The folder an app's runs are kept in: a name made from the app folder's full path, so two apps
/// with the same folder name are kept apart, and a moved folder starts a history of its own.
fn app_folder(history: &Path, app: &Path) -> PathBuf {
    let hex = crate::bundle::sha256(app.to_string_lossy().as_bytes());
    history.join(&hex[..16])
}

/// Makes a folder only its owner can open.
fn private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("making {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("making {} private", path.display()))?;
    }
    Ok(())
}

/// Writes `text` to `path` so only its owner can read it, through no link.
fn private_file(path: &Path, text: &str) -> Result<()> {
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        bail!(
            "{} is a link, and nothing is written through it",
            path.display()
        );
    }
    let staging = path.with_extension(format!("sv-{}", std::process::id()));
    {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write;
        let mut file = options
            .open(&staging)
            .with_context(|| format!("writing {}", staging.display()))?;
        file.write_all(text.as_bytes())?;
    }
    std::fs::rename(&staging, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Keeps `run` for the app at `app` when history is on: `Ok(None)` when it is off.
pub fn keep(app: &Path, run: &Run) -> Result<Option<PathBuf>> {
    if !is_on() {
        return Ok(None);
    }
    let history = folder().context("this computer has no home folder to keep history in")?;
    private_dir(&history)?;
    let mine = app_folder(&history, app);
    private_dir(&mine)?;
    private_file(
        &mine.join("app.json"),
        &serde_json::to_string_pretty(&serde_json::json!({
            "folder": app.to_string_lossy(),
            "app_name": run.app_name,
        }))?,
    )?;
    let path = mine.join(format!("{}.json", run.started_unix_ms));
    private_file(&path, &serde_json::to_string_pretty(run)?)?;
    // The oldest go once there are more than `KEEP`.
    let mut kept = runs_in(&mine);
    while kept.len() > KEEP {
        let (oldest, _) = kept.remove(0);
        std::fs::remove_file(oldest).ok();
    }
    Ok(Some(path))
}

/// The runs in one app's folder, oldest first, with their files. A file that is not a run is passed
/// over.
fn runs_in(folder: &Path) -> Vec<(PathBuf, Run)> {
    let mut runs: Vec<(PathBuf, Run)> = std::fs::read_dir(folder)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "json") && !p.ends_with("app.json"))
        .filter_map(|p| {
            let run: Run = serde_json::from_str(&std::fs::read_to_string(&p).ok()?).ok()?;
            Some((p, run))
        })
        .collect();
    runs.sort_by_key(|(_, r)| r.started_unix_ms);
    runs
}

/// The runs kept for the app at `app`, oldest first.
pub fn runs(app: &Path) -> Vec<Run> {
    folder()
        .map(|h| runs_in(&app_folder(&h, app)))
        .unwrap_or_default()
        .into_iter()
        .map(|(_, r)| r)
        .collect()
}

/// Every app folder history holds a run for, so `sv dashboard` can show them without being told.
pub fn apps() -> Vec<PathBuf> {
    let Some(history) = folder() else {
        return Vec::new();
    };
    let mut apps: Vec<PathBuf> = std::fs::read_dir(history)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let text = std::fs::read_to_string(e.path().join("app.json")).ok()?;
            let v: serde_json::Value = serde_json::from_str(&text).ok()?;
            Some(PathBuf::from(v["folder"].as_str()?))
        })
        .collect();
    apps.sort();
    apps
}

/// `sv history on|off|status|forget FOLDER|forget --all`.
pub fn command(args: &[String]) -> Result<()> {
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let history = folder();
    match words.as_slice() {
        ["on"] => {
            let settings = settings()
                .context("this computer has no folder for sv's settings (neither HOME nor XDG_CONFIG_HOME is set)")?;
            private_dir(&settings)?;
            private_file(
                &settings.join(SWITCH),
                "History is on: each `sv report` keeps a small record of its run. `sv history off` stops it.\n",
            )?;
            println!(
                "History is on. Each `sv report` you run at a terminal now keeps a small record of the run in {}, \
                 readable only by you: the counts, the kind of run, and each finding's title, never your code. \
                 `sv dashboard` shows them. `sv history off` stops it; `sv history forget FOLDER` deletes an app's.",
                history.map(|h| h.display().to_string()).unwrap_or_default()
            );
        }
        ["off"] => {
            if let Some(settings) = settings() {
                std::fs::remove_file(settings.join(SWITCH)).ok();
            }
            println!(
                "History is off. What was kept is still there; `sv history forget --all` deletes it."
            );
        }
        ["status"] | [] => {
            let apps = apps();
            println!(
                "History is {}. Kept for {} app{}{}.",
                if is_on() { "on" } else { "off" },
                apps.len(),
                if apps.len() == 1 { "" } else { "s" },
                history
                    .map(|h| format!(", in {}", h.display()))
                    .unwrap_or_default()
            );
            for app in apps {
                println!("  {} ({} runs)", app.display(), runs(&app).len());
            }
        }
        ["forget", "--all"] => {
            if let Some(h) = history.filter(|h| h.exists()) {
                std::fs::remove_dir_all(&h).with_context(|| format!("deleting {}", h.display()))?;
                println!("Deleted all the history kept, in {}.", h.display());
            } else {
                println!("There is no history kept on this computer.");
            }
        }
        ["forget", app] => {
            let app = std::fs::canonicalize(app).unwrap_or_else(|_| PathBuf::from(app));
            match history.map(|h| app_folder(&h, &app)).filter(|f| f.exists()) {
                Some(f) => {
                    std::fs::remove_dir_all(&f)
                        .with_context(|| format!("deleting {}", f.display()))?;
                    println!("Deleted the history kept for {}.", app.display());
                }
                None => println!("There is no history kept for {}.", app.display()),
            }
        }
        _ => bail!(
            "`sv history` takes on, off, status, forget FOLDER, or forget --all\n\nUSAGE:\n  sv history on|off|status|forget FOLDER|forget --all"
        ),
    }
    Ok(())
}
