//! Confinement: every path a tool argument names is resolved and held inside the root, and a folder
//! is made one level at a time with a link refused at every level.

use super::*;

impl Server {
    /// Resolves a path a tool was given against the root, and refuses anything outside it.
    ///
    /// Canonicalized, so `..` and symlinks are resolved before the check rather than after: a
    /// link inside the root that points outside it lands outside it.
    pub(super) fn app_dir(&self, args: &Value) -> Result<PathBuf> {
        let asked = args.get("path").and_then(Value::as_str).unwrap_or(".");
        let joined = if Path::new(asked).is_absolute() {
            PathBuf::from(asked)
        } else {
            self.root.join(asked)
        };
        // One answer for a path that does not exist and one outside the root, whichever it is: two
        // answers would tell whoever asks, the model or text in the app steering it, which files exist
        // anywhere on this computer (the deep review's improvement 7).
        let refused = || {
            anyhow::anyhow!(
                "{asked} is not a folder inside {}, the folder this server was started for, so it \
                 cannot be read: it is outside that folder, or nothing is there",
                self.root.display()
            )
        };
        let resolved = joined.canonicalize().map_err(|_| refused())?;
        if !resolved.starts_with(&self.root) {
            return Err(refused());
        }
        anyhow::ensure!(resolved.is_dir(), "{asked} is not a folder");
        // The files read by name: a link among them could name a file outside the root, and a
        // manifest that does not parse is quoted back in the error, a line of whatever it points at
        // with it (the review of 6 October, item 1). Refused as reports and notes refuse a link.
        for name in READ_BY_NAME {
            crate::refuse_link(
                &resolved.join(name),
                "Make it a file of the app's own, and ask again.",
            )?;
        }
        Ok(resolved)
    }
}

/// Why a root is too wide to serve, if it is: the whole computer, the whole home folder, or any
/// folder that holds the home folder (`/home`, `/Users`), where an AI tool talked into it could read
/// keys, mail, and every other project, other people's included. `sv mcp` with no `--root` serves
/// the folder it was started in, which is often the home folder (BACKLOG, "Hardening the MCP
/// server", item 5). Until 5 October 2026 only `/` and the home folder itself were refused (R10 of
/// the deep review). Both are canonical paths. With no home folder known, a folder just below the
/// top, such as `/home`, is refused too, since it is where home folders are kept.
pub(super) fn too_wide(root: &Path, home: Option<&Path>) -> Option<&'static str> {
    if root.parent().is_none() {
        return Some("it is the top of the computer's files");
    }
    match home {
        Some(home) if home == root => {
            Some("it is your whole home folder, where your keys and other projects are")
        }
        Some(home) if home.starts_with(root) => Some(
            "it holds your home folder, and so your keys and other projects, and other people's \
             home folders too",
        ),
        None if root.parent().is_some_and(|p| p.parent().is_none()) => Some(
            "it is a folder at the top of the computer's files, where home folders are kept, and \
             this computer's home folder could not be found to tell it apart",
        ),
        _ => None,
    }
}

/// Makes `relative` below `base` one folder at a time, refusing a level that is a link or is not a
/// folder before anything below it is made. `relative` holds only plain names and `.`, which the
/// caller has already checked. Gives the folder, and the ones it made, topmost first; refused part
/// way, it takes away the ones it made.
pub(super) fn create_below(base: &Path, relative: &Path) -> Result<(PathBuf, Vec<PathBuf>)> {
    let mut made = Vec::new();
    let made_here = create_each(base, relative, &mut made);
    if made_here.is_err() {
        for folder in made.iter().rev() {
            let _ = std::fs::remove_dir(folder);
        }
    }
    made_here.map(|here| (here, made))
}

pub(super) fn create_each(
    base: &Path,
    relative: &Path,
    made: &mut Vec<PathBuf>,
) -> Result<PathBuf> {
    let mut here = base.to_path_buf();
    for part in relative.components() {
        let Component::Normal(name) = part else {
            continue;
        };
        here.push(name);
        match std::fs::symlink_metadata(&here) {
            Ok(meta) if meta.file_type().is_symlink() => anyhow::bail!(
                "{} is a link to somewhere else, so nothing is written through it",
                here.display()
            ),
            Ok(meta) => {
                anyhow::ensure!(meta.is_dir(), "{} is not a folder", here.display());
            }
            Err(_) => {
                std::fs::create_dir(&here)
                    .with_context(|| format!("{} cannot be created", here.display()))?;
                made.push(here.clone());
            }
        }
    }
    Ok(here)
}
