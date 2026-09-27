//! One walk of the app folder, shared by every check.
//!
//! Until 27 September 2026 each check walked the folder for itself: the credential scan, the code
//! rules, the corroborators, the outside tools' file list, the test finder, and the ecosystem
//! detection, which the bill of materials, the dependency reader, and the pinning check each call
//! again. Six walks per report at the least, and every walk answered the same three questions on its
//! own. The answers had drifted. Two walks refused to follow a symbolic link and five followed it, out
//! of the app and round in circles: a link `src/loop -> ..` was followed until the operating system
//! refused at the thirty-second level, and a file outside the app was read and reported once at every
//! level. One walk refused a file over 2 MB and said so; two read anything and one kept it all in
//! memory. Here the questions are answered once, and the walks are one.
//!
//! - A folder in `SKIP_DIRS`, or one carrying `sv`'s own report marker, is not entered.
//! - A symbolic link is not followed, whether to a file or a folder, and is listed once in `links`.
//!   The report names them, so a linked `vendor/` is a gap with a name rather than a silence. The
//!   kind comes from the directory entry itself, before anything resolves the link.
//! - Every regular file is listed with its size, so a check can refuse one over [`MAX_FILE_BYTES`]
//!   and say so, instead of parsing a 50 MB bundle or holding it in memory.
//! - Editor folders (`.idea`, `.vscode`) are entered, and their files marked `editor`. The
//!   credential scan reads them, because a settings file holds a token as easily as any other file;
//!   every other check takes `app_files`, which leaves them out, as the old walks did.
//!
//! Every check keeps a function that takes the app folder and walks it, for a caller that has only
//! one thing to ask; `sv report` and `sv check` build the listing once and hand it to each.

use crate::ecosystems::{EDITOR_DIRS, language_of, skip_dir};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The largest file any check reads. A source file this size is generated or vendored, and a
/// credential scan of it is as likely to find a hash as a key; either way, refusing it and saying so
/// is better than reading it quietly or skipping it quietly.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// One regular file under the app folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// From the app folder, with `/` separators whatever the platform.
    pub relative: String,
    pub path: PathBuf,
    /// `None` when the file's details could not be read at all.
    pub size: Option<u64>,
    /// Lowercased, without the dot.
    pub extension: Option<String>,
    /// The language `sv` names for that extension, when it names one.
    pub language: Option<&'static str>,
    /// Under an editor settings folder: read for credentials and by nothing else.
    pub editor: bool,
}

/// Why a listed file was not read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unread {
    /// Over [`MAX_FILE_BYTES`].
    TooLarge,
    /// Its size could not be read, so nothing about it is known.
    NoDetails,
    /// Read, and not text.
    NotText,
    /// Opening or reading it failed.
    Unreadable,
}

impl Unread {
    /// In the words the reports use.
    pub fn explain(&self) -> &'static str {
        match self {
            Unread::TooLarge => "larger than 2 MB",
            Unread::NoDetails => "its details could not be read",
            Unread::NotText => "not a text file",
            Unread::Unreadable => "it could not be read",
        }
    }
}

impl Entry {
    pub fn file_name(&self) -> &str {
        self.relative.rsplit('/').next().unwrap_or(&self.relative)
    }

    pub fn too_large(&self) -> bool {
        self.size.is_some_and(|s| s > MAX_FILE_BYTES)
    }

    /// The file's text, or why it was not read. The size is checked before the file is opened, so a
    /// file over the limit costs nothing to refuse.
    pub fn read_text(&self) -> Result<String, Unread> {
        match self.size {
            None => return Err(Unread::NoDetails),
            Some(s) if s > MAX_FILE_BYTES => return Err(Unread::TooLarge),
            Some(_) => {}
        }
        let bytes = std::fs::read(&self.path).map_err(|_| Unread::Unreadable)?;
        String::from_utf8(bytes).map_err(|_| Unread::NotText)
    }
}

/// What one walk of the app folder found.
#[derive(Debug, Default, Clone)]
pub struct Listing {
    pub root: PathBuf,
    /// Every regular file outside the skipped folders, by relative path, editor folders included.
    pub files: Vec<Entry>,
    /// Every folder entered, relative to the root, not counting the root itself or editor folders.
    pub dirs: Vec<String>,
    /// Symbolic links met and not followed, files and folders alike.
    pub links: Vec<String>,
    /// Folders that are there and could not be opened.
    pub unopened: Vec<String>,
}

impl Listing {
    pub fn of(root: &Path) -> Listing {
        let mut listing = Listing {
            root: root.to_path_buf(),
            ..Default::default()
        };
        walk(root, root, false, &mut listing);
        listing.files.sort_by(|a, b| a.relative.cmp(&b.relative));
        listing.dirs.sort();
        listing.links.sort();
        listing.unopened.sort();
        listing
    }

    /// The app's own files: everything listed except what sits in an editor settings folder.
    pub fn app_files(&self) -> impl Iterator<Item = &Entry> {
        self.files.iter().filter(|f| !f.editor)
    }

    /// Every path in the app, files and folders, as the corroborators look configuration up.
    pub fn all_paths(&self) -> BTreeSet<String> {
        self.dirs
            .iter()
            .cloned()
            .chain(self.app_files().map(|f| f.relative.clone()))
            .collect()
    }

    /// The folders, relative to the root (the root is `""`), that hold a file of this name.
    pub fn dirs_holding(&self, name: &str) -> BTreeSet<String> {
        self.app_files()
            .filter(|f| f.file_name() == name)
            .map(|f| match f.relative.rsplit_once('/') {
                Some((dir, _)) => dir.to_owned(),
                None => String::new(),
            })
            .collect()
    }

    /// The files whose extension names a language `sv` reads.
    pub fn code_files(&self) -> impl Iterator<Item = &Entry> {
        self.app_files().filter(|f| f.language.is_some())
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn walk(root: &Path, dir: &Path, in_editor: bool, out: &mut Listing) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        out.unopened.push(relative(root, dir));
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        // The entry's own kind, before any link is resolved. `path.is_dir()` would follow the link
        // and answer for wherever it leads.
        let kind = entry.file_type().ok();
        if kind.is_some_and(|k| k.is_symlink()) {
            out.links.push(relative(root, &path));
            continue;
        }
        if kind.is_some_and(|k| k.is_dir()) {
            let editor = in_editor
                || path
                    .file_name()
                    .is_some_and(|n| EDITOR_DIRS.contains(&n.to_string_lossy().as_ref()));
            if skip_dir(&path) && !editor {
                continue;
            }
            if !editor {
                out.dirs.push(relative(root, &path));
            }
            walk(root, &path, editor, out);
            continue;
        }
        // A regular file, or something whose kind could not be read: listed, with whatever is known.
        // `DirEntry::metadata` does not follow links either.
        let size = entry.metadata().ok().map(|m| m.len());
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase());
        let language = extension.as_deref().and_then(language_of);
        out.files.push(Entry {
            relative: relative(root, &path),
            path,
            size,
            extension,
            language,
            editor: in_editor,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-files-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn names(entries: &[Entry]) -> Vec<&str> {
        entries.iter().map(|e| e.relative.as_str()).collect()
    }

    #[test]
    fn a_link_out_of_the_app_and_a_loop_are_listed_once_and_never_followed() {
        // The fixture that found this: `vendor-link` points outside the app, `src/loop` points at
        // `..`. Before, the file outside was read and reported at every level of the loop, about
        // thirty times, under paths four hundred characters long.
        let root = scratch("links");
        let app = root.join("app");
        let outside = root.join("outside");
        std::fs::create_dir_all(app.join("src")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(app.join("src/app.py"), "print('hi')\n").unwrap();
        std::fs::write(outside.join("settings.py"), "SECRET = 'outside'\n").unwrap();
        std::os::unix::fs::symlink(&outside, app.join("vendor-link")).unwrap();
        std::os::unix::fs::symlink("..", app.join("src/loop")).unwrap();
        std::os::unix::fs::symlink("app.py", app.join("src/alias.py")).unwrap();

        let listing = Listing::of(&app);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(names(&listing.files), vec!["src/app.py"], "{listing:?}");
        assert_eq!(listing.dirs, vec!["src"]);
        assert_eq!(
            listing.links,
            vec!["src/alias.py", "src/loop", "vendor-link"],
            "every link, to a file or a folder, once"
        );
        assert!(listing.unopened.is_empty());
    }

    #[test]
    fn skipped_folders_and_a_report_folder_are_not_entered() {
        let root = scratch("skips");
        std::fs::create_dir_all(root.join("node_modules/x")).unwrap();
        std::fs::write(root.join("node_modules/x/index.js"), "eval(a)\n").unwrap();
        std::fs::create_dir_all(root.join("my-reports")).unwrap();
        std::fs::write(root.join("my-reports/report.html"), "<html>").unwrap();
        std::fs::write(
            root.join("my-reports")
                .join(crate::ecosystems::REPORT_MARKER),
            "sv\n",
        )
        .unwrap();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(root.join(".github/workflows/ci.yml"), "on: push\n").unwrap();
        std::fs::write(root.join("Dockerfile"), "FROM x\n").unwrap();

        let listing = Listing::of(&root);
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(
            names(&listing.files),
            vec![".github/workflows/ci.yml", "Dockerfile"],
            "a dot-folder that holds CI is entered; a skipped folder and a report folder are not"
        );
        assert_eq!(listing.dirs, vec![".github", ".github/workflows"]);
        let all = listing.all_paths();
        assert!(
            all.contains("Dockerfile") && all.contains(".github"),
            "{all:?}"
        );
    }

    #[test]
    fn editor_folders_are_read_for_credentials_and_by_nothing_else() {
        let root = scratch("editor");
        std::fs::create_dir_all(root.join(".vscode")).unwrap();
        std::fs::write(root.join(".vscode/settings.json"), "{}").unwrap();
        std::fs::write(root.join(".vscode/tasks.js"), "eval(x)\n").unwrap();
        std::fs::write(root.join("app.py"), "x\n").unwrap();
        let listing = Listing::of(&root);
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(
            names(&listing.files),
            vec![".vscode/settings.json", ".vscode/tasks.js", "app.py"],
            "the credential scan sees everything"
        );
        assert_eq!(
            listing
                .app_files()
                .map(|f| f.relative.as_str())
                .collect::<Vec<_>>(),
            vec!["app.py"],
            "every other check sees the app"
        );
        assert_eq!(listing.code_files().count(), 1);
        assert!(listing.dirs.is_empty());
        assert!(!listing.all_paths().contains(".vscode/tasks.js"));
    }

    #[test]
    fn every_file_carries_its_size_language_and_folder() {
        let root = scratch("details");
        std::fs::create_dir_all(root.join("server")).unwrap();
        std::fs::write(root.join("server/package.json"), "{}").unwrap();
        std::fs::write(root.join("server/App.TS"), "let x = 1;\n").unwrap();
        std::fs::write(root.join("package.json"), "{}").unwrap();

        let listing = Listing::of(&root);
        let ts = listing
            .files
            .iter()
            .find(|f| f.relative == "server/App.TS")
            .unwrap();
        // Read while the fixture is still there: the first version of this test removed the folder
        // first and then blamed the listing for the file it could not open.
        let text = ts.read_text();
        std::fs::remove_dir_all(&root).ok();

        assert_eq!(ts.size, Some(11));
        assert_eq!(ts.extension.as_deref(), Some("ts"), "lowercased");
        assert_eq!(ts.language, Some("typescript"));
        assert_eq!(ts.file_name(), "App.TS");
        assert!(!ts.too_large());
        assert_eq!(text.unwrap(), "let x = 1;\n");
        assert_eq!(
            listing.dirs_holding("package.json"),
            ["", "server"].into_iter().map(String::from).collect()
        );
        assert_eq!(listing.code_files().count(), 1);
    }

    #[test]
    fn a_file_over_the_limit_is_refused_before_it_is_opened() {
        let entry = Entry {
            relative: "bundle.js".into(),
            path: PathBuf::from("/nowhere/bundle.js"),
            size: Some(MAX_FILE_BYTES + 1),
            extension: Some("js".into()),
            language: Some("javascript"),
            editor: false,
        };
        assert!(entry.too_large());
        // The path does not exist, so a read that got that far would fail with `Unreadable`.
        assert_eq!(entry.read_text(), Err(Unread::TooLarge));
        let unknown = Entry {
            size: None,
            ..entry.clone()
        };
        assert_eq!(unknown.read_text(), Err(Unread::NoDetails));
    }

    #[test]
    fn a_folder_that_cannot_be_opened_is_named() {
        let root = scratch("unopened");
        let sealed = root.join("sealed");
        std::fs::create_dir_all(&sealed).unwrap();
        std::fs::write(sealed.join("a.py"), "x\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let listing = Listing::of(&root);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::remove_dir_all(&root).ok();
        // Root runs see inside anyway, so the assertion holds either way it went.
        assert!(
            listing.unopened == vec!["sealed"] || names(&listing.files) == vec!["sealed/a.py"],
            "{listing:?}"
        );
    }
}
