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
//! - A folder in `SKIP_DIRS` is not entered; nor is one of `OUTPUT_DIRS` beside the manifest that
//!   explains it, which is listed in `skipped`; nor a report `sv` wrote, holding nothing else.
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

use crate::ecosystems::{EDITOR_DIRS, Skip, language_of, marker_refused, skip_reason};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The largest file any check reads. A source file this size is generated or vendored, and a
/// credential scan of it is as likely to find a hash as a key; either way, refusing it and saying so
/// is better than reading it quietly or skipping it quietly.
pub const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// The largest file a check reads in pieces ([`Entry::in_pieces`]), for the few checks whose question
/// can be answered a piece at a time. Owner's decision, 28 September 2026: a large data file the owner
/// keeps in the app (a vendored standards catalog of 10 MB, in cato-pipeline) should not leave the
/// credential scan unfinished for the whole app. Above this, a file is still refused and named: it is
/// not a file anybody keeps by hand, and reading it would take longer than the rest of the report.
pub const MAX_PIECEWISE_BYTES: u64 = 256 * 1024 * 1024;

/// One piece of a file read in pieces. `text` overlaps the piece before it and the piece after it;
/// `keep` is the part that belongs to this piece alone, so a match that starts inside `keep` is counted
/// here and nowhere else, and is whole as long as it is shorter than the overlap.
#[derive(Debug)]
pub struct Piece<'a> {
    pub text: &'a str,
    /// The line, 1-indexed, that `text` starts on.
    pub first_line: usize,
    /// Byte range of `text` that is this piece's own.
    pub keep: std::ops::Range<usize>,
}

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

    /// The file in overlapping pieces of about `window` bytes, each handed to `each`, holding no more
    /// than one piece in memory. For a question that one line answers, such as whether a credential is
    /// written there: every line is inside some piece whole, provided `overlap` is longer than the
    /// longest thing looked for. Refused, with the reason, as `read_text` refuses: no details, over
    /// [`MAX_PIECEWISE_BYTES`], not text, or not readable.
    pub fn in_pieces(
        &self,
        window: usize,
        overlap: usize,
        mut each: impl FnMut(Piece<'_>),
    ) -> Result<(), Unread> {
        use std::io::Read;
        assert!(
            window > 2 * overlap,
            "a piece must be longer than twice its overlap"
        );
        match self.size {
            None => return Err(Unread::NoDetails),
            Some(s) if s > MAX_PIECEWISE_BYTES => return Err(Unread::TooLarge),
            Some(_) => {}
        }
        let mut file = std::fs::File::open(&self.path).map_err(|_| Unread::Unreadable)?;
        let mut buf: Vec<u8> = Vec::with_capacity(window + 4);
        // How much of `buf`'s start was carried over from the piece before, and so is not this one's.
        let mut carried = 0usize;
        let mut first_line = 1usize;
        let mut chunk = vec![0u8; window];
        let mut at_end = false;
        loop {
            // Fill the piece up to `window`, or to the end of the file.
            while buf.len() < window && !at_end {
                let want = window - buf.len();
                let n = file
                    .read(&mut chunk[..want])
                    .map_err(|_| Unread::Unreadable)?;
                if n == 0 {
                    at_end = true;
                } else {
                    buf.extend_from_slice(&chunk[..n]);
                }
            }
            // Text up to the last whole character; a character cut by the window waits for the next.
            let valid = match std::str::from_utf8(&buf) {
                Ok(_) => buf.len(),
                Err(e) if e.error_len().is_none() && !at_end => e.valid_up_to(),
                Err(_) => return Err(Unread::NotText),
            };
            let text = std::str::from_utf8(&buf[..valid]).expect("checked above");
            let mut keep_to = if at_end {
                text.len()
            } else {
                text.len().saturating_sub(overlap).max(carried)
            };
            while !text.is_char_boundary(keep_to) {
                keep_to -= 1;
            }
            each(Piece {
                text,
                first_line,
                keep: carried..keep_to,
            });
            if at_end {
                return Ok(());
            }
            // The next piece's own part starts exactly where this one's ended, so every byte is
            // owned once. Its text starts `overlap` earlier: look-behind, so a pattern that asks what
            // comes before a match (a word boundary) sees the same character it would in the whole
            // file. The bytes after `keep_to` in this piece were its look-ahead.
            let mut cut = keep_to.saturating_sub(overlap);
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            first_line += text[..cut].bytes().filter(|b| *b == b'\n').count();
            carried = keep_to - cut;
            buf.drain(..cut);
        }
    }

    /// Whether the file's text contains `needle`, read in pieces, for a file too large for
    /// [`Entry::read_text`].
    pub fn mentions(&self, needle: &str) -> Result<bool, Unread> {
        let mut found = false;
        let overlap = needle.len().max(1);
        self.in_pieces(1024 * 1024, overlap, |piece| {
            found = found || piece.text.contains(needle);
        })?;
        Ok(found)
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
    /// Entries that are not a regular file, a folder, or a link: a named pipe, a socket, a device, or
    /// one whose kind could not be read. Never opened: opening a named pipe waits for something to
    /// write into it, which hung `sv` (deep review S12).
    pub special: Vec<String>,
    /// Folders with an ordinary name left out as an ecosystem's output (`dist/` beside a
    /// `package.json`), each with the manifest that explains it. Every check leaves them out, and the
    /// report names them, so a skip is never silent (deep review H6). The folders every app has
    /// (`.git`, `node_modules`) and `sv`'s own reports are not listed.
    pub skipped: Vec<(String, String)>,
    /// Folders carrying `sv`'s report marker, or named as its report folder, that hold something `sv`
    /// does not write. They were read as the app's own code, since the marker proves nothing there.
    pub refused_markers: Vec<String>,
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
        listing.special.sort();
        listing.skipped.sort();
        listing.refused_markers.sort();
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

    /// This listing in two: what lies outside `folders`, and what lies in them, as securevibe.toml's
    /// `not-the-app` names them (`crate::under_any`). Both keep the same root, so paths read the same.
    pub fn split(&self, folders: &[String]) -> (Listing, Listing) {
        let (mut ours, mut theirs) = (
            Listing {
                root: self.root.clone(),
                ..Default::default()
            },
            Listing {
                root: self.root.clone(),
                ..Default::default()
            },
        );
        let side = |path: &str| crate::under_any(path, folders);
        for file in &self.files {
            if side(&file.relative) {
                &mut theirs
            } else {
                &mut ours
            }
            .files
            .push(file.clone());
        }
        for (all, pick) in [(&self.dirs, 0), (&self.links, 1), (&self.unopened, 2)] {
            for path in all {
                let to = if side(path) { &mut theirs } else { &mut ours };
                match pick {
                    0 => to.dirs.push(path.clone()),
                    1 => to.links.push(path.clone()),
                    _ => to.unopened.push(path.clone()),
                }
            }
        }
        (ours, theirs)
    }
}

/// `path` from `root`, its parts joined with `/` whatever the platform. Built from the parts rather
/// than by turning every `\\` in the text into `/`: on macOS and Linux a `\\` is an ordinary character
/// in a name, and `..\\outside\\key.txt` rewritten that way named a file outside the app, which
/// `sv bundle` then read and zipped (the deep review of 4 October 2026, S1).
pub fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/")
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
            if !editor {
                match skip_reason(&path) {
                    Some(Skip::Output { beside }) => {
                        out.skipped
                            .push((relative(root, &path), format!("output beside its {beside}")));
                        continue;
                    }
                    Some(_) => continue,
                    None if marker_refused(&path) => {
                        out.refused_markers.push(relative(root, &path));
                    }
                    None => {}
                }
            }
            if !editor {
                out.dirs.push(relative(root, &path));
            }
            walk(root, &path, editor, out);
            continue;
        }
        if !kind.is_some_and(|k| k.is_file()) {
            out.special.push(relative(root, &path));
            continue;
        }
        // A regular file, listed with whatever is known. `DirEntry::metadata` does not follow links
        // either.
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
    #[cfg(unix)]
    fn a_backslash_in_a_name_stays_part_of_the_name() {
        // S1 of the deep review of 4 October 2026: the relative path is the parts joined, and joined back on
        // to the root it is the file it came from, never one outside the app.
        let root = scratch("backslash");
        let app = root.join("app");
        std::fs::create_dir_all(app.join("sub")).unwrap();
        std::fs::create_dir_all(root.join("outside")).unwrap();
        std::fs::write(root.join("outside/key.txt"), "outside").unwrap();
        std::fs::write(app.join("..\\outside\\key.txt"), "inside").unwrap();
        std::fs::write(app.join("sub/a\\b.py"), "inside").unwrap();
        let listing = Listing::of(&app);
        std::fs::remove_dir_all(&root).ok();
        let names: Vec<&str> = listing.files.iter().map(|f| f.relative.as_str()).collect();
        assert_eq!(names, vec!["..\\outside\\key.txt", "sub/a\\b.py"]);
        for f in &listing.files {
            assert_eq!(app.join(&f.relative), f.path, "{}", f.relative);
        }
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

    #[cfg(unix)]
    #[test]
    fn a_named_pipe_is_named_and_never_opened() {
        // Opening a named pipe waits for a writer, and nothing ever writes: the walk would hang the
        // first time a check read it (deep review S12).
        let root = scratch("pipe");
        std::fs::write(root.join("app.py"), "print('hi')\n").unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(root.join("queue"))
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        let kind = std::fs::symlink_metadata(root.join("queue"))
            .unwrap()
            .file_type();
        assert!(
            !kind.is_file() && !kind.is_dir() && !kind.is_symlink(),
            "the plant is a pipe"
        );

        let listing = Listing::of(&root);
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(names(&listing.files), vec!["app.py"], "{listing:?}");
        assert_eq!(listing.special, vec!["queue"]);
        assert!(listing.links.is_empty() && listing.unopened.is_empty());
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
    fn an_ordinary_folder_name_is_left_out_only_beside_the_manifest_that_explains_it() {
        // H6 of the deep review: `build`, `dist`, `vendor`, and the rest were skipped at any depth.
        let root = scratch("output-dirs");
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        // Explained: a web app's `dist/` beside its package.json, Go's `vendor/` beside go.mod.
        write("web/package.json", "{}\n");
        write("web/dist/bundle.js", "eval(a)\n");
        write("api/go.mod", "module x\n");
        write("api/vendor/lib/lib.go", "package lib\n");
        // Not explained: the app's own `src/build/` and `tools/out/`, and a `target/` with no Cargo.toml.
        write("src/build/steps.py", "print(1)\n");
        write("tools/out/report.js", "console.log(1)\n");
        write("target/main.py", "print(2)\n");

        let listing = Listing::of(&root);
        std::fs::remove_dir_all(&root).ok();

        let files = names(&listing.files);
        for read in [
            "src/build/steps.py",
            "tools/out/report.js",
            "target/main.py",
        ] {
            assert!(files.contains(&read), "{read} is the app's own: {files:?}");
        }
        for left in ["web/dist/bundle.js", "api/vendor/lib/lib.go"] {
            assert!(!files.contains(&left), "{left} is output: {files:?}");
        }
        assert_eq!(
            listing.skipped,
            [
                (
                    "api/vendor".to_owned(),
                    "output beside its go.mod".to_owned()
                ),
                (
                    "web/dist".to_owned(),
                    "output beside its package.json".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_report_marker_counts_only_where_the_folder_holds_nothing_else() {
        // H6 of the deep review: the marker left out every folder it was put in, and an AI tool could
        // put it there. Now a marked folder holding anything `sv` does not write is read as the app's.
        let root = scratch("markers");
        let write = |path: &str, text: &str| {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        let marker = crate::ecosystems::REPORT_MARKER;
        write(&format!("reports/{marker}"), "sv\n");
        write("reports/Report.JSON", "{}\n");
        write(&format!("hidden/{marker}"), "sv\n");
        write("hidden/admin.py", "eval(x)\n");
        write("securevibe-report/report.html", "<html>\n");
        write("securevibe-report/notes.py", "print(1)\n");

        let listing = Listing::of(&root);
        std::fs::remove_dir_all(&root).ok();

        let files = names(&listing.files);
        assert!(!files.contains(&"reports/Report.JSON"), "{files:?}");
        assert!(files.contains(&"hidden/admin.py"), "{files:?}");
        assert!(files.contains(&"securevibe-report/notes.py"), "{files:?}");
        assert_eq!(listing.refused_markers, ["hidden", "securevibe-report"]);
        assert!(listing.skipped.is_empty(), "{:?}", listing.skipped);
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

    fn entry_for(path: &Path, relative: &str) -> Entry {
        Entry {
            relative: relative.into(),
            path: path.to_path_buf(),
            size: std::fs::metadata(path).ok().map(|m| m.len()),
            extension: None,
            language: None,
            editor: false,
        }
    }

    /// Reads `entry` in pieces and puts back together the part each piece owns, checking as it goes
    /// that each piece's `first_line` is the line its own part starts on.
    fn reassemble(entry: &Entry, window: usize, overlap: usize, whole: &str) -> (String, usize) {
        let mut out = String::new();
        let mut pieces = 0;
        entry
            .in_pieces(window, overlap, |piece| {
                pieces += 1;
                let own_start = out.len();
                // The line the piece's own part starts on, counted in the file, against the piece's
                // own count: `first_line` plus the newlines in the overlap before `keep`.
                let expected = 1 + whole[..own_start].matches('\n').count();
                let claimed =
                    piece.first_line + piece.text[..piece.keep.start].matches('\n').count();
                assert_eq!(claimed, expected, "piece {pieces} starts on the wrong line");
                // Every piece after the first carries at least `overlap` bytes before its own part,
                // so a rule that looks at the character before a match sees the file's.
                if pieces > 1 {
                    assert!(
                        piece.keep.start >= overlap,
                        "piece {pieces} has no look-behind"
                    );
                }
                out.push_str(&piece.text[piece.keep.clone()]);
            })
            .expect("the file is read");
        (out, pieces)
    }

    #[test]
    fn a_file_read_in_pieces_is_every_byte_once_with_its_lines_counted() {
        let dir = scratch("pieces");
        let path = dir.join("catalog.txt");
        let whole: String = (0..6000)
            .map(|i| format!("line {i} of the catalog\n"))
            .collect();
        std::fs::write(&path, &whole).unwrap();
        let entry = entry_for(&path, "catalog.txt");
        let (back, pieces) = reassemble(&entry, 4096, 256, &whole);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            pieces > 10,
            "the setup: the file really was read in many pieces ({pieces})"
        );
        assert_eq!(back, whole, "a byte was dropped or counted twice");
    }

    #[test]
    fn a_character_cut_by_a_piece_boundary_is_not_read_as_binary() {
        // Accented letters and an emoji are two to four bytes each; with a small window some of them
        // straddle every boundary. A reader that cut them would call the file "not text".
        let dir = scratch("pieces-utf8");
        let path = dir.join("names.txt");
        let whole: String = (0..400).map(|i| format!("é{i}🔑ü\n")).collect();
        std::fs::write(&path, &whole).unwrap();
        let entry = entry_for(&path, "names.txt");
        let (back, pieces) = reassemble(&entry, 97, 13, &whole);
        std::fs::remove_dir_all(&dir).ok();
        assert!(pieces > 20, "the setup: many boundaries ({pieces})");
        assert_eq!(back, whole);
    }

    #[test]
    fn a_word_split_by_a_piece_boundary_is_still_mentioned() {
        // `mentions` reads in 1 MB pieces; the word is placed across the first boundary, and the
        // file is over the 2 MB limit, as the files it is for are.
        let dir = scratch("mentions");
        let path = dir.join("catalog.json");
        let before = "x".repeat(1024 * 1024 - 3);
        let after = "y".repeat(MAX_FILE_BYTES as usize);
        std::fs::write(&path, format!("{before}command{after}")).unwrap();
        let entry = entry_for(&path, "catalog.json");
        assert!(entry.too_large(), "the setup: over the limit");
        assert_eq!(entry.mentions("command"), Ok(true));
        assert_eq!(entry.mentions("mcpServers"), Ok(false));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_file_read_in_pieces_is_refused_for_the_same_reasons_as_a_whole_one() {
        let dir = scratch("pieces-refused");
        let binary = dir.join("blob.bin");
        std::fs::write(&binary, [b'a', 0xff, 0xfe, b'b']).unwrap();
        assert_eq!(
            entry_for(&binary, "blob.bin").in_pieces(64, 8, |_| {}),
            Err(Unread::NotText)
        );
        std::fs::remove_dir_all(&dir).ok();
        let huge = Entry {
            relative: "dump.json".into(),
            path: PathBuf::from("/nowhere/dump.json"),
            size: Some(MAX_PIECEWISE_BYTES + 1),
            extension: Some("json".into()),
            language: None,
            editor: false,
        };
        // Refused before it is opened: the path does not exist.
        assert_eq!(huge.in_pieces(64, 8, |_| {}), Err(Unread::TooLarge));
        assert_eq!(huge.mentions("command"), Err(Unread::TooLarge));
        let unknown = Entry { size: None, ..huge };
        assert_eq!(unknown.in_pieces(64, 8, |_| {}), Err(Unread::NoDetails));
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
