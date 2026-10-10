//! Where `sv`'s own data is: the OWASP frameworks, its rules, its questions, and its prompts (ADR-036).
//!
//! Every file `sv` reads at run time is found here, so a copy of `sv` moved out of its build folder
//! keeps working when its data goes with it. Looked for, in order:
//!
//! 1. `SV_DATA_DIR`, the whole `data` folder.
//! 2. Beside the program: `data` next to it, or `../share/securevibe/data` from it, following any link
//!    to the program to where it really is.
//! 3. The folder `sv` was built from, so a build in the repository and the Docker image work as they
//!    always have.
//!
//! A folder counts only when it holds the OWASP frameworks.

use crate::paths::Canonical;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// The repository's `data` folder as it was when `sv` was built.
fn built_from() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data")
}

/// Whether `dir` is a data folder: it holds the OWASP frameworks.
fn holds_data(dir: &Path) -> bool {
    dir.join("frameworks").is_dir()
}

/// The places looked in, in order, for a program at `program` (already followed through links)
/// and a build folder at `built`.
fn places(program: Option<&Path>, built: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(folder) = program.and_then(Path::parent) {
        out.push(folder.join("data"));
        // Where `tools/install.sh` puts it, and where it put it before the rename (ADR-062). Joined
        // part by part, so each place is named in its system's own form, `\` on Windows.
        out.push(
            folder
                .join("..")
                .join("share")
                .join(crate::names::CONFIG_DIR)
                .join("data"),
        );
        out.push(
            folder
                .join("..")
                .join("share")
                .join(crate::names::OLD_CONFIG_DIR)
                .join("data"),
        );
    }
    out.push(built.to_path_buf());
    out
}

/// The data folder, from what `SV_DATA_DIR` says, where the program is, and the build folder; or
/// why there is none, naming every place looked in. Separate from the environment so it can be
/// tested.
fn find(env: Option<PathBuf>, program: Option<&Path>, built: &Path) -> Result<PathBuf, String> {
    if let Some(dir) = env {
        // Said on purpose, so never passed over for another: a wrong one is named.
        return if holds_data(&dir) {
            Ok(dir)
        } else {
            Err(format!(
                "SV_DATA_DIR is {}, which holds no `frameworks` folder. Point it at the `data` \
                 folder that came with sv.",
                dir.display()
            ))
        };
    }
    let looked = places(program, built);
    if let Some(found) = looked.iter().find(|dir| holds_data(dir)) {
        return Ok(found.clone());
    }
    Err(format!(
        "cannot find sv's data folder. Looked in {}. Put the `data` folder that came with sv beside \
         it, or set SV_DATA_DIR to it.",
        looked
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Where a program really is, following any link to it: `~/.local/bin/sv` is a link to
/// `~/.local/share/securevibe/sv`, whose data is beside the second. Linux already gives the real
/// place for the running program; macOS can give the link.
fn real_place(program: PathBuf) -> Option<PathBuf> {
    program.canonical().ok()
}

/// The data folder for this run, found once.
pub fn dir() -> Result<PathBuf, String> {
    static FOUND: OnceLock<Result<PathBuf, String>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            let env = std::env::var_os("SV_DATA_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from);
            let program = std::env::current_exe().ok().and_then(real_place);
            find(env, program.as_deref(), &built_from())
        })
        .clone()
}

/// What to say when a data file `sv` ships does not parse (backlog 226, part 2, item 16). The person
/// cannot fix the file, and it most likely belongs to another version of `sv`, so it says that, what
/// to do, and that nothing about the app was checked.
pub fn not_understood(path: &Path) -> String {
    format!(
        "{} is one of the data files `sv` ships, and this `sv` could not read it. It most likely \
         belongs to another version of `sv`: reinstall `sv`, or, if SV_DATA_DIR is set, point it at \
         the `data` folder that came with this one. Nothing about the app was checked.",
        path.display()
    )
}

/// A file in the data folder. When there is no data folder, the path it would have in the build
/// folder, so reading it fails with that path named; `dir` says why there is none.
pub fn file(name: &str) -> PathBuf {
    dir().unwrap_or_else(|_| built_from()).join(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch folder of this test's own, with a data folder at each of `with` (relative paths).
    fn scratch(test: &str, with: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("sv-data-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for place in with {
            std::fs::create_dir_all(root.join(place).join("frameworks")).unwrap();
        }
        std::fs::create_dir_all(root.join("bin")).unwrap();
        root
    }

    #[cfg(unix)]
    #[test]
    fn a_link_to_the_program_is_followed_to_where_it_really_is() {
        // The program and its data in a folder of their own, reached by a link from `bin`: only
        // following the link finds the data.
        let root = scratch("link", &["elsewhere/data"]);
        std::fs::write(root.join("elsewhere/sv"), "").unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere/sv"), root.join("bin/sv")).unwrap();
        let real = real_place(root.join("bin/sv"));
        let found = find(None, real.as_deref(), &root.join("built"));
        let expected = root.join("elsewhere/data").canonical().unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(found, Ok(expected));
    }

    #[test]
    fn data_beside_the_program_is_used_before_the_build_folder() {
        let root = scratch("beside", &["bin/data", "built"]);
        let program = root.join("bin/sv");
        let found = find(None, Some(&program), &root.join("built"));
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(found, Ok(root.join("bin/data")));
    }

    #[test]
    fn an_installed_program_finds_its_data_under_share() {
        let root = scratch("share", &["share/securevibe/data", "built"]);
        let program = root.join("bin/sv");
        let found = find(None, Some(&program), &root.join("built"));
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(found, Ok(root.join("bin/../share/securevibe/data")));
    }

    #[test]
    fn the_build_folder_is_used_when_nothing_is_beside_the_program() {
        let root = scratch("built", &["built"]);
        let found = find(None, Some(&root.join("bin/sv")), &root.join("built"));
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(found, Ok(root.join("built")));
    }

    #[test]
    fn sv_data_dir_comes_first_and_a_wrong_one_is_named_not_passed_over() {
        let root = scratch("env", &["chosen", "bin/data", "built"]);
        let program = root.join("bin/sv");
        let chosen = find(
            Some(root.join("chosen")),
            Some(&program),
            &root.join("built"),
        );
        let wrong = find(
            Some(root.join("nothing")),
            Some(&program),
            &root.join("built"),
        );
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(chosen, Ok(root.join("chosen")));
        let why = wrong.unwrap_err();
        assert!(
            why.contains("SV_DATA_DIR") && why.contains("nothing"),
            "{why}"
        );
    }

    #[test]
    fn a_folder_without_the_frameworks_does_not_count_and_every_place_is_named() {
        let root = scratch("none", &[]);
        // A `data` folder beside the program, but not one of sv's.
        std::fs::create_dir_all(root.join("bin/data")).unwrap();
        let found = find(None, Some(&root.join("bin/sv")), &root.join("built"));
        std::fs::remove_dir_all(&root).ok();
        let why = found.unwrap_err();
        for place in [
            Path::new("bin").join("data"),
            Path::new("share").join("securevibe").join("data"),
            Path::new("share").join("stackvet").join("data"),
            PathBuf::from("built"),
        ] {
            let place = place.display().to_string();
            assert!(why.contains(&place), "{place} not named: {why}");
        }
    }
}
