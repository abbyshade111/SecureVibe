//! The tests of `adapters.rs` that were `mod folder_tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;

#[test]
fn a_path_under_the_app_folder_is_made_relative_however_the_folder_was_typed() {
    let dir = std::env::temp_dir().join(format!("sv-folder-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("backend")).unwrap();
    let abs = dir.display().to_string();
    let file = format!("{abs}/backend/app.py");
    for typed in [
        abs.clone(),
        format!("{abs}/"),
        format!("{abs}/."),
        format!("{abs}/./"),
    ] {
        assert_eq!(
            relative_to(&file, Path::new(&typed)),
            "backend/app.py",
            "{typed}"
        );
    }
    // A tool that echoes the folder as it was given, relative.
    assert_eq!(
        relative_to("./app/backend/x.py", Path::new("./app")),
        "backend/x.py"
    );
    assert_eq!(
        relative_to("app/backend/x.py", Path::new("app/.")),
        "backend/x.py"
    );
    // The controls: a path elsewhere stays as it is, and so does one that only shares the
    // folder's name as the start of a longer one.
    assert_eq!(
        relative_to("/elsewhere/lib.py", Path::new(&abs)),
        "/elsewhere/lib.py"
    );
    let sibling = format!("{abs}-other/x.py");
    assert_eq!(relative_to(&sibling, Path::new(&abs)), sibling);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_folder_is_cleaned_of_its_dots_and_trailing_separator() {
    for (typed, clean) in [
        ("app", "app"),
        ("app/", "app"),
        ("app/.", "app"),
        ("./app", "app"),
        ("./app/./", "app"),
        (".", "."),
        ("./", "."),
        ("/srv/app/.", "/srv/app"),
    ] {
        assert_eq!(clean_folder(Path::new(typed)), Path::new(clean), "{typed}");
    }
}
