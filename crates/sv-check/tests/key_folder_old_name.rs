//! The signing key's folder after the rename (ADR-062): the new folder is used; while it does not
//! exist and the old one does, the old one is used and said; nothing moves a key. The one test
//! in this file sets `XDG_CONFIG_HOME`, which is why it has a file of its own.

use sv_check::seal::Key;
use sv_frameworks::names::{CONFIG_DIR, OLD_CONFIG_DIR};

#[test]
fn the_old_config_folder_is_used_while_the_new_one_does_not_exist_and_said() {
    let root = std::env::temp_dir().join(format!("sv-key-folder-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(&root).unwrap();
    unsafe { std::env::set_var("XDG_CONFIG_HOME", &root) };

    // Neither folder: the new one is where a key would be made.
    assert_eq!(Key::folder(), Some(root.join(CONFIG_DIR)));
    assert_eq!(Key::old_folder_in_use(), None);

    // The old folder, with a key file: used, and said.
    std::fs::create_dir_all(root.join(OLD_CONFIG_DIR)).unwrap();
    std::fs::write(
        root.join(OLD_CONFIG_DIR).join("review-key"),
        "not a real key\n",
    )
    .unwrap();
    assert_eq!(Key::folder(), Some(root.join(OLD_CONFIG_DIR)));
    assert_eq!(
        Key::old_folder_in_use(),
        Some((root.join(OLD_CONFIG_DIR), root.join(CONFIG_DIR)))
    );
    assert!(
        root.join(OLD_CONFIG_DIR).join("review-key").is_file(),
        "nothing moved the key"
    );

    // The new folder made (by the person moving the key): the new one wins, and nothing is said.
    std::fs::create_dir_all(root.join(CONFIG_DIR)).unwrap();
    assert_eq!(Key::folder(), Some(root.join(CONFIG_DIR)));
    assert_eq!(Key::old_folder_in_use(), None);
    unsafe { std::env::remove_var("XDG_CONFIG_HOME") };
    std::fs::remove_dir_all(&root).ok();
}
