//! A bundle made before the rename ends with the old comment, and is still `sv`'s own to replace
//! (ADR-062); a zip ending with any other comment is not.

use std::path::PathBuf;
use sv_frameworks::names::{BUNDLE_COMMENT, OLD_BUNDLE_COMMENT};

/// A zip holding nothing: the end-of-central-directory record alone, with `comment` after it.
fn empty_zip_with_comment(comment: &str) -> Vec<u8> {
    let mut out = 0x0605_4b50u32.to_le_bytes().to_vec();
    out.extend_from_slice(&[0u8; 16]);
    out.extend_from_slice(&(comment.len() as u16).to_le_bytes());
    out.extend_from_slice(comment.as_bytes());
    out
}

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-bundle-comment-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_bundle_with_the_old_comment_is_still_svs_own_and_a_strangers_zip_is_not() {
    let dir = scratch();
    let sv = env!("CARGO_BIN_EXE_sv");
    // `made_by_sv` is `sv bundle`'s own gate: a zip at the output path that is not `sv`'s is
    // refused rather than replaced, so the gate is tried through the binary.
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/partly-passing");
    for (comment, replaced) in [
        (OLD_BUNDLE_COMMENT, true),
        (BUNDLE_COMMENT, true),
        ("Somebody else's archive.", false),
    ] {
        let zip = dir.join(format!("{}.zip", comment.len()));
        std::fs::write(&zip, empty_zip_with_comment(comment)).unwrap();
        let out = std::process::Command::new(sv)
            .arg("bundle")
            .arg(&app)
            .arg("--out")
            .arg(&zip)
            .output()
            .unwrap();
        assert_eq!(
            out.status.success(),
            replaced,
            "{comment:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        if replaced {
            assert!(
                std::fs::metadata(&zip).unwrap().len() > 100,
                "the bundle was written over the old one"
            );
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}
