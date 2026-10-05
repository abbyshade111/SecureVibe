//! A field in the wrong section of securevibe.toml is answered, by every command that reads the
//! file, with the section it was read in and where a field of that name belongs (DESIGN, "A
//! misplaced field names its section"). In the loop pilot an AI coding tool told only the field
//! sent the same line back five times.

use std::process::Command;

#[test]
fn every_command_that_reads_the_manifest_names_the_section() {
    let root = std::env::temp_dir().join(format!("sv-misplaced-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        root.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"Club\"\n\n[stack.run.ai]\nenabled = true\n",
    )
    .unwrap();
    let out = root.join("out");
    let app = root.to_str().unwrap();
    for args in [
        vec!["scope", app],
        vec!["report", app, "--out", out.to_str().unwrap()],
        vec!["audit", app],
        vec!["rules", app],
    ] {
        let done = Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(&args)
            .env_remove("SV_ADVISORY_DIR")
            .output()
            .expect("sv runs");
        let said = format!(
            "{}{}",
            String::from_utf8_lossy(&done.stdout),
            String::from_utf8_lossy(&done.stderr)
        );
        assert_eq!(done.status.code(), Some(3), "{args:?}: {said}");
        assert!(
            said.contains("`enabled` is not a field of [stack.run.ai]."),
            "{args:?}: {said}"
        );
        assert!(
            said.contains("Did you mean [capabilities.ai]?"),
            "{args:?}: {said}"
        );
        assert!(said.contains("line 6"), "{args:?}: {said}");
    }
    std::fs::remove_dir_all(&root).ok();
}
