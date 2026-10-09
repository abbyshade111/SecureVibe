//! `sv review` and the container (`docs/GAP-ANALYSIS.md`, 5.3): someone with only Docker records their
//! answers through the container, and the AI tool's container is given the list of trusted keys alone,
//! read-only, never the folder that holds the key that signs as the owner. Held to the README, to the
//! names the code uses, and, natively, to what that container would see.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo().join(path)).unwrap()
}

/// The guide's step 5.
fn step_five() -> String {
    let guide = read("docs/GETTING-STARTED.md");
    let start = guide.find("## 5. Answer the questions").unwrap();
    let end = start + guide[start..].find("\n## 6.").unwrap();
    guide[start..end].to_owned()
}

/// The fenced blocks of `lang` in `text`.
fn blocks(text: &str, lang: &str) -> Vec<String> {
    let open = format!("```{lang}\n");
    text.split(&open)
        .skip(1)
        .map(|rest| rest.split("```").next().unwrap().to_owned())
        .collect()
}

#[test]
fn the_guide_gives_the_containers_sv_review_as_the_readme_does() {
    let step = step_five();
    let commands = blocks(&step, "bash").join("");
    let review = commands
        .lines()
        .find(|l| l.starts_with("docker run") && l.ends_with(" review ."))
        .unwrap_or_else(|| panic!("no container sv review in step 5: {step}"));
    // The same command the README gives, so the two cannot drift apart.
    assert!(
        read("README.md").contains(&format!("`{review}`")),
        "the README gives another command than {review}"
    );
    for part in [
        "-it",
        "--network none",
        "-v \"$HOME/.config/stackvet\":/sv-config/stackvet",
        "-e XDG_CONFIG_HOME=/sv-config",
    ] {
        assert!(review.contains(part), "{part} in {review}");
    }
    // The folder is made first, with the list in it, so a mount of the list alone finds a file.
    let made = commands
        .lines()
        .find(|l| l.starts_with("mkdir -p ~/.config/stackvet"))
        .expect("the folder is made first");
    assert!(made.contains("chmod 700 ~/.config/stackvet"), "{made}");
    assert!(
        made.contains(&format!(
            "touch ~/.config/stackvet/{}",
            sv_check::signed::TRUSTED_FILE
        )),
        "{made}"
    );
}

#[test]
fn the_ai_tools_container_is_given_the_list_alone_and_read_only() {
    let step = step_five();
    let json = blocks(&step, "json");
    assert_eq!(json.len(), 1, "one .mcp.json in step 5");
    let config: serde_json::Value = serde_json::from_str(&json[0]).expect("the .mcp.json parses");
    let args: Vec<&str> = config["mcpServers"]["stackvet"]["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap())
        .collect();
    let image = args
        .iter()
        .position(|a| a.starts_with("ghcr.io/"))
        .expect("the image is named");
    assert_eq!(&args[image + 1..image + 3], ["mcp", "--root"]);
    // Docker's own options come before the image; after it they would be sv's arguments.
    let mounts: Vec<&str> = args[..image]
        .windows(2)
        .filter(|w| w[0] == "-v")
        .map(|w| w[1])
        .collect();
    let list = format!(
        "/.config/stackvet/{}:/sv-config/stackvet/{}:ro",
        sv_check::signed::TRUSTED_FILE,
        sv_check::signed::TRUSTED_FILE
    );
    assert!(
        mounts.iter().any(|m| m.ends_with(&list)),
        "the list, read-only: {mounts:?}"
    );
    assert!(
        !mounts
            .iter()
            .any(|m| m.ends_with("/.config/securevibe:/sv-config/securevibe")),
        "the whole key folder is given to the AI tool's container: {mounts:?}"
    );
    assert!(
        args[..image]
            .windows(2)
            .any(|w| w == ["-e", "XDG_CONFIG_HOME=/sv-config"]),
        "{args:?}"
    );
}

/// What that container sees, made natively: a settings folder holding the list and nothing else, the
/// list read-only and no signing key anywhere in it. A signed answer still counts as the owner's.
#[test]
fn a_folder_with_only_the_list_is_enough_to_count_a_signed_answer() {
    let dir = std::env::temp_dir().join(format!("sv-review-container-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let app_dir = dir.join("app");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::write(app_dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let mut manifest = read("examples/tested-notes/stackvet.toml");
    let app = sv_check::seal::App::of(&app_dir).unwrap();

    // On the owner's computer: the key, and the list `sv review` keeps beside it.
    let owners = dir.join("owners-config/securevibe");
    let key = sv_check::signed::SigningKey::make_in(&owners, None).unwrap();
    sv_check::signed::trust_here(&owners, &key, &app).unwrap();
    let answer = sv_manifest::DesignAnswer {
        answer: "yes".into(),
        r#where: Some("app.py".into()),
        by: Some("owner".into()),
        ..Default::default()
    };
    let seal = key
        .for_app(&app)
        .seal(&sv_check::seal::as_strs(
            &sv_check::seal::design_answer_fields("V8.3.1", &answer),
        ))
        .unwrap();
    manifest.push_str(&format!(
        "\n[design]\n\"V8.3.1\" = {{ answer = \"yes\", where = \"app.py\", by = \"owner\", seal = \"{seal}\" }}\n"
    ));
    std::fs::write(app_dir.join("stackvet.toml"), &manifest).unwrap();

    // In the container: only the list, copied as the mount shows it, read-only.
    let seen = dir.join("sv-config/securevibe");
    std::fs::create_dir_all(&seen).unwrap();
    let list = seen.join(sv_check::signed::TRUSTED_FILE);
    std::fs::copy(owners.join(sv_check::signed::TRUSTED_FILE), &list).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&list, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let held: Vec<String> = std::fs::read_dir(&seen)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        held,
        [sv_check::signed::TRUSTED_FILE],
        "the setup: the list and nothing else"
    );

    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", dir.join("sv-config"))
        .env_remove(sv_check::signed::TRUSTED_VARIABLE)
        .arg("report")
        .arg(&app_dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .unwrap();
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap_or_default();
    let line = compliance
        .lines()
        .find(|l| l.contains("V8.3.1"))
        .unwrap_or_default()
        .to_owned();
    // No signing key was made in the container's folder by a report.
    let key_made = std::fs::read_dir(&seen)
        .unwrap()
        .flatten()
        .any(|e| e.file_name().to_string_lossy().contains("signing"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&list, std::fs::Permissions::from_mode(0o644)).ok();
    }
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        line.contains("attested by the owner")
            && line.contains(&format!("signed with key {}", key.fingerprint())),
        "{line}"
    );
    assert!(!key_made, "a report made a signing key beside the list");
}
