//! The tests of `adapters.rs` that were `mod presence_tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;

#[test]
fn an_install_hint_reads_as_a_sentence_whether_it_is_a_command_or_steps() {
    // Gap analysis 5.3: "Install it with `download the CodeQL bundle from …`".
    assert_eq!(
        install_step("pip install semgrep"),
        "run `pip install semgrep`"
    );
    let codeql = "download the CodeQL bundle from https://example.org, unpack it";
    assert_eq!(install_step(codeql), codeql);
    // Every hint `sv` ships is one or the other, and each command is one `install_step` knows.
    let adapters =
        Adapters::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
            .unwrap();
    assert!(!adapters.all().is_empty());
    for adapter in adapters.all() {
        let step = install_step(&adapter.install);
        assert!(
            step.starts_with("run `") || step.starts_with("download "),
            "{}: {step}",
            adapter.id
        );
    }
}

#[test]
fn the_install_hint_is_the_one_for_this_kind_of_computer() {
    // Gap analysis 5.3: `pip install` is refused by Homebrew's Python and by recent Debian and
    // Ubuntu, so the general hint fails on most of the computers `sv` runs on.
    let adapters =
        Adapters::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
            .unwrap();
    let tool = |id: &str| adapters.all().iter().find(|a| a.id == id).unwrap();
    let semgrep = tool("semgrep");
    assert_eq!(
        semgrep.install_hint_on(Some("macos")),
        "run `brew install semgrep`"
    );
    assert!(
        semgrep
            .install_hint_on(Some("linux"))
            .starts_with("run `pipx install semgrep`")
    );
    assert_eq!(semgrep.install_hint_on(None), "run `pip install semgrep`");
    assert_eq!(
        semgrep.install_hint_on(Some("windows")),
        "run `pip install semgrep`"
    );
    assert_eq!(
        tool("gosec").install_hint_on(Some("macos")),
        "run `brew install gosec`"
    );
    assert!(
        tool("gosec")
            .install_hint_on(Some("linux"))
            .starts_with("run `go install")
    );
    for os in [Some("macos"), Some("linux"), None] {
        // Bandit writes no report `sv` reads without its SARIF formatter, wherever it is.
        assert!(
            tool("bandit")
                .install_hint_on(os)
                .contains("bandit-sarif-formatter"),
            "{os:?}"
        );
    }
    let mut given = 0;
    for adapter in adapters.all() {
        for (os, hint) in &adapter.install_on {
            given += 1;
            assert!(
                ["macos", "linux"].contains(&os.as_str()),
                "{}: {os}",
                adapter.id
            );
            assert!(hint.starts_with("run `"), "{}: {hint}", adapter.id);
            // `pip install` is what these hints are there to avoid.
            assert!(!hint.contains("pip install"), "{}: {hint}", adapter.id);
        }
    }
    assert!(given >= 5, "the setup: hints for more than one tool");
    // Homebrew has no Brakeman, and its CodeQL has no query packs: no hint was made up for them.
    assert!(tool("brakeman").install_on.is_empty());
    assert!(
        adapters
            .all()
            .iter()
            .filter(|a| a.id.starts_with("codeql"))
            .all(|a| a.install_on.is_empty())
    );
}

#[test]
fn a_silent_127_is_missing_and_one_that_says_why_is_broken() {
    assert_eq!(judge_presence(None), Presence::Missing);
    assert_eq!(
        judge_presence(Some((Some(0), String::new()))),
        Presence::Ready
    );
    assert_eq!(
        judge_presence(Some((Some(127), "\n  \n".into()))),
        Presence::Missing
    );
    assert_eq!(
        judge_presence(Some((
            Some(127),
            "env: 'python3': No such file or directory".into()
        ))),
        Presence::Broken {
            detail: "env: 'python3': No such file or directory".into()
        }
    );
    assert!(matches!(
        judge_presence(Some((Some(1), String::new()))),
        Presence::Broken { .. }
    ));
}

#[cfg(unix)]
#[test]
fn a_program_that_starts_and_exits_127_in_silence_reads_as_missing() {
    // What emulation does to a program that does not exist, played by a real one.
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("sv-presence-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let silent = dir.join("gone");
    std::fs::write(&silent, "#!/bin/sh\nexit 127\n").unwrap();
    std::fs::set_permissions(&silent, std::fs::Permissions::from_mode(0o755)).unwrap();
    let loud = dir.join("broken");
    std::fs::write(
        &loud,
        "#!/bin/sh\necho 'its interpreter is gone' >&2\nexit 127\n",
    )
    .unwrap();
    std::fs::set_permissions(&loud, std::fs::Permissions::from_mode(0o755)).unwrap();
    let adapter = |command: &std::path::Path| {
        let file: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
            )
            .unwrap(),
        )
        .unwrap();
        let mut a: Adapter =
            serde_json::from_value(file["adapters"][0].clone()).expect("a real adapter");
        a.version.command = command.display().to_string();
        a.version.args = Vec::new();
        a
    };
    let silent_presence = presence(&adapter(&silent));
    let loud_presence = presence(&adapter(&loud));
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(silent_presence, Presence::Missing);
    assert!(
        matches!(loud_presence, Presence::Broken { ref detail } if detail.contains("interpreter")),
        "{loud_presence:?}"
    );
}
