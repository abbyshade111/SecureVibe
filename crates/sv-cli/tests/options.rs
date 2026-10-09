//! What `sv` makes of the words after a command: an option is never read as a folder, `--help` works
//! after any command, and `sv --version` says which build this is.

use std::path::PathBuf;
use std::process::{Command, Output};

/// Every command `sv --help` lists.
const COMMANDS: &[&str] = &[
    "init",
    "scope",
    "plan",
    "preflight",
    "brief",
    "notes",
    "questions",
    "rules",
    "prompts",
    "probe",
    "run",
    "check",
    "sbom",
    "audit",
    "report",
    "review",
    "bundle",
    "dashboard",
    "history",
    "mcp",
];

fn sv(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .env_remove("RUST_BACKTRACE")
        .output()
        .expect("sv runs")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn the_list_of_commands_here_is_the_one_the_help_gives() {
    let help = text(&sv(&["--help"]));
    let listed: Vec<&str> = help
        .lines()
        .filter_map(|l| l.strip_prefix("  sv "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| !w.starts_with('-'))
        .collect();
    assert_eq!(listed, COMMANDS, "{help}");
}

#[test]
fn help_after_any_command_shows_that_command_and_does_nothing_else() {
    for command in COMMANDS {
        for flag in ["--help", "-h"] {
            let out = sv(&[command, flag]);
            let said = text(&out);
            assert!(out.status.success(), "sv {command} {flag}: {said}");
            assert!(
                said.starts_with("USAGE:\n") && said.contains(&format!("  sv {command}")),
                "sv {command} {flag}: {said}"
            );
            // Only this command's lines, not the whole list, and nothing was run.
            assert_eq!(
                said.matches("  sv ").count(),
                1,
                "sv {command} {flag}: {said}"
            );
            assert!(!said.contains("not a folder"), "{said}");
        }
    }
    // Also after a folder, and before the command's own required value.
    let out = sv(&["audit", ".", "--help"]);
    assert!(out.status.success(), "{}", text(&out));
}

#[test]
fn an_unknown_option_is_an_error_that_names_the_commands_options_never_a_folder() {
    for command in COMMANDS {
        let out = sv(&[command, "--nonsense"]);
        let said = text(&out);
        assert!(!out.status.success(), "sv {command} --nonsense: {said}");
        assert!(
            said.contains(&format!("unknown option for `sv {command}`: --nonsense")),
            "sv {command} --nonsense: {said}"
        );
        assert!(said.contains("USAGE:"), "{said}");
        for folder_word in ["not a folder", "no stackvet.toml in"] {
            assert!(!said.contains(folder_word), "sv {command}: {said}");
        }
    }
    // The options it names are the command's own.
    let said = text(&sv(&["report", "-x"]));
    assert!(
        said.contains(
            "it takes --run, --slow, --tools, --out, --advisories, --fail-on, and --help"
        ),
        "{said}"
    );
    let said = text(&sv(&["check", "--run"]));
    assert!(said.contains("it takes --fail-on, and --help"), "{said}");
    let said = text(&sv(&["sbom", "--run"]));
    assert!(said.contains("it takes no options but --help"), "{said}");
}

#[test]
fn a_second_folder_an_option_missing_its_value_and_a_word_where_none_is_taken_are_refused() {
    let said = text(&sv(&["check", "one", "two"]));
    assert!(
        said.contains("`sv check` takes one PATH, and was given a second: two"),
        "{said}"
    );
    let said = text(&sv(&["report", ".", "--out"]));
    assert!(said.contains("`--out` needs a value after it"), "{said}");
    let said = text(&sv(&["mcp", "apps"]));
    assert!(
        said.contains("`sv mcp` takes only options, and was given apps"),
        "{said}"
    );
    let said = text(&sv(&["init", "extra"]));
    assert!(said.contains("`sv init` takes only options"), "{said}");
}

#[test]
fn a_value_that_starts_with_a_dash_is_a_value_and_a_dashed_folder_can_be_named() {
    let dir: PathBuf = std::env::temp_dir().join(format!("sv-options-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    let dashed = dir.join("-app");
    std::fs::create_dir_all(&dashed).unwrap();
    std::fs::write(dashed.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dashed.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Dashed\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();

    // The control: the folder is really there and really checked when named plainly.
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["check", "./-app"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    // Named bare, it is taken for an option, and the message says how to name it.
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["check", "-app"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        text(&out).contains("can be given as ./-app"),
        "{}",
        text(&out)
    );
    // Two folders are refused, and neither is checked.
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["check", "./-app", "./-app"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(
        !out.status.success() && text(&out).contains("was given a second: ./-app"),
        "{}",
        text(&out)
    );
    // A value is whatever follows its option, dash or not.
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["rules", "./-app", "--print"])
        .current_dir(&dir)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report", "./-app", "--out", "-out"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let wrote = dir.join("-out").join("report.json").is_file();
    std::fs::remove_dir_all(&dir).ok();
    assert!(out.status.success(), "{}", text(&out));
    assert!(wrote, "no report in -out");
}

#[test]
fn the_version_names_the_build_and_its_commit() {
    for flag in ["--version", "-V", "version"] {
        let out = sv(&[flag]);
        let all = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        assert!(out.status.success(), "{all}");
        let (said, data) = all.split_once('\n').unwrap_or((&all, ""));
        // The second line names the data folder this copy reads (ADR-036).
        assert!(
            data.starts_with("data: ") && data.ends_with("data"),
            "sv {flag}: {all}"
        );
        let expected_start = format!("sv {} (commit ", env!("CARGO_PKG_VERSION"));
        let commit = said
            .strip_prefix(&expected_start)
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or_else(|| panic!("sv {flag}: {said}"));
        assert!(
            commit == "unknown"
                || (commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit())),
            "sv {flag}: {said}"
        );
    }
}

#[test]
fn an_unknown_command_is_still_refused_with_the_whole_help() {
    let out = sv(&["chekc"]);
    let said = text(&out);
    assert!(!out.status.success());
    assert!(
        said.contains("unknown command: chekc") && said.contains("  sv report"),
        "{said}"
    );
}

#[test]
fn help_writes_nothing_even_where_the_command_would() {
    let dir: PathBuf = std::env::temp_dir().join(format!("sv-options-help-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Helped\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap()
    };
    let asked = [
        run(&["report", ".", "--out", "asked", "--help"]),
        run(&["rules", "-h"]),
        run(&["sbom", "--help"]),
    ];
    let written: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "stackvet.toml")
        .collect();
    // The control: without --help, the same report command does write its folder.
    let control = run(&["report", ".", "--out", "asked"]);
    let control_wrote = dir.join("asked").join("report.json").is_file();
    std::fs::remove_dir_all(&dir).ok();
    for out in &asked {
        assert!(out.status.success(), "{}", text(out));
    }
    assert!(written.is_empty(), "help wrote {written:?}");
    assert!(
        // 2: a folder holding only stackvet.toml has no file of the app to read.
        control.status.code() == Some(2) && control_wrote,
        "{}",
        text(&control)
    );
}

#[test]
fn an_option_given_where_a_value_belongs_is_refused_and_nothing_is_written() {
    // The deep review's improvement 7: `sv report --out --run` wrote the report to a folder named
    // `--run`, and did not run the app it was asked to.
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-options-value-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("app")).unwrap();
    std::fs::write(dir.join("app").join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("app").join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"Valued\"\n[stack]\nlanguages = [\"python\"]\n",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["report", "app", "--out", "--run"])
        .current_dir(&dir)
        .output()
        .unwrap();
    let wrote = dir.join("--run").exists();
    let said = text(&out);
    std::fs::remove_dir_all(&dir).ok();
    assert!(!out.status.success(), "{said}");
    assert!(
        said.contains("`--out` needs a value after it, and was given the option --run"),
        "{said}"
    );
    assert!(said.contains("can be given as ./--run"), "{said}");
    assert!(!wrote, "a folder named --run was written");
    for (command, option) in [
        ("audit", "--advisories"),
        ("mcp", "--root"),
        ("check", "--fail-on"),
    ] {
        let said = text(&sv(&[command, option, "--slow"]));
        assert!(
            said.contains(&format!(
                "`{option}` needs a value after it, and was given the option --slow"
            )),
            "{command}: {said}"
        );
    }
}
