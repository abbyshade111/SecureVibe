//! What the entries say about the tools that read the app's folder for themselves (the review of
//! 8 October 2026, item 3): gosec downloads nothing and runs no C compiler, says in its log which
//! files it read, and, with Brakeman, is not run over an app that holds a link. Each line here was
//! read from a real run of the tool on 8 October 2026 (`data/adapters.json`, the entries' notes).

use std::path::PathBuf;
use sv_check::adapters::{Adapter, Adapters};

fn adapters() -> Adapters {
    Adapters::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"))
        .expect("the adapter file loads")
}

fn entry(all: &Adapters, id: &str) -> Adapter {
    all.all()
        .iter()
        .find(|a| a.id == id)
        .unwrap_or_else(|| panic!("{id} is listed"))
        .clone()
}

#[test]
fn gosec_is_kept_from_downloading_modules_and_from_running_the_c_compiler() {
    let gosec = entry(&adapters(), "gosec");
    assert_eq!(gosec.env.get("GOPROXY").map(String::as_str), Some("off"));
    assert_eq!(gosec.env.get("CGO_ENABLED").map(String::as_str), Some("0"));
    assert!(!gosec.network, "and so does not reach the network");
}

#[test]
fn gosec_s_log_is_read_for_what_it_checked_and_what_it_could_not() {
    let gosec = entry(&adapters(), "gosec");
    assert_eq!(gosec.read_log_prefix.as_deref(), Some("Checking file: "));
    // With `-quiet` the log named nothing and a clean run wrote no report, so none was ever
    // credited; `-tests` reads the test files `sv` hands every other tool.
    assert!(
        !gosec.run.args.iter().any(|a| a == "-quiet"),
        "{:?}",
        gosec.run.args
    );
    assert!(
        gosec.run.args.iter().any(|a| a == "-tests"),
        "{:?}",
        gosec.run.args
    );
    assert!(
        gosec
            .unfinished_when
            .iter()
            .any(|u| u.contains == "Error building the SSA representation"
                && u.means.contains("go mod download")),
        "{:?}",
        gosec.unfinished_when
    );
}

#[test]
fn the_tools_shown_to_follow_a_link_say_so_and_the_one_shown_not_to_does_not() {
    let all = adapters();
    for (id, follows) in [
        ("gosec", true),
        ("brakeman", true),
        ("codeql-javascript", false),
        ("codeql-python", false),
        ("bandit", false),
        ("semgrep", false),
    ] {
        let tool = entry(&all, id);
        assert_eq!(tool.follows_links, follows, "{id}");
        if follows {
            assert!(
                !tool.run.args.iter().any(|a| a == "{files}"),
                "{id} walks the folder, so it is not handed the files"
            );
        }
    }
}
