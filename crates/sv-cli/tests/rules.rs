//! `sv rules` writes the security rules for the AI coding tool into the app's `AGENTS.md`: without
//! touching anything the owner wrote there, leaving out what the manifest says does not apply, and
//! crediting OWASP AISVS Appendix C, with its license, every time.

use std::path::PathBuf;
use std::process::Command;

fn sv(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn folder(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-rules-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const CREDIT: [&str; 3] = [
    "OWASP AI Security Verification Standard (AISVS) 1.0, Appendix C",
    "https://github.com/OWASP/AISVS/blob/main/1.0/en/0x92-Appendix-C_AI_for_Code_Generation.md",
    "[CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)",
];

#[test]
fn the_rules_go_into_agents_md_beside_what_the_owner_wrote() {
    let dir = folder("beside");
    let owner = "# Our app\n\nAlways use tabs, and never touch `legacy/`.\n";
    std::fs::write(dir.join("AGENTS.md"), owner).unwrap();
    let said = sv(&["rules", dir.to_str().unwrap()]);
    assert!(said.contains("after what was already in it"), "{said}");
    assert!(said.contains("no stackvet.toml yet"), "{said}");
    let written = std::fs::read_to_string(dir.join("AGENTS.md")).unwrap();
    assert!(written.starts_with(owner.trim_end()), "{written}");
    for credit in CREDIT {
        assert!(written.contains(credit), "missing {credit}:\n{written}");
    }
    assert!(
        written.contains("pull_request_target"),
        "every rule, with nothing known yet"
    );
    // Each rule ends with what it comes from.
    assert!(written.contains("(AC.3.1, AC.3.2)"), "{written}");

    // Again, with a note the owner added after the section: only the section is replaced.
    let later = format!("{written}\n## Deploying\n\nAsk me first.\n");
    std::fs::write(dir.join("AGENTS.md"), &later).unwrap();
    let said = sv(&["rules", dir.to_str().unwrap()]);
    assert!(said.contains("replacing only the section"), "{said}");
    let again = std::fs::read_to_string(dir.join("AGENTS.md")).unwrap();
    assert_eq!(again, later, "the same rules, so nothing changed");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn rules_that_do_not_apply_to_the_app_are_left_out_and_counted() {
    let dir = folder("filtered");
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n[repository]\nci-cd = false\n\
         outside-contributors = false\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    let said = sv(&["rules", dir.to_str().unwrap()]);
    assert!(said.contains("left out"), "{said}");
    let written = std::fs::read_to_string(dir.join("AGENTS.md")).unwrap();
    assert!(
        !written.contains("pull_request_target"),
        "no pipeline, no pipeline rules"
    );
    assert!(written.contains("left out"), "{written}");
    assert!(
        written.contains("Before adding a package"),
        "given to every app, though what it cites is about outside contributions"
    );
    // A rule citing one requirement that is set aside and others that still apply is kept.
    assert!(written.contains("Say in a comment at the top"), "{written}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn print_shows_the_rules_and_writes_nothing() {
    let dir = folder("print");
    let shown = sv(&["rules", dir.to_str().unwrap(), "--print"]);
    assert!(
        shown.contains("## Security rules for the AI coding tool"),
        "{shown}"
    );
    for credit in CREDIT {
        assert!(shown.contains(credit), "missing {credit}");
    }
    assert!(!dir.join("AGENTS.md").exists());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn broken_markers_leave_the_owners_file_alone() {
    let dir = folder("broken");
    let broken = "# Ours\n<!-- securevibe:coding-rules:begin -->\nhalf, and my notes\n";
    std::fs::write(dir.join("AGENTS.md"), broken).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(["rules", dir.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("left as it was"));
    assert_eq!(
        std::fs::read_to_string(dir.join("AGENTS.md")).unwrap(),
        broken
    );
    std::fs::remove_dir_all(&dir).ok();
}
