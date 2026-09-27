//! The AI coding tool's own line saying it wrote a section is not an answer — end to end.
//!
//! `*Written by the AI coding tool from the code; review before relying on it.*` has no colon, so it
//! is not a `Written by:` line, and it is longer than the floor an answer must pass. A section
//! holding nothing else read as the tool's answer, *stated by the AI coding tool*, on 27 September
//! 2026, when nothing had been answered at all.

use serde_json::Value;
use std::process::Command;

fn sv(args: &[&str]) {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_section_holding_only_the_tools_disclaimer_is_not_verified() {
    let dir = std::env::temp_dir().join(format!("sv-notes-disclaimer-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    sv(&["notes", dir.to_str().unwrap()]);
    let path = dir.join("security-notes.md");
    let mut text = std::fs::read_to_string(&path).unwrap();
    // Two sections: one with the disclaimer alone, one with the disclaimer over a real answer.
    for (id, body) in [
        (
            "V11.1.1",
            "*Written by the AI coding tool from the code; review before relying on it.*",
        ),
        (
            // An answer whose first sentence begins "Written by", not in emphasis: still the answer.
            "V8.1.1",
            "Written by our accountant: only the owner may change prices or see payments.\n\n\
             Written by: owner",
        ),
        (
            "V2.1.1",
            "_Written by the AI coding tool from the code, for the owner to review._",
        ),
        (
            "V13.1.1",
            "*Written by the AI coding tool from the code; review before relying on it.*\n\nThe \
             app talks to its own SQLite file and to nothing else over the network.",
        ),
    ] {
        let at = text
            .find(&format!("## {id} "))
            .unwrap_or_else(|| panic!("{id} is not asked"));
        let placeholder = text[at..].find(sv_check::notes::PLACEHOLDER).unwrap() + at;
        text = format!(
            "{}{}{}",
            &text[..placeholder],
            body,
            &text[placeholder + sv_check::notes::PLACEHOLDER.len()..]
        );
    }
    std::fs::write(&path, &text).unwrap();
    let out = dir.join("report");
    sv(&[
        "report",
        dir.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    let report: Value =
        serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap();
    let status = |id: &str| {
        report["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("{id} is not in the report"))["status"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    assert_eq!(status("V11.1.1"), "not-verified", "nothing was answered");
    assert_eq!(status("V2.1.1"), "not-verified", "in underscores, the same");
    assert_eq!(status("V8.1.1"), "documented", "a sentence is not a byline");
    // The control: the same line over a real answer still reads as the tool's answer, so the
    // file was read and the section above really was looked at.
    assert_eq!(status("V13.1.1"), "stated");
    std::fs::remove_dir_all(&dir).ok();
}
