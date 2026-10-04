//! The owner's own answers, end to end (deep review R1): a `[design]` answer or `[checked-by-hand]`
//! result written `by = "owner"` is the owner's word in the report only when `sv review` recorded it.

use std::path::PathBuf;
use std::process::Command;
use sv_check::advisories::Day;

/// The status column of the requirement's row in compliance.md.
fn status_of<'a>(compliance: &'a str, id: &str) -> &'a str {
    let row = compliance
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap_or_else(|| panic!("no row for {id} in the report:\n{compliance}"));
    row.split('|').nth(2).unwrap_or("").trim()
}

#[test]
fn an_owners_answer_is_theirs_only_as_recorded_and_not_changed_since() {
    let today = Day::today().expect("a clock after 1970").show();
    let dir: PathBuf =
        std::env::temp_dir().join(format!("sv-owner-answers-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/tested-notes/securevibe.toml");
    let mut manifest = std::fs::read_to_string(example).unwrap();
    let config = dir.join("config");
    let (key, _) = sv_check::seal::Key::load_or_make_in(&config.join("securevibe")).unwrap();

    let design = |answer: &str| sv_manifest::DesignAnswer {
        answer: answer.into(),
        r#where: Some("app.py".into()),
        by: Some("owner".into()),
        ..Default::default()
    };
    let design_seal = |id: &str, a: &sv_manifest::DesignAnswer| {
        key.seal(&sv_check::seal::as_strs(
            &sv_check::seal::design_answer_fields(id, a),
        ))
    };
    let padlock = "Opened the live site; the padlock shows a trusted certificate.";
    let booked = "Two browsers tried to book one slot, and the second was refused.";
    let hand = |how: &str| sv_manifest::HandCheck {
        result: "done".into(),
        on: Some(today.clone()),
        by: Some("owner".into()),
        how: Some(how.into()),
        ..Default::default()
    };
    let hand_seal = |id: &str, h: &sv_manifest::HandCheck| {
        key.seal(&sv_check::seal::as_strs(
            &sv_check::seal::hand_check_fields(id, h),
        ))
    };
    manifest.push_str(&format!(
        r#"
[design]
"V8.3.1" = {{ answer = "yes", where = "app.py", by = "owner", seal = "{}" }}
"V15.3.1" = {{ answer = "yes", where = "app.py", by = "owner" }}
"V2.2.2" = {{ answer = "yes", where = "app.py", by = "owner", seal = "{}" }}

[checked-by-hand]
"V12.2.2" = {{ result = "done", on = "{today}", by = "owner", how = "{padlock}", seal = "{}" }}
"V2.3.4" = {{ result = "done", on = "{today}", by = "owner", how = "{booked}", seal = "{}" }}
"#,
        design_seal("V8.3.1", &design("yes")),
        // Recorded as "no", then changed to "yes" in the file.
        design_seal("V2.2.2", &design("no")),
        hand_seal("V12.2.2", &hand(padlock)),
        // Recorded with other words for what was seen.
        hand_seal("V2.3.4", &hand("Two browsers booked one slot.")),
    ));
    assert!(
        !manifest.contains("[design]\n[") && manifest.matches("[design]").count() == 1,
        "the example grew answers of its own; this test would be adding to them"
    );
    std::fs::write(dir.join("securevibe.toml"), &manifest).unwrap();

    let out_dir = dir.join("report");
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .env("XDG_CONFIG_HOME", &config)
        .arg("report")
        .arg(&dir)
        .arg("--out")
        .arg(&out_dir)
        .output()
        .expect("sv runs");
    let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let recorded = status_of(&compliance, "V8.3.1");
    assert!(
        recorded.starts_with("attested by the owner")
            && recorded.contains("recorded through `sv review` on this computer"),
        "V8.3.1: {recorded}"
    );
    let by_hand = status_of(&compliance, "V12.2.2");
    assert!(
        by_hand.starts_with("checked by hand by the owner")
            && by_hand.contains("recorded through `sv review` on this computer"),
        "V12.2.2: {by_hand}"
    );
    for (id, why) in [
        ("V15.3.1", "not recorded through `sv review`"),
        ("V2.2.2", "does not match"),
        ("V2.3.4", "does not match"),
    ] {
        let status = status_of(&compliance, id);
        assert!(
            status.starts_with("stated by the AI coding tool")
                && status.contains(why)
                && status.contains("run `sv review`"),
            "{id}: {status}"
        );
    }
}
