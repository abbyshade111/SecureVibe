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
    let example =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes/stackvet.toml");
    let mut manifest = std::fs::read_to_string(example).unwrap();
    let config = dir.join("config");
    let (key, _) =
        sv_check::seal::Key::load_or_make_in(&config.join(sv_frameworks::names::CONFIG_DIR))
            .unwrap();
    // Sealed for this app, as `sv review` run in it seals.
    let key = key.for_app(&sv_check::seal::App::of(&dir).unwrap());

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
    std::fs::write(dir.join("stackvet.toml"), &manifest).unwrap();

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

/// ADR-043: a signed answer counts on a computer given the owner's list as SV_TRUSTED_SEALS, even
/// where a list of its own trusts another key, and the report names the key and the list.
#[test]
fn an_owners_signed_answer_counts_where_sv_trusted_seals_names_its_key() {
    let dir: PathBuf = std::env::temp_dir().join(format!("sv-owner-signed-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "def home():\n    return 'hi'\n").unwrap();
    let example =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/tested-notes/stackvet.toml");
    let mut manifest = std::fs::read_to_string(example).unwrap();
    let app = sv_check::seal::App::of(&dir).unwrap();
    // The owner's key, on the owner's computer, and the line they would give CI.
    let owners = dir.join("owners-computer");
    let key = sv_check::signed::SigningKey::make_in(&owners, None).unwrap();
    let line = key.trusted_line(&app).unwrap();
    // This computer's own list trusts another key for the app.
    let config = dir.join("config");
    let other =
        sv_check::signed::SigningKey::make_in(&config.join(sv_frameworks::names::CONFIG_DIR), None)
            .unwrap();
    sv_check::signed::trust_here(&config.join(sv_frameworks::names::CONFIG_DIR), &other, &app)
        .unwrap();
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
    std::fs::write(dir.join("stackvet.toml"), &manifest).unwrap();

    let report = |list: Option<&str>| {
        let out_dir = dir.join("report");
        let mut sv = Command::new(env!("CARGO_BIN_EXE_sv"));
        sv.env("XDG_CONFIG_HOME", &config)
            .env_remove(sv_check::signed::TRUSTED_VARIABLE);
        if let Some(list) = list {
            sv.env(sv_check::signed::TRUSTED_VARIABLE, list);
        }
        let out = sv
            .arg("report")
            .arg(&dir)
            .arg("--out")
            .arg(&out_dir)
            .output()
            .expect("sv runs");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let compliance = std::fs::read_to_string(out_dir.join("compliance.md")).unwrap();
        status_of(&compliance, "V8.3.1").to_owned()
    };
    let given = report(Some(&line));
    let mine = report(None);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        given.starts_with("attested by the owner")
            && given.contains(&format!("signed with key {}", key.fingerprint()))
            && given.contains("the list of trusted keys in SV_TRUSTED_SEALS trusts for this app"),
        "{given}"
    );
    assert!(
        mine.starts_with("stated by the AI coding tool")
            && mine.contains(&key.fingerprint())
            && mine.contains("this computer's list of trusted keys does not name"),
        "{mine}"
    );
}
