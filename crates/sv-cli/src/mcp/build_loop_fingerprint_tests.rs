//! Between the first check of the build loop and the last, which findings went because the AI tool
//! changed the code, which a person set aside as false alarms, and which were new (ADR-084,
//! decision 6), through the server, with a person's review sealed as `sv review` seals it.

use super::tests::{call, scratch_app, text};
use super::*;

const MANIFEST: &str =
    "manifest-version = 1\n[app]\nname = \"Looped\"\n[stack]\nlanguages = [\"python\"]\n";
const APP: &str = "from flask import Flask, redirect, request\napp = Flask(__name__)\n\n@app.route(\"/go\")\ndef go():\n    return redirect(request.args.get(\"next\"))\n";
const SQL: &str = "\ndef find(db, user_id):\n    cur = db.cursor()\n    cur.execute(\"SELECT * FROM notes WHERE owner = \" + user_id)\n";

fn report(app: &Path) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(
            sv_scan::ecosystems::default_report_dir_in(app).join("report.json"),
        )
        .unwrap(),
    )
    .unwrap()
}

/// A person's false-alarm entry for the finding of `rule`, sealed as `sv review` seals it.
fn false_alarm(app: &Path, rule: &str, file: &str, fingerprint: &str) -> String {
    let on = sv_check::advisories::Day::today().unwrap().show();
    let review = sv_manifest::FindingReview {
        rule: rule.into(),
        file: file.into(),
        fingerprint: fingerprint.into(),
        verdict: "false-alarm".into(),
        why: "The next= value is checked against our own list of paths first.".into(),
        by: Some("owner".into()),
        on: Some(on.clone()),
        seal: None,
    };
    let folder = sv_check::seal::Key::folder().expect("the tests' key folder");
    let key = sv_check::seal::Key::load_or_make_in(&folder)
        .unwrap()
        .0
        .for_app(&sv_check::seal::App::of(app).unwrap());
    let seal = key.seal(&sv_check::seal::as_strs(
        &sv_check::seal::finding_review_fields(&review),
    ));
    format!(
        "\n[[finding-review]]\nrule = \"{rule}\"\nfile = \"{file}\"\nfingerprint = \"{fingerprint}\"\nverdict = \"false-alarm\"\nwhy = \"{}\"\nby = \"owner\"\non = \"{on}\"\nseal = \"{seal}\"\n",
        review.why
    )
}

#[test]
fn the_report_counts_findings_gone_set_aside_and_new_between_the_first_check_and_the_last() {
    let root = scratch_app("build-loop-fingerprints", "tested-notes");
    let app = root.join("app");
    for entry in std::fs::read_dir(&app).unwrap().flatten() {
        std::fs::remove_file(entry.path()).ok();
    }
    std::fs::write(app.join("stackvet.toml"), MANIFEST).unwrap();
    std::fs::write(app.join("app.py"), APP).unwrap();
    let server = Server::new(&root).unwrap().recording(true);

    // The first check, as a report, to learn the findings' names.
    let first = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(first["isError"], false, "{}", text(&first));
    let found = report(&app);
    let fingerprint = |rule: &str| {
        found["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["rule_id"] == rule)
            .and_then(|f| f["fingerprint"].as_str())
            .unwrap_or_else(|| panic!("the setup: no {rule} finding in {}", found["findings"]))
            .to_owned()
    };
    let redirect = fingerprint("ast.open-redirect");
    fingerprint("config.security-contact");

    // The AI tool adds a SECURITY.md, which takes one finding away, and code with a new one; the
    // person sets the redirect aside as a false alarm.
    std::fs::write(app.join("SECURITY.md"), "Write to security@example.com.\n").unwrap();
    std::fs::write(app.join("app.py"), format!("{APP}{SQL}")).unwrap();
    std::fs::write(
        app.join("stackvet.toml"),
        format!(
            "{MANIFEST}{}",
            false_alarm(&app, "ast.open-redirect", "app.py", &redirect)
        ),
    )
    .unwrap();
    let checked = call(&server, "stackvet_check", json!({ "path": "app" }));
    assert_eq!(checked["isError"], false, "{}", text(&checked));

    // The record keeps hashes only: no finding's words.
    let record = std::fs::read_to_string(
        sv_scan::ecosystems::default_report_dir_in(&app)
            .join(sv_scan::ecosystems::BUILD_LOOP_RECORD),
    )
    .unwrap();
    assert!(record.contains(&redirect), "{record}");
    assert!(!record.contains("redirect("), "{record}");

    let last = call(&server, "stackvet_write_report", json!({ "path": "app" }));
    assert_eq!(last["isError"], false, "{}", text(&last));
    let moved = &report(&app)["build_loop"]["findings_moved"];
    assert_eq!(
        moved,
        &json!({ "no_longer_found": 1, "set_aside": 1, "new": 1 }),
        "{}\n{record}",
        report(&app)["build_loop"]
    );
    let page = std::fs::read_to_string(
        sv_scan::ecosystems::default_report_dir_in(&app).join("report.html"),
    )
    .unwrap();
    assert!(
        page.contains("1 finding was no longer found (fixed, or no longer reached by the check"),
        "{page}"
    );
    assert!(
        page.contains("1 was set aside by a person as a false alarm, and 1 was new"),
        "{page}"
    );
    std::fs::remove_dir_all(&root).ok();
}
