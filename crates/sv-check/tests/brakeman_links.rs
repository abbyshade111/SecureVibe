//! Brakeman reads a linked file in the app, and so is not run over an app that holds a link (the
//! review of 8 October 2026, item 3). The control runs Brakeman bare over the fixture app with a
//! linked controller pointing outside it and sees the SQL injection in that file reported.
//!
//! Needs the real Brakeman: without it on `PATH` this says so and checks nothing. Run here on 8
//! October 2026 with Brakeman 8.1.0.

mod scratch;

use scratch::Scratch;
use std::path::PathBuf;
use std::process::Command;
use sv_check::adapters::{self, Adapters, Outcome};

fn fixture_app() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/brakeman/app")
}

fn real_adapters() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json")
}

fn copy_tree(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn brakeman_is_not_run_over_an_app_with_a_link_because_it_would_read_through_it() {
    let adapters = Adapters::load(&real_adapters()).unwrap();
    let brakeman = adapters
        .all()
        .iter()
        .find(|a| a.id == "brakeman")
        .unwrap()
        .clone();
    if !adapters::is_installed(&brakeman) {
        println!("brakeman is not installed here; the real run is skipped");
        return;
    }
    let dir = Scratch::new("brakeman-links");
    let app = dir.join("app");
    copy_tree(&fixture_app(), &app);
    let outside = dir.join("outside_controller.rb");
    std::fs::write(
        &outside,
        "class OutsideController < ApplicationController\n  def show\n    @user = \
         User.find_by_sql(\"SELECT * FROM users WHERE id = #{params[:id]}\")\n  end\nend\n",
    )
    .unwrap();
    let link = "app/controllers/outside_controller.rb";
    std::os::unix::fs::symlink(&outside, app.join(link)).unwrap();

    // The control: Brakeman run bare follows the link and reports the SQL injection there.
    let bare = dir.join("bare.sarif");
    let settings = dir.join("empty.yml");
    std::fs::write(&settings, adapters::EMPTY_SETTINGS).unwrap();
    let out = Command::new("brakeman")
        .arg("-c")
        .arg(&settings)
        .args(["--format", "sarif", "--output"])
        .arg(&bare)
        .args(["--no-progress", "--quiet"])
        .arg(&app)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(out.code().is_some_and(|c| c == 0 || c == 3), "{out:?}");
    let report = std::fs::read_to_string(&bare).unwrap();
    assert!(
        report.contains("outside_controller.rb"),
        "the control: the linked file is in Brakeman's report"
    );

    // Through `sv`: not run, naming the link.
    let outcome = adapters::run_one(
        &brakeman,
        &app,
        &dir.join("sv.sarif"),
        &sv_check::secrets::SecretRules::load(
            &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/secret-rules.json"),
        )
        .unwrap(),
    );
    let Outcome::NotRun { why } = &outcome else {
        panic!("{outcome:?}");
    };
    assert!(
        why.contains("follows a link") && why.contains(&format!("`{link}`")),
        "{why}"
    );
}
