//! `sv explain` repeats an app's report only when `sv` can show it wrote it (backlog 0226, part 1,
//! item 9). Until 9 October 2026 it repeated any `report.json` in the report folder, which the AI
//! coding tool can write.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Scratch(PathBuf);

impl Scratch {
    /// A copy of an example app, and a home of its own for this computer's report key.
    fn new(tag: &str) -> Scratch {
        let root =
            std::env::temp_dir().join(format!("sv-explain-seal-{tag}-{}", std::process::id()));
        std::fs::remove_dir_all(&root).ok();
        let from = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/partly-passing"
        ));
        copy(from, &root.join("app"));
        std::fs::create_dir_all(root.join("home")).unwrap();
        Scratch(root)
    }
    fn app(&self) -> PathBuf {
        self.0.join("app")
    }
    fn sv(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(args)
            .env("HOME", self.0.join("home"))
            .env_remove("XDG_CONFIG_HOME")
            .env_remove("RUST_BACKTRACE")
            .output()
            .expect("sv runs")
    }
    fn report_json(&self) -> PathBuf {
        self.app().join("stackvet-report").join("report.json")
    }
    /// `sv report` on the app, and the id of a requirement its report lists.
    fn reported(&self) -> String {
        let app = self.app();
        self.sv(&["report", app.to_str().unwrap()]);
        let json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.report_json()).expect("a report"))
                .unwrap();
        json["requirements"][0]["id"]
            .as_str()
            .expect("the report lists a requirement")
            .to_owned()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

fn copy(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            copy(&path, &to.join(entry.file_name()));
        } else {
            std::fs::copy(&path, to.join(entry.file_name())).unwrap();
        }
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_report_sv_sealed_is_repeated() {
    let s = Scratch::new("sealed");
    let id = s.reported();
    let out = s.sv(&["explain", &id, "--app", s.app().to_str().unwrap()]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("last report"), "{said}");
    assert!(!said.contains("is left out"), "{said}");
}

#[test]
fn a_report_changed_after_sealing_is_not_repeated_as_svs() {
    let s = Scratch::new("changed");
    let id = s.reported();
    // The AI coding tool, or anything that can write the folder, rewrites the status.
    let path = s.report_json();
    let mut json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    json["requirements"][0]["status"] = serde_json::json!("checked");
    json["app_name"] = serde_json::json!("A rewritten report");
    std::fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
    let out = s.sv(&["explain", &id, "--app", s.app().to_str().unwrap()]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(
        said.contains("is left out: sv cannot show it wrote that report"),
        "{said}"
    );
    assert!(!said.contains("A rewritten report"), "{said}");
    assert!(!said.contains("last report"), "{said}");
}

#[test]
fn a_report_nothing_sealed_is_not_repeated_as_svs() {
    let s = Scratch::new("forged");
    let folder = s.app().join("stackvet-report");
    std::fs::create_dir_all(&folder).unwrap();
    std::fs::write(
        folder.join("report.json"),
        r#"{"app_name": "A forged report", "requirements": [{"id": "V3.5.1", "status": "checked"}]}"#,
    )
    .unwrap();
    let out = s.sv(&["explain", "V3.5.1", "--app", s.app().to_str().unwrap()]);
    let said = text(&out);
    assert!(out.status.success(), "{said}");
    assert!(said.contains("is left out"), "{said}");
    assert!(!said.contains("A forged report"), "{said}");
}
