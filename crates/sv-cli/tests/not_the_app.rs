//! Folders the manifest says are not the app, end to end. On `sv`'s own repository, fixture and
//! example apps overruled the manifest 19 times: an example's `authlib` switched on the sign-in
//! requirements for a tool nobody signs in to. Named in `[repository] not-the-app`, they are still
//! checked, their findings still count, listed apart, and they cannot change what applies.

use std::path::{Path, PathBuf};
use std::process::Command;

fn app(name: &str, not_the_app: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-not-the-app-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(dir.join("demo/shop")).unwrap();
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    std::fs::write(
        dir.join("demo/shop/requirements.txt"),
        "flask-login==0.6.3\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("demo/shop/app.py"),
        "import hashlib\n\ndef digest(b):\n    return hashlib.md5(b).hexdigest()\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("securevibe.toml"),
        format!(
            "manifest-version = 1\n[app]\nname = \"Shop\"\n[stack]\nlanguages = [\"python\"]\n\
             [capabilities]\nauth = false\n[repository]\n{not_the_app}\n"
        ),
    )
    .unwrap();
    dir
}

fn sv(args: &[&str], app: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .arg(app)
        .output()
        .expect("sv runs");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn report(app: &Path) -> (String, String) {
    let out = app.join("report");
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(app)
        .arg("--out")
        .arg(&out)
        .output()
        .expect("sv runs");
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    (
        std::fs::read_to_string(out.join("security.md")).unwrap(),
        std::fs::read_to_string(out.join("report.json")).unwrap(),
    )
}

const OVERRULED: &str = "securevibe.toml says auth is not used, but `flask-login`";

#[test]
fn an_example_app_cannot_overrule_the_manifest_once_it_is_named() {
    // The control: unnamed, the example is read as the app and overrules the manifest.
    let whole = app("whole", "");
    let scope = sv(&["scope"], &whole);
    assert!(scope.contains(OVERRULED), "{scope}");
    let (security, _) = report(&whole);
    assert!(!security.contains("in test or sample code"), "{security}");
    std::fs::remove_dir_all(&whole).ok();

    let named = app("named", "not-the-app = [\"demo\"]");
    let scope = sv(&["scope"], &named);
    assert!(!scope.contains(OVERRULED), "{scope}");
    let (security, json) = report(&named);

    // Still checked, and still counted: the weak hash in the example is found, listed apart.
    let list = &security[security.find("in test or sample code").expect(&security)..];
    assert!(list.contains("`demo/shop/app.py` line 4"), "{security}");
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let hash = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["location"]["file"] == "demo/shop/app.py")
        .expect("the example's finding is in report.json");
    assert_eq!(hash["marked_test_code"], true);
    assert!(
        json["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "V11.4.1" && r["status"] == "needs-attention"),
        "the requirement it is about still needs attention"
    );

    // And the report says which folders were set apart.
    assert!(security.contains("not-the-app"), "{security}");
    assert!(security.contains("`demo`"), "{security}");
    std::fs::remove_dir_all(&named).ok();
}

#[test]
fn an_entry_that_would_hide_the_whole_app_is_refused_and_said_to_be() {
    let dir = app("refused", "not-the-app = [\".\", \"docs\"]");
    let scope = sv(&["scope"], &dir);
    assert!(
        scope.contains(OVERRULED),
        "the app is read as the app: {scope}"
    );
    let (security, _) = report(&dir);
    assert!(
        security.contains("`.`: it names the whole app"),
        "{security}"
    );
    assert!(
        security.contains("none of them is in this app"),
        "{security}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
