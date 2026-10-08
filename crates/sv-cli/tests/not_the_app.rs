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
        dir.join("stackvet.toml"),
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

const OVERRULED: &str = "stackvet.toml says auth is not used, but `flask-login`";

#[test]
fn an_example_app_cannot_overrule_the_manifest_once_it_is_named() {
    // The control: unnamed, the example is read as the app and overrules the manifest.
    let whole = app("whole", "");
    let scope = sv(&["scope"], &whole);
    assert!(scope.contains(OVERRULED), "{scope}");
    let (security, _) = report(&whole);
    assert!(!security.contains("in test or sample code"), "{security}");
    std::fs::remove_dir_all(&whole).ok();

    let named = app("named", "not-the-app = [\"demo\", \"nowhere\"]");
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
    assert!(
        security.contains("Named but not found: `nowhere`."),
        "{security}"
    );
    assert!(
        security.contains("`demo`, holding 1 of the app's 2 code files"),
        "{security}"
    );
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

#[test]
fn a_list_that_would_set_apart_all_the_app_s_code_is_not_used_and_said_to_be() {
    // Deep review R12: the app's own code all lies under `demo`, and `src` names nothing. Taken
    // together the list would leave no code to say what the app uses.
    let dir = app("all-apart", "not-the-app = [\"demo\", \"src\"]");
    std::fs::remove_file(dir.join("app.py")).unwrap();
    let scope = sv(&["scope"], &dir);
    assert!(
        scope.contains(OVERRULED),
        "the code is read as the app: {scope}"
    );
    let (security, json) = report(&dir);
    assert!(
        security.contains(
            "`demo`, `src`: together they would set apart all 1 of the app's code file, leaving \
             nothing to say what the app uses, so the list is not used"
        ),
        "{security}"
    );
    assert!(
        !security.contains("in test or sample code"),
        "the app's findings are its own: {security}"
    );
    let json: serde_json::Value = serde_json::from_str(&json).unwrap();
    let hash = json["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["location"]["file"] == "demo/shop/app.py")
        .expect("the finding is in report.json");
    // Written only when true.
    assert!(hash.get("marked_test_code").is_none(), "{hash}");
    std::fs::remove_dir_all(&dir).ok();
}

/// The status `report.json` gives one requirement: `excluded` when it does not apply.
fn status_of(json: &str, id: &str) -> String {
    let json: serde_json::Value = serde_json::from_str(json).unwrap();
    if json["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == id)
    {
        return "excluded".to_owned();
    }
    if json["undecided"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == id)
    {
        return "undecided".to_owned();
    }
    json["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .unwrap_or_else(|| panic!("{id} is in report.json"))["status"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn what_only_a_folder_set_apart_shows_is_a_question_not_a_no() {
    // Gap analysis, item 19. An XML parser only inside `demo`: listing `demo` used to turn V1.5.1
    // (XML external entities) to "does not apply", from a condition no owner is asked.
    let with_xml = |name: &str, list: &str| {
        let dir = app(name, list);
        std::fs::write(
            dir.join("demo/shop/feed.py"),
            "import xml.etree.ElementTree as ET\n",
        )
        .unwrap();
        dir
    };
    // The control: with no XML anywhere, it does not apply.
    let none = app("no-xml", "not-the-app = [\"demo\"]");
    let (_, json) = report(&none);
    let control = status_of(&json, "V1.5.1");
    std::fs::remove_dir_all(&none).ok();
    assert_eq!(control, "excluded", "the setup");

    let named = with_xml("xml-apart", "not-the-app = [\"demo\"]");
    let (security, json) = report(&named);
    std::fs::remove_dir_all(&named).ok();
    assert_eq!(status_of(&json, "V1.5.1"), "undecided");
    assert!(
        security.contains("whether the app itself has `xml`"),
        "{security}"
    );
    assert!(security.contains("demo/shop/feed.py"), "{security}");
    assert!(
        security.contains("its requirements wait on that question rather than being set aside"),
        "{security}"
    );
    // The owner's own answer stands, and is said to: `auth = false`, with `flask-login` in `demo`.
    assert!(
        security.contains("whether the app itself has `auth`"),
        "{security}"
    );
    assert!(
        security.contains("stackvet.toml says it does not, and that answer stands"),
        "{security}"
    );
}

#[test]
fn a_folder_holding_the_file_the_start_command_runs_is_refused() {
    // Gap analysis, item 19: the app's own entry point is never "not the app".
    let dir = app("start", "not-the-app = [\"demo\"]");
    let manifest = std::fs::read_to_string(dir.join("stackvet.toml")).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        manifest.replace(
            "[capabilities]",
            "[stack.run]\nstart = \"python demo/shop/app.py --port 8000\"\n[capabilities]",
        ),
    )
    .unwrap();
    let scope = sv(&["scope"], &dir);
    assert!(
        scope.contains(OVERRULED),
        "demo is read as the app: {scope}"
    );
    let (security, _) = report(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        security.contains("`demo`: it holds `demo/shop/app.py`, which the start command runs"),
        "{security}"
    );
}
