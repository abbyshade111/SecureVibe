//! V1.2.4 is not credited while the app builds its queries through a package whose own query calls
//! the rule does not read (the gap analysis of 7 October 2026, finding 1; ADR-018, Later, 9 October
//! 2026), end to end through the binary.
//!
//! The fault this pins: an app whose only query was knex's `whereRaw("name = '" + name + "'")` had
//! V1.2.4 *checked*, because `ast.sql-built-by-hand` had not been taught `whereRaw` and found
//! nothing. Four apps: the package declared in a manifest with no lockfile (the bill of materials
//! lists nothing then), the package only in a lockfile, a Python package written in another case (Supabase),
//! and a control the rule does read, so a hold-back on everything would fail it.
//!
//! Since 9 October 2026 the rule reads every package the finding named, and its list is empty. The
//! hold-back is still how a package added to the list is handled, so these tests run `sv` on a copy
//! of `data/` (through `SV_DATA_DIR`) whose rule lists Supabase's clients as a stand-in, with apps
//! whose queries the rule finds nothing in. One more test runs on the real data: the filter text
//! these apps once hid is read now.

use std::path::{Path, PathBuf};
use std::process::Command;

const RULE: &str = "ast.sql-built-by-hand";

fn app(name: &str, language: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-orm-held-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        format!(
            "manifest-version = 1\n\n[app]\nname = \"Users\"\ndescription = \"A list of users.\"\n\
             audience = \"customers\"\ndeployment = \"internet\"\n\n[stack]\nlanguages = [\"{language}\"]\n"
        ),
    )
    .unwrap();
    for (name, contents) in files {
        std::fs::write(dir.join(name), contents).unwrap();
    }
    dir
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A copy of `data/` whose SQL rule lists Supabase's clients as packages it does not read: a
/// stand-in, since the real list is empty.
fn stand_in_data() -> &'static Path {
    static DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("sv-orm-held-data-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        copy_dir(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data"),
            &dir,
        );
        let path = dir.join("ast-rules.json");
        let mut rules: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let list = rules["rules"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["id"] == RULE)
            .expect("the rule is in the data")
            .get_mut("unreadPackages")
            .expect("the rule has an unread list");
        // The setup: the real list is empty, so whatever is held back here is the stand-in's doing.
        assert!(
            list.as_object()
                .unwrap()
                .values()
                .all(|p| p.as_object().is_some_and(|p| p.is_empty())),
            "the real list is not empty: {list}"
        );
        list["npm"]["@supabase/supabase-js"] = "filter text such as `.or(...)`".into();
        list["Python"]["supabase"] = "filter text such as `.or_(...)`".into();
        std::fs::write(&path, rules.to_string()).unwrap();
        dir
    })
}

/// Who checked V1.2.4, and the report's gaps, for the app at `dir`, with the stand-in list.
fn v124_and_gaps(dir: &Path) -> (Vec<String>, Vec<(String, String)>) {
    v124_and_gaps_with(dir, Some(stand_in_data()))
}

/// The same, with `data` as `SV_DATA_DIR`, or the real data when `None`.
fn v124_and_gaps_with(dir: &Path, data: Option<&Path>) -> (Vec<String>, Vec<(String, String)>) {
    let out_dir = dir.join("report");
    let mut command = Command::new(env!("CARGO_BIN_EXE_sv"));
    if let Some(data) = data {
        command.env("SV_DATA_DIR", data);
    }
    let report = command
        .args([
            "report",
            dir.to_str().unwrap(),
            "--out",
            out_dir.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        report.status.success(),
        "sv report failed: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out_dir.join("report.json")).unwrap())
            .unwrap();
    let v124 = json["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|q| q["id"] == "V1.2.4")
        .expect("V1.2.4 is in the report");
    let checked_by = v124["checked_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.to_string())
        .collect();
    let gaps = json["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| {
            (
                g["what"].as_str().unwrap_or_default().to_owned(),
                g["why"].as_str().unwrap_or_default().to_owned(),
            )
        })
        .collect();
    (checked_by, gaps)
}

fn credited(checked_by: &[String]) -> bool {
    checked_by.iter().any(|c| c.contains(RULE))
}

/// The gap that names `package`, if there is one.
fn gap_naming<'a>(gaps: &'a [(String, String)], package: &str) -> Option<&'a (String, String)> {
    gaps.iter()
        .find(|(what, why)| what.contains(RULE) && why.contains(&format!("uses {package} (")))
}

// Supabase's client stands in as the package the rule cannot see into (`stand_in_data`). Its
// filter text here is fixed, so the rule finds nothing and only the hold-back can take the credit.
const SUPABASE_JS: &str = "const { createClient } = require('@supabase/supabase-js');\n\
    const supabase = createClient(process.env.URL, process.env.KEY);\n\
    module.exports = (req, res) => supabase.from('users').select('*')\
    .or('role.eq.admin,role.eq.owner').then(r => res.json(r.data));\n";

/// The same app with the filter text built from the request, as the stand-in once hid.
const SUPABASE_JS_BUILT: &str = "const { createClient } = require('@supabase/supabase-js');\n\
    const supabase = createClient(process.env.URL, process.env.KEY);\n\
    module.exports = (req, res) => supabase.from('users').select('*')\
    .or(`name.eq.${req.query.name}`).then(r => res.json(r.data));\n";

#[test]
fn a_package_declared_with_no_lockfile_holds_the_credit_back() {
    let dir = app(
        "manifest",
        "javascript",
        &[
            (
                "package.json",
                "{ \"name\": \"users\", \"dependencies\": { \"@supabase/supabase-js\": \"2.45.0\" } }\n",
            ),
            ("users.js", SUPABASE_JS),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked by the rule for an app whose queries go through Supabase's client: {checked_by:?}"
    );
    let gap = gap_naming(&gaps, "@supabase/supabase-js")
        .expect("a gap says Supabase's client held the rule back");
    assert!(
        gap.1.contains("`.or(...)`"),
        "the gap names the calls the rule does not read: {gap:?}"
    );
}

#[test]
fn a_package_only_in_the_lockfile_holds_the_credit_back() {
    // Supabase's client arrives through another package: package.json does not declare it, the lockfile lists it.
    let lock = "{ \"name\": \"users\", \"lockfileVersion\": 3, \"packages\": { \
        \"\": { \"name\": \"users\", \"dependencies\": { \"users-db\": \"1.0.0\" } }, \
        \"node_modules/users-db\": { \"version\": \"1.0.0\" }, \
        \"node_modules/@supabase/supabase-js\": { \"version\": \"2.45.0\" } } }\n";
    let dir = app(
        "lockfile",
        "javascript",
        &[
            (
                "package.json",
                "{ \"name\": \"users\", \"dependencies\": { \"users-db\": \"1.0.0\" } }\n",
            ),
            ("package-lock.json", lock),
            ("users.js", SUPABASE_JS),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked with Supabase's client in the lockfile: {checked_by:?}"
    );
    assert!(
        gap_naming(&gaps, "@supabase/supabase-js").is_some(),
        "no gap names supabase-js: {gaps:?}"
    );
}

#[test]
fn a_python_package_matches_whatever_its_case() {
    let dir = app(
        "supabase-py",
        "python",
        &[
            // Supabase's Python client, under the stand-in list, written in another case.
            ("requirements.txt", "Supabase==2.7.4\n"),
            (
                "views.py",
                "from supabase import create_client\n\n\
                 def users(request):\n    return create_client(URL, KEY).table('users').select('*').or_(\"role.eq.admin,role.eq.owner\").execute()\n",
            ),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked for a Supabase app: {checked_by:?}"
    );
    assert!(
        gap_naming(&gaps, "supabase").is_some(),
        "no gap names supabase: {gaps:?}"
    );
}

#[test]
fn an_app_with_no_such_package_is_still_credited() {
    // The control: without it, holding back every app's credit would pass the three tests above.
    let dir = app(
        "control",
        "javascript",
        &[
            (
                "package.json",
                "{ \"name\": \"users\", \"dependencies\": { \"pg\": \"8.11.0\" } }\n",
            ),
            (
                "users.js",
                "const { Pool } = require('pg');\nconst pool = new Pool();\n\
                 module.exports = (req, res) => pool.query('SELECT * FROM users WHERE name = $1', [req.query.name]).then(r => res.json(r.rows));\n",
            ),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        credited(&checked_by),
        "the rule read an app with pg's query and found nothing, and still did not credit V1.2.4: \
         {checked_by:?}"
    );
    assert!(
        gaps.iter().all(|(what, _)| !what.contains(RULE)),
        "a gap held the rule back with no such package: {gaps:?}"
    );
}

#[test]
fn the_filter_text_the_stand_in_once_hid_is_found_on_the_real_data() {
    let dir = app(
        "found",
        "javascript",
        &[
            (
                "package.json",
                "{ \"name\": \"users\", \"dependencies\": { \"@supabase/supabase-js\": \"2.45.0\" } }\n",
            ),
            ("users.js", SUPABASE_JS_BUILT),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps_with(&dir, None);
    let report = std::fs::read_to_string(dir.join("report/report.json")).unwrap();
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked for filter text built from the request: {checked_by:?}"
    );
    assert!(
        gaps.iter().all(|(what, _)| !what.contains(RULE)),
        "the real list held the rule back: {gaps:?}"
    );
    let report: serde_json::Value = serde_json::from_str(&report).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == RULE && f["location"]["file"] == "users.js"),
        "no finding from the rule in users.js: {}",
        report["findings"]
    );
}
