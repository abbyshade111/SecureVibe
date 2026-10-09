//! V1.2.4 is not credited while the app builds its queries through a package whose own query calls
//! the rule does not read (the gap analysis of 7 October 2026, finding 1; ADR-018, Later, 9 October
//! 2026), end to end through the binary.
//!
//! The fault this pins: an app whose only query was knex's `whereRaw("name = '" + name + "'")` had
//! V1.2.4 *checked*, because `ast.sql-built-by-hand` had not been taught `whereRaw` and found
//! nothing. Four apps: the package declared in a manifest with no lockfile (the bill of materials
//! lists nothing then), the package only in a lockfile, a Python package written in another case,
//! and a control the rule does read, so a hold-back on everything would fail it.

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

/// Who checked V1.2.4, and the report's gaps, for the app at `dir`.
fn v124_and_gaps(dir: &Path) -> (Vec<String>, Vec<(String, String)>) {
    let out_dir = dir.join("report");
    let report = Command::new(env!("CARGO_BIN_EXE_sv"))
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

const KNEX_JS: &str = "const db = require('knex')({ client: 'sqlite3' });\n\
    module.exports = (req, res) => db('users').whereRaw(\"name = '\" + req.query.name + \"'\").then(r => res.json(r));\n";

#[test]
fn a_package_declared_with_no_lockfile_holds_the_credit_back() {
    let dir = app(
        "manifest",
        "javascript",
        &[
            (
                "package.json",
                "{ \"name\": \"users\", \"dependencies\": { \"knex\": \"3.1.0\" } }\n",
            ),
            ("users.js", KNEX_JS),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked by the rule for an app whose queries go through knex: {checked_by:?}"
    );
    let gap = gap_naming(&gaps, "knex").expect("a gap says knex held the rule back");
    assert!(
        gap.1.contains("whereRaw"),
        "the gap names the calls the rule does not read: {gap:?}"
    );
}

#[test]
fn a_package_only_in_the_lockfile_holds_the_credit_back() {
    // knex arrives through another package: package.json does not declare it, the lockfile lists it.
    let lock = "{ \"name\": \"users\", \"lockfileVersion\": 3, \"packages\": { \
        \"\": { \"name\": \"users\", \"dependencies\": { \"users-db\": \"1.0.0\" } }, \
        \"node_modules/users-db\": { \"version\": \"1.0.0\" }, \
        \"node_modules/knex\": { \"version\": \"3.1.0\" } } }\n";
    let dir = app(
        "lockfile",
        "javascript",
        &[
            (
                "package.json",
                "{ \"name\": \"users\", \"dependencies\": { \"users-db\": \"1.0.0\" } }\n",
            ),
            ("package-lock.json", lock),
            ("users.js", KNEX_JS),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked with knex in the lockfile: {checked_by:?}"
    );
    assert!(
        gap_naming(&gaps, "knex").is_some(),
        "no gap names knex: {gaps:?}"
    );
}

#[test]
fn a_python_package_matches_whatever_its_case() {
    let dir = app(
        "django",
        "python",
        &[
            ("requirements.txt", "Django==5.0.6\n"),
            (
                "views.py",
                "from django.contrib.auth.models import User\n\n\
                 def users(request):\n    return User.objects.extra(where=[\"name = '%s'\" % request.GET['name']])\n",
            ),
        ],
    );
    let (checked_by, gaps) = v124_and_gaps(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        !credited(&checked_by),
        "V1.2.4 was checked for a Django app: {checked_by:?}"
    );
    assert!(
        gap_naming(&gaps, "django").is_some(),
        "no gap names django: {gaps:?}"
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
