//! `report.json`'s `examined` list, end to end through the binary (DESIGN, "What was examined,
//! for a program").
//!
//! A program that reads `report.json` and closes its own records when a finding stops appearing
//! must be able to tell "fixed" from "not looked for this time". Each test here makes one limit
//! true of an app, checks the gap a person reads says so (the setup worked), and then checks the
//! entry a program reads says the same.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn app(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-examined-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    dir
}

fn report(dir: &Path, extra: &[&str]) -> Value {
    let out = dir.join("report");
    let mut args = vec![
        "report".to_owned(),
        dir.to_str().unwrap().to_owned(),
        "--out".to_owned(),
        out.to_str().unwrap().to_owned(),
    ];
    args.extend(extra.iter().map(|a| (*a).to_owned()));
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(&args)
        .output()
        .expect("sv runs");
    // Finished: 0, or 2 where a check could not run, which several of these set up on purpose.
    assert!(
        matches!(run.status.code(), Some(0 | 2)),
        "sv report failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    serde_json::from_str(&std::fs::read_to_string(out.join("report.json")).unwrap()).unwrap()
}

/// The entry for exactly these rules, as (state, why).
fn entry(report: &Value, rules: &str) -> (String, String) {
    let found = report["examined"]
        .as_array()
        .expect("report.json has an examined list")
        .iter()
        .find(|e| e["rules"] == rules)
        .unwrap_or_else(|| panic!("no examined entry for {rules}: {}", report["examined"]));
    (
        found["state"].as_str().unwrap().to_owned(),
        found["why"].as_str().unwrap_or("").to_owned(),
    )
}

fn has_gap(report: &Value, what_starts: &str) -> bool {
    report["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["what"].as_str().unwrap().starts_with(what_starts))
}

fn adapter_ids() -> Vec<String> {
    let file: Value = serde_json::from_str(
        &std::fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/adapters.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let ids: Vec<String> = file["adapters"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.len() >= 5, "adapters.json lists the outside tools");
    ids
}

#[test]
fn without_tools_a_database_or_a_run_nothing_outside_counts_as_looked_at() {
    let dir = app("plain");
    let report = report(&dir, &[]);
    assert!(has_gap(
        &report,
        "the security tool this language already has"
    ));
    for id in adapter_ids() {
        let (state, why) = entry(&report, &format!("{id}."));
        assert_eq!(state, "not-run", "{id}");
        assert!(why.contains("--tools"), "{id}: {why}");
    }
    assert_eq!(entry(&report, "advisory.").0, "not-run");
    assert_eq!(entry(&report, "probe.").0, "not-run");
    for family in ["ast.", "secrets.", "config.", "sbom."] {
        assert_eq!(entry(&report, family).0, "ran", "{family}");
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_language_without_a_parser_leaves_the_code_rules_looked_at_in_part() {
    let dir = app("objc");
    std::fs::write(dir.join("legacy.m"), "#import <Foundation/Foundation.h>\n").unwrap();
    let report = report(&dir, &[]);
    assert!(has_gap(&report, "code written in"), "{}", report["gaps"]);
    let (state, why) = entry(&report, "ast.");
    assert_eq!(state, "partly");
    assert!(why.contains("no parser for"), "{why}");
    // Only the code rules read code; the credential scan read every file it opens.
    assert_eq!(entry(&report, "secrets.").0, "ran");
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn a_link_nothing_followed_leaves_every_check_that_reads_files_looked_at_in_part() {
    let dir = app("link");
    std::os::unix::fs::symlink(std::env::temp_dir(), dir.join("elsewhere")).unwrap();
    let report = report(&dir, &[]);
    assert!(has_gap(&report, "1 symbolic link"), "{}", report["gaps"]);
    for family in ["ast.", "secrets.", "config."] {
        let (state, why) = entry(&report, family);
        assert_eq!(state, "partly", "{family}");
        assert!(why.contains("symbolic link"), "{family}: {why}");
    }
    assert_eq!(entry(&report, "sbom.").0, "ran");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_check_that_could_not_run_has_its_own_entry_and_the_rest_of_its_family_ran() {
    let dir = app("nogit");
    let report_outside_git = report(&dir, &[]);
    assert!(has_gap(
        &report_outside_git,
        "the check `config.secrets-file-committed`"
    ));
    let (state, why) = entry(&report_outside_git, "config.secrets-file-committed");
    assert_eq!(state, "not-run");
    assert!(why.contains("git"), "{why}");
    assert_eq!(entry(&report_outside_git, "config.").0, "ran");

    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(&dir)
        .status()
        .expect("git runs");
    assert!(init.success(), "git init worked");
    let in_git = report(&dir, &[]);
    assert!(!has_gap(
        &in_git,
        "the check `config.secrets-file-committed`"
    ));
    let entries = in_git["examined"].as_array().unwrap();
    assert!(
        !entries
            .iter()
            .any(|e| e["rules"] == "config.secrets-file-committed"),
        "once it can run, the family entry decides for it"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// An npm app shipping lodash 4.17.15, with its lockfile, so the list of packages is complete.
fn npm_app(name: &str) -> PathBuf {
    let dir = app(name);
    std::fs::remove_file(dir.join("app.py")).unwrap();
    std::fs::create_dir_all(dir.join("osv")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.15"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo"},
           "node_modules/lodash":{"version":"4.17.15"}}}"#,
    )
    .unwrap();
    dir
}

fn advisory(dir: &Path, id: &str, ecosystem: &str, package: &str) {
    std::fs::write(
        dir.join("osv").join(format!("{id}.json")),
        format!(
            r#"{{"id":"{id}","summary":"A vulnerability.","published":"2026-01-01T00:00:00Z",
                "affected":[{{"package":{{"ecosystem":"{ecosystem}","name":"{package}"}},
                "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"99"}}]}}]}}]}}"#
        ),
    )
    .unwrap();
}

#[test]
fn known_vulnerabilities_count_as_looked_for_only_when_the_whole_app_was_compared() {
    let dir = npm_app("adv");
    let osv = dir.join("osv");
    let osv = osv.to_str().unwrap();

    let empty = report(&dir, &["--advisories", osv]);
    assert_eq!(entry(&empty, "advisory.").0, "not-run");

    advisory(&dir, "PYSEC-0000-1", "PyPI", "requests");
    let elsewhere = report(&dir, &["--advisories", osv]);
    assert!(has_gap(
        &elsewhere,
        "known vulnerabilities in this app's npm packages"
    ));
    let (state, why) = entry(&elsewhere, "advisory.");
    assert_eq!(state, "partly");
    assert!(why.contains("npm"), "{why}");

    advisory(&dir, "GHSA-0000-0000-0001", "npm", "lodash");
    let covered = report(&dir, &["--advisories", osv]);
    assert!(
        covered["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "advisory.GHSA-0000-0000-0001"),
        "the comparison really ran: {}",
        covered["findings"]
    );
    assert_eq!(entry(&covered, "advisory.").0, "ran");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_pyproject_app_locked_by_requirements_lock_is_compared_in_full() {
    // What cato-pipeline hit: `uv pip compile` writes `requirements.lock` beside `pyproject.toml`,
    // and `sv` read nothing from it, so the app was told it had no lockfile and its packages were
    // never compared.
    let dir = app("pyproject-lock");
    std::fs::create_dir_all(dir.join("osv")).unwrap();
    std::fs::write(
        dir.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"PyYAML>=6.0\"]\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("requirements.lock"),
        "colorama==0.4.6 ; sys_platform == 'win32' \\\n    --hash=sha256:0000\n    # via demo\n\
         pyyaml==6.0.2 \\\n    --hash=sha256:1111\n    # via demo\n",
    )
    .unwrap();
    advisory(&dir, "PYSEC-0000-2", "PyPI", "pyyaml");
    let osv = dir.join("osv");
    let report = report(&dir, &["--advisories", osv.to_str().unwrap()]);

    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f["rule_id"] == "advisory.PYSEC-0000-2"),
        "pyyaml from the lockfile was compared: {findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|f| f["rule_id"] == "config.versions-pinned"),
        "the lockfile is there: {findings:?}"
    );
    assert_eq!(entry(&report, "advisory.").0, "ran");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_large_data_file_leaves_the_credential_scan_and_the_mcp_check_finished() {
    // cato-pipeline's reproduction: a JSON file of plain text over the 2 MB limit, no code in it
    // and no MCP configuration. Before, the credential scan was `partly` and the MCP check
    // not-run, for the whole app, for as long as the file was there.
    let dir = app("large-data");
    std::fs::write(
        dir.join("catalog.json"),
        format!("{{\"text\": \"{}\"}}\n", "y".repeat(3_000_000)),
    )
    .unwrap();
    let large = report(&dir, &[]);
    let (state, why) = entry(&large, "secrets.");
    assert_eq!(state, "ran", "{why}");
    let mcp = large["examined"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["rules"] == "config.mcp-server-unpinned");
    assert!(
        mcp.is_none_or(|e| e["state"] != "not-run"),
        "the MCP check still did not run: {mcp:?}"
    );
    // A person reading the report is told how the large file was read.
    assert!(
        large.to_string().contains("read in pieces"),
        "the report does not say the catalog was read in pieces"
    );
    std::fs::remove_dir_all(&dir).ok();

    // The word `command` in the catalog's prose, as NIST's uses it: still finished (the check was
    // narrowed to a `command` key on 29 September 2026).
    let dir = app("large-data-prose");
    std::fs::write(
        dir.join("catalog.json"),
        format!(
            "{{\"text\": \"{} the command and control of the system \"}}\n",
            "y".repeat(3_000_000)
        ),
    )
    .unwrap();
    let prose = report(&dir, &[]);
    let mcp = prose["examined"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["rules"] == "config.mcp-server-unpinned");
    assert!(
        mcp.is_none_or(|e| e["state"] != "not-run"),
        "the word alone stopped the check: {mcp:?}"
    );
    std::fs::remove_dir_all(&dir).ok();

    // The same catalog setting `command` to a program that starts a server: it could, so the check
    // says it could not finish, and names the file.
    let dir = app("large-data-command");
    std::fs::write(
        dir.join("catalog.json"),
        format!(
            "{{\"text\": \"{}\", \"command\": \"npx\"}}\n",
            "y".repeat(3_000_000)
        ),
    )
    .unwrap();
    let starts = report(&dir, &[]);
    let (state, why) = entry(&starts, "config.mcp-server-unpinned");
    assert_eq!(state, "not-run", "{why}");
    assert!(why.contains("catalog.json"), "{why}");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_second_lockfile_nothing_read_keeps_known_vulnerabilities_from_counting_as_looked_for() {
    // `package-lock.json` is read and compared; a `yarn.lock` beside it is not, and may be the one
    // the app is installed from. A finding that disappears because the other file was read is not
    // a fixed finding, so a program must not be told the comparison was whole.
    let dir = npm_app("two-lockfiles");
    advisory(&dir, "GHSA-0000-0000-0002", "npm", "lodash");
    let osv = dir.join("osv");
    let osv = osv.to_str().unwrap();

    let one = report(&dir, &["--advisories", osv]);
    assert_eq!(
        entry(&one, "advisory.").0,
        "ran",
        "the control: one lockfile"
    );
    assert!(!has_gap(&one, "which lockfile"));

    std::fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    let two = report(&dir, &["--advisories", osv]);
    assert!(
        two["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "advisory.GHSA-0000-0000-0002"),
        "the lockfile that was read is still compared: {}",
        two["findings"]
    );
    assert!(has_gap(&two, "which lockfile npm is installed from"));
    let (state, why) = entry(&two, "advisory.");
    assert_eq!(state, "partly");
    assert!(
        why.contains("`yarn.lock`") && why.contains("`package-lock.json`"),
        "{why}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_manifest_that_disagrees_with_its_lockfile_keeps_known_vulnerabilities_from_counting_as_looked_for()
 {
    // `package-lock.json` is what is read and compared. When `package.json` asks for another
    // version, whoever installs from the manifest runs something the comparison never saw.
    let dir = npm_app("manifest-disagrees");
    advisory(&dir, "GHSA-0000-0000-0003", "npm", "lodash");
    let osv = dir.join("osv");
    let osv = osv.to_str().unwrap();

    let agreeing = report(&dir, &["--advisories", osv]);
    assert_eq!(
        entry(&agreeing, "advisory.").0,
        "ran",
        "the control: the two agree"
    );
    assert!(!has_gap(&agreeing, "whether npm is installed"));
    assert!(!has_gap(&agreeing, "whether `package.json`"));

    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}"#,
    )
    .unwrap();
    let disagreeing = report(&dir, &["--advisories", osv]);
    assert!(
        has_gap(
            &disagreeing,
            "whether npm is installed from `package-lock.json` or `package.json`"
        ),
        "{}",
        disagreeing["gaps"]
    );
    let (state, why) = entry(&disagreeing, "advisory.");
    assert_eq!(state, "partly", "{why}");
    assert!(
        why.contains("`package.json` asks for other versions than `package-lock.json` has"),
        "{why}"
    );
    // The lockfile is still what is listed and compared.
    assert!(
        disagreeing["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "advisory.GHSA-0000-0000-0003"),
        "{}",
        disagreeing["findings"]
    );

    // A range `sv` cannot hold the lock to is said, and does not stop the claim: the list is still
    // a full reading of the lockfile, as it was before anything was compared.
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"latest"}}"#,
    )
    .unwrap();
    let unread = report(&dir, &["--advisories", osv]);
    assert!(
        has_gap(
            &unread,
            "whether `package.json` and `package-lock.json` agree about every package"
        ),
        "{}",
        unread["gaps"]
    );
    assert!(!has_gap(&unread, "whether npm is installed"));
    assert_eq!(entry(&unread, "advisory.").0, "ran");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn sbom_and_audit_say_when_the_manifest_asks_for_something_else() {
    let dir = npm_app("manifest-disagrees-cli");
    // An advisory about another npm package: npm is covered, and nothing the app has is affected,
    // so with the two files in step the audit is clean.
    advisory(&dir, "GHSA-0000-0000-0004", "npm", "left-pad");
    let run = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_sv"))
            .args(args)
            .output()
            .expect("sv runs");
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    };
    let path = dir.to_str().unwrap();
    let osv = dir.join("osv");
    let osv = osv.to_str().unwrap();
    // The control: in step, neither says anything about it, and the audit is clean.
    let (_, sbom) = run(&["sbom", path]);
    assert!(sbom.contains("so this is what is installed"), "{sbom}");
    assert!(!sbom.contains("disagree"), "{sbom}");
    let (code, audit) = run(&["audit", path, "--advisories", osv]);
    assert_eq!(code, Some(0), "{audit}");
    assert!(!audit.contains("disagree"), "{audit}");

    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    let (_, sbom) = run(&["sbom", path]);
    assert!(
        sbom.contains("npm: `package.json` and `package-lock.json` disagree about 1 package: `lodash ^4.17.21` (the lockfile has 4.17.15)"),
        "{sbom}"
    );
    assert!(
        sbom.contains("not the manifest that disagrees with it"),
        "{sbom}"
    );
    assert!(!sbom.contains("so this is what is installed"), "{sbom}");
    let (code, audit) = run(&["audit", path, "--advisories", osv]);
    assert_eq!(code, Some(2), "not assessed, never clean:\n{audit}");
    assert!(
        audit.contains("Not assessed — npm: `package.json` and `package-lock.json` disagree"),
        "{audit}"
    );
    std::fs::remove_dir_all(&dir).ok();
}
