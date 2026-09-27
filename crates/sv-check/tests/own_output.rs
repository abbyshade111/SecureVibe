//! `sv`'s own report is never read as the app's code.
//!
//! Found in the owner's first build (26 September 2026): `sv report` writes into the app's folder by
//! default, the next check read `report.html` as part of the app, and while a page no code rule could
//! fully read was there, no code rule claimed anything. The requirements checked fell from 9 to 1,
//! twice, and the tool building the app found the cause only by undoing its own changes one at a time.
//!
//! Every folder `sv report` writes carries `REPORT_MARKER`, and every walk of the app leaves such a
//! folder out, whatever it is called, since `--out` takes any name.

use std::path::{Path, PathBuf};
use sv_check::ast::AstRules;
use sv_check::secrets::SecretRules;
use sv_scan::ecosystems::REPORT_MARKER;

fn data(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../data")
        .join(name)
}

/// What a report page looks like to the code rules: a script they cannot fully read, and a string
/// the credential scan would take for a key if it read it.
const REPORT_PAGE: &str = "<html><body><script>const s = `${a}`; eval(q)</script>\n\
    <p>AKIAABCDEFGHIJKLMNOP</p></body></html>\n";

fn app(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-own-output-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("app.py"), "print('hello')\n").unwrap();
    dir
}

fn report_in(dir: &Path, marked: bool) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("report.html"), REPORT_PAGE).unwrap();
    std::fs::write(dir.join("report.js"), "eval(req.query.x);\n").unwrap();
    if marked {
        std::fs::write(dir.join(REPORT_MARKER), "sv\n").unwrap();
    }
}

fn read(app: &Path) -> (usize, usize, usize, Vec<String>) {
    let ast = sv_check::ast::scan_dir(&AstRules::load(&data("ast-rules.json")).unwrap(), app);
    let secrets =
        sv_check::secrets::scan_dir(&SecretRules::load(&data("secret-rules.json")).unwrap(), app);
    (
        ast.files_parsed,
        ast.findings.len(),
        secrets.findings.len(),
        ast.unparsed_files.clone(),
    )
}

#[test]
fn a_report_in_a_folder_of_any_name_is_left_out_once_marked() {
    let dir = app("marked");
    report_in(&dir.join("my-reports"), true);
    let (parsed, ast_findings, secret_findings, unparsed) = read(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(parsed, 1, "only app.py is the app's code");
    assert_eq!(ast_findings, 0, "the report's script is not the app's");
    assert_eq!(secret_findings, 0, "the report's text is not the app's");
    assert!(unparsed.is_empty(), "{unparsed:?}");
}

#[test]
fn the_default_report_folder_is_left_out_even_without_the_marker() {
    // Reports written before the marker existed are in `securevibe-report` without one.
    let dir = app("default");
    report_in(&dir.join("securevibe-report"), false);
    let (parsed, ast_findings, _, _) = read(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(parsed, 1);
    assert_eq!(ast_findings, 0);
}

#[test]
fn an_unmarked_folder_of_another_name_is_still_the_apps_code() {
    // The other half: the marker is what makes a folder `sv`'s, not a guess from what is in it. The
    // same files in an ordinary folder are read, and found, which is what shows the two tests above
    // pass because of the marker and not because these files are never read.
    let dir = app("unmarked");
    report_in(&dir.join("my-reports"), false);
    let (parsed, ast_findings, secret_findings, _) = read(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(parsed > 1, "the folder's code is read");
    assert!(ast_findings > 0, "and its eval found");
    assert!(secret_findings > 0, "and its key found");
}

#[test]
fn the_credential_scan_still_reads_editor_settings() {
    // One skip list now, with one exception kept on purpose: `.vscode` is not the app's code, but a
    // settings file there can hold a token.
    let dir = app("editor");
    std::fs::create_dir_all(dir.join(".vscode")).unwrap();
    std::fs::write(
        dir.join(".vscode").join("settings.json"),
        "{ \"aws.key\": \"AKIAABCDEFGHIJKLMNOP\" }\n",
    )
    .unwrap();
    let (_, _, secret_findings, _) = read(&dir);
    std::fs::remove_dir_all(&dir).ok();
    assert!(
        secret_findings > 0,
        "a key in editor settings is still found"
    );
}
