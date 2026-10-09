//! A planted report marker (the review of 8 October 2026, item 4): `stackvet_write_report` with
//! `out` at a folder of the app's that carries a copied `.stackvet-report` replaced the app's own
//! files there whose names are a report's. A marked folder that holds files `sv` did not write is
//! written to only when this computer can show, by its seal, that `sv` wrote the report there.
use super::tests::{call, scratch_app, text};
use super::*;

/// The app's own `docs/`: a README and a `security.md` of its own, and a marker copied in.
fn planted(root: &Path, marker: &str) -> PathBuf {
    let docs = root.join("app/docs");
    std::fs::create_dir_all(&docs).unwrap();
    std::fs::write(docs.join("README.md"), "Our docs.\n").unwrap();
    std::fs::write(docs.join("security.md"), "How to report a problem to us.\n").unwrap();
    std::fs::write(docs.join(sv_scan::ecosystems::REPORT_MARKER), marker).unwrap();
    docs
}

#[test]
fn a_planted_marker_does_not_let_a_report_replace_the_apps_files() {
    // A marker as `sv` writes it, with no seal; and one with a seal line `sv` did not make.
    for (tag, marker) in [
        (
            "bare",
            "This folder holds a report written by sv. sv leaves it out when it checks the app.\n",
        ),
        (
            "forged",
            "This folder holds a report written by sv. sv leaves it out when it checks the app.\nseal: AAAA\n",
        ),
        // Every file a seal covers is there too, so only the seal's key stands in the way.
        (
            "forged-whole",
            "This folder holds a report written by sv. sv leaves it out when it checks the app.\nseal: AAAA\n",
        ),
    ] {
        let root = scratch_app(&format!("planted-marker-{tag}"), "flask-booking");
        let docs = planted(&root, marker);
        if tag == "forged-whole" {
            for name in sv_scan::ecosystems::REPORT_FILES {
                if !docs.join(name).exists() {
                    std::fs::write(docs.join(name), "theirs\n").unwrap();
                }
            }
        }
        // The setup: the folder is marked, and holds a file of the app's under one of a report's names.
        assert!(docs.join(sv_scan::ecosystems::REPORT_MARKER).is_file());
        assert!(sv_scan::ecosystems::REPORT_FOLDER_NAMES.contains(&"security.md"));
        let server = Server::new(&root).unwrap();
        let result = call(
            &server,
            "stackvet_write_report",
            json!({ "path": "app", "out": "docs" }),
        );
        let security = std::fs::read_to_string(docs.join("security.md")).unwrap();
        let report_json = std::fs::read_to_string(docs.join("report.json")).ok();
        std::fs::remove_dir_all(&root).ok();
        assert_eq!(result["isError"], true, "{tag}: {}", text(&result));
        assert!(
            text(&result).contains("cannot show it wrote the report there"),
            "{tag}: {}",
            text(&result)
        );
        assert_eq!(
            security, "How to report a problem to us.\n",
            "{tag}: the app's own security.md was replaced"
        );
        let planted_json = (tag == "forged-whole").then(|| "theirs\n".to_owned());
        assert_eq!(
            report_json, planted_json,
            "{tag}: a report was written into the app's docs"
        );
    }
}

#[test]
fn a_folder_sv_sealed_still_takes_a_report_beside_a_file_of_the_owners() {
    let root = scratch_app("sealed-marker", "flask-booking");
    let server = Server::new(&root).unwrap();
    let first = call(
        &server,
        "stackvet_write_report",
        json!({ "path": "app", "out": "report" }),
    );
    assert_ne!(first["isError"], true, "{}", text(&first));
    let folder = root.join("app/report");
    // The setup: the first report was sealed on this computer, or the rest would prove nothing.
    assert!(
        crate::report_seal::sealed_here(&folder).is_ok(),
        "the first report was not sealed: {:?}",
        crate::report_seal::sealed_here(&folder)
    );
    std::fs::write(folder.join("notes-to-self.txt"), "mine\n").unwrap();
    let again = call(
        &server,
        "stackvet_write_report",
        json!({ "path": "app", "out": "report" }),
    );
    let kept = std::fs::read_to_string(folder.join("notes-to-self.txt")).unwrap();
    std::fs::remove_dir_all(&root).ok();
    assert_ne!(again["isError"], true, "{}", text(&again));
    assert_eq!(kept, "mine\n");
}
