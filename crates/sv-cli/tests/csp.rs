//! `report.html`, as `sv report` writes it, carries the Content-Security-Policy tag in its head
//! (the review of 8 October 2026, item 6), and holds no script for the policy to refuse.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn the_written_report_page_carries_the_policy() {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/partly-passing");
    let out = std::env::temp_dir().join(format!("sv-csp-{}", std::process::id()));
    std::fs::remove_dir_all(&out).ok();
    let run = Command::new(env!("CARGO_BIN_EXE_sv"))
        .arg("report")
        .arg(&app)
        .arg("--out")
        .arg(&out)
        .output()
        .unwrap();
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let page = std::fs::read_to_string(out.join("report.html")).unwrap();
    std::fs::remove_dir_all(&out).ok();
    let head = page.split("</head>").next().unwrap();
    assert!(
        head.contains(sv_report::html::CSP_META.trim_end()),
        "the head holds no policy: {head}"
    );
    assert!(
        !page.contains("<script"),
        "a script the policy would refuse"
    );
}
