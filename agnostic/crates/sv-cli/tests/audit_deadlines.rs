//! What `sv audit` prints about the owner's time frames, end to end through the binary.
//!
//! The check itself is pinned in `advisories.rs`. These pin what reaches the reader: a guard on the
//! input is not a guard on the output, and a late vulnerability printed under "inside the time
//! frame" would undo the check without failing any of its tests.

use std::path::{Path, PathBuf};
use std::process::Command;

const HIGH: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N";
const CRITICAL: &str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H";

/// An npm app with three vulnerable packages, and an advisory database with one record for each:
/// lodash published long ago (late), minimist published in 2099 (inside any time frame, whatever
/// today is), and qs rated critical, a severity the time frames below leave out (not judged).
fn app(name: &str, securevibe_toml: Option<&str>) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("sv-deadline-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    let (dir, osv) = (root.join("app"), root.join("osv"));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::create_dir_all(&osv).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"demo","version":"1.0.0","dependencies":{"lodash":"4.17.15","minimist":"1.2.0","qs":"6.5.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"demo","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"},
           "node_modules/lodash":{"version":"4.17.15"},"node_modules/minimist":{"version":"1.2.0"},
           "node_modules/qs":{"version":"6.5.0"}}}"#,
    )
    .unwrap();
    if let Some(text) = securevibe_toml {
        std::fs::write(dir.join("securevibe.toml"), text).unwrap();
    }
    for (id, package, published, vector) in [
        ("GHSA-late", "lodash", "2020-07-15T00:00:00Z", HIGH),
        ("GHSA-inside", "minimist", "2099-01-01T00:00:00Z", HIGH),
        ("GHSA-unjudged", "qs", "2020-07-15T00:00:00Z", CRITICAL),
    ] {
        std::fs::write(
            osv.join(format!("{id}.json")),
            format!(
                r#"{{"id":"{id}","summary":"A vulnerability.","published":"{published}",
                    "severity":[{{"type":"CVSS_V3","score":"{vector}"}}],
                    "affected":[{{"package":{{"ecosystem":"npm","name":"{package}"}},
                    "ranges":[{{"type":"ECOSYSTEM","events":[{{"introduced":"0"}},{{"fixed":"99"}}]}}]}}]}}"#
            ),
        )
        .unwrap();
    }
    (dir, osv)
}

fn audit(dir: &Path, osv: &Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sv"))
        .args([
            "audit",
            dir.to_str().unwrap(),
            "--advisories",
            osv.to_str().unwrap(),
        ])
        .output()
        .expect("sv runs");
    assert!(
        out.status.success(),
        "sv audit failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn at(text: &str, needle: &str) -> usize {
    text.find(needle)
        .unwrap_or_else(|| panic!("{needle:?} is not in the output:\n{text}"))
}

#[test]
fn each_vulnerability_is_printed_under_where_it_stands() {
    let (dir, osv) = app(
        "grouped",
        Some("[policy]\nfix-within-days = { high = 30, medium = 90, low = 180 }\n"),
    );
    let text = audit(&dir, &osv);
    let late = at(&text, "Past the time frame you set");
    let unjudged = at(&text, "Not judged against a time frame");
    let inside = at(&text, "Inside the time frame you set");
    let (lodash, qs, minimist) = (
        at(&text, "lodash 4.17.15"),
        at(&text, "qs 6.5.0"),
        at(&text, "minimist 1.2.0"),
    );
    assert!(
        late < lodash && lodash < unjudged && unjudged < qs && qs < inside && inside < minimist,
        "late, then not judged, then inside, each holding its own package:\n{text}"
    );
    assert!(
        text.contains("no time frame for critical vulnerabilities"),
        "the reader is not told why qs was not judged:\n{text}"
    );
    assert!(
        !text.contains("Nothing in what was compared"),
        "a known vulnerability inside its time frame is not a clean result:\n{text}"
    );
}

#[test]
fn with_no_time_frames_everything_counts_as_it_always_did_and_the_owner_is_told_how_to_change_that()
{
    let (dir, osv) = app("none", None);
    let text = audit(&dir, &osv);
    let unjudged = at(&text, "Not judged against a time frame");
    for package in ["lodash 4.17.15", "minimist 1.2.0", "qs 6.5.0"] {
        assert!(
            unjudged < at(&text, package),
            "{package} is not under not judged:\n{text}"
        );
    }
    assert!(!text.contains("Past the time frame you set"), "{text}");
    assert!(!text.contains("Inside the time frame you set"), "{text}");
    assert!(
        text.contains("fix-within-days = {"),
        "no hint how to set one:\n{text}"
    );
}
