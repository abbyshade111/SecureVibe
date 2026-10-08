//! A manifest that cannot be compared with its lockfile is said to be not compared, rather than left
//! out (the review of 8 October 2026, item 5): when `package.json` could not be read or understood,
//! no disagreement was recorded, and the report read as though it and the lockfile agreed.

use super::*;
use std::fs;

const LOCK: &str = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.21"}}}"#;

fn app(name: &str, manifest: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sv-sbom-not-compared-{name}-{}",
        std::process::id()
    ));
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("package.json"), manifest).unwrap();
    fs::write(dir.join("package-lock.json"), LOCK).unwrap();
    dir
}

#[test]
fn a_manifest_that_cannot_be_read_or_understood_is_said_not_compared() {
    for (name, manifest, why) in [
        (
            "broken",
            &b"{ \"dependencies\": { \"lodash\": "[..],
            "could not be understood",
        ),
        (
            "not-text",
            &b"{\"dependencies\":{\"lodash\":\"\xff\xfe\"}}"[..],
            "could not be read",
        ),
    ] {
        let dir = app(name, manifest);
        let sbom = build(&dir);
        fs::remove_dir_all(&dir).ok();
        // The setup: the lockfile was read, and its list stands.
        assert!(
            sbom.components.iter().any(|c| c.name == "lodash"),
            "{name}: {sbom:?}"
        );
        assert!(
            sbom.is_complete(),
            "{name}: the list is still the lockfile's: {sbom:?}"
        );
        let said: Vec<String> = sbom
            .disagreements
            .iter()
            .filter(|d| d.comparison.not_all_compared())
            .map(Disagreement::explain_not_compared)
            .collect();
        assert_eq!(said.len(), 1, "{name}: {sbom:?}");
        assert!(
            said[0].contains(&format!("`package.json` {why}"))
                && said[0].contains("was not compared, and is not known"),
            "{name}: {}",
            said[0]
        );
        assert!(
            !sbom.disagreements[0].differs(),
            "{name}: nothing was found to differ"
        );
    }
}

#[test]
fn a_manifest_that_agrees_with_its_lockfile_says_nothing() {
    let dir = app("agrees", br#"{"dependencies":{"lodash":"^4.17.0"}}"#);
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    assert!(
        sbom.components.iter().any(|c| c.name == "lodash"),
        "{sbom:?}"
    );
    assert!(sbom.disagreements.is_empty(), "{:?}", sbom.disagreements);
}
