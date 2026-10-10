//! The image's smoke test (`tools/image_smoke.py`) checks the tools the server in the image offers
//! against a list of its own. That list fell behind the server's on 10 October 2026, when
//! `stackvet_status` was added, and only the image job in CI noticed; this holds the two together
//! here, where `cargo test` sees it.

use std::path::PathBuf;

#[test]
fn the_image_smoke_test_expects_the_tools_the_server_lists() {
    let script = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tools/image_smoke.py"),
    )
    .unwrap();
    let start = script
        .find("TOOLS = [")
        .expect("the script's list of tools");
    let end = start + script[start..].find(']').expect("the list's end");
    let expected: Vec<&str> = script[start..end].split('"').skip(1).step_by(2).collect();
    let listed: Vec<String> = super::catalog::tool_list()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    // The control: the list was found and is not empty.
    assert!(expected.len() > 5, "{expected:?}");
    assert_eq!(
        expected, listed,
        "tools/image_smoke.py's TOOLS and the server's list differ"
    );
}
