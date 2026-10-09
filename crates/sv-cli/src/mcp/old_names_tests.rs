//! The tools by their old names (ADR-062): a call to `securevibe_*` is answered as the `stackvet_*`
//! tool it names, the list names only the new ones, and the server is `stackvet`.

use super::tests::call;
use super::*;
use sv_frameworks::names::{MCP_SERVER, MCP_TOOL_PREFIX, OLD_MCP_TOOL_PREFIX};

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

#[test]
fn an_old_tool_name_is_answered_as_the_new_tool_and_the_list_names_only_the_new() {
    let server = Server::new(&examples().join("tested-notes")).unwrap();
    let new = call(&server, "stackvet_spec", json!({}));
    let old = call(&server, "securevibe_spec", json!({}));
    assert_eq!(old, new, "the old name is the same tool");
    assert_eq!(old["isError"], false, "{old}");
    // A name that is neither is still refused, so the alias is not a wildcard.
    let unknown = server
        .handle(&json!({
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": { "name": "securevibe_nothing", "arguments": {} }
        }))
        .unwrap();
    assert!(
        unknown.get("error").is_some() || unknown["result"]["isError"] == true,
        "{unknown}"
    );
    let list = server
        .handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
        .unwrap();
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(!names.is_empty());
    assert!(
        names.iter().all(|n| n.starts_with(MCP_TOOL_PREFIX)),
        "{names:?}"
    );
    assert!(
        !names.iter().any(|n| n.starts_with(OLD_MCP_TOOL_PREFIX)),
        "the list teaches only the new names: {names:?}"
    );
    let init = server
        .handle(&json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {} }))
        .unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], MCP_SERVER, "{init}");
}
