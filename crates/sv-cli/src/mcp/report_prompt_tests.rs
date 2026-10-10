//! The prompt for reading the report with the person (backlog 0217 part 5), as the MCP server
//! offers it: listed after the design-time prompts, sent as the person's message with its mark,
//! and in the stateless protocol too.

use super::tests::{examples, stateless};
use super::*;

#[test]
fn the_report_prompt_is_listed_with_its_mark_and_comes_back_as_the_persons_message() {
    let server = Server::new(&examples()).unwrap();
    let list = server
        .handle(&json!({"jsonrpc":"2.0","id":1,"method":"prompts/list"}))
        .unwrap();
    let listed = list["result"]["prompts"].as_array().unwrap();
    let offered = listed
        .iter()
        .find(|p| p["name"] == crate::report_prompt::ID)
        .unwrap_or_else(|| panic!("{} is not listed: {list}", crate::report_prompt::ID));
    assert_eq!(offered["title"], crate::report_prompt::TITLE);
    assert_eq!(offered["description"], "Not tried yet.");

    let got = server
        .handle(&json!({"jsonrpc":"2.0","id":2,"method":"prompts/get",
            "params":{"name": crate::report_prompt::ID}}))
        .unwrap();
    let message = &got["result"]["messages"][0];
    assert_eq!(message["role"], "user", "{got}");
    let text = message["content"]["text"].as_str().unwrap();
    assert!(
        text.starts_with(crate::report_prompt::TEXT.trim_end()),
        "the prompt's own words come first: {text}"
    );
    assert!(text.contains("Not tried yet."), "{text}");
    assert!(text.contains("an instruction, not evidence"), "{text}");
    assert_eq!(got["result"]["description"], "Not tried yet.");
}

#[test]
fn the_report_prompt_is_offered_in_the_stateless_protocol_too() {
    let server = Server::new(&examples()).unwrap();
    let got = server
        .handle(&stateless(
            3,
            "prompts/get",
            "2026-07-28",
            json!({ "name": crate::report_prompt::ID }),
        ))
        .unwrap();
    assert_eq!(got["result"]["resultType"], "complete", "{got}");
    assert_eq!(got["result"]["cacheScope"], "public");
    assert_eq!(got["result"]["messages"][0]["role"], "user", "{got}");
}
