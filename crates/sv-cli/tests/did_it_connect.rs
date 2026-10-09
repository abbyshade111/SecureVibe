//! When StackVet is not connected, the AI coding tool builds without it and nothing says so
//! (`docs/GAP-ANALYSIS.md`, 5.3). The guide gives a check that works in any tool, the prompt it gives
//! tells the tool to stop, and so do the rules `sv rules` writes into `AGENTS.md`, which a tool reads
//! whether or not StackVet is connected. Held here to the tools the server really has.

use std::path::{Path, PathBuf};
use std::process::Command;

const SV: &str = env!("CARGO_BIN_EXE_sv");

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn guide() -> String {
    std::fs::read_to_string(repo().join("docs/GETTING-STARTED.md")).unwrap()
}

/// The names of the tools the MCP server lists, asked of the server itself.
fn tool_names() -> Vec<String> {
    use std::io::Write;
    let root = std::env::temp_dir().join(format!("sv-connect-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let mut child = Command::new(SV)
        .args(["mcp", "--root", root.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for line in [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
    ] {
        writeln!(stdin, "{line}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    std::fs::remove_dir_all(&root).ok();
    let listed = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find(|v| v["id"] == 2)
        .expect("the server answers tools/list");
    listed["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

fn in_words(n: usize) -> &'static str {
    [
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
    ]
    .get(n)
    .copied()
    .unwrap_or("more than twenty")
}

#[test]
fn the_guide_says_how_to_tell_and_how_many_tools_there_are() {
    let names = tool_names();
    assert!(
        names.len() > 5,
        "the setup: the server lists its tools: {names:?}"
    );
    let guide = guide();
    let start = guide
        .find("\n### Did it connect?\n")
        .expect("the guide has a step to check StackVet connected");
    let step = &guide[start..start + guide[start..].find("\n### A tool").unwrap()];
    assert!(
        step.contains("Which `stackvet_` tools can you call?"),
        "{step}"
    );
    let says = format!("It should list {}, among them", in_words(names.len()));
    assert!(
        step.contains(&says),
        "the count is not the server's {}: {step}",
        names.len()
    );
    for named in ["stackvet_spec", "stackvet_check"] {
        assert!(names.iter().any(|n| n == named), "{named} is not a tool");
        assert!(step.contains(&format!("`{named}`")), "{step}");
    }
    // Every other place the guide counts the tools agrees, such as VS Code's "the thirteen".
    let mut counted = 0;
    for (at, _) in guide.match_indices(" `stackvet_` tools") {
        let word = guide[..at].split_whitespace().last().unwrap_or_default();
        if (0..=20).any(|n| in_words(n) == word) {
            counted += 1;
            assert_eq!(
                word,
                in_words(names.len()),
                "the guide counts the tools as {word}"
            );
        }
    }
    assert!(
        counted >= 1,
        "the setup: VS Code's section counts the tools"
    );
}

#[test]
fn the_prompt_tells_the_tool_to_stop_when_the_tools_are_missing() {
    let guide = guide();
    let prompt = &guide[guide
        .find("## 4. Start the build with this prompt")
        .unwrap()..];
    let prompt = &prompt[..prompt.find("\n## 5.").unwrap()];
    let joined: String = prompt
        .lines()
        .map(|l| l.trim_start_matches('>').trim())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        joined.contains(
            "If you cannot call the `stackvet_` tools, stop and tell me before writing any code"
        ),
        "{prompt}"
    );
}

#[test]
fn agents_md_tells_the_tool_to_stop_when_the_tools_are_missing() {
    let dir = std::env::temp_dir().join(format!("sv-connect-rules-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let rule = "stop and tell the person before you write any code";
    let printed = Command::new(SV)
        .args(["rules", dir.to_str().unwrap(), "--print"])
        .output()
        .unwrap();
    let printed = String::from_utf8_lossy(&printed.stdout).into_owned();
    let wrote = Command::new(SV)
        .args(["rules", dir.to_str().unwrap()])
        .output()
        .unwrap();
    let written = std::fs::read_to_string(dir.join("AGENTS.md")).unwrap_or_default();
    std::fs::remove_dir_all(&dir).ok();
    assert!(wrote.status.success(), "{wrote:?}");
    // The setup: the rules are there, so the line is looked for in the right place.
    assert!(
        written.contains("## Security rules for the AI coding tool"),
        "{written}"
    );
    assert!(printed.contains(rule), "{printed}");
    assert!(written.contains(rule), "{written}");
    // Right under the heading, where a tool reads first.
    let heading = written
        .find("## Security rules for the AI coding tool")
        .unwrap();
    let first_rule = written[heading..]
        .find("\n### ")
        .map_or(written.len(), |i| heading + i);
    assert!(written[heading..first_rule].contains(rule), "{written}");
}
