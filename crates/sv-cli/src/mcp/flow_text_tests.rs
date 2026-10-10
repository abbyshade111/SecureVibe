//! The text an AI coding tool reads from the server, held in step and in the owner's words: the tools
//! named in one order wherever the way to build is told, and no word that calls an app safe and no
//! British spelling in any of it (BACKLOG, "From the architecture assessment of 8 October 2026",
//! item 10). Until 9 October 2026 the instructions, the tool list, the spec, and the guide's pasted
//! prompt were kept in step by hand, and the spec and the instructions gave two steps in opposite
//! orders.

use super::tests::{call, text};
use super::*;

fn examples() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn server() -> Server {
    Server::new(&examples().join("tested-notes")).unwrap()
}

/// The instructions, as `initialize` gives them.
fn instructions(server: &Server) -> String {
    let hello = server
        .handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}))
        .unwrap();
    hello["result"]["instructions"].as_str().unwrap().to_owned()
}

/// Every tool's name, in the order the list gives them.
fn listed() -> Vec<String> {
    tools()
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect()
}

/// The tool names in `said`, each where it is first named, in the order they come.
fn named_in(said: &str, names: &[String]) -> Vec<String> {
    let mut at: Vec<(usize, &String)> = names
        .iter()
        .filter_map(|n| first_as_a_word(said, n).map(|i| (i, n)))
        .collect();
    at.sort();
    at.into_iter().map(|(_, n)| n.clone()).collect()
}

/// Where `name` is first written as a whole name, not as the start of a longer one.
fn first_as_a_word(said: &str, name: &str) -> Option<usize> {
    said.match_indices(name)
        .find(|(i, _)| {
            !said[i + name.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
        .map(|(i, _)| i)
}

/// The prompt the guide gives the person to paste, its quoted lines under its heading.
fn pasted_prompt() -> String {
    let guide = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/GETTING-STARTED.md"),
    )
    .unwrap();
    let start = guide
        .find("## 4. Start the build with this prompt")
        .expect("the guide's heading for the prompt");
    let prompt: Vec<&str> = guide[start..]
        .lines()
        .skip_while(|l| !l.starts_with('>'))
        .take_while(|l| l.starts_with('>'))
        .collect();
    prompt.join("\n")
}

#[test]
fn the_instructions_name_every_tool_in_the_order_the_list_gives_them() {
    let names = listed();
    assert_eq!(names.len(), 12, "{names:?}");
    let said = instructions(&server());
    assert_eq!(
        named_in(&said, &names),
        names,
        "the instructions tell the way to build in one order and the list gives another"
    );
}

#[test]
fn the_guides_pasted_prompt_names_the_tools_in_the_lists_order() {
    let names = listed();
    let prompt = pasted_prompt();
    let named = named_in(&prompt, &names);
    // The control: the prompt is found, and names the steps it always has.
    for step in [
        "stackvet_spec",
        "stackvet_guidance",
        "stackvet_check",
        "stackvet_record_answer",
    ] {
        assert!(named.iter().any(|n| n == step), "{step}: {prompt}");
    }
    let in_list_order: Vec<String> = names
        .iter()
        .filter(|n| named.contains(n))
        .cloned()
        .collect();
    assert_eq!(named, in_list_order, "{prompt}");
}

#[test]
fn the_spec_gives_its_steps_in_the_order_the_instructions_give_the_tools() {
    // The spec is printed at a terminal by `sv init` as well as given by `stackvet_spec`, so it names
    // the commands, each the terminal's way to what a tool does.
    let as_tools = [
        ("`sv prompts`", "stackvet_prompts"),
        ("`sv plan", "stackvet_plan"),
        ("`sv brief", "stackvet_before"),
        ("`sv preflight", "stackvet_preflight"),
    ];
    let spec = text(&call(&server(), "stackvet_spec", json!({}))).to_owned();
    let mut at: Vec<(usize, String)> = as_tools
        .iter()
        .filter_map(|(command, tool)| spec.find(command).map(|i| (i, (*tool).to_owned())))
        .collect();
    at.sort();
    let named: Vec<String> = at.into_iter().map(|(_, t)| t).collect();
    assert!(
        named.len() >= 2,
        "the spec names fewer steps than it did: {named:?}"
    );
    let names = listed();
    let in_list_order: Vec<String> = names
        .iter()
        .filter(|n| named.contains(n))
        .cloned()
        .collect();
    assert_eq!(named, in_list_order);
}

/// Every string an AI tool can read from the server before it calls a tool on an app: the
/// instructions, every name, title, and description in the tool list and the prompt list, and the
/// spec.
fn everything_read(server: &Server) -> Vec<String> {
    fn strings(v: &Value, out: &mut Vec<String>) {
        match v {
            Value::String(s) => out.push(s.clone()),
            Value::Array(a) => a.iter().for_each(|v| strings(v, out)),
            Value::Object(o) => o.values().for_each(|v| strings(v, out)),
            _ => {}
        }
    }
    let mut out = vec![instructions(server)];
    strings(&tools(), &mut out);
    let prompts = server
        .handle(&json!({"jsonrpc":"2.0","id":2,"method":"prompts/list","params":{}}))
        .unwrap();
    strings(&prompts["result"], &mut out);
    out.push(text(&call(server, "stackvet_spec", json!({}))).to_owned());
    out
}

/// A word that says an app, or a requirement, is safe, written after a word that says it of
/// something ("the app is secure", "looks safe", "requirements are passed"). Bare, each has other
/// senses the server uses ("must pass `--fail-on`", "the whole suite passes", "secure coding", the
/// `compliance` format), which a list of words alone would forbid.
const CLAIMS: &[&str] = &[
    "secure",
    "safe",
    "compliant",
    "certified",
    "verified",
    "passed",
    "passing",
    "approved",
];

/// The words that say a claim of something.
const SAYING: &[&str] = &[
    "is", "are", "be", "was", "been", "being", "looks", "seems", "as", "now", "fully", "marked",
];

/// What makes a sentence with a claim in it a denial, as in "do not tell the person the app is
/// secure".
const DENIALS: &[&str] = &[
    "not", "never", "no", "nothing", "neither", "nor", "without", "cannot",
];

/// British spellings, each a word as a whole (`DESIGN.md`'s rule: American English everywhere a
/// person reads, and what an AI tool reads is passed on to the person).
const BRITISH: &[&str] = &[
    "behaviour",
    "colour",
    "favour",
    "honour",
    "centre",
    "catalogue",
    "programme",
    "licence",
    "defence",
    "offence",
    "judgement",
    "analyse",
    "organise",
    "organisation",
    "recognise",
    "realise",
    "prioritise",
    "summarise",
    "authorise",
    "authorisation",
    "minimise",
    "sanitise",
    "normalise",
    "initialise",
    "customise",
    "whilst",
    "amongst",
    "learnt",
    "spelt",
    "misspelt",
    "travelling",
    "cancelled",
    "labelled",
    "modelling",
];

fn words(sentence: &str) -> Vec<String> {
    sentence
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The sentences of `said`, cut at a full stop, a semicolon, a colon, or a line's end.
fn sentences(said: &str) -> impl Iterator<Item = &str> {
    said.split(['.', ';', ':', '\n'])
        .filter(|s| !s.trim().is_empty())
}

#[test]
fn nothing_an_ai_tool_reads_calls_an_app_safe_or_spells_a_word_the_british_way() {
    let read = everything_read(&server());
    // The control: the instructions, the twelve tools' descriptions, and the spec are all there.
    assert!(read.len() > 40, "{}", read.len());
    assert!(read.iter().any(|s| s.contains("stackvet_check gives them")));
    assert!(
        read.iter()
            .any(|s| s.contains("Every capability line starts commented out"))
    );
    let mut wrong = Vec::new();
    for said in &read {
        for sentence in sentences(said) {
            let words = words(sentence);
            let denied = words.iter().any(|w| DENIALS.contains(&w.as_str()));
            for (i, pair) in words.windows(2).enumerate() {
                // "what is safe to do twice" speaks of something to do, not of the app.
                let of_doing = words.get(i + 2).is_some_and(|w| w == "to");
                if SAYING.contains(&pair[0].as_str())
                    && CLAIMS.contains(&pair[1].as_str())
                    && !denied
                    && !of_doing
                {
                    wrong.push(format!("{:?}: {sentence}", pair.join(" ")));
                }
            }
            for british in BRITISH {
                if words
                    .iter()
                    .any(|w| w == british || w.starts_with(&format!("{british}s")))
                {
                    wrong.push(format!("{british:?}: {sentence}"));
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}
