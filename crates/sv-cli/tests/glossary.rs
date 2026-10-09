//! `docs/GLOSSARY.md` (backlog 0217, part 7): every link into it lands on a word it explains, the guide
//! sends readers to it, and what it says about StackVet's own names is what `sv` uses.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap()
}

/// The anchor GitHub gives a heading: lower case, spaces as hyphens, and only letters, digits, hyphens,
/// and underscores kept.
fn anchor(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_alphanumeric() || c == '-' || c == '_' => Some(c),
            _ => None,
        })
        .collect()
}

fn anchors() -> Vec<String> {
    read("docs/GLOSSARY.md")
        .lines()
        .filter_map(|l| l.strip_prefix("## "))
        .map(anchor)
        .collect()
}

/// Every `GLOSSARY.md#anchor` link in a file.
fn links_in(text: &str) -> Vec<String> {
    text.match_indices("GLOSSARY.md#")
        .map(|(i, m)| {
            text[i + m.len()..]
                .chars()
                .take_while(|c| *c != ')')
                .collect()
        })
        .collect()
}

#[test]
fn every_link_into_the_glossary_lands_on_a_word_it_explains() {
    let anchors = anchors();
    assert!(anchors.len() >= 15, "{anchors:?}");
    let mut checked = 0;
    for file in ["docs/GETTING-STARTED.md", "docs/GLOSSARY.md", "README.md"] {
        for link in links_in(&read(file)) {
            assert!(
                anchors.contains(&link),
                "{file} links #{link}, which is not in {anchors:?}"
            );
            checked += 1;
        }
    }
    // The links really are there to check: the guide's first uses of these words.
    assert!(checked >= 5, "only {checked} links into the glossary");
}

#[test]
fn the_anchor_is_the_one_github_makes() {
    assert_eq!(anchor("Folder path"), "folder-path");
    assert_eq!(anchor("`stackvet.toml`"), "stackvettoml");
    assert_eq!(anchor("`sv`"), "sv");
    assert_eq!(anchor("MCP"), "mcp");
}

#[test]
fn the_guide_sends_readers_to_the_glossary_near_its_start() {
    let guide = read("docs/GETTING-STARTED.md");
    let at = guide
        .find("(GLOSSARY.md)")
        .expect("the guide links the glossary");
    let step_one = guide.find("## 1.").expect("step 1");
    assert!(
        at < step_one,
        "before step 1, where the first unfamiliar words are"
    );
}

#[test]
fn every_word_has_an_explanation() {
    let text = read("docs/GLOSSARY.md");
    let sections: Vec<&str> = text.split("\n## ").skip(1).collect();
    assert_eq!(sections.len(), anchors().len());
    for section in sections {
        let (word, body) = section.split_once('\n').unwrap();
        assert!(
            body.split_whitespace().count() >= 12,
            "{word} needs more than a few words"
        );
    }
}

#[test]
fn what_it_says_about_stackvets_own_names_is_what_sv_uses() {
    let text = read("docs/GLOSSARY.md");
    assert!(text.contains(&format!("`{}`", sv_frameworks::names::IMAGE)));
    for tool in ["claude", "vscode", "cursor"] {
        let file = sv_cli::connect::Tool::named(tool).unwrap().settings_file();
        assert!(text.contains(&format!("`{file}`")), "{file}");
    }
    assert!(text.contains("`stackvet-report`"));
    assert_eq!(
        sv_scan::ecosystems::default_report_dir_in(Path::new("app")),
        Path::new("app").join("stackvet-report")
    );
}

#[test]
fn the_words_the_guide_relies_on_are_linked_from_it_and_explained() {
    let guide = read("docs/GETTING-STARTED.md");
    let anchors = anchors();
    assert!(
        guide.contains("[the glossary](GLOSSARY.md)"),
        "the guide's pointer"
    );
    for word in ["docker", "terminal", "git", "mcp", "not-assessed"] {
        assert!(
            anchors.contains(&word.to_owned()),
            "the glossary explains {word}"
        );
        assert!(
            guide.contains(&format!("(GLOSSARY.md#{word})")),
            "the guide links {word}"
        );
    }
}
