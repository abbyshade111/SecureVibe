//! "Read my report with me" (backlog 0217 part 5), held to the report `sv` writes: every section
//! and file the prompt names is one a real report has, `sv prompts report` prints the prompt, and
//! the page a person reads (`docs/prompts/report.md`) holds the same words.

use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sv(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(args)
        .output()
        .expect("sv runs")
}

/// Whitespace and the page's quote marks set aside, so wrapping a line differently is not a change.
fn words(text: &str) -> String {
    text.lines()
        .map(|l| l.strip_prefix('>').unwrap_or(l))
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// What the prompt puts in double quotes: the names of sections and lines in the report.
fn quoted_names(text: &str) -> Vec<String> {
    text.split('"').skip(1).step_by(2).map(words).collect()
}

/// What the prompt puts in backticks: the folder and the files it tells the tool to read.
fn file_names(text: &str) -> Vec<String> {
    text.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// A report on a small app, in the folder an AI tool would look in.
fn a_report() -> (PathBuf, String) {
    let dir = std::env::temp_dir().join(format!("sv-report-prompt-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("stackvet.toml"),
        "manifest-version = 1\n[app]\nname = \"x\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("app.py"), "print('hi')\n").unwrap();
    let run = sv(&["report", dir.to_str().unwrap()]);
    assert!(
        matches!(run.status.code(), Some(0 | 2)),
        "sv report failed: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    let compliance = std::fs::read_to_string(dir.join("stackvet-report/compliance.md"))
        .expect("the report is where the prompt says it is");
    (dir, compliance)
}

#[test]
fn every_section_and_file_the_prompt_names_is_in_a_report_sv_writes() {
    let text = sv_cli::report_prompt::TEXT;
    let (dir, compliance) = a_report();
    let names = quoted_names(text);
    // The setup worked: the prompt names sections, and the report is a real one.
    assert!(names.len() >= 4, "{names:?}");
    assert!(compliance.contains("## The short version"), "{compliance}");
    for name in &names {
        let found = compliance
            .lines()
            .any(|l| l.trim_start_matches('#').trim().starts_with(name.as_str()));
        assert!(
            found,
            "the prompt names \"{name}\", which compliance.md has no heading or line for:\n{compliance}"
        );
    }
    let files = file_names(text);
    for file in ["stackvet-report", "compliance.md", "security.md"] {
        assert!(files.iter().any(|f| f == file), "{files:?}");
    }
    for file in ["compliance.md", "security.md"] {
        assert!(
            dir.join("stackvet-report").join(file).is_file(),
            "{file} is not in the report folder"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_prompt_starts_with_what_was_not_checked_and_never_says_secure() {
    let text = sv_cli::report_prompt::TEXT;
    let at = |s: &str| {
        text.find(s)
            .unwrap_or_else(|| panic!("no {s:?} in the prompt"))
    };
    assert!(at("What was not checked, first") < at("At most three things to do first"));
    assert!(at("\"What was not examined\"") < at("\"What to do next\""));
    assert!(text.contains("Never tell me the app is secure, safe, compliant, or that it passed"));
    assert!(text.contains("Do not soften what the report says"));
    assert!(text.contains("do not guess what a report would say"));
}

#[test]
fn sv_prompts_report_prints_the_prompt_with_its_mark() {
    let run = sv(&["prompts", "report"]);
    assert!(run.status.success(), "{run:?}");
    let out = String::from_utf8(run.stdout).unwrap();
    assert!(
        out.starts_with(sv_cli::report_prompt::TEXT.trim_end()),
        "{out}"
    );
    assert!(out.contains("Not tried yet."), "{out}");
    // Anything more is refused rather than read as some other request.
    for refused in [
        &["prompts", "report", "--app", "."][..],
        &["prompts", "reprot"],
        &["prompts", "--app", ".", "report"],
    ] {
        let run = sv(refused);
        assert!(!run.status.success(), "{refused:?} was not refused");
    }
}

#[test]
fn the_page_a_person_reads_holds_the_same_words() {
    let page = std::fs::read_to_string(root().join("docs/prompts/report.md")).unwrap();
    let start = page
        .find("<!-- report-prompt:start -->")
        .expect("start marker")
        + "<!-- report-prompt:start -->".len();
    let end = page.find("<!-- report-prompt:end -->").expect("end marker");
    assert_eq!(
        words(&page[start..end]),
        words(sv_cli::report_prompt::TEXT),
        "docs/prompts/report.md and crates/sv-cli/src/report_prompt.rs say different things"
    );
    assert!(
        page.contains(sv_cli::report_prompt::ID),
        "the page names the prompt as the server offers it"
    );
    let guide = std::fs::read_to_string(root().join("docs/GETTING-STARTED.md")).unwrap();
    assert!(
        guide.contains("(prompts/report.md)"),
        "the guide links the prompt"
    );
}

#[test]
fn words_finds_a_change_inside_a_line_and_ignores_one_in_wrapping() {
    assert_eq!(words("> a b\n> c"), words("a\nb c"));
    assert_ne!(words("> a b\n> c"), words("a b d"));
    assert_eq!(quoted_names("x \"one\" y \"two\" z"), ["one", "two"]);
}
