//! The Python tools read and write text as UTF-8 with Unix line endings on every system (backlog
//! 0120). Python's own default is the system's: on Windows a code page, not UTF-8, and CRLF when it
//! writes. `tools/coverage.py` failed there on its first read, and four tests with it; a file it wrote
//! there would have differed from the one committed. This holds every tool to the explicit form.

use std::path::Path;

/// Each line of a tool that leaves the encoding, or the line endings it writes, to the system.
fn system_dependent(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let code = line.split(" #").next().unwrap_or(line);
        let bad = code.contains(".read_text()")
            || code.contains(".write_text(")
            || (code.contains("text=True") && !code.contains("encoding="))
            || (code.contains("open(")
                && !code.contains("encoding=")
                && !code.contains("urlopen(")
                && !code.contains("os.open(")
                && !code.contains("def ")
                && !["'rb'", "\"rb\"", "'wb'", "\"wb\"", "'ab'", "\"ab\""]
                    .iter()
                    .any(|mode| code.contains(mode)));
        if bad {
            found.push(format!("{}: {}", n + 1, line.trim()));
        }
    }
    found
}

#[test]
fn every_tool_says_utf_8_and_unix_line_endings() {
    let tools = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools");
    let mut read = 0;
    let mut faults = Vec::new();
    for entry in std::fs::read_dir(&tools).unwrap().flatten() {
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "py") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        read += 1;
        for line in system_dependent(&text) {
            faults.push(format!("{}:{line}", path.display()));
        }
    }
    // The walk reached the tools: there are more than ten.
    assert!(read > 10, "only {read} tools read");
    assert!(
        faults.is_empty(),
        "give each an explicit encoding=\"utf-8\" (and newline=\"\\n\" when writing; the tools' own \
         write_text helper does both):\n{}",
        faults.join("\n")
    );
}

#[test]
fn the_guard_finds_each_form_it_is_for() {
    for bad in [
        "x = p.read_text()",
        "p.write_text(s)",
        "subprocess.run(a, capture_output=True, text=True)",
        "data = json.load(open(path))",
        "open(path, 'w').write(s)",
    ] {
        assert_eq!(system_dependent(bad).len(), 1, "{bad}");
    }
    for good in [
        "x = p.read_text(encoding=\"utf-8\")",
        "write_text(p, s)",
        "subprocess.run(a, capture_output=True, text=True, encoding=\"utf-8\")",
        "data = json.load(open(path, encoding=\"utf-8\"))",
        "tomllib.load(open(path, 'rb'))",
        "with urllib.request.urlopen(req) as r:",
    ] {
        assert!(system_dependent(good).is_empty(), "{good}");
    }
}
