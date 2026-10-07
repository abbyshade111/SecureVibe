//! Copies of other projects' libraries kept inside the app: jQuery in `public/js`, Bootstrap in
//! `static/`, Moment.js in `assets/javascripts` (Semgrep follow-up 1).
//!
//! Measured on 4 October 2026 (`docs/SEMGREP-FALSE-ALARMS.md`), 315 of 555 false alarms over 25 apps
//! were in such copies, and none of the true findings. A copy is the library's code, not the app's:
//! the fix for a problem in it is a newer copy, or loading it from its package, never an edit. So its
//! findings are listed apart from the app's own, named for the library, and still counted, as test
//! code's are.
//!
//! A copy is known the way retire.js knows one, by the library's own file: a string only that
//! library writes, or the comment a built library opens with, naming itself and its version
//! (`/*! jQuery v3.6.1 | (c) OpenJS Foundation …`). Not by long lines alone, which the app's own
//! built code has too, and not by the file's name, which says nothing about what is in it.

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use crate::Finding;

/// How much of a file is read to know it: the comment a library opens with is at the very start,
/// and the strings below are in its first lines. Only there: an app's own built bundle can hold a
/// whole library further down, and the app's code in it is still the app's.
const READ: usize = 2 * 1024;

/// Where the strings only a library writes must be: in its first lines, where every library in
/// `KNOWN` puts them (Underscore's `define('underscore', …)` is the furthest in, at about 150
/// characters), and not deeper, where an app's own bundle may hold the library after its own code.
const KNOWN_WITHIN: usize = 512;

/// Libraries that are often kept in an app, by a string only each writes, with its version when
/// the string carries one.
static KNOWN: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("jQuery", r"jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)"),
        ("Bootstrap", r"Bootstrap v(\d+\.\d+\.\d+)"),
        (
            "Moment.js",
            r"//! moment\.js(?:\s*//! version : (\d+\.\d+\.\d+))?",
        ),
        ("Underscore.js", r#"define\(\s*['"]underscore['"]"#),
        ("Lodash", r"@license\s+Lodash|lodash\.com/license"),
        ("React", r"@license React\b"),
        ("Vue.js", r"Vue\.js v(\d+\.\d+\.\d+)"),
        ("AngularJS", r"@license AngularJS v(\d+\.\d+\.\d+)"),
        ("D3", r"https://d3js\.org v(\d+\.\d+\.\d+)"),
        ("Chart.js", r"Chart\.js v(\d+\.\d+\.\d+)"),
        ("Popper", r"@popperjs/core v(\d+\.\d+\.\d+)"),
        ("DOMPurify", r"@license DOMPurify (\d+\.\d+\.\d+)"),
        (
            "three.js",
            r"@license\s+Copyright 2010-\d{4} Three\.js Authors",
        ),
    ]
    .into_iter()
    .map(|(name, p)| (name, Regex::new(p).expect("static pattern")))
    .collect()
});

/// The library a file is a copy of, and its version when it says: from a string only that library
/// writes, or from the comment the file opens with (`library_banner`). `None` for anything else,
/// which is what an app's own code is.
pub fn library_in(text: &str) -> Option<String> {
    let head = &text[..floor_char_boundary(text, READ)];
    let start = &text[..floor_char_boundary(text, KNOWN_WITHIN)];
    for (name, pattern) in KNOWN.iter() {
        if let Some(found) = pattern.captures(start) {
            return Some(match found.get(1) {
                Some(version) => format!("{name} {}", version.as_str()),
                None => (*name).to_owned(),
            });
        }
    }
    library_banner(head)
}

/// The comment a file opens with, when it names a version as a built library's does:
/// `/*! Name v1.2.3 …`, `/** name v1.2.3 - …`, or a `/*!`, `@license`, or `@preserve` comment with a
/// version in it. A version without a `v` counts only in a comment marked as a library's, and only
/// with three parts, so a license's own (`Apache License, Version 2.0`) is not taken for one.
fn library_banner(text: &str) -> Option<String> {
    static VERSION: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?:^|[^\w.])(v?)(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)(?:[^\w.]|$)")
            .expect("static pattern")
    });
    static THREE_PARTS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\d+\.\d+\.\d+").expect("static pattern"));
    static LEADING: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[\s/*!]*(?:@license|@preserve)?\s*").expect("static pattern")
    });
    let text = text.trim_start_matches(['\u{feff}', ' ', '\t', '\r', '\n']);
    let comment = text.strip_prefix("/*")?;
    let comment = &text[..2 + comment.find("*/")? + 2];
    let marked =
        comment.starts_with("/*!") || comment.contains("@license") || comment.contains("@preserve");
    for found in VERSION.captures_iter(comment) {
        let (Some(v), Some(version)) = (found.get(1), found.get(2)) else {
            continue;
        };
        let line = comment[..v.start()].lines().last().unwrap_or("");
        if v.as_str().is_empty() && (!marked || !THREE_PARTS.is_match(version.as_str())) {
            continue;
        }
        let name = LEADING
            .replace(line, "")
            .trim_matches(|c: char| c.is_whitespace() || matches!(c, '-' | ':' | '|' | ','))
            .to_owned();
        if name.is_empty() || name.chars().count() > 60 {
            continue;
        }
        return Some(format!("{name} {}", version.as_str()));
    }
    None
}

/// The largest index no greater than `at` that falls between two characters of `text`.
fn floor_char_boundary(text: &str, at: usize) -> usize {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    at
}

/// Whether a file is one a library could be copied in as: a script or a style sheet.
fn could_be_a_copy(relative: &str) -> bool {
    let name = relative
        .rsplit('/')
        .next()
        .unwrap_or(relative)
        .to_lowercase();
    [".js", ".mjs", ".cjs", ".css"]
        .iter()
        .any(|ext| name.ends_with(ext))
}

/// Names the library each finding's file is a copy of, so the reports list it apart. Each file is
/// read once, its first 2 KB.
pub fn mark_bundled_libraries(app_dir: &Path, findings: &mut [Finding]) {
    let mut read: HashMap<String, Option<String>> = HashMap::new();
    for f in findings {
        if !could_be_a_copy(&f.location.file) {
            continue;
        }
        let library = read.entry(f.location.file.clone()).or_insert_with(|| {
            let mut head = Vec::with_capacity(READ);
            std::fs::File::open(app_dir.join(&f.location.file))
                .ok()
                .and_then(|file| {
                    use std::io::Read;
                    file.take(READ as u64).read_to_end(&mut head).ok()
                })
                .and_then(|_| library_in(&String::from_utf8_lossy(&head)))
        });
        f.bundled_library.clone_from(library);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_library_is_known_by_its_own_banner_or_a_string_only_it_writes() {
        for (text, expected) in [
            // jQuery's, both as Debian and the jQuery site ship it.
            (
                "/*! jQuery v3.6.1 | (c) OpenJS Foundation and other contributors | jquery.org/license */\n!function(e,t){}",
                "jQuery 3.6.1",
            ),
            (
                "/*!\n * jQuery JavaScript Library v3.6.1\n * https://jquery.com/\n */\n(function(){})",
                "jQuery 3.6.1",
            ),
            // React names itself and no version.
            (
                "/**\n * @license React\n * react-dom.development.js\n */\n'use strict';",
                "React",
            ),
            // Underscore's build opens with no comment at all.
            (
                "(function (global, factory) {\n  typeof define === 'function' && define.amd ? define('underscore', factory) : 0;\n})",
                "Underscore.js",
            ),
            // Any library whose build opens with its name and version.
            (
                "/**\n * marked v18.0.13 - a markdown parser\n * Copyright (c) 2018-2026, MarkedJS. (MIT License)\n */\n(function(g,f){})",
                "marked 18.0.13",
            ),
            (
                "/** @license URI.js v4.4.1 (c) 2011 Gary Court. License: http://github.com/garycourt/uri-js */\n!function(e,r){}",
                "URI.js 4.4.1",
            ),
            (
                "/*!\n * FullCalendar 3.10.2\n * Docs & License: https://fullcalendar.io/\n */\n",
                "FullCalendar 3.10.2",
            ),
        ] {
            assert_eq!(library_in(text).as_deref(), Some(expected), "{text}");
        }
    }

    #[test]
    fn the_app_s_own_code_and_a_license_alone_are_not_a_library() {
        for text in [
            // An app's own script, with and without a comment.
            "// The booking page's date picker.\nexport function pick(d) { return d; }\n",
            "/* Booking app, version 2 of the form. */\nconst x = 1;\n",
            // A comment with a version that is not a library's: no `v`, and not marked as one.
            "/**\n * Upgraded to 1.2.3 of the API.\n */\nfetch('/api');\n",
            // A license's own version names no library: RxJS's build opens with the Apache license.
            "/**\n @license\n Apache License\n Version 2.0, January 2004\n */\n(function(){})",
            // The library's name in the app's own text is not the library.
            "// Uses jQuery from the CDN.\n$(function () {});\n",
        ] {
            assert_eq!(library_in(text), None, "{text}");
        }
        // The app's own built bundle, with a whole library further down: its code is still the app's.
        let bundle = format!(
            "// The booking app, built.\n{}\n/*! jQuery v3.6.1 | (c) OpenJS Foundation */\n/*! FullCalendar v3.10.2 */\n",
            "export function book(d) { return d; }\n".repeat(30)
        );
        assert!(bundle.len() < READ, "the library is within what is read");
        assert_eq!(library_in(&bundle), None, "{bundle}");
    }

    #[test]
    fn only_scripts_and_style_sheets_are_looked_at_and_each_is_named_from_its_own_file() {
        let dir = std::env::temp_dir().join(format!("sv-bundled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("public/js")).unwrap();
        let banner = "/*! jQuery v3.6.1 | (c) OpenJS Foundation */\n";
        std::fs::write(
            dir.join("public/js/jquery.min.js"),
            format!("{banner}eval(x);\n"),
        )
        .unwrap();
        std::fs::write(dir.join("public/js/app.js"), "eval(x);\n").unwrap();
        // The same banner in a file that is not a script is not a copy of the library.
        std::fs::write(dir.join("notes.md"), format!("{banner}eval(x);\n")).unwrap();
        let finding = |file: &str| Finding {
            rule_id: "ast.dynamic-code-execution".into(),
            title: String::new(),
            severity: crate::Severity::High,
            confidence: crate::Confidence::Medium,
            location: crate::Location {
                file: file.into(),
                line: 2,
            },
            secret: None,
            requirement_ids: Vec::new(),
            cwe: Vec::new(),
            description: String::new(),
            impact: String::new(),
            fix: String::new(),
            also_reported_by: Vec::new(),
            fingerprint: String::new(),
            earlier_fingerprints: Vec::new(),
            marked_test_code: false,
            bundled_library: None,
            outranked: None,
            also_on_this_line: Vec::new(),
        };
        let mut findings = vec![
            finding("public/js/jquery.min.js"),
            finding("public/js/app.js"),
            finding("notes.md"),
        ];
        mark_bundled_libraries(&dir, &mut findings);
        std::fs::remove_dir_all(&dir).ok();
        let named: Vec<Option<&str>> = findings
            .iter()
            .map(|f| f.bundled_library.as_deref())
            .collect();
        assert_eq!(named, [Some("jQuery 3.6.1"), None, None]);
        assert!(findings[0].apart() && !findings[1].apart() && !findings[2].apart());
    }
}
