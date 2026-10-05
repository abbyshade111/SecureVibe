//! V1.3.1: a rich-text editor in the app, and no well-known HTML sanitizer anywhere in it.
//!
//! V1.3.1 asks that HTML from WYSIWYG editors is sanitized with a well-known library. Whether every
//! path an editor's HTML takes goes through one is not something files show, so this can only ever
//! show the requirement failing: an editor among the app's packages, and no sanitizer among its
//! packages or named in its code. Finding a sanitizer credits nothing; it may clean a different field.
//!
//! Frameworks whose rich text sanitizes itself (Rails' Action Text, Wagtail) are not counted as an
//! editor without a sanitizer. Editors that store a document as structured data rather than HTML
//! (Slate, Lexical, ProseMirror) are counted, because apps built on them commonly turn it into HTML to
//! store or show, and the finding says it matters only if they do.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use crate::sbom::Sbom;
use crate::verified::Verified;
use sv_scan::files::Listing;

pub const RICH_TEXT: &str = "config.rich-text-without-sanitizer";

/// Rich-text editor packages, as `(ecosystem, name)`. A name ending in `/` is a prefix: every package
/// in that scope.
const EDITORS: &[(&str, &str)] = &[
    ("npm", "quill"),
    ("npm", "react-quill"),
    ("npm", "react-quill-new"),
    ("npm", "ngx-quill"),
    ("npm", "vue-quill-editor"),
    ("npm", "@vueup/vue-quill"),
    ("npm", "tinymce"),
    ("npm", "@tinymce/"),
    ("npm", "ckeditor4"),
    ("npm", "ckeditor5"),
    ("npm", "@ckeditor/"),
    ("npm", "draft-js"),
    ("npm", "react-draft-wysiwyg"),
    ("npm", "slate"),
    ("npm", "slate-react"),
    ("npm", "@tiptap/"),
    ("npm", "prosemirror-view"),
    ("npm", "lexical"),
    ("npm", "@lexical/"),
    ("npm", "froala-editor"),
    ("npm", "react-froala-wysiwyg"),
    ("npm", "trix"),
    ("npm", "summernote"),
    ("npm", "medium-editor"),
    ("npm", "@editorjs/editorjs"),
    ("npm", "jodit"),
    ("npm", "jodit-react"),
    ("npm", "suneditor"),
    ("npm", "suneditor-react"),
    ("npm", "@toast-ui/editor"),
    ("npm", "react-simple-wysiwyg"),
    ("npm", "@blocknote/"),
    ("Python", "django-ckeditor"),
    ("Python", "django-ckeditor-5"),
    ("Python", "django-tinymce"),
    ("Python", "django-summernote"),
    ("Python", "django-quill-editor"),
    ("Python", "django-froala-editor"),
    ("Python", "flask-ckeditor"),
    ("Ruby", "ckeditor"),
    ("Ruby", "tinymce-rails"),
    ("Ruby", "trix-rails"),
    ("PHP", "ckeditor/ckeditor"),
    ("PHP", "tinymce/tinymce"),
    ("PHP", "froala/wysiwyg-editor"),
];

/// Well-known HTML sanitizers, and frameworks whose rich text is sanitized by the framework itself.
const SANITIZERS: &[(&str, &str)] = &[
    ("npm", "dompurify"),
    ("npm", "isomorphic-dompurify"),
    ("npm", "sanitize-html"),
    ("npm", "xss"),
    ("npm", "rehype-sanitize"),
    ("npm", "@jitbit/htmlsanitizer"),
    ("Python", "bleach"),
    ("Python", "nh3"),
    ("Python", "html-sanitizer"),
    ("Python", "django-bleach"),
    ("Python", "wagtail"),
    ("Ruby", "sanitize"),
    ("Ruby", "loofah"),
    ("Ruby", "rails-html-sanitizer"),
    ("Ruby", "actiontext"),
    ("PHP", "ezyang/htmlpurifier"),
    ("PHP", "mews/purifier"),
    ("PHP", "symfony/html-sanitizer"),
    ("PHP", "stevebauman/purify"),
    ("Go", "github.com/microcosm-cc/bluemonday"),
    ("Rust", "ammonia"),
];

/// A sanitizer named in the code, for one loaded from a page (`purify.min.js` from a CDN) or
/// vendored rather than installed as a package.
const SANITIZER_WORDS: &[&str] = &[
    "DOMPurify",
    "purify.min.js",
    "sanitizeHtml(",
    "bleach.clean(",
    "nh3.clean(",
    "HTMLPurifier",
    "HtmlSanitizer",
    "HtmlPolicyBuilder",
    "Jsoup.clean(",
    "bluemonday.",
    "ammonia::",
    "Sanitize.fragment(",
];

/// Python package names compare with `_`, `.`, and `-` alike and in any case.
fn same_name(ecosystem: &str, a: &str, b: &str) -> bool {
    if ecosystem == "Python" {
        let norm = |s: &str| s.to_lowercase().replace(['_', '.'], "-");
        norm(a) == norm(b)
    } else {
        a == b
    }
}

fn listed(list: &[(&str, &str)], ecosystem: &str, name: &str) -> bool {
    list.iter().any(|(e, n)| {
        *e == ecosystem
            && match n.strip_suffix('/') {
                Some(scope) => name.starts_with(&format!("{scope}/")),
                None => same_name(ecosystem, n, name),
            }
    })
}

/// The manifest line that names a package, for the finding's location.
fn where_named(listing: &Listing, name: &str) -> Location {
    const MANIFESTS: &[&str] = &[
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "Pipfile",
        "setup.py",
        "Gemfile",
        "composer.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Gemfile.lock",
        "composer.lock",
    ];
    for manifest in MANIFESTS {
        for entry in listing.app_files().filter(|f| f.file_name() == *manifest) {
            let Ok(text) = entry.read_text() else {
                continue;
            };
            if let Some(index) = text.lines().position(|l| l.contains(name)) {
                return Location {
                    file: entry.relative.clone(),
                    line: index + 1,
                };
            }
        }
    }
    Location {
        file: "package.json".into(),
        line: 1,
    }
}

/// The packages of the ecosystems the bill of materials could not read, by the names their manifests
/// declare, and the ecosystems whose manifest could not be read either, with the reason.
///
/// Found testing the prompt library (4 October 2026): an npm app with no lockfile, which is how an
/// AI tool leaves an app when nothing could be installed where it wrote it, has no packages in the
/// bill of materials, so `quill` with no sanitizer was reported as "0 packages: none is a rich-text
/// editor". This check needs which packages, not which versions, and the manifest says that.
fn declared_where_unread(listing: &Listing, sbom: &Sbom) -> (Vec<(String, String)>, Vec<String>) {
    let mut declared = Vec::new();
    let mut unreadable = Vec::new();
    if sbom.unread.is_empty() {
        return (declared, unreadable);
    }
    let detected = sv_scan::ecosystems::detect_in(listing);
    for (ecosystem, why) in &sbom.unread {
        let mut read_one = false;
        for eco in detected.iter().filter(|e| &e.name == ecosystem) {
            let names = std::fs::read_to_string(listing.root.join(&eco.manifest))
                .ok()
                .and_then(|text| {
                    crate::manifest_lock::declared_names(
                        sv_scan::ecosystems::file_name(&eco.manifest),
                        &text,
                    )
                });
            if let Some(names) = names {
                read_one = true;
                declared.extend(names.into_iter().map(|n| (ecosystem.clone(), n)));
            }
        }
        if !read_one {
            unreadable.push(format!("{ecosystem} ({why})"));
        }
    }
    (declared, unreadable)
}

pub fn check(listing: &Listing, sbom: &Sbom, report: &mut ConfigReport) {
    let (declared, unreadable) = declared_where_unread(listing, sbom);
    let packages: Vec<(&str, &str)> = sbom
        .components
        .iter()
        .map(|c| (c.ecosystem.as_str(), c.name.as_str()))
        .chain(declared.iter().map(|(e, n)| (e.as_str(), n.as_str())))
        .collect();
    let mut editors: Vec<&str> = packages
        .iter()
        .filter(|(ecosystem, name)| listed(EDITORS, ecosystem, name))
        .map(|(_, name)| *name)
        .collect();
    editors.sort();
    editors.dedup();
    let sanitizer = packages
        .iter()
        .find(|(ecosystem, name)| listed(SANITIZERS, ecosystem, name))
        .map(|(_, name)| format!("`{name}`"))
        .or_else(|| {
            listing
                .app_files()
                .filter(|f| {
                    f.language.is_some()
                        || matches!(
                            f.extension.as_deref(),
                            Some("html" | "htm" | "vue" | "svelte")
                        )
                })
                .find_map(|f| {
                    let text = f.read_text().ok()?;
                    SANITIZER_WORDS
                        .iter()
                        .find(|w| text.contains(*w))
                        .map(|w| format!("`{}` in `{}`", w.trim_end_matches('('), f.relative))
                })
        });
    let Some(first) = editors.first() else {
        // An editor may be in the part of the app `sv` could not read, so "none" is not said.
        if !unreadable.is_empty() {
            report.not_assessed.push((
                RICH_TEXT.to_owned(),
                format!(
                    "No rich-text editor among the packages `sv` read, but it could not read {}, \
                     where one may be.",
                    unreadable.join(", ")
                ),
            ));
            return;
        }
        let from_manifest = if declared.is_empty() {
            String::new()
        } else {
            format!(
                " ({} of them as the manifest declares them, with no lockfile to read)",
                declared.len()
            )
        };
        report.passed.push(Verified::new(
            RICH_TEXT,
            &[],
            format!(
                "{} packages{from_manifest}: none is a rich-text editor `sv` knows",
                packages.len()
            ),
        ));
        return;
    };
    if let Some(sanitizer) = sanitizer {
        report.passed.push(Verified::new(
            RICH_TEXT,
            &[],
            format!(
                "a rich-text editor ({}) and a sanitizer ({sanitizer}); whether the sanitizer cleans \
                 everything the editor sends is not something files show",
                editors.iter().map(|e| format!("`{e}`")).collect::<Vec<_>>().join(", ")
            ),
        ));
        return;
    }
    // A sanitizer may be in the part of the app `sv` could not read, so nothing is claimed either way.
    if !unreadable.is_empty() {
        report.not_assessed.push((
            RICH_TEXT.to_owned(),
            format!(
                "The app has a rich-text editor (`{first}`) and no sanitizer among the packages `sv` \
                 read, but it could not read {}, where one may be.",
                unreadable.join(", ")
            ),
        ));
        return;
    }
    report.findings.push(Finding {
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        rule_id: "config.rich-text-without-sanitizer".into(),
        title: "A rich-text editor is used and no HTML sanitizer is anywhere in the app".into(),
        severity: Severity::Medium,
        confidence: Confidence::Low,
        location: where_named(listing, first),
        secret: None,
        requirement_ids: vec!["V1.3.1".into()],
        cwe: vec!["CWE-79".into()],
        description: format!(
            "The app uses {} to let people write formatted text, and none of the well-known HTML \
             sanitizers (DOMPurify, sanitize-html, bleach, nh3, HTML Purifier, Loofah, bluemonday, \
             ammonia, and others) is among its packages or named in its code. If what the editor \
             produces is kept or shown as HTML, nothing cleans it.",
            editors.iter().map(|e| format!("`{e}`")).collect::<Vec<_>>().join(", ")
        ),
        impact: "Anyone who can type into the editor, or send the app the request the editor sends, \
                 can save a script instead of formatting. It then runs in the browser of everyone \
                 who views that text, signed in as themselves, which is how accounts are taken over."
            .into(),
        fix: "Clean the editor's HTML on the server, when it is saved, with a well-known sanitizer: \
              `sanitize-html` or `isomorphic-dompurify` for Node.js, `nh3` or `bleach` for Python, \
              `Loofah` or `sanitize` for Ruby, HTML Purifier for PHP. Cleaning only in the browser is \
              not enough, because the request can be sent without it. If the editor's output is \
              never used as HTML (it is stored and shown as the editor's own data), this does not \
              apply and can be set aside."
            .into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-rich-{name}-{}", std::process::id()));
        fs::remove_dir_all(&dir).ok();
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn run(dir: &std::path::Path) -> ConfigReport {
        let listing = Listing::of(dir);
        let sbom = crate::sbom::build_in(&listing);
        let mut report = ConfigReport::default();
        check(&listing, &sbom, &mut report);
        report
    }

    fn lock(dir: &std::path::Path, packages: &[&str]) {
        let deps: Vec<String> = packages
            .iter()
            .map(|p| format!("\"{p}\": \"1.0.0\""))
            .collect();
        let locked: Vec<String> = packages
            .iter()
            .map(|p| format!("\"node_modules/{p}\": {{\"version\": \"1.0.0\"}}"))
            .collect();
        fs::write(
            dir.join("package.json"),
            format!(
                "{{\"name\": \"app\",\n\"dependencies\": {{\n{}\n}}}}\n",
                deps.join(",\n")
            ),
        )
        .unwrap();
        fs::write(
            dir.join("package-lock.json"),
            format!(
                "{{\"lockfileVersion\": 3, \"packages\": {{\"\": {{}}, {}}}}}\n",
                locked.join(", ")
            ),
        )
        .unwrap();
    }

    fn findings(report: &ConfigReport) -> Vec<&Finding> {
        report
            .findings
            .iter()
            .filter(|f| f.rule_id == RICH_TEXT)
            .collect()
    }

    #[test]
    fn an_editor_with_no_sanitizer_is_found_and_one_with_a_sanitizer_is_not() {
        let dir = scratch("editor");
        lock(&dir, &["express", "@tiptap/react"]);
        let report = run(&dir);
        let hits = findings(&report);
        assert_eq!(
            hits.len(),
            1,
            "{:?} {:?}",
            report.findings,
            report.not_assessed
        );
        assert_eq!(hits[0].requirement_ids, ["V1.3.1"]);
        assert_eq!(
            (hits[0].location.file.as_str(), hits[0].location.line),
            ("package.json", 4)
        );
        assert!(
            hits[0].description.contains("`@tiptap/react`"),
            "{}",
            hits[0].description
        );

        // The control: the same app with a sanitizer package, and with one named only in the code.
        lock(&dir, &["express", "@tiptap/react", "sanitize-html"]);
        let with_package = run(&dir);
        assert!(
            findings(&with_package).is_empty(),
            "{:?}",
            with_package.findings
        );
        let passed = with_package
            .passed
            .iter()
            .find(|v| v.check_id == RICH_TEXT)
            .unwrap();
        assert!(
            passed.requirement_ids.is_empty(),
            "finding a sanitizer credits nothing"
        );
        assert!(passed.scope.contains("`sanitize-html`"), "{}", passed.scope);

        lock(&dir, &["express", "@tiptap/react"]);
        fs::write(
            dir.join("index.html"),
            "<script src=\"/vendor/purify.min.js\"></script>\n",
        )
        .unwrap();
        assert!(
            findings(&run(&dir)).is_empty(),
            "a sanitizer loaded from the page counts"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn no_editor_credits_nothing_and_an_unread_manifest_is_not_a_finding() {
        let dir = scratch("none");
        lock(&dir, &["express"]);
        let report = run(&dir);
        assert!(findings(&report).is_empty());
        assert!(
            report
                .passed
                .iter()
                .any(|v| v.check_id == RICH_TEXT && v.requirement_ids.is_empty())
        );

        // An editor, no sanitizer seen, and a Python half `sv` cannot read at all, neither its
        // lockfile nor its manifest: not a finding.
        lock(&dir, &["quill"]);
        fs::write(dir.join("pyproject.toml"), "this is not [[ toml\n").unwrap();
        fs::write(dir.join("poetry.lock"), "this is not a lockfile\n").unwrap();
        let report = run(&dir);
        assert!(findings(&report).is_empty(), "{:?}", report.findings);
        assert!(
            report
                .not_assessed
                .iter()
                .any(|(id, why)| id == RICH_TEXT && why.contains("`quill`")),
            "{:?}",
            report.not_assessed
        );
        fs::remove_dir_all(&dir).ok();
    }

    /// `package.json` alone, as an AI tool leaves an app when nothing could be installed.
    fn declare(dir: &std::path::Path, packages: &[&str]) {
        let deps: Vec<String> = packages
            .iter()
            .map(|p| format!("\"{p}\": \"^2.0.0\""))
            .collect();
        fs::write(
            dir.join("package.json"),
            format!(
                "{{\"name\": \"app\",\n\"dependencies\": {{\n{}\n}}}}\n",
                deps.join(",\n")
            ),
        )
        .unwrap();
        fs::remove_file(dir.join("package-lock.json")).ok();
    }

    #[test]
    fn with_no_lockfile_the_manifests_names_are_read() {
        let dir = scratch("declared");
        // The setup is what it says: no lockfile, so the bill of materials holds nothing.
        declare(&dir, &["express", "quill"]);
        let listing = Listing::of(&dir);
        let sbom = crate::sbom::build_in(&listing);
        assert!(sbom.components.is_empty(), "{:?}", sbom.components);
        assert!(!sbom.unread.is_empty());

        let report = run(&dir);
        let hits = findings(&report);
        assert_eq!(
            hits.len(),
            1,
            "{:?} {:?}",
            report.passed,
            report.not_assessed
        );
        assert!(
            hits[0].description.contains("`quill`"),
            "{}",
            hits[0].description
        );
        assert_eq!(hits[0].location.file, "package.json");

        // A declared sanitizer keeps it quiet, and credits nothing.
        declare(&dir, &["express", "quill", "sanitize-html"]);
        let report = run(&dir);
        assert!(findings(&report).is_empty(), "{:?}", report.findings);
        let passed = report
            .passed
            .iter()
            .find(|v| v.check_id == RICH_TEXT)
            .unwrap();
        assert!(passed.requirement_ids.is_empty());

        // No editor declared: said, and said to be from the manifest.
        declare(&dir, &["express"]);
        let report = run(&dir);
        let passed = report
            .passed
            .iter()
            .find(|v| v.check_id == RICH_TEXT)
            .unwrap();
        assert!(
            passed.scope.contains("as the manifest declares them"),
            "{}",
            passed.scope
        );

        // A manifest that cannot be read either: not "none is an editor", but not assessed.
        fs::write(dir.join("package.json"), "{ this is not json\n").unwrap();
        let report = run(&dir);
        assert!(
            !report.passed.iter().any(|v| v.check_id == RICH_TEXT),
            "{:?}",
            report.passed
        );
        assert!(
            report.not_assessed.iter().any(|(id, _)| id == RICH_TEXT),
            "{:?}",
            report.not_assessed
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn python_names_match_however_they_are_written() {
        assert!(listed(EDITORS, "Python", "Django_CKEditor"));
        assert!(listed(SANITIZERS, "Python", "NH3"));
        assert!(!listed(EDITORS, "npm", "@tiptapx/react"));
        assert!(listed(EDITORS, "npm", "@tiptap/starter-kit"));
        assert!(!listed(EDITORS, "npm", "quill-delta-to-html"));
    }
}
