//! V3.7.1: client-side technology that is no longer supported, in the app's code (ADR-070).
//!
//! V3.7.1 asks that the app uses only client-side technology that is still supported. Two kinds are
//! looked for: the retired browser plug-ins it names (Flash, Shockwave, Silverlight, Java applets,
//! ActiveX controls, VBScript), whose traces in a page or among the app's files are unmistakable;
//! and front-end libraries whose makers have ended support, among the packages the bill of
//! materials lists and in an address that loads one from a CDN with its version. Only ever a
//! finding: no list of what a page loads is complete, so finding none shows nothing.

use crate::config::ConfigReport;
use crate::finding::{Confidence, Finding, Location, Severity};
use crate::sbom::Sbom;
use regex::Regex;
use std::sync::LazyLock;
use sv_scan::files::Listing;

pub const CLIENT_TECH: &str = "config.client-tech-unsupported";

/// Front-end libraries whose makers no longer support a major version: the npm package, the
/// highest unsupported major version, the library's name in words, and when support ended, as a
/// sentence. Read
/// from endoflife.date on 9 October 2026 (ADR-070); a library or a date is added here, not in the
/// rule.
const ENDED: &[(&str, u64, &str, &str)] = &[
    (
        "angular",
        u64::MAX,
        "AngularJS",
        "Its makers ended support on 31 December 2021",
    ),
    (
        "vue",
        2,
        "Vue 2 or older",
        "Its makers ended support for Vue 2 on 31 December 2023",
    ),
    (
        "bootstrap",
        4,
        "Bootstrap 4 or older",
        "Its makers ended support for Bootstrap 4 on 1 January 2023, and for Bootstrap 3 on 24 July 2019",
    ),
    (
        "jquery",
        2,
        "jQuery 1 or 2",
        "Its makers support only jQuery 3 and 4",
    ),
];

/// A library loaded from a CDN with its version in the address: `code.jquery.com/jquery-1.12.4.js`,
/// `cdnjs…/ajax/libs/angular.js/1.8.2/…`, `cdn.jsdelivr.net/npm/vue@2.7.16`,
/// `…bootstrapcdn.com/bootstrap/3.4.1/…`. The name must follow `/`, `@` or `-` directly, so
/// `myvue@2` is not Vue, and be followed by its version, so `@angular/core@18` (Angular, still
/// supported) is not AngularJS.
static FROM_CDN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)https?://[^\s"'<>()]*?[/@-](angularjs|angular\.js|angular|vue|bootstrap|jquery)[@/-]v?(\d+)\.\d+"#,
    )
    .expect("a fixed pattern")
});

/// Retired plug-ins in a page or a template, each with what it is in words.
static PLUG_INS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    [
        (r"(?i)<applet\b", "a Java applet"),
        (
            r#"(?i)<object\b[^>]*\bclassid\s*=\s*["']?clsid:"#,
            "an ActiveX control",
        ),
        (r"(?i)application/x-shockwave-flash", "a Flash object"),
        (
            r#"(?i)<embed\b[^>]*\bsrc\s*=\s*["']?[^"'\s>]+\.swf\b"#,
            "a Flash object",
        ),
        (r"(?i)application/x-silverlight", "a Silverlight object"),
        (r#"(?i)\blanguage\s*=\s*["']?vbscript\b"#, "VBScript"),
    ]
    .into_iter()
    .map(|(p, what)| (Regex::new(p).expect("a fixed pattern"), what))
    .collect()
});

/// The files a page, a template, or a component is written in.
fn holds_markup(extension: Option<&str>) -> bool {
    matches!(
        extension,
        Some(
            "html"
                | "htm"
                | "xhtml"
                | "vue"
                | "svelte"
                | "jsx"
                | "tsx"
                | "js"
                | "ts"
                | "erb"
                | "ejs"
                | "hbs"
                | "handlebars"
                | "njk"
                | "jinja"
                | "jinja2"
                | "j2"
                | "twig"
                | "php"
                | "cshtml"
                | "razor"
                | "jsp"
                | "aspx"
                | "mustache"
                | "liquid"
        )
    )
}

/// The major version a version or a range starts with: `^2.6.14` is 2, `1.12.4` is 1.
fn major(version: &str) -> Option<u64> {
    let digits: String = version
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse().ok()
}

/// The entry for a library, when this major version of it is past its end of life.
fn ended(
    package: &str,
    version_major: u64,
) -> Option<&'static (&'static str, u64, &'static str, &'static str)> {
    let package = match package.to_ascii_lowercase().as_str() {
        "angularjs" | "angular.js" => "angular".to_owned(),
        other => other.to_owned(),
    };
    ENDED
        .iter()
        .find(|(name, last, _, _)| *name == package && version_major <= *last)
}

pub fn check(listing: &Listing, sbom: &Sbom, report: &mut ConfigReport) {
    let mut seen = std::collections::BTreeSet::new();
    for component in sbom.components.iter().filter(|c| c.ecosystem == "npm") {
        let Some(m) = major(&component.version) else {
            continue;
        };
        if let Some(entry) = ended(&component.name, m)
            && seen.insert(entry.2)
        {
            report.findings.push(library_finding(
                crate::rich_text::where_named(listing, &format!("\"{}\"", component.name)),
                entry,
                &format!("`{}` {}", component.name, component.version),
            ));
        }
    }
    // What a `package.json` asks for, for an app with no lockfile to read, or a library the
    // lockfile does not list: the version asked for, which may be a range, by its first number.
    for entry in listing
        .app_files()
        .filter(|f| f.file_name() == "package.json")
    {
        let Some(manifest) = entry
            .read_text()
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        else {
            continue;
        };
        for table in ["dependencies", "devDependencies", "peerDependencies"] {
            let Some(listed) = manifest.get(table).and_then(serde_json::Value::as_object) else {
                continue;
            };
            for (name, asked) in listed {
                let Some(m) = asked.as_str().and_then(major) else {
                    continue;
                };
                if let Some(library) = ended(name, m)
                    && seen.insert(library.2)
                {
                    report.findings.push(library_finding(
                        crate::rich_text::where_named(listing, &format!("\"{name}\"")),
                        library,
                        &format!(
                            "`{name}` {} (as `{}` asks for it)",
                            asked.as_str().unwrap_or(""),
                            entry.relative
                        ),
                    ));
                }
            }
        }
    }
    for entry in listing.app_files() {
        let extension = entry.extension.as_deref();
        if matches!(extension, Some("swf" | "xap")) {
            report.findings.push(plug_in_finding(
                Location {
                    file: entry.relative.clone(),
                    line: 1,
                },
                if extension == Some("swf") {
                    "a Flash file"
                } else {
                    "a Silverlight file"
                },
            ));
            continue;
        }
        if !holds_markup(extension) {
            continue;
        }
        let Ok(text) = entry.read_text() else {
            continue;
        };
        let line_of = |at: usize| text[..at].matches('\n').count() + 1;
        for (pattern, what) in PLUG_INS.iter() {
            if let Some(found) = pattern.find(&text) {
                report.findings.push(plug_in_finding(
                    Location {
                        file: entry.relative.clone(),
                        line: line_of(found.start()),
                    },
                    what,
                ));
            }
        }
        for found in FROM_CDN.captures_iter(&text) {
            let Some(m) = found[2].parse::<u64>().ok() else {
                continue;
            };
            if let Some(library) = ended(&found[1], m)
                && seen.insert(library.2)
            {
                let whole = found.get(0).expect("the whole match");
                report.findings.push(library_finding(
                    Location {
                        file: entry.relative.clone(),
                        line: line_of(whole.start()),
                    },
                    library,
                    &format!("`{}`", whole.as_str()),
                ));
            }
        }
    }
}

#[track_caller]
fn library_finding(
    location: Location,
    (_, _, name, when): &(&str, u64, &str, &str),
    what: &str,
) -> Finding {
    crate::finding::found(Finding {
        evidence: Vec::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: "config.client-tech-unsupported".into(),
        title: "The app's pages use client-side technology that is no longer supported".into(),
        severity: Severity::Medium,
        confidence: Confidence::Medium,
        location,
        secret: None,
        requirement_ids: vec!["V3.7.1".into()],
        cwe: vec!["CWE-1104".into()],
        description: format!(
            "The app loads {what}, which is {name}. {when} (endoflife.date), so a security fault \
             found in it now is not fixed."
        ),
        impact:
            "A fault found in an unsupported library stays open for good, in every browser that \
                 loads the app's pages, and the people who find such faults look first at the \
                 libraries nobody is fixing any more."
                .into(),
        fix: "Move to a supported version, or to a supported library that does the same job: \
              Angular or another current framework in place of AngularJS, Vue 3, Bootstrap 5, \
              jQuery 3 or 4 (or none: most of what it did, browsers now do themselves)."
            .into(),
    })
}

#[track_caller]
fn plug_in_finding(location: Location, what: &str) -> Finding {
    crate::finding::found(Finding {
        evidence: Vec::new(),
        also_reported_by: Vec::new(),
        fingerprint: String::new(),
        earlier_fingerprints: Vec::new(),
        marked_test_code: false,
        bundled_library: None,
        outranked: None,
        also_on_this_line: Vec::new(),
        rule_id: CLIENT_TECH.into(),
        title: "The app's pages use client-side technology that is no longer supported".into(),
        severity: Severity::Medium,
        confidence: Confidence::High,
        location,
        secret: None,
        requirement_ids: vec!["V3.7.1".into()],
        cwe: vec!["CWE-1104".into()],
        description: format!(
            "The app's pages use {what}, a browser plug-in technology that no current browser runs \
             and whose makers have ended it."
        ),
        impact: "Nobody can use that part of the page in a current browser, and anyone who keeps an \
                 old browser or plug-in to reach it carries faults that will never be fixed."
            .into(),
        fix: "Replace it with what browsers do natively: HTML, CSS and JavaScript (video, canvas, \
              WebAssembly) in place of Flash, Silverlight, Java applets and ActiveX, and JavaScript \
              in place of VBScript."
            .into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sv-client-tech-{name}-{}", std::process::id()));
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

    fn hits(report: &ConfigReport) -> Vec<(String, usize, String)> {
        let mut out: Vec<(String, usize, String)> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == CLIENT_TECH)
            .map(|f| {
                (
                    f.location.file.clone(),
                    f.location.line,
                    f.description.clone(),
                )
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn libraries_past_their_end_of_life_and_retired_plug_ins_are_found() {
        // ADR-070, V3.7.1. From the packages, each library at its last unsupported version.
        let dir = scratch("old");
        fs::write(
            dir.join("package.json"),
            r#"{"name": "x", "dependencies": {"angular": "^1.8.3", "vue": "^2.7.16"}}"#,
        )
        .unwrap();
        fs::create_dir_all(dir.join("templates")).unwrap();
        fs::write(
            dir.join("templates/base.html"),
            "<html><head>\n\
             <link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css\">\n\
             <script src=\"https://code.jquery.com/jquery-1.12.4.min.js\"></script>\n\
             </head><body>\n\
             <object type=\"application/x-shockwave-flash\" data=\"game.swf\"></object>\n\
             <applet code=\"Clock.class\"></applet>\n\
             <script language=\"vbscript\">MsgBox \"hi\"</script>\n\
             </body></html>\n",
        )
        .unwrap();
        fs::create_dir_all(dir.join("static")).unwrap();
        fs::write(dir.join("static/banner.xap"), b"PK").unwrap();
        let report = run(&dir);
        let found = hits(&report);
        let said = |file: &str, line: usize, words: &str| {
            found
                .iter()
                .any(|(f, l, d)| f == file && *l == line && d.contains(words))
        };
        assert!(said("package.json", 1, "AngularJS"), "{found:#?}");
        assert!(said("package.json", 1, "Vue 2"), "{found:#?}");
        assert!(
            said("templates/base.html", 2, "Bootstrap 3 on 24 July 2019"),
            "{found:#?}"
        );
        assert!(
            said("templates/base.html", 3, "jQuery 1 or 2"),
            "{found:#?}"
        );
        assert!(
            said("templates/base.html", 5, "a Flash object"),
            "{found:#?}"
        );
        assert!(
            said("templates/base.html", 6, "a Java applet"),
            "{found:#?}"
        );
        assert!(said("templates/base.html", 7, "VBScript"), "{found:#?}");
        assert!(
            said("static/banner.xap", 1, "a Silverlight file"),
            "{found:#?}"
        );
        assert_eq!(found.len(), 8, "{found:#?}");
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.requirement_ids == ["V3.7.1"]),
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn a_version_only_the_lockfile_names_is_found_from_it() {
        // The manifest asks for any jQuery; what is installed, per the lockfile, is 2.2.4.
        let dir = scratch("locked");
        fs::write(
            dir.join("package.json"),
            r#"{"name": "x", "version": "1.0.0", "dependencies": {"jquery": "*"}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{"name": "x", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": {"": {"name": "x", "version": "1.0.0", "dependencies": {"jquery": "*"}}, "node_modules/jquery": {"version": "2.2.4", "resolved": "https://registry.npmjs.org/jquery/-/jquery-2.2.4.tgz"}}}"#,
        )
        .unwrap();
        let report = run(&dir);
        let found = hits(&report);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].2.contains("`jquery` 2.2.4"), "{found:#?}");
    }

    #[test]
    fn angularjs_is_found_under_each_name_a_cdn_gives_it() {
        for (n, address) in [
            "https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js",
            "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
            "https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js",
        ]
        .into_iter()
        .enumerate()
        {
            let dir = scratch(&format!("ng{n}"));
            fs::write(
                dir.join("index.html"),
                format!("<script src=\"{address}\"></script>\n"),
            )
            .unwrap();
            let found = hits(&run(&dir));
            assert!(
                found.len() == 1 && found[0].2.contains("AngularJS"),
                "{address}: {found:#?}"
            );
        }
    }

    #[test]
    fn supported_versions_and_look_alikes_are_left_alone_and_nothing_is_credited() {
        let dir = scratch("current");
        fs::write(
            dir.join("package.json"),
            r#"{"name": "x", "dependencies": {"@angular/core": "^18.0.0", "vue": "^3.5.0", "vue-router": "^2.0.0", "bootstrap": "5.3.8", "jquery": "3.7.1"}}"#,
        )
        .unwrap();
        fs::write(
            dir.join("index.html"),
            "<script src=\"https://cdn.jsdelivr.net/npm/@angular/core@18.1.0/bundles/core.umd.js\"></script>\n\
             <script src=\"https://unpkg.com/vue-router@3.6.5/dist/vue-router.js\"></script>\n\
             <script src=\"https://code.jquery.com/jquery-3.7.1.min.js\"></script>\n\
             <link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css\">\n\
             <script>try { new ActiveXObject('Msxml2.XMLHTTP') } catch (e) {}</script>\n\
             <script src=\"https://cdn.example.com/npm/myvue@2.1.0/x.js\"></script>\n\
             <script src=\"https://cdn.example.com/superjquery-1.0.2.js\"></script>\n",
        )
        .unwrap();
        let report = run(&dir);
        assert!(hits(&report).is_empty(), "{:#?}", report.findings);
        assert!(
            !report
                .passed
                .iter()
                .any(|v| v.check_id == CLIENT_TECH
                    || v.requirement_ids.iter().any(|q| q == "V3.7.1")),
            "{:?}",
            report.passed
        );
    }
}
