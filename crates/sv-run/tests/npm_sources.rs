//! The install step downloads only from the npm registry, and is given only the app's own dependency
//! files (the review of 8 October 2026, item 2). `npm ci` fetches each package from the address its
//! lockfile names, in the one container of `sv`'s that can reach the internet; a lockfile is a file
//! anyone can edit, so a package from a server of someone else's, or with no fingerprint for npm to
//! check, is refused before anything runs. So is a dependency file that is a link, which would
//! otherwise be followed to wherever it points.

use std::path::{Path, PathBuf};
use sv_run::install::{NPM_REGISTRY, not_from_the_registry, plan};

const NODE: &str = "node:22-alpine";

/// A lockfile of version 3 with the packages given, each `(path, entry)`.
fn lock_v3(packages: &[(&str, serde_json::Value)]) -> String {
    let mut all = serde_json::Map::new();
    all.insert(
        String::new(),
        serde_json::json!({ "name": "app", "version": "1.0.0" }),
    );
    for (path, entry) in packages {
        all.insert((*path).to_owned(), entry.clone());
    }
    serde_json::json!({ "name": "app", "lockfileVersion": 3, "packages": all }).to_string()
}

fn from_registry(name: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "1.0.0",
        "resolved": format!("{NPM_REGISTRY}{name}/-/{name}-1.0.0.tgz"),
        "integrity": "sha512-AAAA",
    })
}

fn app(tag: &str, lock: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-npm-sources-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"app","version":"1.0.0"}"#,
    )
    .unwrap();
    std::fs::write(dir.join("package-lock.json"), lock).unwrap();
    dir
}

#[test]
fn a_lockfile_whose_packages_all_come_from_the_registry_is_installed() {
    let lock = lock_v3(&[
        ("node_modules/express", from_registry("express")),
        (
            "node_modules/express/node_modules/debug",
            from_registry("debug"),
        ),
        // Bundled inside another package's download: nothing of its own to fetch.
        (
            "node_modules/npm/node_modules/abbrev",
            serde_json::json!({ "version": "1.0.0", "inBundle": true }),
        ),
    ]);
    assert_eq!(not_from_the_registry(&lock).unwrap(), Vec::<String>::new());
    let dir = app("clean", &lock);
    let planned = plan(&dir, NODE);
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(planned.unwrap().len(), 1);
}

#[test]
fn a_package_from_anywhere_else_or_without_a_fingerprint_is_refused_and_named() {
    #[rustfmt::skip]
    let cases: &[(&str, serde_json::Value, &str)] = &[
        ("evil", serde_json::json!({ "version": "1.0.0", "resolved": "https://example.com/evil-1.0.0.tgz", "integrity": "sha512-AAAA" }), "evil (from https://example.com/evil-1.0.0.tgz)"),
        // A look-alike: the registry's name as the start of another host.
        ("twin", serde_json::json!({ "version": "1.0.0", "resolved": "https://registry.npmjs.org.example.com/twin/-/twin-1.0.0.tgz", "integrity": "sha512-AAAA" }), "twin (from https://registry.npmjs.org.example.com/"),
        ("plain", serde_json::json!({ "version": "1.0.0", "resolved": "http://registry.npmjs.org/plain/-/plain-1.0.0.tgz", "integrity": "sha512-AAAA" }), "plain (from http://registry.npmjs.org/"),
        ("gitdep", serde_json::json!({ "version": "1.0.0", "resolved": "git+ssh://git@github.com/someone/gitdep.git#abc" }), "gitdep (from git+ssh://"),
        ("nowhere", serde_json::json!({ "version": "1.0.0" }), "nowhere (no download address)"),
        ("unchecked", serde_json::json!({ "version": "1.0.0", "resolved": format!("{NPM_REGISTRY}unchecked/-/unchecked-1.0.0.tgz") }), "unchecked (no integrity fingerprint)"),
        ("weak", serde_json::json!({ "version": "1.0.0", "resolved": format!("{NPM_REGISTRY}weak/-/weak-1.0.0.tgz"), "integrity": "sha1-AAAA" }), "weak (no integrity fingerprint)"),
        ("local", serde_json::json!({ "resolved": "packages/local", "link": true }), "local (a folder on this computer)"),
    ];
    for (name, entry, said) in cases {
        let lock = lock_v3(&[
            ("node_modules/express", from_registry("express")),
            (&format!("node_modules/{name}"), entry.clone()),
        ]);
        let found = not_from_the_registry(&lock).unwrap();
        assert!(
            found.len() == 1 && found[0].starts_with(said),
            "{name}: {found:?}"
        );
        let dir = app(name, &lock);
        let refused = plan(&dir, NODE).unwrap_err();
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            refused.contains(NPM_REGISTRY) && refused.contains(&format!("`{said}")),
            "{name}: {refused}"
        );
    }
}

#[test]
fn a_lockfile_of_version_1_is_read_through_its_nested_dependencies() {
    let lock = serde_json::json!({
        "name": "app", "lockfileVersion": 1,
        "dependencies": {
            "express": {
                "version": "4.0.0",
                "resolved": format!("{NPM_REGISTRY}express/-/express-4.0.0.tgz"),
                "integrity": "sha512-AAAA",
                "dependencies": {
                    "deep": { "version": "1.0.0", "resolved": "https://example.com/deep.tgz", "integrity": "sha512-AAAA" }
                }
            }
        }
    })
    .to_string();
    assert_eq!(
        not_from_the_registry(&lock).unwrap(),
        ["deep (from https://example.com/deep.tgz)"]
    );
}

#[test]
fn a_lockfile_sv_cannot_read_is_refused_rather_than_taken_as_clean() {
    for text in ["not json", r#"{"name":"app","lockfileVersion":3}"#] {
        assert!(not_from_the_registry(text).is_err(), "{text}");
        let dir = app("unreadable", text);
        let refused = plan(&dir, NODE);
        std::fs::remove_dir_all(&dir).ok();
        assert!(refused.is_err(), "{text}");
    }
}

#[cfg(unix)]
#[test]
fn a_dependency_file_that_is_a_link_is_refused_before_it_is_read() {
    let lock = lock_v3(&[("node_modules/express", from_registry("express"))]);
    for (name, image, ok_text) in [
        ("package-lock.json", NODE, lock.as_str()),
        ("package.json", NODE, r#"{"name":"app"}"#),
        ("requirements.txt", "python:3.12-slim", "six==1.16.0\n"),
    ] {
        let dir = std::env::temp_dir().join(format!(
            "sv-npm-sources-link-{}-{}",
            name.replace('.', "-"),
            std::process::id()
        ));
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        let elsewhere = dir.with_extension("elsewhere");
        std::fs::write(&elsewhere, ok_text).unwrap();
        if name != "requirements.txt" {
            for other in ["package.json", "package-lock.json"] {
                if other != name {
                    let text = if other == "package.json" {
                        r#"{"name":"app"}"#
                    } else {
                        lock.as_str()
                    };
                    std::fs::write(dir.join(other), text).unwrap();
                }
            }
        }
        std::os::unix::fs::symlink(&elsewhere, dir.join(name)).unwrap();
        // The setup: the link is real and reads as a good file, so only the link is refused.
        assert_eq!(
            std::fs::read_to_string(dir.join(name)).unwrap(),
            ok_text,
            "{name}"
        );
        let refused = plan(&dir, image);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&elsewhere).ok();
        let refused = refused.unwrap_err();
        assert!(
            refused.contains(&format!("{name} is a link")),
            "{name}: {refused}"
        );
    }
    // And the same files, not links, are installed: the refusal is the link's, not the files'.
    let dir = app("not-a-link", &lock);
    let planned = plan(Path::new(&dir), NODE);
    std::fs::remove_dir_all(&dir).ok();
    assert!(planned.is_ok(), "{planned:?}");
}
