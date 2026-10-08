//! The tests of `sbom.rs` that were `mod tests` inside it until 8 October 2026, moved out so
//! two sessions adding a test do not meet in one file (the architecture assessment of that day, item 11).

use super::*;
use std::fs;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sv-sbom-{name}-{}", std::process::id()));
    fs::remove_dir_all(&dir).ok();
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_locked_npm_app_lists_what_is_installed() {
    let dir = scratch("npm");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{"packages":{"":{"name":"app"},"node_modules/express":{"version":"4.18.2"}}}"#,
    )
    .unwrap();
    let sbom = build(&dir);
    assert_eq!(sbom.components.len(), 1);
    assert_eq!(sbom.components[0].name, "express");
    assert_eq!(sbom.components[0].version, "4.18.2");
    assert_eq!(sbom.components[0].source, VersionSource::Locked);
    assert_eq!(sbom.components[0].purl(), "pkg:npm/express@4.18.2");
    assert!(sbom.is_complete());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_npm_v1_lockfile_lists_the_copies_installed_under_other_packages() {
    // Lockfile v1 keeps a second version of a package under the one that needs it. That copy is
    // installed, and an advisory against it is about this app, so it is listed by its own name.
    let dir = scratch("npm-v1");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{"name":"app","lockfileVersion":1,"dependencies":{
                "express":{"version":"4.18.2","dependencies":{
                    "debug":{"version":"2.6.9","dependencies":{
                        "ms":{"version":"2.0.0"}}}}},
                "debug":{"version":"4.3.4"},
                "ms":{"version":"2.1.2"}}}"#,
    )
    .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(
        purls,
        vec![
            "pkg:npm/debug@2.6.9",
            "pkg:npm/debug@4.3.4",
            "pkg:npm/express@4.18.2",
            "pkg:npm/ms@2.0.0",
            "pkg:npm/ms@2.1.2",
        ],
        "{sbom:?}"
    );
    assert!(sbom.is_complete(), "{sbom:?}");
}

#[test]
fn a_range_is_not_a_version_and_the_document_says_so() {
    // requirements.txt with no lockfile: `flask>=2` tells nobody what is installed. Listing it as
    // though it were a version is the failure this whole module is arranged around.
    let dir = scratch("ranges");
    fs::write(dir.join("requirements.txt"), "flask>=2.0\ngunicorn\n").unwrap();
    let sbom = build(&dir);
    assert!(
        sbom.components.is_empty(),
        "a range must not become a component: {sbom:?}"
    );
    assert!(!sbom.is_complete());
    // Named, not only counted (deep review H9).
    assert!(
        sbom.unread
            .iter()
            .any(|(_, why)| why.contains("flask") && why.contains("gunicorn")),
        "{:?}",
        sbom.unread
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn what_a_requirements_file_installs_without_one_version_is_named() {
    // Deep review H9: beside `stripe==7.8.0`, each of these was left out of the list and not
    // named, so the list looked like everything the file asks for.
    let dir = scratch("requirements-named");
    fs::write(
        dir.join("requirements.txt"),
        "# what the app needs\n\
             stripe==7.8.0\n\
             flask>=2  # the web framework\n\
             gunicorn\n\
             requests==2.*\n\
             jinja2==3.1,<4\n\
             pillow==10.0.0 ; python_version > '3.8'\n\
             pkg @ https://example.com/pkg-1.0.whl\n\
             -e git+https://example.com/team/tool.git#egg=helper\n\
             --requirement=base.txt\n\
             -r extra.txt  # optional extras\n\
             pyyaml \\\n    >=6\n\
             -e .\n\
             -c constraints.txt\n\
             --index-url https://pypi.org/simple\n\
             numpy==1.26.0 \\\n    --hash=sha256:abc\n",
    )
    .unwrap();
    let sbom = build(&dir);
    let mut listed: Vec<(&str, &str)> = sbom
        .components
        .iter()
        .map(|c| (c.name.as_str(), c.version.as_str()))
        .collect();
    listed.sort();
    assert_eq!(
        listed,
        [
            ("numpy", "1.26.0"),
            ("pillow", "10.0.0"),
            ("stripe", "7.8.0")
        ]
    );
    let why = sbom
        .unread
        .iter()
        .map(|(_, why)| why.as_str())
        .find(|why| why.contains("requirements.txt"))
        .unwrap_or_else(|| panic!("{:?}", sbom.unread));
    for name in [
        "flask",
        "gunicorn",
        "requests",
        "jinja2",
        "pkg",
        "helper",
        "`base.txt`",
        "`extra.txt`",
        "pyyaml",
    ] {
        assert!(why.contains(name), "{name} is not named: {why}");
    }
    assert!(why.contains("9 of what it installs"), "{why}");
    for not in [
        "constraints",
        "pypi.org",
        "example.com",
        "the web framework",
        "optional",
        ">=6",
        "stripe",
    ] {
        assert!(!why.contains(not), "{not} is named: {why}");
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn exact_pins_are_read_and_marked_as_declared() {
    let dir = scratch("pins");
    fs::write(
        dir.join("requirements.txt"),
        "flask==3.0.0\nstripe==7.8.0\n",
    )
    .unwrap();
    let sbom = build(&dir);
    assert_eq!(sbom.components.len(), 2);
    assert!(
        sbom.components
            .iter()
            .all(|c| c.source == VersionSource::Declared)
    );
    // Declared is not complete: nothing has confirmed that is what is installed.
    assert!(!sbom.is_complete());
    assert_eq!(sbom.declared_count(), 2);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_caveats_travel_with_the_document() {
    // The terminal is not where an SBOM ends up. Someone receives this file and asks it a question.
    let dir = scratch("caveats");
    fs::write(dir.join("requirements.txt"), "flask==3.0.0\n").unwrap();
    let sbom = build(&dir);
    let json = serde_json::to_string(&to_cyclonedx(&sbom)).unwrap();
    assert!(json.contains("securevibe:complete"), "{json}");
    assert!(json.contains("\"value\":\"false\""), "{json}");
    assert!(json.contains("asked for"), "{json}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_complete_document_does_not_carry_a_warning_it_has_not_earned() {
    let dir = scratch("clean");
    fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
    fs::write(
        dir.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n",
    )
    .unwrap();
    let sbom = build(&dir);
    assert!(sbom.is_complete(), "{sbom:?}");
    assert!(incompleteness_finding(&sbom).is_none());
    assert_eq!(sbom.components[0].purl(), "pkg:cargo/serde@1.0.229");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn poetry_pdm_and_uv_share_cargos_shape() {
    for (manifest, lock) in [
        ("pyproject.toml", "poetry.lock"),
        ("pyproject.toml", "pdm.lock"),
        ("pyproject.toml", "uv.lock"),
    ] {
        let dir = scratch(&format!("toml-{lock}"));
        fs::write(dir.join(manifest), "[project]\nname='x'\n").unwrap();
        fs::write(
            dir.join(lock),
            "[[package]]\nname = \"flask\"\nversion = \"3.0.0\"\ndescription = \"web\"\n",
        )
        .unwrap();
        let sbom = build(&dir);
        assert_eq!(sbom.components.len(), 1, "{lock}: {sbom:?}");
        assert_eq!(sbom.components[0].purl(), "pkg:pypi/flask@3.0.0", "{lock}");
        assert!(sbom.is_complete(), "{lock} should be a complete read");
        fs::remove_dir_all(&dir).ok();
    }
}

/// A `pylock.toml` as pip writes it, cut down: each package's wheels carry a `name` that is a
/// file name, which must not be read as a package.
const PYLOCK: &str = r#"lock-version = "1.0"
created-by = "pip"
requires-python = ">=3.12"

[[packages]]
name = "flask"
version = "3.1.3"

[[packages.wheels]]
name = "flask-3.1.3-py3-none-any.whl"
url = "https://files.pythonhosted.org/flask-3.1.3-py3-none-any.whl"
hashes = { sha256 = "0000" }

[[packages]]
name = "werkzeug"
version = "3.1.9"

[[packages.wheels]]
name = "werkzeug-3.1.9-py3-none-any.whl"
hashes = { sha256 = "0000" }
"#;

#[test]
fn a_pylock_file_is_read_as_the_list_of_what_is_installed() {
    let dir = scratch("pylock-read");
    fs::write(dir.join("requirements.txt"), "flask>=3\n").unwrap();
    fs::write(dir.join("pylock.toml"), PYLOCK).unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(
        purls,
        vec!["pkg:pypi/flask@3.1.3", "pkg:pypi/werkzeug@3.1.9"],
        "{sbom:?}"
    );
    assert!(
        sbom.components
            .iter()
            .all(|c| c.source == VersionSource::Locked)
    );
    assert!(sbom.is_complete(), "{sbom:?}");
}

#[test]
fn a_pylock_package_with_no_version_leaves_the_list_incomplete_and_says_so() {
    let dir = scratch("pylock-unversioned");
    fs::write(dir.join("pyproject.toml"), "[project]\nname = \"demo\"\n").unwrap();
    fs::write(
            dir.join("pylock.toml"),
            format!(
                "{PYLOCK}\n[[packages]]\nname = \"local-tools\"\n\n[packages.directory]\npath = \"./tools\"\n"
            ),
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    assert_eq!(sbom.components.len(), 2, "{sbom:?}");
    assert!(!sbom.is_complete());
    assert!(
        sbom.unread
            .iter()
            .any(|(_, why)| why.contains("local-tools") && why.contains("the rest are")),
        "{:?}",
        sbom.unread
    );
}

#[test]
fn a_requirements_file_that_pins_and_hashes_everything_is_listed_as_installed() {
    // family-hub, reported on 3 October 2026: listed "at the version asked for rather than the
    // version installed", though pip installs exactly these.
    let dir = scratch("requirements-hashed-sbom");
    let hash = "ab".repeat(32);
    fs::write(
            dir.join("requirements.txt"),
            format!(
                "blinker==1.9.0 \\\n    --hash=sha256:{hash}\nflask[async]==3.1.3 \\\n    --hash=sha256:{hash}\n"
            ),
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(
        purls,
        vec!["pkg:pypi/blinker@1.9.0", "pkg:pypi/flask@3.1.3"],
        "{sbom:?}"
    );
    assert!(sbom.is_complete(), "{sbom:?}");
    assert!(incompleteness_finding(&sbom).is_none());
    assert!(sbom.disagreements.is_empty(), "{:?}", sbom.disagreements);
}

#[test]
fn a_requirements_lock_beside_pyproject_is_read_hashes_and_markers_included() {
    // What `uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock`
    // writes: a continuation backslash, `--hash` lines, `# via` comments, and a marker line, here
    // written both with and without the space before its `;`.
    let dir = scratch("pyproject-requirements-lock");
    fs::write(
        dir.join("pyproject.toml"),
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\ndependencies = [\"PyYAML>=6.0\"]\n",
    )
    .unwrap();
    fs::write(
            dir.join("requirements.lock"),
            "# This file was autogenerated by uv via the following command:\n\
             #    uv pip compile pyproject.toml --universal --generate-hashes -o requirements.lock\n\
             colorama==0.4.6 ; sys_platform == 'win32' \\\n    \
             --hash=sha256:08695f5cb7ed6e0531a20572697297273c47b8cae5a63ffc6d6ed5c201be6e44\n    \
             # via demo\n\
             pywin32==306;sys_platform=='win32'\n\
             pyyaml==6.0.2 \\\n    \
             --hash=sha256:0a9a2848a5b7feac301353437eb7d5957887edbf81d56e903999a75a3d743086\n    \
             # via demo\n",
        )
        .unwrap();
    let sbom = build(&dir);
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(
        purls,
        [
            "pkg:pypi/colorama@0.4.6",
            "pkg:pypi/pywin32@306",
            "pkg:pypi/pyyaml@6.0.2"
        ],
        "{sbom:?}"
    );
    assert!(sbom.is_complete(), "{sbom:?}");
    assert!(
        sbom.components
            .iter()
            .all(|c| c.source == VersionSource::Locked),
        "{sbom:?}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_manifest_that_disagrees_with_its_lockfile_is_named_in_the_document() {
    let dir = scratch("manifest-disagrees");
    fs::write(
        dir.join("requirements.txt"),
        "flask==3.0.0\npyjwt==2.13.0\n",
    )
    .unwrap();
    fs::write(
        dir.join("requirements.lock"),
        "flask==3.0.0\npyjwt==2.8.0\n",
    )
    .unwrap();
    fs::create_dir_all(dir.join("server")).unwrap();
    fs::write(
        dir.join("server/package.json"),
        r#"{"name":"web","dependencies":{"lodash":"^4.17.21","left-pad":"1.3.0"}}"#,
    )
    .unwrap();
    fs::write(
        dir.join("server/package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    )
    .unwrap();
    let sbom = build(&dir);
    // The list is still the lockfiles', and still complete.
    assert!(sbom.is_complete(), "{sbom:?}");
    assert!(
        sbom.components
            .iter()
            .any(|c| c.name == "pyjwt" && c.version == "2.8.0"),
        "{sbom:?}"
    );
    let said: Vec<(&str, &str, &str)> = sbom
        .disagreements
        .iter()
        .map(|d| (d.project.as_str(), d.manifest.as_str(), d.lockfile.as_str()))
        .collect();
    assert_eq!(
        said,
        vec![
            ("Python", "requirements.txt", "requirements.lock"),
            (
                "npm in server/",
                "server/package.json",
                "server/package-lock.json"
            ),
        ]
    );
    let doc = serde_json::to_value(to_cyclonedx(&sbom)).unwrap();
    let property = |name: &str| {
        doc["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["name"] == name)
            .and_then(|p| p["value"].as_str())
            .map(str::to_owned)
    };
    let python = property("securevibe:manifest-disagrees:Python")
        .unwrap_or_else(|| panic!("the document names it: {doc}"));
    assert!(
        python.contains("`pyjwt==2.13.0` (the lockfile has 2.8.0)")
            && python.contains("about 1 package:"),
        "{python}"
    );
    let npm = property("securevibe:manifest-disagrees:npm in server/").unwrap();
    assert!(
        npm.contains("`left-pad 1.3.0` (not in the lockfile)"),
        "{npm}"
    );

    // In step, nothing is said.
    fs::write(
        dir.join("requirements.lock"),
        "flask==3.0.0\npyjwt==2.13.0\n",
    )
    .unwrap();
    fs::write(
        dir.join("server/package.json"),
        r#"{"name":"web","dependencies":{"lodash":"^4.17.21"}}"#,
    )
    .unwrap();
    let in_step = build(&dir);
    assert!(
        in_step.disagreements.is_empty(),
        "{:?}",
        in_step.disagreements
    );
    let doc = serde_json::to_string(&to_cyclonedx(&in_step)).unwrap();
    assert!(!doc.contains("manifest-"), "{doc}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_other_manifests_are_held_to_their_lockfiles_too() {
    let dir = scratch("other-manifests");
    fs::write(dir.join("Gemfile"), "gem \"rails\", \"~> 7.1.0\"\n").unwrap();
    fs::write(
            dir.join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.2.0)\n\nDEPENDENCIES\n  rails (~> 7.1.0)\n",
        )
        .unwrap();
    fs::create_dir_all(dir.join("svc")).unwrap();
    fs::write(
        dir.join("svc/Cargo.toml"),
        "[package]\nname = \"svc\"\n[dependencies]\nserde = \"1.0\"\n",
    )
    .unwrap();
    fs::write(
        dir.join("svc/Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.228\"\n",
    )
    .unwrap();
    let sbom = build(&dir);
    let said: Vec<(&str, Vec<String>)> = sbom
        .disagreements
        .iter()
        .map(|d| {
            (
                d.project.as_str(),
                d.comparison
                    .differs
                    .iter()
                    .map(|x| x.asked.clone())
                    .collect(),
            )
        })
        .collect();
    // The Gemfile asks for 7.1 and the lock has 7.2; Cargo's two agree, and say nothing.
    assert_eq!(said, vec![("Ruby", vec!["rails ~> 7.1.0".to_owned()])]);
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_lockfile_passed_over_is_named_in_the_document_and_leaves_it_complete() {
    let dir = scratch("passed-over");
    fs::write(dir.join("Cargo.toml"), "[package]\nname='x'\n").unwrap();
    fs::write(
        dir.join("Cargo.lock"),
        "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\n",
    )
    .unwrap();
    fs::write(dir.join("package.json"), "{\"name\":\"web\"}").unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    )
    .unwrap();
    fs::write(dir.join("yarn.lock"), "# yarn lockfile v1\n").unwrap();
    let sbom = build(&dir);
    assert_eq!(
        sbom.passed_over,
        vec![PassedOver {
            project: "npm".into(),
            read: "package-lock.json".into(),
            not_read: vec!["yarn.lock".into()],
        }]
    );
    assert!(
        sbom.is_complete(),
        "a full reading of one lockfile: {sbom:?}"
    );
    let doc = serde_json::to_value(to_cyclonedx(&sbom)).unwrap();
    let said = doc["metadata"]["properties"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "securevibe:lockfile-passed-over:npm")
        .unwrap_or_else(|| panic!("the document names it: {doc}"));
    let said = said["value"].as_str().unwrap();
    assert!(
        said.contains("`package-lock.json` was read") && said.contains("`yarn.lock` is there too"),
        "{said}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn pipfile_lock_strips_the_pin_from_the_version() {
    // Pipfile.lock writes "==3.0.0": the specifier travels with the value, and a purl carrying
    // `@==3.0.0` matches no advisory anywhere.
    let dir = scratch("pipfile");
    fs::write(dir.join("requirements.txt"), "flask\n").unwrap();
    fs::write(
        dir.join("Pipfile.lock"),
        r#"{"default":{"flask":{"version":"==3.0.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}"#,
    )
    .unwrap();
    let sbom = build(&dir);
    let flask = sbom
        .components
        .iter()
        .find(|c| c.name == "flask")
        .expect("flask");
    assert_eq!(
        flask.version, "3.0.0",
        "the == must not survive into the version"
    );
    assert_eq!(flask.purl(), "pkg:pypi/flask@3.0.0");
    assert_eq!(
        sbom.components.len(),
        2,
        "development packages ship too: {sbom:?}"
    );
    fs::remove_dir_all(&dir).ok();
}

/// A `Pipfile.lock` as `pipenv lock` writes it, cut down: `_meta`, then each category.
const PIPFILE_LOCK: &str = r#"{
        "_meta": {"hash": {"sha256": "x"}, "pipfile-spec": 6, "requires": {"python_version": "3.11"},
                  "sources": [{"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": true}]},
        "default": {
            "django": {"hashes": ["sha256:y"], "index": "pypi", "version": "==2.2.0"},
            "sqlparse": {"hashes": ["sha256:z"], "markers": "python_version >= '3.5'", "version": "==0.4.4"}
        },
        "develop": {"pytest": {"hashes": ["sha256:w"], "version": "==8.0.0"}},
        "docs": {"sphinx": {"version": "==7.2.6"}}
    }"#;

#[test]
fn a_pipenv_app_alone_is_read_from_its_lockfile() {
    // Deep review H9: with only `Pipfile` and `Pipfile.lock`, nothing at all was listed.
    let dir = scratch("pipenv-alone");
    fs::write(
        dir.join("Pipfile"),
        "[[source]]\nurl = \"https://pypi.org/simple\"\nname = \"pypi\"\n\n\
             [packages]\ndjango = \"==2.2.0\"\n\n[dev-packages]\npytest = \"*\"\n\n\
             [docs]\nsphinx = \"*\"\n\n[requires]\npython_version = \"3.11\"\n",
    )
    .unwrap();
    fs::write(dir.join("Pipfile.lock"), PIPFILE_LOCK).unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();

    let listed: Vec<String> = sbom
        .components
        .iter()
        .map(|c| format!("{} {} {:?}", c.name, c.version, c.source))
        .collect();
    assert_eq!(
        listed,
        [
            "django 2.2.0 Locked",
            "pytest 8.0.0 Locked",
            "sphinx 7.2.6 Locked",
            "sqlparse 0.4.4 Locked",
        ],
        "every section is read, development packages and other categories too"
    );
    assert!(sbom.is_complete(), "{sbom:?}");
    assert!(
        sbom.disagreements.is_empty(),
        "the Pipfile agrees with its lockfile: {:?}",
        sbom.disagreements
    );
}

#[test]
fn a_pipfile_that_asks_for_another_version_than_its_lockfile_is_named() {
    let dir = scratch("pipenv-disagrees");
    fs::write(dir.join("Pipfile"), "[packages]\ndjango = \"==2.2.28\"\n").unwrap();
    fs::write(dir.join("Pipfile.lock"), PIPFILE_LOCK).unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let disagreement = sbom.disagreements.first().expect("named");
    assert!(disagreement.differs(), "{disagreement:?}");
    assert!(
        disagreement
            .explain()
            .contains("`django ==2.2.28` (the lockfile has 2.2.0)"),
        "{}",
        disagreement.explain()
    );
}

#[test]
fn a_pipfile_lock_package_with_no_version_is_named_not_dropped() {
    // Pipenv locks a package from a repository by its commit, and one from a folder by its
    // path: no version. Installed all the same, so the list is not the whole of what is
    // (deep review H21, for this reader). The app's own folder is the app, not a package.
    let dir = scratch("pipenv-unversioned");
    fs::write(dir.join("Pipfile"), "[packages]\ndjango = \"*\"\n").unwrap();
    fs::write(
        dir.join("Pipfile.lock"),
        r#"{"_meta": {},
                "default": {
                    "django": {"version": "==4.2.11"},
                    "myapp": {"editable": true, "path": "."},
                    "toolkit": {"git": "https://example.com/toolkit.git", "ref": "abc123"},
                    "shared": {"editable": true, "path": "./libs/shared"}
                },
                "develop": {}}"#,
    )
    .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();

    assert_eq!(sbom.components.len(), 1, "{sbom:?}");
    assert_eq!(sbom.unread.len(), 1, "{:?}", sbom.unread);
    let (eco, why) = &sbom.unread[0];
    assert_eq!(eco, "Python");
    assert!(
        why.contains("2 package(s) in `Pipfile.lock` give no version")
            && why.contains("shared, toolkit"),
        "{why}"
    );
    assert!(
        !why.contains("myapp"),
        "the app itself is not a package: {why}"
    );
    assert!(!sbom.is_complete());
}

#[test]
fn a_pipfile_without_its_lockfile_lists_only_its_pins_and_names_the_rest() {
    let dir = scratch("pipfile-alone");
    fs::write(
        dir.join("Pipfile"),
        "[packages]\ndjango = \"==2.2.0\"\nrequests = \"*\"\n\
             flask = {version = \"==3.0.0\", extras = [\"async\"]}\n\
             toolkit = {git = \"https://example.com/toolkit.git\"}\n\n\
             [dev-packages]\npytest = \">=8\"\n",
    )
    .unwrap();
    let sbom = build(&dir);
    fs::write(dir.join("Pipfile"), "[packages]\nrequests = \"*\"\n").unwrap();
    let none_pinned = build(&dir);
    fs::remove_dir_all(&dir).ok();

    let listed: Vec<String> = sbom
        .components
        .iter()
        .map(|c| format!("{} {} {:?}", c.name, c.version, c.source))
        .collect();
    assert_eq!(listed, ["django 2.2.0 Declared", "flask 3.0.0 Declared"]);
    assert_eq!(sbom.unread.len(), 1, "{:?}", sbom.unread);
    assert!(
        sbom.unread[0].1.contains("3 of its packages")
            && sbom.unread[0].1.contains("pytest, requests, toolkit"),
        "{:?}",
        sbom.unread
    );
    assert!(!sbom.is_complete());

    assert!(none_pinned.components.is_empty());
    assert_eq!(
        none_pinned.unread.len(),
        1,
        "one reason, not that one and the general one too: {:?}",
        none_pinned.unread
    );
    assert!(none_pinned.unread[0].1.contains("requests"));
}

#[test]
fn python_declarations_sv_does_not_read_leave_the_list_incomplete_and_say_which() {
    // Beside a locked npm app, so the list is not empty and a clean comparison of it would
    // otherwise have been credited (deep review H9).
    let dir = scratch("python-declarations");
    fs::write(dir.join("package.json"), r#"{"name":"web"}"#).unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}"#,
    )
    .unwrap();
    let control = build(&dir);
    assert!(control.is_complete(), "the control: {control:?}");

    let cases: &[(&str, &str, &str)] = &[
        (
            "worker/setup.py",
            "from setuptools import setup\nsetup(name='w', install_requires=['celery'])\n",
            "`worker/setup.py` names Python packages",
        ),
        (
            "worker/setup.cfg",
            "[options]\ninstall_requires =\n    celery\n",
            "`worker/setup.cfg` names Python packages",
        ),
        (
            "requirements-dev.txt",
            "pytest==8.0.0\n",
            "`requirements-dev.txt` lists Python packages",
        ),
        (
            "requirements/prod.txt",
            "gunicorn>=22\n",
            "`requirements/prod.txt` lists Python packages",
        ),
        (
            "environment.yml",
            "name: lab\ndependencies:\n  - numpy\n",
            "`environment.yml` is a Conda environment",
        ),
    ];
    for (path, text, said) in cases {
        let file = dir.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, text).unwrap();
        let sbom = build(&dir);
        fs::remove_file(&file).ok();
        assert!(!sbom.is_complete(), "{path}: {sbom:?}");
        assert!(
            sbom.unread
                .iter()
                .any(|(eco, why)| eco == "Python" && why.contains(said)),
            "{path}: {:?}",
            sbom.unread
        );
    }
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_setup_py_beside_a_python_lockfile_is_stood_for_by_it() {
    let dir = scratch("setup-beside-lock");
    fs::write(
        dir.join("setup.py"),
        "from setuptools import setup\nsetup(install_requires=['django'])\n",
    )
    .unwrap();
    let alone = build(&dir);
    fs::write(
        dir.join("Pipfile"),
        "[packages]\nmyapp = {path = \".\", editable = true}\n",
    )
    .unwrap();
    fs::write(dir.join("Pipfile.lock"), PIPFILE_LOCK).unwrap();
    let locked = build(&dir);
    fs::remove_dir_all(&dir).ok();

    assert!(
        alone
            .unread
            .iter()
            .any(|(_, why)| why.contains("`setup.py`")),
        "the control: {alone:?}"
    );
    assert!(locked.is_complete(), "{locked:?}");
}

#[test]
fn a_requirements_file_under_another_name_that_pins_and_hashes_is_read() {
    let dir = scratch("requirements-dev-hashed");
    let hash = format!("sha256:{}", "a".repeat(64));
    fs::write(
        dir.join("requirements-dev.txt"),
        format!("pytest==8.0.0 \\\n    --hash={hash}\n"),
    )
    .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    assert!(sbom.unread.is_empty(), "{:?}", sbom.unread);
    assert_eq!(
        sbom.components,
        [Component {
            name: "pytest".into(),
            version: "8.0.0".into(),
            ecosystem: "Python".into(),
            source: VersionSource::Locked,
        }]
    );
    // It is named as where the list came from.
    assert_eq!(
        sbom.what_was_read(),
        "1 Python package, read from `requirements-dev.txt`"
    );
}

#[test]
fn yarn_lock_reads_one_package_from_several_ranges() {
    // The header is the range that was asked for, not the name, and one package can have several
    // headers. Treating each header as a package would invent packages and double the list.
    let dir = scratch("yarn");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
            dir.join("yarn.lock"),
            "# yarn lockfile v1\n\nlodash@^4.17.0, lodash@~4.17.20:\n  version \"4.17.21\"\n  resolved \"https://x\"\n\n\"@babel/core@^7.0.0\":\n  version \"7.23.0\"\n",
        )
        .unwrap();
    let sbom = build(&dir);
    let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["@babel/core", "lodash"], "{sbom:?}");
    // A scoped package keeps its scope: the name is everything before the LAST @.
    assert!(
        sbom.components
            .iter()
            .any(|c| c.purl() == "pkg:npm/@babel/core@7.23.0")
    );
    fs::remove_dir_all(&dir).ok();
}

const YARN_BERRY: &str = r#"# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"@babel/core@npm:^7.0.0":
  version: 7.23.0
  resolution: "@babel/core@npm:7.23.0"
  dependencies:
    "@babel/code-frame": "npm:^7.22.13"
  checksum: 10c0/0a1b2c
  languageName: node
  linkType: hard

"lodash@npm:^4.17.0, lodash@npm:~4.17.20":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21"
  checksum: 10c0/3d4e5f
  languageName: node
  linkType: hard

"my-app@workspace:.":
  version: 0.0.0-use.local
  resolution: "my-app@workspace:."
  dependencies:
    lodash: "npm:^4.17.0"
  languageName: unknown
  linkType: soft

"local-lib@file:../lib::locator=my-app%40workspace%3A.":
  version: 1.0.0
  resolution: "local-lib@file:../lib#../lib::hash=1a2b3c&locator=my-app%40workspace%3A."
  languageName: node
  linkType: hard

"resolve@patch:resolve@npm%3A^1.22.0#optional!builtin<compat/resolve>":
  version: 1.22.8
  resolution: "resolve@patch:resolve@npm%3A1.22.8#optional!builtin<compat/resolve>::version=1.22.8&hash=c3c19d"
  languageName: node
  linkType: hard
"#;

#[test]
fn a_yarn_berry_lockfile_lists_what_came_from_the_registry_and_nothing_else() {
    let dir = scratch("yarn-berry");
    fs::write(dir.join("package.json"), r#"{"name":"my-app"}"#).unwrap();
    fs::write(dir.join("yarn.lock"), YARN_BERRY).unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    // Not the app itself, not `__metadata`'s own version, and the patched `resolve` once, by
    // its own name. The folder it links is installed too, from outside the registry, so it is
    // named as not listed rather than dropped without a word; the app's own workspace is not.
    assert_eq!(
        purls,
        vec![
            "pkg:npm/@babel/core@7.23.0",
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/resolve@1.22.8",
        ],
        "{sbom:?}"
    );
    assert_eq!(sbom.unread.len(), 1, "{:?}", sbom.unread);
    assert!(
        sbom.unread[0].1.contains("(local-lib)"),
        "{:?}",
        sbom.unread
    );
    assert!(!sbom.is_complete());
}

const BUN_LOCK: &str = r#"{
  "lockfileVersion": 1,
  "workspaces": {
    "": {
      "name": "my-app",
      "dependencies": {
        "@babel/core": "^7.0.0",
        "lodash": "^4.17.0",
      },
    },
    "packages/ui": {
      "name": "ui",
    },
  },
  "packages": {
    "@babel/core": ["@babel/core@7.23.0", "", { "dependencies": { "debug": "^4.1.0" } }, "sha512-AAAA=="],
    "lodash": ["lodash@4.17.21", "", {}, "sha512-BBBB=="],
    "ui": ["ui@workspace:packages/ui"],
    "some-git": ["some-git@github:owner/repo#1a2b3c", {}],
    "debug/ms": ["ms@2.1.2", "", {}, "sha512-CCCC=="],
  },
}
"#;

#[test]
fn a_bun_lockfile_is_read_with_its_trailing_commas() {
    let dir = scratch("bun");
    fs::write(dir.join("package.json"), r#"{"name":"my-app"}"#).unwrap();
    fs::write(dir.join("bun.lock"), BUN_LOCK).unwrap();
    let eco = sv_scan::ecosystems::detect(&dir);
    let pinning = eco.first().map(|e| sv_scan::ecosystems::pinning(&dir, e));
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    // Bun's lockfile pins: a Bun app is not told it has none.
    assert_eq!(
        pinning,
        Some(sv_scan::ecosystems::Pinning::Lockfile("bun.lock".into()))
    );
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    // A package installed under another one is listed by its own name; a workspace member and a
    // GitHub dependency are not registry packages.
    assert_eq!(
        purls,
        vec![
            "pkg:npm/@babel/core@7.23.0",
            "pkg:npm/lodash@4.17.21",
            "pkg:npm/ms@2.1.2",
        ],
        "{sbom:?}"
    );
    assert!(sbom.unread.is_empty(), "{:?}", sbom.unread);
}

#[test]
fn bun_s_binary_lockfile_pins_and_says_it_cannot_be_read() {
    let dir = scratch("bun-binary");
    fs::write(dir.join("package.json"), r#"{"name":"my-app"}"#).unwrap();
    fs::write(dir.join("bun.lockb"), [0x23, 0x21, 0x2f, 0x00, 0xff, 0x01]).unwrap();
    let eco = sv_scan::ecosystems::detect(&dir);
    let pinning = eco.first().map(|e| sv_scan::ecosystems::pinning(&dir, e));
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    assert_eq!(
        pinning,
        Some(sv_scan::ecosystems::Pinning::Lockfile("bun.lockb".into()))
    );
    assert!(sbom.components.is_empty());
    assert!(
        sbom.unread
            .iter()
            .any(|(eco, why)| eco == "npm" && why.contains("binary") && why.contains("bun.lock")),
        "{:?}",
        sbom.unread
    );
}

#[test]
fn only_a_comma_before_a_closing_bracket_and_outside_a_string_is_dropped() {
    assert_eq!(
        without_trailing_commas(r#"{"a": [1, 2,], "b": "x,}", "c": "q\",]",}"#),
        r#"{"a": [1, 2], "b": "x,}", "c": "q\",]"}"#
    );
    assert_eq!(without_trailing_commas("[1 ,\n ]"), "[1 \n ]");
}

#[test]
fn a_project_below_the_top_has_its_lockfile_read() {
    // A `server/` project's packages were missing from the bill of materials, because only the
    // top of the app folder was looked at.
    let dir = scratch("nested");
    fs::create_dir_all(dir.join("server")).unwrap();
    fs::write(dir.join("server/package.json"), r#"{"name":"server"}"#).unwrap();
    fs::write(
            dir.join("server/package-lock.json"),
            r#"{"lockfileVersion":3,"packages":{"":{"name":"server"},"node_modules/express":{"version":"4.19.2"}}}"#,
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    assert!(
        sbom.components
            .iter()
            .any(|c| c.purl() == "pkg:npm/express@4.19.2"),
        "{sbom:?}"
    );
}

#[test]
fn a_nested_rust_project_has_its_lockfile_read() {
    // Second witness, another ecosystem and another reader.
    let dir = scratch("nested-cargo");
    fs::create_dir_all(dir.join("worker")).unwrap();
    fs::write(
        dir.join("worker/Cargo.toml"),
        "[package]\nname = \"worker\"\n",
    )
    .unwrap();
    fs::write(
        dir.join("worker/Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.210\"\n",
    )
    .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    assert!(
        sbom.components
            .iter()
            .any(|c| c.name == "serde" && c.version == "1.0.210"),
        "{sbom:?}"
    );
}

#[test]
fn gradle_lockfile_skips_its_empty_configuration_line() {
    // A real gradle.lockfile ends with `empty=someConfiguration` for configurations that resolved
    // nothing. Reading it as a coordinate would put a package called "empty" in the document.
    let dir = scratch("gradle");
    fs::write(dir.join("build.gradle"), "plugins { id 'java' }\n").unwrap();
    fs::write(
            dir.join("gradle.lockfile"),
            "# This is a Gradle generated file for dependency locking.\norg.springframework:spring-core:6.1.0=compileClasspath,runtimeClasspath\nempty=annotationProcessor\n",
        )
        .unwrap();
    let sbom = build(&dir);
    assert_eq!(sbom.components.len(), 1, "{sbom:?}");
    assert_eq!(sbom.components[0].name, "org.springframework:spring-core");
    assert_eq!(sbom.components[0].version, "6.1.0");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn pnpm_lock_v9_is_read_including_scopes_and_peer_variants() {
    let dir = scratch("pnpm9");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\nsettings:\n  autoInstallPeers: true\n\npackages:\n\n  express@4.18.2:\n    resolution: {integrity: sha512-x}\n    engines: {node: '>= 0.10.0'}\n\n  '@babel/core@7.23.0':\n    resolution: {integrity: sha512-y}\n\n  vite@5.0.0(terser@5.0.0):\n    resolution: {integrity: sha512-z}\n\nsnapshots:\n\n  express@4.18.2:\n    dependencies:\n      body-parser: 1.20.1\n",
        )
        .unwrap();
    let sbom = build(&dir);
    let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, vec!["@babel/core", "express", "vite"], "{sbom:?}");
    // A peer variant is one package, and the peer is not a second one.
    assert!(
        sbom.components.iter().all(|c| c.name != "terser"),
        "{sbom:?}"
    );
    assert!(
        sbom.components
            .iter()
            .any(|c| c.purl() == "pkg:npm/@babel/core@7.23.0")
    );
    // `snapshots:` repeats the same keys; reading both blocks would double the list.
    assert_eq!(sbom.components.len(), 3, "{sbom:?}");
    assert!(sbom.is_complete(), "{sbom:?}");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn pnpm_lock_v6_uses_a_slash_and_an_at_and_is_read_too() {
    // pnpm 8's lockfile 6.0: `/name@version`, with peer variants in brackets as in v9.
    let dir = scratch("pnpm6");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '6.0'\n\npackages:\n\n  /express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /@babel/core@7.23.0:\n    resolution: {integrity: sha512-y}\n\n  /vite@5.0.0(terser@5.0.0):\n    resolution: {integrity: sha512-z}\n",
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(
        purls,
        vec![
            "pkg:npm/@babel/core@7.23.0",
            "pkg:npm/express@4.18.2",
            "pkg:npm/vite@5.0.0",
        ],
        "{sbom:?}"
    );
    assert!(sbom.is_complete(), "{sbom:?}");
}

#[test]
fn pnpm_lock_v5_uses_slashes_and_its_peer_suffix_is_not_the_version() {
    let dir = scratch("pnpm5");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: 5.4\n\npackages:\n\n  /express/4.18.2:\n    resolution: {integrity: sha512-x}\n\n  /@babel/core/7.23.0:\n    resolution: {integrity: sha512-y}\n\n  /react-dom/18.2.0_react@18.2.0:\n    resolution: {integrity: sha512-z}\n",
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(
        purls,
        vec![
            "pkg:npm/@babel/core@7.23.0",
            "pkg:npm/express@4.18.2",
            "pkg:npm/react-dom@18.2.0",
        ],
        "{sbom:?}"
    );
    assert!(sbom.is_complete(), "{sbom:?}");
}

#[test]
fn a_pnpm_package_with_no_version_is_named_not_dropped() {
    // pnpm 9 lists a package installed from a folder or an address by that, not by a version.
    // It is installed, so the list is not complete, and says which.
    let dir = scratch("pnpm9-file");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
            dir.join("pnpm-lock.yaml"),
            "lockfileVersion: '9.0'\n\npackages:\n\n  express@4.18.2:\n    resolution: {integrity: sha512-x}\n\n  my-lib@file:../lib:\n    resolution: {directory: ../lib, type: directory}\n\n  left-pad@https://codeload.github.com/x/left-pad/tar.gz/abc:\n    resolution: {tarball: https://codeload.github.com/x/left-pad/tar.gz/abc}\n",
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(purls, vec!["pkg:npm/express@4.18.2"], "{sbom:?}");
    assert!(!sbom.is_complete(), "{sbom:?}");
    assert!(
        sbom.unread.iter().any(|(eco, why)| eco == "npm"
            && why.contains("2 package(s)")
            && why.contains("left-pad")
            && why.contains("my-lib")),
        "{sbom:?}"
    );
}

#[test]
fn a_yarn_package_with_no_registry_version_is_named_not_dropped() {
    // Berry: a folder, a link, and a repository are named; the app's own workspace is not.
    let dir = scratch("yarn-unversioned");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
            dir.join("yarn.lock"),
            "__metadata:\n  version: 8\n\n\"lodash@npm:^4.17.0\":\n  version: 4.17.21\n  resolution: \"lodash@npm:4.17.21\"\n\n\"my-lib@file:../lib::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n\n\"shared@link:../shared::locator=app%40workspace%3A.\":\n  version: 0.0.0-use.local\n\n\"left-pad@https://github.com/x/left-pad.git#commit=abc\":\n  version: 1.3.0\n\n\"app@workspace:.\":\n  version: 0.0.0-use.local\n",
        )
        .unwrap();
    let sbom = build(&dir);
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    assert_eq!(purls, vec!["pkg:npm/lodash@4.17.21"], "{sbom:?}");
    assert!(!sbom.is_complete(), "{sbom:?}");
    let said = sbom
        .unread
        .iter()
        .find(|(eco, _)| eco == "npm")
        .map(|(_, why)| why.clone())
        .unwrap_or_default();
    assert!(said.contains("3 package(s)"), "{said}");
    for name in ["my-lib", "shared", "left-pad"] {
        assert!(said.contains(name), "{name}: {said}");
    }
    assert!(!said.contains("app,") && !said.contains("app)"), "{said}");

    // Classic: an entry that never says its version is named too.
    fs::write(
            dir.join("yarn.lock"),
            "# yarn lockfile v1\n\nlodash@^4.17.0:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n\n\"my-lib@file:../lib\":\n  resolved \"file:../lib\"\n\nzod@^3.22.0:\n  version \"3.22.4\"\n\n\"tail-lib@file:../tail\":\n  resolved \"file:../tail\"\n",
        )
        .unwrap();
    let sbom = build(&dir);
    fs::remove_dir_all(&dir).ok();
    let purls: Vec<String> = sbom.components.iter().map(Component::purl).collect();
    // One without a version between two with, and one at the very end.
    assert_eq!(
        purls,
        vec!["pkg:npm/lodash@4.17.21", "pkg:npm/zod@3.22.4"],
        "{sbom:?}"
    );
    for name in ["my-lib", "tail-lib"] {
        assert!(
            sbom.unread
                .iter()
                .any(|(eco, why)| eco == "npm" && why.contains(name)),
            "{name}: {sbom:?}"
        );
    }
}

#[test]
fn a_pnpm_file_this_reader_does_not_understand_is_named_not_emptied() {
    // The guard that makes hand-parsing acceptable. A future lockfile version, or a file that is
    // not really a pnpm lock, must come back as "not read" — an empty list is indistinguishable
    // from an app with no dependencies, which is the one wrong answer available here.
    let dir = scratch("pnpmfuture");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(
        dir.join("pnpm-lock.yaml"),
        "lockfileVersion: '99.0'\n\nmodules:\n  something: else\n",
    )
    .unwrap();
    let sbom = build(&dir);
    assert!(sbom.components.is_empty());
    assert!(
        sbom.unread
            .iter()
            .any(|(eco, why)| eco == "npm" && why.contains("no packages could be taken")),
        "an unrecognized pnpm lockfile must be named, and say why: {sbom:?}"
    );
    assert!(!sbom.is_complete());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_lockfile_that_parses_to_nothing_is_named_rather_than_silently_empty() {
    // Not pnpm-specific: any reader that returns an empty list leaves the ecosystem present and
    // the document silent about it, which reads exactly like having nothing to say.
    let dir = scratch("emptylock");
    fs::write(dir.join("package.json"), r#"{"name":"app"}"#).unwrap();
    fs::write(dir.join("package-lock.json"), r#"{"lockfileVersion":3}"#).unwrap();
    let sbom = build(&dir);
    assert!(sbom.components.is_empty());
    assert!(
        sbom.unread
            .iter()
            .any(|(eco, why)| eco == "npm" && why.contains("no packages")),
        "{sbom:?}"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn an_ecosystem_is_never_silently_nothing() {
    // The invariant behind every "named rather than dropped" test, stated once: if an ecosystem is
    // in use, the document either lists something from it or says why it does not. Silence about an
    // ecosystem that is present is the one outcome that reads like an answer and is not.
    let cases: &[(&str, &str, &str)] = &[
        (
            "package.json",
            "pnpm-lock.yaml",
            "lockfileVersion: '99.0'\nmodules:\n  x: y\n",
        ),
        (
            "package.json",
            "package-lock.json",
            r#"{"packages":{"node_modules/x":{"version":"1.0.0"}}}"#,
        ),
        (
            "Gemfile",
            "Gemfile.lock",
            "GEM\n  specs:\n    rake (13.0.6)\n",
        ),
        ("requirements.txt", "", "flask>=2\n"),
        ("Pipfile", "", "[packages]\nflask = \"*\"\n"),
        (
            "Pipfile",
            "Pipfile.lock",
            r#"{"default":{"flask":{"git":"https://example.com/flask.git"}}}"#,
        ),
        ("go.mod", "go.sum", "example.com/m v1.0.0 h1:x=\n"),
    ];
    for (manifest, lock, contents) in cases {
        let dir = scratch(&format!("invariant-{manifest}-{lock}"));
        if lock.is_empty() {
            fs::write(dir.join(manifest), contents).unwrap();
        } else {
            fs::write(dir.join(manifest), "placeholder\n").unwrap();
            fs::write(dir.join(lock), contents).unwrap();
        }
        let detected = sv_scan::ecosystems::detect(&dir);
        assert!(!detected.is_empty(), "{manifest} should be detected");
        let sbom = build(&dir);
        assert!(
            !sbom.components.is_empty() || !sbom.unread.is_empty(),
            "{manifest}/{lock}: an ecosystem was present and the document says nothing about it: {sbom:?}"
        );
        fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn go_mod_names_the_version_built_and_go_sum_s_older_ones_are_not_listed() {
    // A3: go.sum keeps checksums for versions Go has since moved past. Only go.mod's own
    // `require` lines say which one the app is built with.
    let go_mod = "module example.com/app\n\ngo 1.21\n\nrequire (\n\tgithub.com/gorilla/websocket v1.5.1\n\tgolang.org/x/net v0.23.0 // indirect\n)\n\nrequire github.com/google/uuid v1.6.0\n";
    let go_sum = "github.com/gorilla/websocket v1.4.2 h1:a=\ngithub.com/gorilla/websocket v1.4.2/go.mod h1:b=\ngithub.com/gorilla/websocket v1.5.1 h1:c=\ngolang.org/x/net v0.17.0/go.mod h1:d=\ngolang.org/x/net v0.23.0 h1:e=\ngithub.com/google/uuid v1.6.0 h1:f=\nexample.com/dropped v1.0.0 h1:g=\n";
    let got = from_go_mod(go_mod, Some(go_sum));
    let mut pairs = got.pairs.clone();
    pairs.sort();
    assert_eq!(
        pairs,
        [
            ("github.com/google/uuid".to_owned(), "v1.6.0".to_owned()),
            (
                "github.com/gorilla/websocket".to_owned(),
                "v1.5.1".to_owned()
            ),
            ("golang.org/x/net".to_owned(), "v0.23.0".to_owned()),
        ]
    );
    assert!(got.local.is_empty());

    // `replace` decides what is built: another module at a version, or a folder of the app's own.
    let replaced = "module x\ngo 1.22\nrequire (\n  a.example/one v1.0.0\n  b.example/two v1.0.0\n  c.example/three v2.0.0\n)\nreplace (\n  a.example/one => a.example/fork v1.0.5\n  b.example/two v1.0.0 => ../two\n  c.example/three v9.9.9 => ../never\n)\n";
    let got = from_go_mod(replaced, None);
    assert!(
        got.pairs
            .contains(&("a.example/fork".to_owned(), "v1.0.5".to_owned())),
        "{got:?}"
    );
    assert!(
        got.pairs
            .contains(&("c.example/three".to_owned(), "v2.0.0".to_owned())),
        "a replace for another version leaves this one: {got:?}"
    );
    assert_eq!(got.local, ["b.example/two"]);

    // Before Go 1.17 go.mod may leave the indirect modules out, so go.sum names them, at the
    // highest version it holds.
    let old = "module x\ngo 1.16\nrequire github.com/a/direct v1.2.0\n";
    let sum = "github.com/a/direct v1.1.0 h1:x=\ngithub.com/a/direct v1.2.0 h1:x=\ngithub.com/b/indirect v0.9.0 h1:x=\ngithub.com/b/indirect v0.10.0 h1:x=\ngithub.com/b/indirect v0.11.0/go.mod h1:x=\n";
    let mut got = from_go_mod(old, Some(sum)).pairs;
    got.sort();
    assert_eq!(
        got,
        [
            ("github.com/a/direct".to_owned(), "v1.2.0".to_owned()),
            ("github.com/b/indirect".to_owned(), "v0.10.0".to_owned()),
        ]
    );
}

#[test]
fn a_go_app_is_listed_from_go_mod_and_says_what_a_folder_replaced() {
    let dir = scratch("go-mod");
    fs::write(
            dir.join("go.mod"),
            "module x\ngo 1.21\nrequire (\n  github.com/gorilla/websocket v1.5.1\n  example.com/local v0.1.0\n)\nreplace example.com/local => ./local\n",
        )
        .unwrap();
    fs::write(
        dir.join("go.sum"),
        "github.com/gorilla/websocket v1.4.2 h1:a=\ngithub.com/gorilla/websocket v1.5.1 h1:b=\n",
    )
    .unwrap();
    let sbom = build(&dir);
    let versions: Vec<&str> = sbom.components.iter().map(|c| c.version.as_str()).collect();
    assert_eq!(versions, ["v1.5.1"], "{sbom:?}");
    assert!(
        sbom.unread
            .iter()
            .any(|(_, why)| why.contains("example.com/local")),
        "{:?}",
        sbom.unread
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn go_mod_is_compared_with_go_sum_and_not_with_itself() {
    // Found in the review of 1 to 4 October (item 23): since A3 the list comes from go.mod,
    // and the comparison was given that list, so go.mod could never disagree with go.sum.
    let dir = scratch("go-mod-sum");
    fs::write(
            dir.join("go.mod"),
            "module x\ngo 1.21\nrequire (\n  github.com/gorilla/websocket v1.5.1\n  github.com/google/uuid v1.6.0\n)\n",
        )
        .unwrap();
    fs::write(
        dir.join("go.sum"),
        "github.com/gorilla/websocket v1.4.2 h1:a=\ngithub.com/google/uuid v1.6.0 h1:b=\n",
    )
    .unwrap();
    let sbom = build(&dir);
    let differs: Vec<&str> = sbom
        .disagreements
        .iter()
        .flat_map(|d| d.comparison.differs.iter().map(|x| x.asked.as_str()))
        .collect();
    assert_eq!(differs, ["github.com/gorilla/websocket v1.5.1"], "{sbom:?}");
    // The list is still what go.mod says is built.
    let mut versions: Vec<&str> = sbom.components.iter().map(|c| c.version.as_str()).collect();
    versions.sort_unstable();
    assert_eq!(versions, ["v1.5.1", "v1.6.0"]);
    // The control: with go.sum holding the version go.mod asks for, nothing disagrees.
    fs::write(
        dir.join("go.sum"),
        "github.com/gorilla/websocket v1.5.1 h1:a=\ngithub.com/google/uuid v1.6.0 h1:b=\n",
    )
    .unwrap();
    assert!(build(&dir).disagreements.is_empty());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn go_sum_lists_each_module_once() {
    let dir = scratch("go");
    fs::write(dir.join("go.mod"), "module x\n").unwrap();
    fs::write(
            dir.join("go.sum"),
            "github.com/gorilla/websocket v1.5.0 h1:abc=\ngithub.com/gorilla/websocket v1.5.0/go.mod h1:def=\n",
        )
        .unwrap();
    let sbom = build(&dir);
    assert_eq!(sbom.components.len(), 1, "{sbom:?}");
    assert_eq!(sbom.components[0].version, "v1.5.0");
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn gemfile_lock_reads_specs_and_not_their_dependencies() {
    let dir = scratch("gem");
    fs::write(dir.join("Gemfile"), "source 'x'\n").unwrap();
    fs::write(
            dir.join("Gemfile.lock"),
            "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.1.0)\n      actionpack (= 7.1.0)\n    rake (13.0.6)\n",
        )
        .unwrap();
    let sbom = build(&dir);
    let names: Vec<&str> = sbom.components.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["rails", "rake"],
        "nested dependencies are not separate packages"
    );
    fs::remove_dir_all(&dir).ok();
}
