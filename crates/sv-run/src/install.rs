//! The install step (ADR-052): an app's packages, downloaded before the run in a container of their
//! own, and given to the fenced app read-only.
//!
//! The app's folder is mounted read-only on a network with no way out (ADR-019), so its `build` step
//! cannot install anything, and an app that needs packages never starts. When the owner asks for it
//! (`install = true` under `[stack.run]`), this step runs first, in a throwaway container that:
//!
//! - sees only the dependency files, each mounted read-only on its own: never the app's code, its
//!   `.env`, or anything else in its folder, so nothing secret is in reach while the network is open;
//! - takes only exact versions: every line of `requirements.txt` pinned with `==`, or a
//!   `package-lock.json` beside `package.json`;
//! - runs no package code while it can reach the internet: wheels only for Python, so no `setup.py`
//!   runs, and `npm ci --ignore-scripts` for Node;
//! - writes into a Docker volume named from a fingerprint of the image and the dependency files, so
//!   a second run with the same files downloads nothing. The volume lives in the container backend,
//!   not in any folder of the owner's.
//!
//! The app then runs exactly as before, fenced, with that volume mounted read-only.

use std::path::{Path, PathBuf};

/// Where a Python app finds its installed packages, on `PYTHONPATH`; their commands are in `bin/`.
pub const PYTHON_DEPS: &str = "/sv-deps";
/// Where a Node app finds its installed packages. Node looks for `node_modules` in the app's folder
/// and then in each folder above it, so one at the top of the file system is found from `/app`
/// without touching the app's own read-only folder.
pub const NODE_DEPS: &str = "/node_modules";
/// Written last by a finished install, so a volume an interrupted install left half full is never
/// taken for a finished one.
pub const INSTALLED_MARK: &str = ".sv-installed";
/// The install container's scratch space: room for npm's download cache and its unpacked tree.
pub const INSTALL_TMPFS: &str = "/tmp:size=1g";
/// The label on every volume this step makes, so a person can list or remove them all at once
/// (`docker volume ls --filter label=securevibe.deps`).
pub const VOLUME_LABEL: &str = "securevibe.deps";

/// Which package manager an app's dependency files are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Python,
    Node,
}

impl Ecosystem {
    /// Where the packages come from, for the report.
    pub fn registry(self) -> &'static str {
        match self {
            Ecosystem::Python => "PyPI",
            Ecosystem::Node => "the npm registry",
        }
    }

    /// The files the install container is given, and nothing else.
    pub fn files(self) -> &'static [&'static str] {
        match self {
            Ecosystem::Python => &["requirements.txt"],
            Ecosystem::Node => &["package.json", "package-lock.json"],
        }
    }

    /// Where the installed packages are mounted in the app's container.
    pub fn mount_point(self) -> &'static str {
        match self {
            Ecosystem::Python => PYTHON_DEPS,
            Ecosystem::Node => NODE_DEPS,
        }
    }

    /// Where their commands are, to go first on the app's `PATH`.
    pub fn bin(self) -> String {
        match self {
            Ecosystem::Python => format!("{PYTHON_DEPS}/bin"),
            Ecosystem::Node => format!("{NODE_DEPS}/.bin"),
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Ecosystem::Python => "py",
            Ecosystem::Node => "node",
        }
    }

    /// The command the install container runs. Packages are downloaded and unpacked, never run:
    /// `--only-binary=:all:` refuses a package that would need its `setup.py` run to install, and
    /// `--ignore-scripts` skips every package's install scripts. The mark is written only when the
    /// install succeeded.
    pub fn command(self) -> String {
        match self {
            Ecosystem::Python => format!(
                "pip install --no-cache-dir --disable-pip-version-check --no-input \
                 --only-binary=:all: --target /out -r /in/requirements.txt \
                 && touch /out/{INSTALLED_MARK}"
            ),
            Ecosystem::Node => format!(
                "mkdir -p /tmp/w && cp /in/package.json /in/package-lock.json /tmp/w/ \
                 && cd /tmp/w && npm ci --ignore-scripts --no-audit --no-fund \
                 && cp -a node_modules/. /out/ && touch /out/{INSTALLED_MARK}"
            ),
        }
    }
}

/// One install: what it is for, the files it is given, and the volume it fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Install {
    pub ecosystem: Ecosystem,
    /// Each dependency file, by its place on this computer and its name in the container.
    pub files: Vec<(PathBuf, &'static str)>,
    pub volume: String,
}

impl Install {
    /// The arguments of the `docker run` that fills the volume. Hardened like every container
    /// (read-only, no capabilities: `docker::HARDENING`, put on by `prepared` when it is sent), but
    /// not fenced: this is the one container of a run that can reach the internet, and it is given
    /// nothing to send.
    pub fn args(&self, name: &str, image: &str) -> Vec<String> {
        let mut args: Vec<String> = [
            "run",
            "--rm",
            "--name",
            name,
            "--tmpfs",
            INSTALL_TMPFS,
            // Nothing of the owner's: no API keys, no home directory.
            "--env-file",
            "/dev/null",
            "-e",
            "HOME=/tmp",
            "-e",
            "npm_config_cache=/tmp/.npm",
            "-v",
        ]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
        args.push(format!("{}:/out", self.volume));
        for (host, name) in &self.files {
            args.push("-v".to_owned());
            args.push(format!("{}:/in/{name}:ro", host.display()));
        }
        args.extend([
            image.to_owned(),
            "sh".to_owned(),
            "-c".to_owned(),
            self.ecosystem.command(),
        ]);
        args
    }

    /// The mount that gives the app the installed packages, read-only.
    pub fn app_mount(&self) -> String {
        format!("{}:{}:ro", self.volume, self.ecosystem.mount_point())
    }
}

/// Whether `image` is one of Docker's own `python` or `node` images, the only ones the install step
/// runs in.
///
/// The install container is the one part of a run with a way out to the internet, and what runs
/// in it is the image's own `sh`, `pip`, or `npm`. In Docker's own images those are known; in an
/// image `securevibe.toml` names from anywhere else they are whatever its author put there, and
/// the step would run that author's code with the network open, which is what the fence exists to
/// prevent (the review of 8 October 2026, item 1; ADR-052, Later). The two images are also the
/// only ones where the packages are sure to fit the interpreter the app then runs them with.
///
/// Accepted: `python` or `node`, with or without a tag (`python:3.12-slim`, `node:22-alpine`), with
/// or without a digest, and with or without Docker Hub's own prefix (`docker.io/library/`,
/// `library/`, `docker.io/`). Nothing else.
pub fn official_image(image: &str) -> bool {
    let name = ["docker.io/library/", "library/", "docker.io/"]
        .iter()
        .find_map(|prefix| image.strip_prefix(prefix))
        .unwrap_or(image);
    let (name, digest) = match name.split_once('@') {
        Some((name, digest)) => (name, Some(digest)),
        None => (name, None),
    };
    let (name, tag) = match name.split_once(':') {
        Some((name, tag)) => (name, Some(tag)),
        None => (name, None),
    };
    let tag_ok = tag.is_none_or(|t| {
        !t.is_empty()
            && t.len() <= 128
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    });
    let digest_ok = digest.is_none_or(|d| {
        d.strip_prefix("sha256:")
            .is_some_and(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
    });
    matches!(name, "python" | "node") && tag_ok && digest_ok
}

/// What the app's folder asks to have installed, or, in plain words, why it cannot be.
pub fn plan(app_dir: &Path, image: &str) -> Result<Vec<Install>, String> {
    if !official_image(image) {
        return Err(format!(
            "the install runs in the image securevibe.toml names, with a way out to the internet, \
             and `sv` does that only in one of Docker's own `python` or `node` images (such as \
             `python:3.12-slim` or `node:22-alpine`), whose `sh`, `pip`, and `npm` are known. This \
             app names `{image}`, and in an image of someone else's those could be anything. Name \
             one of Docker's own, or build the packages into your own image and leave `install` \
             out."
        ));
    }
    // A dependency file that is a link would be followed into the container that can reach the
    // internet, wherever it points (the review of 8 October 2026, item 2).
    for name in ["requirements.txt", "package.json", "package-lock.json"] {
        if std::fs::symlink_metadata(app_dir.join(name)).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(format!(
                "{name} is a link to another file. The install container is given the app's own \
                 dependency files and nothing else, so `sv` does not follow it: put the file itself \
                 in the app's folder."
            ));
        }
    }
    let mut installs = Vec::new();
    let requirements = app_dir.join("requirements.txt");
    if requirements.is_file() {
        let text = std::fs::read_to_string(&requirements)
            .map_err(|e| format!("requirements.txt could not be read: {e}"))?;
        let loose = unpinned(&text);
        if !loose.is_empty() {
            return Err(format!(
                "every line of requirements.txt must name one exact version (`name==1.2.3`), and \
                 {} do{} not: {}. Only exact versions are installed, so what is downloaded is what \
                 the app names.",
                if loose.len() == 1 {
                    "this one"
                } else {
                    "these"
                },
                if loose.len() == 1 { "es" } else { "" },
                loose
                    .iter()
                    .take(3)
                    .map(|l| format!("`{l}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        installs.push(Ecosystem::Python);
    }
    if app_dir.join("package.json").is_file() {
        if !app_dir.join("package-lock.json").is_file() {
            return Err(
                "package.json has no package-lock.json beside it. Only the exact versions \
                        a lockfile names are installed: run `npm install` once to write it."
                    .to_owned(),
            );
        }
        let text = std::fs::read_to_string(app_dir.join("package-lock.json"))
            .map_err(|e| format!("package-lock.json could not be read: {e}"))?;
        let elsewhere = not_from_the_registry(&text)?;
        if !elsewhere.is_empty() {
            return Err(format!(
                "every package in package-lock.json must be downloaded from the npm registry \
                 (`{NPM_REGISTRY}`) and carry an `integrity` fingerprint npm checks it against, and \
                 {} do{} not: {}. Only those are installed, so what is downloaded is what the \
                 lockfile names, from where every app's packages come.",
                if elsewhere.len() == 1 {
                    "this one"
                } else {
                    "these"
                },
                if elsewhere.len() == 1 { "es" } else { "" },
                elsewhere
                    .iter()
                    .take(3)
                    .map(|l| format!("`{l}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        installs.push(Ecosystem::Node);
    }
    if installs.is_empty() {
        return Err(
            "`install = true` is set, but the app's folder has neither a requirements.txt \
                    nor a package.json at its top, so there is nothing to install."
                .to_owned(),
        );
    }
    installs
        .into_iter()
        .map(|ecosystem| {
            let mut files = Vec::new();
            let mut contents = Vec::new();
            for name in ecosystem.files() {
                let path = app_dir.join(name);
                contents.push(
                    std::fs::read(&path).map_err(|e| format!("{name} could not be read: {e}"))?,
                );
                files.push((path, *name));
            }
            Ok(Install {
                ecosystem,
                volume: volume_name(ecosystem, image, &contents),
                files,
            })
        })
        .collect()
}

/// Where every package an npm lockfile installs must come from.
pub const NPM_REGISTRY: &str = "https://registry.npmjs.org/";

/// The packages of a `package-lock.json` that would be downloaded from anywhere but the npm
/// registry, or without an `integrity` fingerprint for npm to check the download against, each as
/// its name and why; `Err` when the file is not a lockfile `sv` can read. Read from `packages`
/// (lockfile versions 2 and 3) and, failing that, the nested `dependencies` of version 1. The app's
/// own entry, and a package bundled inside another (`inBundle`), download nothing of their own. A
/// local folder (`link`) is refused, since the install is given no folder of the app's.
pub fn not_from_the_registry(text: &str) -> Result<Vec<String>, String> {
    let lock: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("package-lock.json is not a lockfile sv can read: {e}"))?;
    let mut found = Vec::new();
    let mut judge = |name: &str, entry: &serde_json::Value| {
        if entry.get("inBundle").and_then(|b| b.as_bool()) == Some(true)
            || entry.get("bundled").and_then(|b| b.as_bool()) == Some(true)
        {
            return;
        }
        if entry.get("link").and_then(|b| b.as_bool()) == Some(true) {
            found.push(format!("{name} (a folder on this computer)"));
            return;
        }
        let resolved = entry.get("resolved").and_then(|r| r.as_str()).unwrap_or("");
        let integrity = entry
            .get("integrity")
            .and_then(|r| r.as_str())
            .unwrap_or("");
        if !resolved.starts_with(NPM_REGISTRY) {
            found.push(if resolved.is_empty() {
                format!("{name} (no download address)")
            } else {
                format!("{name} (from {})", one_line(resolved))
            });
        } else if !["sha512-", "sha384-", "sha256-"]
            .iter()
            .any(|p| integrity.starts_with(p))
        {
            found.push(format!("{name} (no integrity fingerprint)"));
        }
    };
    if let Some(packages) = lock.get("packages").and_then(|p| p.as_object()) {
        for (path, entry) in packages {
            if path.is_empty() {
                continue;
            }
            let name = path.rsplit("node_modules/").next().unwrap_or(path);
            judge(name, entry);
        }
    } else if let Some(deps) = lock.get("dependencies").and_then(|d| d.as_object()) {
        let mut stack: Vec<(&String, &serde_json::Value)> = deps.iter().collect();
        while let Some((name, entry)) = stack.pop() {
            judge(name, entry);
            if let Some(inner) = entry.get("dependencies").and_then(|d| d.as_object()) {
                stack.extend(inner.iter());
            }
        }
    } else {
        return Err(
            "package-lock.json lists no packages sv can read (neither `packages` nor `dependencies`)"
                .to_owned(),
        );
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// A download address as one short line, for a sentence.
fn one_line(text: &str) -> String {
    let flat: String = text.chars().filter(|c| !c.is_control()).collect();
    if flat.chars().count() > 80 {
        format!("{}…", flat.chars().take(80).collect::<String>())
    } else {
        flat
    }
}

/// The lines of a requirements file that do not name one exact version. Allowed: `name==version`,
/// with extras (`name[extra]==version`), an environment marker after `;`, and `--hash=` options,
/// over continued lines. Anything else is refused, notably another file (`-r`), an editable or
/// local install (`-e`, `.`), another index (`--index-url`), and an address (`git+…`, `https://…`),
/// each of which could install something the file does not name.
pub fn unpinned(text: &str) -> Vec<String> {
    let mut logical = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let line = match line.find(" #") {
            Some(at) => &line[..at],
            None if line.trim_start().starts_with('#') => "",
            None => line,
        };
        let trimmed = line.trim_end();
        if let Some(head) = trimmed.strip_suffix('\\') {
            current.push_str(head);
            current.push(' ');
            continue;
        }
        current.push_str(trimmed);
        if !current.trim().is_empty() {
            logical.push(current.trim().to_owned());
        }
        current.clear();
    }
    if !current.trim().is_empty() {
        logical.push(current.trim().to_owned());
    }
    logical.into_iter().filter(|line| !pinned(line)).collect()
}

fn pinned(line: &str) -> bool {
    let (spec, options) = match line.find(" --") {
        Some(at) => (&line[..at], &line[at..]),
        None => (line, ""),
    };
    if !options.split_whitespace().all(|o| o.starts_with("--hash=")) {
        return false;
    }
    let spec = spec.split(';').next().unwrap_or("").trim();
    let Some((name, version)) = spec.split_once("==") else {
        return false;
    };
    let name = name.trim();
    let name = match name.split_once('[') {
        Some((base, extras)) if extras.ends_with(']') => base,
        Some(_) => return false,
        None => name,
    };
    let version = version.trim();
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && !version.is_empty()
        && !version.starts_with('=')
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '!' | '-' | '_'))
        && !version.contains('*')
}

/// The volume for these files in this image: the same files in the same image give the same name,
/// so a second run finds the first one's packages. The name carries the first 128 bits of a SHA-256
/// over the ecosystem, the image, and each file with its length. Until 8 October 2026 it was two
/// FNV-1a passes, which is a checksum, not a hash anyone would struggle to collide: a dependency
/// file written to land on another app's volume name would have had that app's packages served to
/// this one (the review of that day, item 6). A collision in a cryptographic hash's first 128 bits
/// is not something a file can be written for.
pub fn volume_name(ecosystem: Ecosystem, image: &str, contents: &[Vec<u8>]) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(ecosystem.short().as_bytes());
    hasher.update([0]);
    hasher.update(image.as_bytes());
    for c in contents {
        hasher.update([0]);
        hasher.update((c.len() as u64).to_le_bytes());
        hasher.update(c);
    }
    let digest = hasher.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("sv-deps-{}-{hex}", ecosystem.short())
}

/// The app's `PATH`: the installed packages' commands first, then the image's own `PATH`.
pub fn app_path(installs: &[Install], image_path: &str) -> String {
    let mut parts: Vec<String> = installs.iter().map(|i| i.ecosystem.bin()).collect();
    parts.push(image_path.to_owned());
    parts.join(":")
}

/// The sentence the report and `sv run` give when packages were installed.
pub fn sentence(installed: &[(Ecosystem, bool)]) -> Option<String> {
    if installed.is_empty() {
        return None;
    }
    let from = installed
        .iter()
        .map(|(e, _)| e.registry())
        .collect::<Vec<_>>()
        .join(" and ");
    let files = installed
        .iter()
        .flat_map(|(e, _)| e.files().iter().copied())
        .map(|f| format!("`{f}`"))
        .collect::<Vec<_>>()
        .join(" and ");
    let reused = installed.iter().all(|(_, reused)| *reused);
    Some(format!(
        "Before it started, its packages {} from {from} in a separate container that could reach \
         the internet and was given only {files}, never the app's code; no package's own code ran \
         there. They were given to the app read-only, and the app itself ran with no way out.",
        if reused {
            "were taken from an earlier run's download, which had been made"
        } else {
            "were downloaded"
        }
    ))
}

#[cfg(test)]
mod volume_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_versions_pass_and_everything_that_could_install_something_unnamed_is_refused() {
        let good = "\
# a comment
flask==3.0.3
Werkzeug==3.0.4  # pinned by hand
requests[socks]==2.32.3
tomli==2.0.1 ; python_version < \"3.11\"
gunicorn==23.0.0 \\
    --hash=sha256:aaaa \\
    --hash=sha256:bbbb
";
        assert_eq!(unpinned(good), Vec::<String>::new());
        for bad in [
            "flask",
            "flask>=3.0",
            "flask~=3.0",
            "flask==3.*",
            "flask===3.0",
            "-r other.txt",
            "-e .",
            ".",
            "--index-url https://example.com/simple",
            "--extra-index-url https://example.com/simple",
            "git+https://github.com/pallets/flask",
            "flask @ https://example.com/flask.whl",
            "flask==3.0.3 --no-binary=:all:",
            "flask[async==3.0.3",
        ] {
            assert_eq!(
                unpinned(bad),
                vec![bad.to_owned()],
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn the_install_container_sees_only_the_dependency_files_and_runs_no_package_code() {
        let dir = std::env::temp_dir().join(format!("sv-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        std::fs::write(dir.join("app.py"), "import six\n").unwrap();
        std::fs::write(dir.join(".env"), "SECRET=x\n").unwrap();
        let installs = plan(&dir, "python:3.12-slim").unwrap();
        assert_eq!(installs.len(), 1);
        let args = installs[0].args("run-install", "python:3.12-slim");
        let joined = args.join(" ");
        // Mounted: the volume, and requirements.txt read-only. Not the app's folder, nor .env.
        let mounts: Vec<&String> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i > 0 && args[i - 1] == "-v")
            .map(|(_, m)| m)
            .collect();
        assert_eq!(mounts.len(), 2, "{mounts:?}");
        assert!(mounts[0].ends_with(":/out"), "{mounts:?}");
        assert!(
            mounts[1].ends_with("requirements.txt:/in/requirements.txt:ro"),
            "{mounts:?}"
        );
        assert!(
            !joined.contains(".env") && !joined.contains("app.py"),
            "{joined}"
        );
        assert!(
            !mounts
                .iter()
                .any(|m| m.starts_with(&format!("{}:", dir.display())))
        );
        // Nothing of the owner's, and no package code run. The hardening is put on by `prepared`
        // when the arguments are sent, as for every container (tested in `docker`).
        for needed in ["--env-file /dev/null", "--only-binary=:all:"] {
            assert!(joined.contains(needed), "{needed} missing: {joined}");
        }
        assert!(Ecosystem::Node.command().contains("--ignore-scripts"));
        assert!(Ecosystem::Node.command().contains("npm ci "));
        // Not on any fenced network, and nothing published.
        assert!(
            !joined.contains("--network") && !joined.contains(" -p "),
            "{joined}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_install_runs_only_in_dockers_own_python_or_node_images() {
        for ok in [
            "python",
            "python:3.12-slim",
            "python:3.13.1-slim-bookworm",
            "node:22-alpine",
            "node:22.9.0",
            "docker.io/library/python:3.12-slim",
            "library/node:22",
            "docker.io/node:22-alpine",
            "python:3.12-slim@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            assert!(official_image(ok), "{ok} is one of Docker's own");
        }
        for not in [
            "",
            "ghcr.io/someone/python:3.12-slim",
            "someone/python:3.12",
            "pythonx:3.12",
            "Python:3.12",
            "node:",
            "node:22 alpine",
            "python:3.12-slim@sha256:short",
            "python:3.12-slim@md5:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "ruby:3.3",
            "my-app:latest",
            "--privileged",
        ] {
            assert!(!official_image(not), "{not:?} is not one of Docker's own");
        }
        // Through `plan`: refused before the folder is looked at, in plain words naming the image
        // and the way out.
        let dir = std::env::temp_dir().join(format!("sv-install-image-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("requirements.txt"), "six==1.16.0\n").unwrap();
        let refused = plan(&dir, "ghcr.io/someone/app:1").unwrap_err();
        assert!(
            refused.contains("`ghcr.io/someone/app:1`")
                && refused.contains("Docker's own `python` or `node` images")
                && refused.contains("build the packages into your own image"),
            "{refused}"
        );
        assert_eq!(plan(&dir, "python:3.12-slim").unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_folder_with_nothing_exact_to_install_is_refused_in_plain_words() {
        let dir = std::env::temp_dir().join(format!("sv-install-refuse-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let none = plan(&dir, "python:3.12-slim").unwrap_err();
        assert!(
            none.contains("neither a requirements.txt nor a package.json"),
            "{none}"
        );
        std::fs::write(dir.join("package.json"), "{}").unwrap();
        let no_lock = plan(&dir, "node:22-alpine").unwrap_err();
        assert!(no_lock.contains("package-lock.json"), "{no_lock}");
        std::fs::remove_file(dir.join("package.json")).unwrap();
        std::fs::write(dir.join("requirements.txt"), "flask\nrequests>=2\n").unwrap();
        let loose = plan(&dir, "python:3.12-slim").unwrap_err();
        assert!(
            loose.contains("`flask`") && loose.contains("`requests>=2`"),
            "{loose}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_same_files_in_the_same_image_reuse_one_volume_and_any_change_makes_a_new_one() {
        let a = volume_name(
            Ecosystem::Python,
            "python:3.12-slim",
            &[b"six==1.16.0\n".to_vec()],
        );
        assert_eq!(
            a,
            volume_name(
                Ecosystem::Python,
                "python:3.12-slim",
                &[b"six==1.16.0\n".to_vec()]
            )
        );
        assert_ne!(
            a,
            volume_name(
                Ecosystem::Python,
                "python:3.12-slim",
                &[b"six==1.17.0\n".to_vec()]
            )
        );
        assert_ne!(
            a,
            volume_name(
                Ecosystem::Python,
                "python:3.13-slim",
                &[b"six==1.16.0\n".to_vec()]
            )
        );
        assert!(
            a.starts_with("sv-deps-py-") && a.len() == "sv-deps-py-".len() + 32,
            "{a}"
        );
    }

    #[test]
    fn the_app_finds_the_packages_read_only_and_their_commands_first() {
        let install = Install {
            ecosystem: Ecosystem::Python,
            files: vec![],
            volume: "sv-deps-py-x".to_owned(),
        };
        assert_eq!(install.app_mount(), "sv-deps-py-x:/sv-deps:ro");
        assert_eq!(
            app_path(
                std::slice::from_ref(&install),
                "/usr/local/bin:/usr/bin:/bin"
            ),
            "/sv-deps/bin:/usr/local/bin:/usr/bin:/bin"
        );
        let node = Install {
            ecosystem: Ecosystem::Node,
            files: vec![],
            volume: "sv-deps-node-x".to_owned(),
        };
        assert_eq!(node.app_mount(), "sv-deps-node-x:/node_modules:ro");
    }

    #[test]
    fn the_report_says_where_packages_came_from_and_that_the_app_stayed_fenced() {
        assert_eq!(sentence(&[]), None);
        let s = sentence(&[(Ecosystem::Python, false)]).unwrap();
        assert!(
            s.contains("were downloaded from PyPI") && s.contains("`requirements.txt`"),
            "{s}"
        );
        assert!(
            s.contains("never the app's code") && s.contains("no way out"),
            "{s}"
        );
        let again = sentence(&[(Ecosystem::Python, true)]).unwrap();
        assert!(again.contains("earlier run's download"), "{again}");
    }
}
