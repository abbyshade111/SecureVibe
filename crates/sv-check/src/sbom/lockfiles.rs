//! The readers of each lockfile and package manifest: npm, Yarn, pnpm, Bun, Cargo, Poetry, PDM, uv,
//! Pipenv, pip (`requirements.txt` and `pylock.toml`), Composer, Bundler, Go modules, and Gradle. Moved
//! out of `sbom.rs` unchanged on 9 October 2026 (architecture assessment, item 11).

// Each returns (name, version) pairs; none guesses.

pub(super) fn from_package_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // Lockfile v2/v3: a "packages" map keyed by path, where "" is the app itself.
    if let Some(map) = v.get("packages").and_then(|p| p.as_object()) {
        for (path, entry) in map {
            if path.is_empty() {
                continue;
            }
            let name = entry
                .get("name")
                .and_then(|n| n.as_str())
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    path.rsplit("node_modules/")
                        .next()
                        .unwrap_or(path)
                        .to_owned()
                });
            if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
                out.push((name, version.to_owned()));
            }
        }
    }
    // Lockfile v1: a nested "dependencies" map.
    if out.is_empty()
        && let Some(map) = v.get("dependencies").and_then(|p| p.as_object())
    {
        package_lock_v1(map, &mut out);
    }
    out
}

/// Lockfile v1 nests a package's own copy of another under that package's `dependencies`, when it
/// needs a version the top level does not have. Those copies are installed too, so each is listed.
pub(super) fn package_lock_v1(
    map: &serde_json::Map<String, serde_json::Value>,
    out: &mut Vec<(String, String)>,
) {
    for (name, entry) in map {
        if let Some(version) = entry.get("version").and_then(|x| x.as_str()) {
            out.push((name.clone(), version.to_owned()));
        }
        if let Some(nested) = entry.get("dependencies").and_then(|d| d.as_object()) {
            package_lock_v1(nested, out);
        }
    }
}

/// TOML lockfiles built from `[[package]]` tables: Cargo, Poetry, PDM and uv all use this shape.
pub(super) fn from_package_table_toml(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let (mut name, mut version) = (None, None);
    for line in text.lines().map(str::trim) {
        if line == "[[package]]" {
            name = None;
            version = None;
            continue;
        }
        if let Some(rest) = line.strip_prefix("name = ") {
            name = Some(rest.trim_matches('"').to_owned());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            version = Some(rest.trim_matches('"').to_owned());
        }
        if let (Some(n), Some(v)) = (&name, &version) {
            out.push((n.clone(), v.clone()));
            name = None;
            version = None;
        }
    }
    out
}

/// `Pipfile.lock` is JSON, and its versions carry the `==` with them.
///
/// Every section is read: `default`, `develop` (development packages are listed, as every other
/// ecosystem's are), and any other package category the `Pipfile` adds; `_meta` is the only key
/// that is not packages. Gives the pairs, and the names of the packages with no version: those
/// installed from a repository, a folder, or an address, which Pipenv locks by commit or path.
/// The app's own folder (`"path": "."`, what `pipenv install -e .` writes) is the app, not a
/// package it depends on, and is left out of both.
pub(super) fn from_pipfile_lock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return (Vec::new(), Vec::new());
    };
    let (mut pairs, mut unversioned) = (Vec::new(), Vec::new());
    for (section, packages) in v.as_object().into_iter().flatten() {
        if section == "_meta" {
            continue;
        }
        for (name, entry) in packages.as_object().into_iter().flatten() {
            match entry.get("version").and_then(|x| x.as_str()) {
                // "==3.0.0" is a pin written as a specifier; the version is what follows it.
                Some(version) => {
                    pairs.push((name.clone(), version.trim_start_matches("==").to_owned()))
                }
                None if entry.get("path").and_then(|p| p.as_str()) == Some(".") => {}
                None => unversioned.push(name.clone()),
            }
        }
    }
    unversioned.sort();
    unversioned.dedup();
    (pairs, unversioned)
}

/// The packages a manifest pins to one version, and the names of the rest.
pub(super) type Pinned = (Vec<(String, String)>, Vec<String>);

/// A `Pipfile` read as a manifest, for when there is no `Pipfile.lock`: the packages pinned to one
/// version (`"==2.2.0"`, or a table whose `version` is that), and the names of the rest, which
/// ask for a range, for any version (`"*"`), or for a repository or a folder. `None` when it is
/// not TOML.
pub(super) fn from_pipfile(text: &str) -> Option<Pinned> {
    let doc: toml::Table = text.parse().ok()?;
    let (mut pinned, mut rest) = (Vec::new(), Vec::new());
    for (category, packages) in &doc {
        if sv_scan::deps::PIPFILE_NOT_PACKAGES.contains(&category.as_str()) {
            continue;
        }
        for (name, value) in packages.as_table().into_iter().flatten() {
            let asked = match value {
                toml::Value::String(v) => Some(v.as_str()),
                toml::Value::Table(t) => t.get("version").and_then(|v| v.as_str()),
                _ => None,
            };
            let exact = asked
                .map(str::trim)
                .and_then(|v| v.strip_prefix("===").or_else(|| v.strip_prefix("==")))
                .map(str::trim)
                .filter(|v| !v.is_empty() && !v.contains([',', '*', ' ', ';']));
            match exact {
                Some(version) => pinned.push((name.clone(), version.to_owned())),
                None => rest.push(name.clone()),
            }
        }
    }
    rest.sort();
    rest.dedup();
    Some((pinned, rest))
}

/// Yarn's lockfile, classic or Berry: a header line naming one or more ranges, then an indented
/// version.
///
/// The header is the *range* that was asked for, which is not the package name — `lodash@^4.17.0` and
/// `lodash@~4.17.20` are two headers for one package. Classic Yarn (v1) writes `version "4.17.21"`,
/// and the name is everything before the last `@`, so a scoped package like `@babel/core@^7` keeps its
/// scope. Yarn 2 and later ("Berry", which starts the file with `__metadata:`) write `version: 4.17.21`
/// and put a protocol in each range, `lodash@npm:^4.17.0`, so there the name ends at the first `@`
/// after any scope, and only packages from the registry are listed: the app itself
/// (`@workspace:`), and anything linked from a folder, are not packages anyone publishes advisories
/// about.
/// Yarn's `yarn.lock`, classic (v1) or Berry (v2 and later). Gives the pairs, and the names of the
/// packages it lists with no version from a registry: in Berry, those from a folder, a link, or a
/// repository (`file:`, `link:`, `portal:`, `git`, `https:`, ...); in classic, an entry with no
/// `version` line. The app's own workspaces (`workspace:`) are its own code and are left out.
pub(super) fn from_yarn_lock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let berry = text.lines().any(|l| l.trim_end() == "__metadata:");
    let mut out: Vec<(String, String)> = Vec::new();
    let mut unversioned: Vec<String> = Vec::new();
    let mut pending: Option<String> = None;
    for line in text.lines() {
        if line.trim_start().starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // A classic entry that never said its version.
            if let Some(name) = pending.take()
                && !berry
            {
                unversioned.push(name);
            }
            // A header may list several ranges separated by commas; they are all the same package.
            let first = line.trim_end_matches(':').split(',').next().unwrap_or(line);
            let spec = first.trim().trim_matches('"');
            if spec == "__metadata" {
                continue;
            }
            pending = if berry {
                let at = spec
                    .char_indices()
                    .skip(1)
                    .find(|(_, c)| *c == '@')
                    .map(|(i, _)| i);
                match at {
                    Some(i) => {
                        let protocol = &spec[i + 1..];
                        if protocol.starts_with("npm:") || protocol.starts_with("patch:") {
                            Some(spec[..i].to_owned())
                        } else {
                            if !protocol.starts_with("workspace:") {
                                unversioned.push(spec[..i].to_owned());
                            }
                            None
                        }
                    }
                    None => None,
                }
            } else {
                spec.rfind('@')
                    .filter(|i| *i > 0)
                    .map(|i| spec[..i].to_owned())
            };
            continue;
        }
        let version = if berry {
            line.trim().strip_prefix("version:")
        } else {
            line.trim().strip_prefix("version ")
        };
        if let Some(rest) = version
            && let Some(name) = pending.take()
        {
            out.push((name, rest.trim().trim_matches('"').to_owned()));
        }
    }
    if let Some(name) = pending
        && !berry
    {
        unversioned.push(name);
    }
    out.sort();
    out.dedup();
    unversioned.sort();
    unversioned.dedup();
    (out, unversioned)
}

/// Bun's text lockfile (Bun 1.2 and later): JSON that allows a comma before a closing bracket.
/// `packages` maps each install path to an array whose first entry is `name@version`. An entry
/// whose version names a protocol (`workspace:`, `file:`, `github:`, and the like) is not a package
/// from the registry, and is left out as Yarn's are.
pub(super) fn from_bun_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&without_trailing_commas(text)) else {
        return Vec::new();
    };
    let mut out: Vec<(String, String)> = v
        .get("packages")
        .and_then(|p| p.as_object())
        .into_iter()
        .flat_map(|p| p.values())
        .filter_map(|entry| entry.get(0)?.as_str())
        .filter_map(|spec| {
            let at = spec.rfind('@').filter(|i| *i > 0)?;
            let (name, version) = (&spec[..at], &spec[at + 1..]);
            (!name.is_empty() && !version.is_empty() && !version.contains(':'))
                .then(|| (name.to_owned(), version.to_owned()))
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// JSON with every comma that stands just before a `}` or `]` removed, outside strings.
pub(super) fn without_trailing_commas(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for (i, &c) in chars.iter().enumerate() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        if c == '"' {
            in_string = true;
        } else if c == ','
            && chars[i + 1..]
                .iter()
                .find(|n| !n.is_whitespace())
                .is_some_and(|n| *n == '}' || *n == ']')
        {
            continue;
        }
        out.push(c);
    }
    out
}

/// Gradle's lockfile: `group:artifact:version=configuration,configuration`.
pub(super) fn from_gradle_lockfile(text: &str) -> Vec<(String, String)> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split('=').next())
        .filter_map(|coord| {
            // `group:artifact:version`; the version follows the last colon. A line with no colon at
            // all is Gradle's `empty=configuration` marker, which is not a package.
            let (name, version) = coord.rsplit_once(':')?;
            (!version.is_empty() && !name.is_empty()).then(|| (name.to_owned(), version.to_owned()))
        })
        .collect()
}

pub(super) fn from_composer_lock(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in ["packages", "packages-dev"] {
        if let Some(list) = v.get(key).and_then(|p| p.as_array()) {
            for entry in list {
                if let (Some(n), Some(ver)) = (
                    entry.get("name").and_then(|x| x.as_str()),
                    entry.get("version").and_then(|x| x.as_str()),
                ) {
                    out.push((n.to_owned(), ver.to_owned()));
                }
            }
        }
    }
    out
}

/// pnpm's lockfile, read without a YAML parser.
///
/// Deliberate. The only YAML needed here is the set of keys directly under `packages:`, and the
/// established serde YAML crate has been archived since 2024 — putting an unmaintained parser into a tool
/// whose subject is supply-chain hygiene is a poor trade for one file format. So this reads the one block
/// it needs and refuses to guess at anything else.
///
/// Returns an empty list when the file does not look like a pnpm lockfile it understands. The caller
/// turns that into "read, and no packages could be taken from it", which is the honest thing to tell
/// somebody and is checked one place rather than two — an inner guard here duplicated it and could be
/// deleted without any test noticing.
///
/// Two key shapes, and peer suffixes on either:
///   v9:  `express@4.18.2:` and `@babel/core@7.23.0:`, sometimes `vite@5.0.0(terser@5.0.0):`
///   v6:  `/express@4.18.2:` and `/@babel/core@7.23.0:`, with peer variants in brackets as in v9
///   v5:  `/express/4.18.2:` and `/@babel/core/7.23.0:`, sometimes `/foo/1.0.0_bar@2.0.0:`
pub(super) fn from_pnpm_lock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let mut out = Vec::new();
    let mut unversioned = Vec::new();
    let mut in_packages = false;
    // Lockfile 5.x writes `/name/version`, with a peer variant after `_`; 6.0 and later write
    // `/name@version` and `name@version`, with a peer variant in brackets. Without the version
    // line, the `@` shape is tried first and the slash shape after it.
    let slash_shape = text
        .lines()
        .find_map(|l| l.strip_prefix("lockfileVersion:"))
        .map(|v| v.trim().trim_matches(|c| c == '\'' || c == '"'))
        .and_then(|v| v.split('.').next()?.parse::<u32>().ok())
        .is_some_and(|major| major <= 5);

    for line in text.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        // A key at column zero ends whatever block we were in.
        if !line.starts_with(' ') {
            in_packages = line.trim_end() == "packages:";
            continue;
        }
        if !in_packages {
            continue;
        }
        // Only the block's own keys, which are indented one level; anything deeper describes a package.
        let indent = line.len() - line.trim_start().len();
        if indent != 2 {
            continue;
        }
        let key = line.trim();
        let Some(key) = key.strip_suffix(':') else {
            continue;
        };
        let key = key.trim_matches(|c| c == '\'' || c == '"');
        // `vite@5.0.0(terser@5.0.0)` is one package with a peer variant, not two.
        let key = key.split('(').next().unwrap_or(key);
        let rest = key.strip_prefix('/').unwrap_or(key);

        let by_at = || {
            // name@version, where a scoped name contains its own @.
            rest.rsplit_once('@')
                .filter(|(name, _)| !name.is_empty())
                .map(|(name, version)| (name.to_owned(), version.to_owned()))
        };
        let by_slash = || {
            // name/version, where a scoped name contains a slash of its own, and the version may
            // carry a peer variant after `_`.
            rest.rsplit_once('/').map(|(name, version)| {
                let version = version.split('_').next().unwrap_or(version);
                (name.to_owned(), version.to_owned())
            })
        };
        let parsed = if slash_shape {
            by_slash()
        } else {
            by_at().or_else(by_slash)
        };
        // A version starts with a digit. A key whose version is an address (`file:`, `https:`,
        // `link:`) is a package installed from somewhere else, named as such; a key that fits
        // neither shape is not invented into a package.
        match parsed {
            Some((name, version)) if version.starts_with(|c: char| c.is_ascii_digit()) => {
                out.push((name, version));
            }
            Some((name, version)) if version.contains(':') => unversioned.push(name),
            _ => {}
        }
    }

    out.sort();
    out.dedup();
    unversioned.sort();
    unversioned.dedup();
    (out, unversioned)
}

pub(super) fn from_gemfile_lock(text: &str) -> Vec<(String, String)> {
    // Specs are indented four spaces under `specs:`; their dependencies are indented six and are not
    // separate packages.
    let mut out = Vec::new();
    let mut in_specs = false;
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        if in_specs && !trimmed.starts_with("    ") {
            in_specs = false;
        }
        if !in_specs || trimmed.starts_with("      ") {
            continue;
        }
        let entry = trimmed.trim();
        // `nokogiri (1.15.4-x86_64-linux)`: Bundler writes a gem built for one platform with the
        // platform after the first `-`, and reads it back the same way, so the version is what
        // comes before it. Kept, the platform would read as a pre-release of 1.15.4.
        if let Some((name, rest)) = entry.split_once(" (")
            && let Some(version) = rest.strip_suffix(')')
        {
            let version = version.split('-').next().unwrap_or(version);
            out.push((name.to_owned(), version.to_owned()));
        }
    }
    out
}

/// What go.mod says is built: one version of each module, and the modules swapped for a folder.
#[derive(Debug, Default)]
pub(super) struct GoModules {
    pub(super) pairs: Vec<(String, String)>,
    pub(super) local: Vec<String>,
}

/// The modules a Go app is built from, and the one version of each, from go.mod: its `require`
/// lines, with its `replace` lines applied. go.sum keeps a checksum for every version Go has looked
/// at, older ones included, so reading it as the versions in use reported versions the app no
/// longer builds with (A3 of the deep review).
///
/// From Go 1.17 on, go.mod lists every module in the build, indirect ones too. Before it, or with no
/// `go` line, which Go reads as 1.16, it may not, and a module named only in go.sum is given the
/// highest version there: the one Go would choose whenever go.sum holds the version it chose.
pub(super) fn from_go_mod(go_mod: &str, go_sum: Option<&str>) -> GoModules {
    let words = |line: &str| -> Vec<String> {
        let line = line.split("//").next().unwrap_or("");
        line.split_whitespace()
            .map(|w| w.trim_matches('"').to_owned())
            .collect()
    };
    let (mut required, mut replaces) = (Vec::<(String, String)>::new(), Vec::new());
    let mut go_version: Option<String> = None;
    let mut block: Option<String> = None;
    for raw in go_mod.lines() {
        let w = words(raw);
        if w.is_empty() {
            continue;
        }
        if block.is_some() && w[0] == ")" {
            block = None;
            continue;
        }
        if block.is_none() && w.get(1).is_some_and(|x| x == "(") {
            block = Some(w[0].clone());
            continue;
        }
        let (verb, rest): (&str, &[String]) = match &block {
            Some(verb) => (verb.as_str(), &w[..]),
            None => (w[0].as_str(), &w[1..]),
        };
        match verb {
            "go" => go_version = rest.first().cloned(),
            "require" if rest.len() >= 2 => required.push((rest[0].clone(), rest[1].clone())),
            "replace" => {
                if let Some(arrow) = rest.iter().position(|x| x == "=>") {
                    let old = &rest[..arrow];
                    let new = &rest[arrow + 1..];
                    if let (Some(old_path), Some(new_path)) = (old.first(), new.first()) {
                        replaces.push((
                            old_path.clone(),
                            old.get(1).cloned(),
                            new_path.clone(),
                            new.get(1).cloned(),
                        ));
                    }
                }
            }
            _ => {}
        }
    }
    // Before 1.17, go.mod may leave out the indirect modules; go.sum names them.
    let lists_everything = go_version.as_deref().is_some_and(|v| {
        crate::advisories::compare(v, "1.17").is_some_and(|o| o != std::cmp::Ordering::Less)
    });
    if !lists_everything && let Some(sum) = go_sum {
        let mut highest: Vec<(String, String)> = Vec::new();
        for (name, version) in from_go_sum(sum) {
            if required.iter().any(|(r, _)| *r == name) {
                continue;
            }
            match highest.iter_mut().find(|(n, _)| *n == name) {
                Some((_, kept)) => {
                    if crate::advisories::compare(&version, kept)
                        == Some(std::cmp::Ordering::Greater)
                    {
                        *kept = version;
                    }
                }
                None => highest.push((name, version)),
            }
        }
        required.extend(highest);
    }
    let mut out = GoModules::default();
    for (name, version) in required {
        let replaced = replaces
            .iter()
            .find(|(old, old_version, _, _)| {
                *old == name && old_version.as_ref().is_none_or(|v| *v == version)
            })
            .map(|(_, _, new, new_version)| (new.clone(), new_version.clone()));
        match replaced {
            None => out.pairs.push((name, version)),
            Some((new, Some(new_version))) => out.pairs.push((new, new_version)),
            Some((_, None)) => out.local.push(name),
        }
    }
    out
}

pub(super) fn from_go_sum(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(name), Some(version)) = (parts.next(), parts.next()) else {
            continue;
        };
        // `module v1.2.3/go.mod h1:…` repeats the module; keep the one naming the module itself.
        if version.ends_with("/go.mod") {
            continue;
        }
        out.push((name.to_owned(), version.to_owned()));
    }
    out
}

/// Exact pins only. `flask>=2` says which versions are acceptable, not which one is there.
/// A line may end in an environment marker, `colorama==0.4.6 ; sys_platform == 'win32'`, with or
/// without the space before the `;`. The marker is not read: the package is listed wherever it would
/// be installed, which for the comparison with advisories is the safe side, and makes the list say
/// slightly more than one computer installs.
/// PEP 751's `pylock.toml`: a `[[packages]]` entry for everything installed, transitive
/// dependencies included, each with its `name` and, when it comes from an index, its `version`. A
/// TOML reading rather than a line one: each package's `[[packages.wheels]]` carry a `name` too,
/// which is a file name. Gives the pairs, and the names of the packages with no version.
pub(super) fn from_pylock(text: &str) -> (Vec<(String, String)>, Vec<String>) {
    let Ok(table) = text.parse::<toml::Table>() else {
        return (Vec::new(), Vec::new());
    };
    let (mut pairs, mut unversioned) = (Vec::new(), Vec::new());
    for package in table
        .get("packages")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
    {
        let Some(name) = package.get("name").and_then(|n| n.as_str()) else {
            continue;
        };
        match package.get("version").and_then(|v| v.as_str()) {
            Some(version) => pairs.push((name.to_owned(), version.to_owned())),
            None => unversioned.push(name.to_owned()),
        }
    }
    (pairs, unversioned)
}

pub(super) fn from_pinned_requirements(text: &str) -> Vec<(String, String)> {
    from_requirements(text).0
}

/// A requirements file read line by line: the packages pinned to one version (`name==1.0`), and
/// what else it installs, by name: a package asking for a range or for any version (`flask>=2`,
/// `gunicorn`), one installed from an address or a folder, and another requirements file it pulls
/// in (`-r base.txt`). Deep review H9: before, all of those were left out without a word, so a
/// `requirements.txt` with no lockfile had a list that looked like everything it asked for.
///
/// `-e .` is the app itself, as in `Pipfile.lock`, and is not named. A constraints file (`-c`) and
/// the lines that only say where pip looks install nothing.
pub(super) fn from_requirements(text: &str) -> Pinned {
    let (mut pinned, mut rest) = (Vec::new(), Vec::new());
    // A line ending in `\` goes on on the next one, as pip reads it.
    let joined = text.replace("\\\r\n", " ").replace("\\\n", " ");
    for line in joined.lines() {
        // A comment starts at a `#` at the start of a line or after a space.
        let line = match line.find(" #") {
            Some(i) => &line[..i],
            None => line,
        };
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('-') {
            let (option, value) = line
                .split_once(['=', ' ', '\t'])
                .map_or((line, ""), |(o, v)| (o, v.trim()));
            match option {
                "-r" | "--requirement" => rest.push(format!("`{value}`, which it pulls in")),
                "-e" | "--editable" if !matches!(value, "." | "./") && !value.starts_with(".[") => {
                    rest.push(requirement_name(value))
                }
                _ => {}
            }
            continue;
        }
        let requirement = line.split_once(';').map_or(line, |(r, _marker)| r).trim();
        let exact = requirement
            .split_once("==")
            .filter(|(name, _)| !name.contains(['<', '>', '!', '~', '@']))
            .map(|(name, version)| {
                (
                    name,
                    version
                        .trim_start_matches('=')
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim(),
                )
            })
            .filter(|(_, version)| !version.is_empty() && !version.contains(['*', ',']));
        match exact {
            // `name[extra]==1.0` installs `name`.
            Some((name, version)) => pinned.push((
                name.split('[').next().unwrap_or(name).trim().to_owned(),
                version.to_owned(),
            )),
            None => rest.push(requirement_name(requirement)),
        }
    }
    rest.sort();
    rest.dedup();
    (pinned, rest)
}

/// The package a requirement names: the name at its start, the `#egg=` of an address, or, when
/// neither is there, the requirement itself.
pub(super) fn requirement_name(requirement: &str) -> String {
    let name: String = requirement
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        .collect();
    // `git+https://…` and `https://…` start with their scheme, not a name; `pkg @ https://…` does not.
    let after = &requirement[name.len()..];
    let address =
        after.starts_with("://") || after.starts_with('+') || requirement.starts_with(['.', '/']);
    if !name.is_empty() && !address {
        return name;
    }
    match requirement.split_once("#egg=") {
        Some((_, egg)) => egg.split('&').next().unwrap_or(egg).to_owned(),
        None => requirement.chars().take(60).collect(),
    }
}
