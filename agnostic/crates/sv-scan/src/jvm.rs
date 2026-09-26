//! Whether a Maven or Gradle build pins the versions it asks for.
//!
//! Neither uses a lockfile by default. Maven has none at all, and Gradle's `gradle.lockfile` is
//! something a project turns on. Both resolve the same versions every time when every version the
//! build names is exact, so for them "does this app pin what it installs" is answered by reading the
//! versions rather than by looking for a file. Asking for the file instead reported every Gradle
//! project without one as pinning nothing, which is the wrong statement ADR-012 exists to stop, and
//! left every Maven project as an open question forever.
//!
//! Each version lands in one of three places:
//!
//! - **exact** (`1.2.3`, Maven's `[1.2.3]`, Gradle's `1.2.3!!`), or given by something that is (a
//!   parent POM, a BOM, a platform, the Kotlin plugin), or your own project's version;
//! - **floating**: a range, `LATEST` or `RELEASE`, Gradle's `1.+` and `latest.release`, and a
//!   `-SNAPSHOT`, which is republished under the same version. The build takes whatever is newest
//!   when it runs;
//! - **unsettled**: what `sv` cannot work out from the files — a property set in a parent outside
//!   the folder or on the command line, a variable it cannot find, a line it does not understand.
//!   Never counted as either of the others.
//!
//! Not a resolver, and it says what it does not see. It reads the versions this build names, not
//! the ones its dependencies name in turn: a library that asks for a range of another library can
//! still move underneath an app whose own versions are all exact. That is rare on Maven Central and
//! is written down in DESIGN rather than claimed away. Build plugins (Maven's `<build>`, Gradle's
//! `plugins {}` and `classpath`) are left out: they build the app and are not shipped in it.

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

/// A version that is floating or unsettled, with where it is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionAt {
    /// The build file's path from the app folder.
    pub manifest: String,
    pub line: usize,
    /// `group:artifact`, or what the line said when it could not be read as one.
    pub dependency: String,
    /// As written, and as resolved when a property stood for it: `${spring.version} = [5.0,6.0)`.
    pub version: String,
    /// Why it is floating or unsettled, in words the owner can read.
    pub why: String,
}

/// What reading one build file found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reading {
    /// Dependencies whose version is exact, or given by something that is.
    pub exact: usize,
    pub floating: Vec<VersionAt>,
    pub unsettled: Vec<VersionAt>,
}

enum Kind {
    Exact,
    Floating(&'static str),
}

const RANGE: &str = "a range, which takes the newest version inside it when the build runs";
const NEWEST: &str = "whatever version is newest when the build runs";
const PLUS: &str = "a prefix ending in `+`, which takes the newest version that matches it";
const SNAPSHOT: &str = "a snapshot, which is republished under the same version number";

fn classify(version: &str, gradle: bool) -> Kind {
    let v = version.trim();
    let v = if gradle { v.trim_end_matches("!!") } else { v };
    if v.ends_with("-SNAPSHOT") {
        return Kind::Floating(SNAPSHOT);
    }
    if !gradle && matches!(v, "LATEST" | "RELEASE") {
        return Kind::Floating(NEWEST);
    }
    if gradle && v.starts_with("latest.") {
        return Kind::Floating(NEWEST);
    }
    if gradle && v.contains('+') {
        return Kind::Floating(PLUS);
    }
    if v.starts_with(['[', '(']) || (gradle && v.starts_with(']')) {
        // `[1.2.3]` is Maven's and Gradle's way of saying exactly 1.2.3.
        let inner = &v[1..v.len().saturating_sub(1)];
        let closed = v.starts_with('[') && v.ends_with(']');
        return if closed && !inner.contains(',') && !inner.is_empty() {
            Kind::Exact
        } else {
            Kind::Floating(RANGE)
        };
    }
    Kind::Exact
}

/// Blanks every match of `re` while keeping every byte offset and line number where it was.
fn blank(text: &str, re: &Regex) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for m in re.find_iter(text) {
        out.push_str(&text[last..m.start()]);
        for c in m.as_str().chars() {
            if c == '\n' {
                out.push('\n');
            } else {
                out.extend(std::iter::repeat_n(' ', c.len_utf8()));
            }
        }
        last = m.end();
    }
    out.push_str(&text[last..]);
    out
}

fn line_at(text: &str, byte: usize) -> usize {
    text[..byte].matches('\n').count() + 1
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("a valid pattern")
}

/// Records one written version: exact, floating, or unsettled.
fn judge(
    reading: &mut Reading,
    at: (&str, usize),
    dependency: String,
    resolved: Result<String, String>,
    written: &str,
    gradle: bool,
) {
    let (manifest, line) = at;
    let version = match &resolved {
        Ok(v) if v != written => format!("{written} = {v}"),
        _ => written.to_owned(),
    };
    let push = |why: String| VersionAt {
        manifest: manifest.to_owned(),
        line,
        dependency,
        version,
        why,
    };
    match resolved {
        Err(why) => reading.unsettled.push(push(why)),
        Ok(v) => match classify(&v, gradle) {
            Kind::Exact => reading.exact += 1,
            Kind::Floating(why) => reading.floating.push(push(why.to_owned())),
        },
    }
}

// ---------------------------------------------------------------------------------------------
// Maven

static XML_COMMENT: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<!--.*?-->"));
static BUILD: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<build>.*?</build>"));
static REPORTING: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<reporting>.*?</reporting>"));
static PROPERTIES: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<properties>(.*?)</properties>"));
static PROPERTY: LazyLock<Regex> = LazyLock::new(|| re(r"<([\w.\-]+)>\s*([^<]*?)\s*</([\w.\-]+)>"));
static PARENT: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<parent>(.*?)</parent>"));
static DEPENDENCY: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)<dependency>(.*?)</dependency>"));
static MANAGEMENT: LazyLock<Regex> =
    LazyLock::new(|| re(r"(?s)<dependencyManagement>(.*?)</dependencyManagement>"));
static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| re(r"\$\{([^}]+)\}"));

/// Properties that stand for the project's own version: a dependency on one of your own modules.
const OWN_VERSION: &[&str] = &[
    "project.version",
    "version",
    "pom.version",
    "project.parent.version",
    "parent.version",
];

/// The text of `<name>` inside `block`, and where it starts in `block`.
fn tag<'a>(block: &'a str, name: &str) -> Option<(&'a str, usize)> {
    let open = format!("<{name}>");
    let start = block.find(&open)? + open.len();
    let end = start + block[start..].find(&format!("</{name}>"))?;
    Some((block[start..end].trim(), start))
}

fn pom_properties(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for block in PROPERTIES.captures_iter(text) {
        for p in PROPERTY.captures_iter(&block[1]) {
            if p[1] == p[3] {
                out.entry(p[1].to_owned())
                    .or_insert_with(|| p[2].to_owned());
            }
        }
    }
    out
}

/// Adds the properties of the parent POM when it is in the app folder, then of its parent, the way
/// Maven inherits them; the nearer one wins.
fn inherit(
    app_dir: &Path,
    pom: &Path,
    parent: &str,
    props: &mut BTreeMap<String, String>,
    depth: usize,
) {
    if depth > 8 || parent.contains("<relativePath/>") {
        return;
    }
    let relative = tag(parent, "relativePath").map_or("../pom.xml", |(r, _)| r);
    if relative.is_empty() {
        return;
    }
    let Some(dir) = pom.parent() else { return };
    let mut candidate = dir.join(relative);
    if candidate.is_dir() {
        candidate = candidate.join("pom.xml");
    }
    let (Ok(found), Ok(root)) = (candidate.canonicalize(), app_dir.canonicalize()) else {
        return;
    };
    let Ok(text) = std::fs::read_to_string(&found) else {
        return;
    };
    if !found.starts_with(&root) {
        return;
    }
    let text = blank(&text, &XML_COMMENT);
    // The file at that path is the parent only if it is the project the parent section names.
    let own = blank(&text, &PARENT);
    if tag(&own, "artifactId").map(|(a, _)| a) != tag(parent, "artifactId").map(|(a, _)| a) {
        return;
    }
    for (k, v) in pom_properties(&text) {
        props.entry(k).or_insert(v);
    }
    if let Some(next) = PARENT.captures(&text) {
        inherit(app_dir, &found, &next[1], props, depth + 1);
    }
}

/// The version once every `${…}` in it is replaced, or why it could not be. `None` when it is the
/// project's own version, which is a dependency on one of your own modules and exact by definition.
fn resolve_pom(written: &str, props: &BTreeMap<String, String>) -> Option<Result<String, String>> {
    let mut v = written.to_owned();
    for _ in 0..10 {
        let Some(c) = PLACEHOLDER.captures(&v) else {
            return Some(Ok(v));
        };
        let name = c[1].to_owned();
        if OWN_VERSION.contains(&name.as_str()) {
            return None;
        }
        let Some(value) = props.get(&name) else {
            return Some(Err(format!(
                "`${{{name}}}` is set somewhere `sv` did not read: a parent outside this folder, a \
                 profile, or the command line"
            )));
        };
        v = v.replacen(&c[0], value, 1);
    }
    Some(Err(
        "its properties refer to each other too many times to follow".to_owned(),
    ))
}

/// Reads a `pom.xml`. `None` when the file cannot be read at all.
pub fn read_pom(app_dir: &Path, manifest: &str) -> Option<Reading> {
    let path = app_dir.join(manifest);
    let text = blank(&std::fs::read_to_string(&path).ok()?, &XML_COMMENT);
    let mut props = pom_properties(&text);
    let parent = PARENT.captures(&text).map(|c| c.get(1).expect("a group"));
    if let Some(p) = parent {
        inherit(app_dir, &path, p.as_str(), &mut props, 0);
    }

    let mut reading = Reading::default();
    if let Some(p) = parent {
        let block = p.as_str();
        let name = format!(
            "{}:{} (the parent)",
            tag(block, "groupId").map_or("", |t| t.0),
            tag(block, "artifactId").map_or("", |t| t.0)
        );
        match tag(block, "version") {
            Some((v, at)) => {
                let line = line_at(&text, p.start() + at);
                if let Some(resolved) = resolve_pom(v, &props) {
                    judge(&mut reading, (manifest, line), name, resolved, v, false);
                } else {
                    reading.exact += 1;
                }
            }
            None => reading.unsettled.push(VersionAt {
                manifest: manifest.to_owned(),
                line: line_at(&text, p.start()),
                dependency: name,
                version: String::new(),
                why: "the parent section names no version".to_owned(),
            }),
        }
    }

    let body = blank(&blank(&text, &BUILD), &REPORTING);
    let mut managed = BTreeSet::new();
    let mut boms = false;
    for m in MANAGEMENT.captures_iter(&body) {
        for d in DEPENDENCY.captures_iter(&m[1]) {
            let key = |t| tag(&d[1], t).map_or("", |x: (&str, usize)| x.0);
            managed.insert(format!("{}:{}", key("groupId"), key("artifactId")));
            boms |= key("scope") == "import";
        }
    }

    let opened = body.matches("<dependency>").count();
    let mut read = 0;
    for d in DEPENDENCY.captures_iter(&body) {
        read += 1;
        let whole = d.get(1).expect("a group");
        let block = whole.as_str();
        let name = format!(
            "{}:{}",
            tag(block, "groupId").map_or("", |t| t.0),
            tag(block, "artifactId").map_or("", |t| t.0)
        );
        match tag(block, "version") {
            Some((v, at)) => {
                let line = line_at(&body, whole.start() + at);
                match resolve_pom(v, &props) {
                    Some(resolved) => {
                        judge(&mut reading, (manifest, line), name, resolved, v, false)
                    }
                    None => reading.exact += 1,
                }
            }
            // No version: Maven takes it from dependency management here, a BOM imported there,
            // or the parent — each of which is read and judged in its own right.
            None if managed.contains(&name) || boms || parent.is_some() => reading.exact += 1,
            None => reading.unsettled.push(VersionAt {
                manifest: manifest.to_owned(),
                line: line_at(&body, whole.start()),
                dependency: name,
                version: String::new(),
                why: "no version, and nothing in this file or a parent says which".to_owned(),
            }),
        }
    }
    if read != opened {
        reading.unsettled.push(VersionAt {
            manifest: manifest.to_owned(),
            line: 1,
            dependency: "the <dependency> sections".to_owned(),
            version: String::new(),
            why: format!("{opened} are opened and {read} could be read"),
        });
    }
    Some(reading)
}

// ---------------------------------------------------------------------------------------------
// Gradle

static BLOCK_COMMENT: LazyLock<Regex> = LazyLock::new(|| re(r"(?s)/\*.*?\*/"));
// A `//` at the start of a line or after a space is a comment; one after `:` is an address.
static LINE_COMMENT: LazyLock<Regex> = LazyLock::new(|| re(r"(?m)(^|\s)//.*$"));
static DECLARATION: LazyLock<Regex> = LazyLock::new(|| re(r"^([A-Za-z_]\w*)\s*[(\s](.*)$"));
static QUOTED: LazyLock<Regex> = LazyLock::new(|| re(r#"["']([^"']*)["']"#));
static COORDINATE_LIKE: LazyLock<Regex> =
    LazyLock::new(|| re(r#"["'][\w.\-]+:[\w.\-]+(:[^"']*)?["']"#));
static CATALOG: LazyLock<Regex> = LazyLock::new(|| re(r"\blibs\.([\w.]+)"));
static MAP_GROUP: LazyLock<Regex> = LazyLock::new(|| re(r#"\bgroup\s*[:=]\s*["']([^"']+)["']"#));
static MAP_NAME: LazyLock<Regex> = LazyLock::new(|| re(r#"\bname\s*[:=]\s*["']([^"']+)["']"#));
static MAP_VERSION: LazyLock<Regex> =
    LazyLock::new(|| re(r#"\bversion\s*[:=]\s*["']([^"']+)["']"#));
static RICH: LazyLock<Regex> =
    LazyLock::new(|| re(r#"\b(strictly|require|prefer)\s*[(=]?\s*["']([^"']+)["']"#));
static VARIABLE: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"(?m)(?:\b(?:val|var|def)\s+|\bext\.|\bextra\[")?(\w+)"?\]?\s*=\s*["']([^"'$]+)["']"#)
});
static INTERPOLATION: LazyLock<Regex> = LazyLock::new(|| {
    re(r#"\$\{(?:project\.)?(?:property|findProperty)\(["'](\w+)["']\)\}|\$\{([\w.]+)\}|\$(\w+)"#)
});

/// The configurations a dependency is declared in, by how their names end: `implementation`,
/// `testImplementation`, `debugApi`, `kapt`, and the rest. `classpath` is the build's own tooling.
fn is_configuration(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "implementation",
        "api",
        "compileonly",
        "runtimeonly",
        "compile",
        "runtime",
        "annotationprocessor",
        "kapt",
        "ksp",
        "developmentonly",
    ]
    .iter()
    .any(|c| lower.ends_with(c))
}

/// Line ranges `(start, end)` of every `dependencies { … }` block, by index into `lines`.
fn dependency_blocks(lines: &[&str]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut open: Vec<(usize, i32)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let starts = t.starts_with("dependencies")
            && t["dependencies".len()..].trim_start().starts_with('{');
        if starts {
            open.push((i, depth));
        }
        let mut quote: Option<char> = None;
        for c in line.chars() {
            match (quote, c) {
                (Some(q), c) if c == q => quote = None,
                (Some(_), _) => {}
                (None, '"' | '\'') => quote = Some(c),
                (None, '{') => depth += 1,
                (None, '}') => {
                    depth -= 1;
                    if let Some(&(start, at)) = open.last()
                        && depth == at
                    {
                        out.push((start, i));
                        open.pop();
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Values the build file and `gradle.properties` give to names, for `"g:a:$version"`.
fn gradle_variables(app_dir: &Path, manifest: &str, text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for c in VARIABLE.captures_iter(text) {
        out.entry(c[1].to_owned())
            .or_insert_with(|| c[2].to_owned());
    }
    for dir in folders_up(manifest) {
        let Ok(props) = std::fs::read_to_string(app_dir.join(dir).join("gradle.properties")) else {
            continue;
        };
        for line in props.lines().map(str::trim) {
            if line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once(['=', ':']) {
                out.entry(k.trim().to_owned())
                    .or_insert_with(|| v.trim().to_owned());
            }
        }
    }
    out
}

/// The build file's folder and each one above it, up to the app folder: `a/b`, `a`, ``.
fn folders_up(manifest: &str) -> Vec<String> {
    let mut parts: Vec<&str> = manifest.split('/').collect();
    parts.pop();
    let mut out = Vec::new();
    loop {
        out.push(parts.join("/"));
        if parts.pop().is_none() {
            return out;
        }
    }
}

fn resolve_gradle(written: &str, vars: &BTreeMap<String, String>) -> Result<String, String> {
    let mut v = written.to_owned();
    for _ in 0..10 {
        let Some(c) = INTERPOLATION.captures(&v) else {
            return Ok(v);
        };
        let name = c
            .get(1)
            .or(c.get(2))
            .or(c.get(3))
            .expect("a group")
            .as_str();
        let short = name.rsplit('.').next().unwrap_or(name);
        let Some(value) = vars.get(name).or(vars.get(short)) else {
            return Err(format!(
                "`{}` is set somewhere `sv` did not read: another build file, a plugin, or the \
                 command line",
                &c[0]
            ));
        };
        v = v.replacen(&c[0], value, 1);
    }
    Err("its variables refer to each other too many times to follow".to_owned())
}

/// A version catalog: `gradle/libs.versions.toml`, which `libs.…` in a build file reads from.
struct Catalog {
    path: String,
    table: toml::Table,
}

fn find_catalog(app_dir: &Path, manifest: &str) -> Option<Catalog> {
    folders_up(manifest).into_iter().find_map(|dir| {
        let rel = if dir.is_empty() {
            "gradle/libs.versions.toml".to_owned()
        } else {
            format!("{dir}/gradle/libs.versions.toml")
        };
        let text = std::fs::read_to_string(app_dir.join(&rel)).ok()?;
        Some(Catalog {
            path: rel,
            table: text.parse().ok()?,
        })
    })
}

fn alias(s: &str) -> String {
    s.to_ascii_lowercase().replace(['-', '_'], ".")
}

/// One catalog library as `(group:artifact, version)`; the version is `None` when the entry names
/// none, and an error when it names one `sv` cannot find.
type CatalogEntry = (String, Option<Result<String, String>>);

fn catalog_library(catalog: &Catalog, accessor: &str) -> Option<CatalogEntry> {
    let libraries = catalog.table.get("libraries")?.as_table()?;
    let (_, entry) = libraries
        .iter()
        .find(|(k, _)| alias(k) == alias(accessor))?;
    let versions = catalog.table.get("versions").and_then(|v| v.as_table());
    let rich = |v: &toml::Value| -> Option<String> {
        match v {
            toml::Value::String(s) => Some(s.clone()),
            toml::Value::Table(t) => ["strictly", "require", "prefer"]
                .iter()
                .find_map(|k| t.get(*k)?.as_str().map(str::to_owned)),
            _ => None,
        }
    };
    Some(match entry {
        toml::Value::String(s) => {
            let mut parts = s.splitn(3, ':');
            let coordinate = format!("{}:{}", parts.next()?, parts.next()?);
            (coordinate, parts.next().map(|v| Ok(v.to_owned())))
        }
        toml::Value::Table(t) => {
            let coordinate = match t.get("module").and_then(|m| m.as_str()) {
                Some(m) => m.to_owned(),
                None => format!("{}:{}", t.get("group")?.as_str()?, t.get("name")?.as_str()?),
            };
            let version = t.get("version").map(|v| match v {
                toml::Value::Table(r) if r.contains_key("ref") => {
                    let name = r["ref"].as_str().unwrap_or_default();
                    versions
                        .and_then(|vs| vs.get(name))
                        .and_then(rich)
                        .ok_or_else(|| {
                            format!("the catalog's `{name}` version is not in its [versions]")
                        })
                }
                other => {
                    rich(other).ok_or_else(|| "the catalog's version is not readable".to_owned())
                }
            });
            (coordinate, version)
        }
        _ => return None,
    })
}

/// Reads a `build.gradle` or `build.gradle.kts`. `None` when the file cannot be read at all.
pub fn read_gradle(app_dir: &Path, manifest: &str) -> Option<Reading> {
    let raw = std::fs::read_to_string(app_dir.join(manifest)).ok()?;
    let text = blank(&blank(&raw, &BLOCK_COMMENT), &LINE_COMMENT);
    let lines: Vec<&str> = text.split('\n').collect();
    let vars = gradle_variables(app_dir, manifest, &text);
    let catalog = find_catalog(app_dir, manifest);
    // Where a dependency without a version gets one: a platform or BOM, Spring's dependency
    // management plugin, constraints, or the Kotlin plugin for Kotlin's own libraries.
    let managed = [
        "platform(",
        "enforcedPlatform(",
        "io.spring.dependency-management",
        "dependencyManagement",
        "mavenBom",
        "constraints",
    ]
    .iter()
    .any(|m| text.contains(m));
    let kotlin_plugin = text.contains("org.jetbrains.kotlin") || text.contains("kotlin(\"");

    let mut reading = Reading::default();
    let mut seen = BTreeSet::new();
    for (start, end) in dependency_blocks(&lines) {
        for i in start + 1..end {
            if !seen.insert(i) {
                continue; // a line inside two blocks (buildscript's, say) is read once
            }
            let line = lines[i].trim();
            let at = (manifest, i + 1);
            let Some(decl) = DECLARATION
                .captures(line)
                .filter(|c| is_configuration(&c[1]))
            else {
                // Not a declaration this reads. If it still names a coordinate, it is one written
                // some other way (`add("implementation", …)`), and it is said rather than skipped.
                if COORDINATE_LIKE.is_match(line)
                    && !RICH.is_match(line)
                    && !line.starts_with("classpath")
                    && !line.starts_with("exclude")
                {
                    reading.unsettled.push(VersionAt {
                        manifest: manifest.to_owned(),
                        line: i + 1,
                        dependency: line.to_owned(),
                        version: String::new(),
                        why: "a dependency written in a way `sv` does not read".to_owned(),
                    });
                }
                continue;
            };
            let arg = decl[2].trim();
            if [
                "project(",
                "files(",
                "fileTree(",
                "gradleApi(",
                "localGroovy(",
                "gradleTestKit(",
            ]
            .iter()
            .any(|s| arg.contains(s))
            {
                continue; // your own code, or files kept in the repository
            }
            if let Some(c) = CATALOG.captures(arg) {
                let path = c[1].trim_end_matches(".get");
                let accessors: Vec<String> = match path.strip_prefix("bundles.") {
                    Some(bundle) => catalog
                        .as_ref()
                        .and_then(|cat| cat.table.get("bundles")?.as_table())
                        .and_then(|b| b.iter().find(|(k, _)| alias(k) == alias(bundle)))
                        .and_then(|(_, v)| v.as_array())
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default(),
                    None => vec![path.to_owned()],
                };
                let found: Vec<CatalogEntry> = accessors
                    .iter()
                    .filter_map(|a| catalog.as_ref().and_then(|cat| catalog_library(cat, a)))
                    .collect();
                if found.is_empty() {
                    reading.unsettled.push(VersionAt {
                        manifest: manifest.to_owned(),
                        line: i + 1,
                        dependency: format!("libs.{path}"),
                        version: String::new(),
                        why: match &catalog {
                            Some(cat) => format!("not found in `{}`", cat.path),
                            None => "a version catalog `sv` did not find".to_owned(),
                        },
                    });
                }
                for (coordinate, version) in found {
                    let written = format!(
                        "libs.{path} in {}",
                        catalog.as_ref().map_or("", |c| c.path.as_str())
                    );
                    match version {
                        Some(v) => judge(&mut reading, at, coordinate, v, &written, true),
                        None if managed => reading.exact += 1,
                        None => versionless(&mut reading, at, coordinate),
                    }
                }
                continue;
            }
            if let Some(module) = arg.strip_prefix("kotlin(") {
                let q: Vec<&str> = QUOTED
                    .captures_iter(module)
                    .map(|c| c.get(1).expect("a group").as_str())
                    .collect();
                match q.as_slice() {
                    // `kotlin("stdlib")` takes the Kotlin plugin's own version.
                    [_] => reading.exact += 1,
                    [name, v, ..] => judge(
                        &mut reading,
                        at,
                        format!("org.jetbrains.kotlin:kotlin-{name}"),
                        resolve_gradle(v, &vars),
                        v,
                        true,
                    ),
                    [] => versionless(&mut reading, at, line.to_owned()),
                }
                continue;
            }
            let (coordinate, version) =
                if let (Some(g), Some(n)) = (MAP_GROUP.captures(arg), MAP_NAME.captures(arg)) {
                    (
                        format!("{}:{}", &g[1], &n[1]),
                        MAP_VERSION.captures(arg).map(|v| v[1].to_owned()),
                    )
                } else if let Some(q) = QUOTED.captures(arg) {
                    let written = q[1].split('@').next().unwrap_or_default();
                    let parts: Vec<&str> = written.split(':').collect();
                    if parts.len() < 2 {
                        reading.unsettled.push(VersionAt {
                            manifest: manifest.to_owned(),
                            line: i + 1,
                            dependency: line.to_owned(),
                            version: String::new(),
                            why: "a dependency written in a way `sv` does not read".to_owned(),
                        });
                        continue;
                    }
                    (
                        format!("{}:{}", parts[0], parts[1]),
                        parts
                            .get(2)
                            .filter(|v| !v.is_empty())
                            .map(|v| (*v).to_owned()),
                    )
                } else {
                    reading.unsettled.push(VersionAt {
                        manifest: manifest.to_owned(),
                        line: i + 1,
                        dependency: line.to_owned(),
                        version: String::new(),
                        why: "a dependency written in a way `sv` does not read".to_owned(),
                    });
                    continue;
                };
            match version {
                Some(v) => judge(
                    &mut reading,
                    at,
                    coordinate,
                    resolve_gradle(&v, &vars),
                    &v,
                    true,
                ),
                None => {
                    // `implementation("g:a") { version { strictly("1.2") } }` gives it below.
                    let rich = line
                        .ends_with('{')
                        .then(|| lines[i + 1..end].iter().find_map(|l| RICH.captures(l)))
                        .flatten();
                    match rich {
                        Some(r) => judge(
                            &mut reading,
                            at,
                            coordinate,
                            resolve_gradle(&r[2], &vars),
                            &r[2],
                            true,
                        ),
                        None if managed => reading.exact += 1,
                        None if kotlin_plugin
                            && coordinate.starts_with("org.jetbrains.kotlin:") =>
                        {
                            reading.exact += 1
                        }
                        None => versionless(&mut reading, at, coordinate),
                    }
                }
            }
        }
    }
    Some(reading)
}

fn versionless(reading: &mut Reading, at: (&str, usize), dependency: String) {
    reading.unsettled.push(VersionAt {
        manifest: at.0.to_owned(),
        line: at.1,
        dependency,
        version: String::new(),
        why: "no version, and nothing in this file says where one comes from".to_owned(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_exact(v: &str, gradle: bool) -> bool {
        matches!(classify(v, gradle), Kind::Exact)
    }

    #[test]
    fn exact_versions_and_the_ways_versions_float() {
        for v in [
            "1.2.3",
            "5.3.31",
            "2.0",
            "[1.2.3]",
            "1.0.0.Final",
            "3.2.0-RC1",
        ] {
            assert!(is_exact(v, false), "maven {v}");
            assert!(is_exact(v, true), "gradle {v}");
        }
        assert!(is_exact("1.2.3!!", true));
        for v in [
            "[1.0,2.0)",
            "(,1.0]",
            "[1.0,)",
            "LATEST",
            "RELEASE",
            "1.0-SNAPSHOT",
            "[]",
        ] {
            assert!(!is_exact(v, false), "maven {v}");
        }
        for v in [
            "1.+",
            "+",
            "latest.release",
            "latest.integration",
            "]1.0,2.0[",
            "[1.0,2.0)",
            "2.1-SNAPSHOT",
        ] {
            assert!(!is_exact(v, true), "gradle {v}");
        }
    }

    #[test]
    fn blanking_keeps_every_offset() {
        let text = "a<!-- é\nx -->b";
        let out = blank(text, &XML_COMMENT);
        assert_eq!(out.len(), text.len());
        assert_eq!(out.find('b'), text.find('b'));
        assert_eq!(out.matches('\n').count(), 1);
    }

    #[test]
    fn folders_up_ends_at_the_app_folder() {
        assert_eq!(folders_up("a/b/build.gradle"), vec!["a/b", "a", ""]);
        assert_eq!(folders_up("build.gradle"), vec![""]);
    }

    #[test]
    fn dependency_blocks_ignore_braces_in_strings() {
        let lines: Vec<&str> =
            "plugins { }\ndependencies {\n  implementation \"a:b:{1}\"\n}\nafter {\n}"
                .split('\n')
                .collect();
        assert_eq!(dependency_blocks(&lines), vec![(1, 3)]);
    }

    fn app(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-jvm-{name}-{}", std::process::id()));
        std::fs::remove_dir_all(&dir).ok();
        for (path, text) in files {
            let p = dir.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    fn summary(r: &Reading) -> (usize, Vec<String>, Vec<String>) {
        let names = |v: &Vec<VersionAt>| {
            v.iter()
                .map(|x| format!("{}@{}", x.dependency, x.line))
                .collect()
        };
        (r.exact, names(&r.floating), names(&r.unsettled))
    }

    #[test]
    fn a_catalog_is_read_through_its_aliases_references_and_bundles() {
        let dir = app(
            "catalog",
            &[
                (
                    "gradle/libs.versions.toml",
                    "[versions]\nguava = \"33.3.1-jre\"\nslf = { strictly = \"[2.0,3.0)\" }\n\n\
                     [libraries]\nguava = { module = \"com.google.guava:guava\", version.ref = \"guava\" }\n\
                     slf4j-api = { group = \"org.slf4j\", name = \"slf4j-api\", version.ref = \"slf\" }\n\
                     junit = \"org.junit.jupiter:junit-jupiter:5.11.2\"\n\n\
                     [bundles]\ntesting = [\"junit\"]\n",
                ),
                (
                    "app/build.gradle.kts",
                    "dependencies {\n    implementation(libs.guava)\n    implementation(libs.slf4j.api)\n\
                     testImplementation(libs.bundles.testing)\n    implementation(libs.missing)\n}\n",
                ),
            ],
        );
        let r = read_gradle(&dir, "app/build.gradle.kts").unwrap();
        std::fs::remove_dir_all(&dir).ok();
        assert_eq!(
            summary(&r),
            (
                2,
                vec!["org.slf4j:slf4j-api@3".to_owned()],
                vec!["libs.missing@5".to_owned()]
            )
        );
    }

    #[test]
    fn gradle_variables_come_from_the_file_and_gradle_properties() {
        let dir = app(
            "vars",
            &[
                ("gradle.properties", "# versions\njacksonVersion=2.18.0\n"),
                (
                    "build.gradle",
                    "def springVersion = '6.1.13'\n// implementation 'org.x:commented:1.+'\n\
                     /* implementation 'org.x:blocked:1.+' */\ndependencies {\n\
                     implementation \"org.springframework:spring-web:$springVersion\"\n\
                     implementation \"com.fasterxml.jackson.core:jackson-databind:${jacksonVersion}\"\n\
                     implementation group: 'org.x', name: 'map', version: '1.0'\n\
                     implementation \"org.x:unknown:${nowhere}\"\n\
                     add(\"implementation\", \"org.x:added:1.0\")\n\
                     implementation project(':core')\n\
                     implementation('org.x:rich') {\n        version { strictly '[1.0,2.0)' }\n    }\n}\n",
                ),
            ],
        );
        let r = read_gradle(&dir, "build.gradle").unwrap();
        std::fs::remove_dir_all(&dir).ok();
        let (exact, floating, unsettled) = summary(&r);
        assert_eq!(exact, 3, "{r:?}");
        assert_eq!(floating, vec!["org.x:rich@11"]);
        assert_eq!(unsettled.len(), 2, "{unsettled:?}");
        assert!(unsettled[0].starts_with("org.x:unknown@8"), "{unsettled:?}");
        assert!(
            unsettled[1].contains("added") && unsettled[1].ends_with("@9"),
            "{unsettled:?}"
        );
    }

    #[test]
    fn a_pom_inherits_properties_from_a_parent_in_the_folder_and_ignores_its_build() {
        let dir = app(
            "pom",
            &[
                (
                    "pom.xml",
                    "<project><artifactId>root</artifactId><properties><lib.version>[1,2)</lib.version>\
                     <ok.version>4.0</ok.version></properties></project>",
                ),
                (
                    "web/pom.xml",
                    "<project>\n<parent><groupId>g</groupId><artifactId>root</artifactId><version>1.0</version></parent>\n\
                     <artifactId>web</artifactId>\n<dependencies>\n\
                     <!-- <dependency><groupId>c</groupId><artifactId>c</artifactId><version>LATEST</version></dependency> -->\n\
                     <dependency><groupId>a</groupId><artifactId>a</artifactId><version>${lib.version}</version></dependency>\n\
                     <dependency><groupId>b</groupId><artifactId>b</artifactId><version>${ok.version}</version></dependency>\n\
                     <dependency><groupId>g</groupId><artifactId>core</artifactId><version>${project.version}</version></dependency>\n\
                     <dependency><groupId>d</groupId><artifactId>d</artifactId></dependency>\n\
                     </dependencies>\n<build><plugins><plugin><artifactId>p</artifactId><version>LATEST</version>\
                     <dependencies><dependency><groupId>e</groupId><artifactId>e</artifactId><version>LATEST</version></dependency></dependencies>\
                     </plugin></plugins></build>\n</project>",
                ),
            ],
        );
        let r = read_pom(&dir, "web/pom.xml").unwrap();
        std::fs::remove_dir_all(&dir).ok();
        // The parent, b, core, and d (managed through the parent) are exact; a floats through
        // the parent's property; the commented dependency and the build plugin, with a dependency of its
        // own, are not read.
        assert_eq!(summary(&r), (4, vec!["a:a@6".to_owned()], vec![]));
        assert_eq!(r.floating[0].version, "${lib.version} = [1,2)");
    }

    #[test]
    fn a_version_nobody_supplies_is_unsettled_and_one_a_platform_supplies_is_not() {
        let bare = app(
            "bare",
            &[
                (
                    "build.gradle",
                    "dependencies {\n    implementation 'org.x:bare'\n}\n",
                ),
                (
                    "pom.xml",
                    "<project><artifactId>x</artifactId><dependencies>\n<dependency><groupId>org.x</groupId>\
                     <artifactId>bare</artifactId></dependency></dependencies></project>",
                ),
            ],
        );
        let gradle = read_gradle(&bare, "build.gradle").unwrap();
        let maven = read_pom(&bare, "pom.xml").unwrap();
        std::fs::remove_dir_all(&bare).ok();
        assert_eq!(
            summary(&gradle),
            (0, vec![], vec!["org.x:bare@2".to_owned()])
        );
        assert_eq!(
            summary(&maven),
            (0, vec![], vec!["org.x:bare@2".to_owned()])
        );

        let managed = app(
            "managed",
            &[(
                "build.gradle",
                "dependencies {\n    implementation platform('org.springframework.boot:spring-boot-dependencies:3.3.4')\n\
                 implementation 'org.springframework.boot:spring-boot-starter-web'\n}\n",
            )],
        );
        let r = read_gradle(&managed, "build.gradle").unwrap();
        std::fs::remove_dir_all(&managed).ok();
        assert_eq!(summary(&r), (2, vec![], vec![]));
    }
}
