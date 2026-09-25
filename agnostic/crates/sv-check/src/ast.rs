//! Rules that read the code itself, rather than the text of it.
//!
//! Everything else in `sv-check` works on strings. That is right for credentials, where the thing being
//! looked for *is* a string, and wrong for "is this SQL built by pasting a variable into it", where a
//! regex either misses the case split over two lines or fires on the word `execute` in a comment.
//!
//! So this parses. tree-sitter was taken as a dependency where a YAML crate was not, for the reason that
//! decides these: there is no honest hand-rolled alternative to a parser, it is actively maintained, and
//! four grammars build in about four seconds.
//!
//! # Queries are data, judgement is code
//!
//! `data/ast-rules.json` holds a tree-sitter query per language, so teaching a rule about Ruby is a data
//! entry. What a query cannot express is judgement — "the argument is a literal, so this `eval` is ugly
//! rather than dangerous" — and that lives here, in Rust, where it can be tested. It is the same split
//! as the secrets scanner: patterns as data, the decision about what they mean as code.
//!
//! # A language with no grammar is a language not read
//!
//! C++ has no grammar compiled in yet, so files in it are not scanned — and that is reported rather
//! than left to look like a clean result, the same way the secrets scanner reports the
//! files it skipped.

use crate::finding::{Confidence, Finding, Location, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AstRule {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub requirement_ids: Vec<String>,
    pub cwe: Vec<String>,
    pub description: String,
    pub impact: String,
    pub fix: String,
    /// When true, a match whose `@arg` capture is a plain literal is not reported.
    ///
    /// `eval("1 + 1")` cannot be made to run anything the author did not write. Reporting it next to
    /// `eval(request.args["x"])` at the same seriousness is how a rule teaches people to skip its
    /// findings.
    #[serde(default)]
    pub literal_argument_is_safe: bool,
    /// The called name a match must have, per language, as a regular expression over `@fn`.
    ///
    /// Per language because the dangerous names differ: Python's are `eval`, `exec` and `compile`,
    /// JavaScript's are `eval` and `Function`. One pattern for all of them would either miss some or
    /// report the wrong ones.
    ///
    /// Not a `#match?` predicate in the query: the Rust binding parses those and then does not apply
    /// them, so a rule written that way matches every call in the file while looking correct. Load
    /// refuses any query containing one.
    #[serde(default)]
    pub function_patterns: BTreeMap<String, String>,
    /// The same, per language, for the `@mod` capture — the object or module the call is on.
    #[serde(default)]
    pub module_patterns: BTreeMap<String, String>,
    /// Per language, what the `@arg` capture's text must match for the call to be reported at all.
    ///
    /// For the rules whose danger is in *which* value is passed rather than whether it was built:
    /// `createHash("md5")` and `createHash("sha256")` are the same call with a literal argument, and
    /// only the first is a finding. A match with no `@arg` capture is not reported, so a query that
    /// forgets the capture reports nothing rather than everything.
    #[serde(default)]
    pub argument_patterns: BTreeMap<String, String>,
    /// Per language, an `@arg` text that is known to be safe, so the call is not reported.
    ///
    /// Narrow on purpose, and each one written for a named idiom: `redirect(url_for("index"))` builds
    /// its destination from the app's own routes, and `res.sendFile(path.join(__dirname, "a.html"))`
    /// joins nothing but fixed text onto the app's own folder. Neither is a literal, and reporting
    /// either beside the real thing is how a rule teaches people to skip it.
    #[serde(default)]
    pub safe_argument_patterns: BTreeMap<String, String>,
    /// One tree-sitter query per language. A language absent here is one this rule says nothing about.
    pub queries: BTreeMap<String, String>,
    /// Languages `sv` reads that have nothing for this rule to find, each with the reason.
    ///
    /// Go has no `eval`, and a Go file cannot hide one. Without this entry a Go file would stop the
    /// rule claiming anything for a mixed app, because a language the rule reads nothing in is
    /// otherwise a language it has not ruled out. Each entry is a statement about the language, so
    /// it carries its reason, and a language cannot have both this and a query.
    #[serde(default)]
    pub nothing_to_find: BTreeMap<String, String>,
    /// What the rule looks for, in plain words, shown beside a clean result so it says what was
    /// looked for and not only how many files were read.
    ///
    /// "1 shell file" beside a path-traversal rule reads as "your shell scripts were checked for path
    /// traversal", when in shell the rule only looks at commands given a web request variable. A
    /// clean result is a claim about what the rule can see, and it should say so.
    #[serde(default)]
    pub looks_for: String,
    /// Per language, where the rule looks for something narrower than `looks_for` says.
    #[serde(default)]
    pub looks_for_in: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(rename = "_comment", default)]
    _comment: String,
    rules: Vec<AstRule>,
}

/// A rule with its queries compiled, one per language.
struct Compiled {
    rule: AstRule,
    queries: BTreeMap<String, Query>,
    /// The `typescript` query compiled against the TSX grammar, for `.tsx` files.
    tsx: Option<Query>,
    function: BTreeMap<String, regex::Regex>,
    module: BTreeMap<String, regex::Regex>,
    argument: BTreeMap<String, regex::Regex>,
    safe_argument: BTreeMap<String, regex::Regex>,
}

pub struct AstRules {
    compiled: Vec<Compiled>,
}

impl AstRules {
    /// Every rule as it was loaded. Used by the citation guard, which reads each rule's own words
    /// back against the requirement it names.
    pub fn rules(&self) -> impl Iterator<Item = &AstRule> {
        self.compiled.iter().map(|c| &c.rule)
    }

    /// Every rule, with the languages it can read and the requirements it is about.
    ///
    /// Needed to say what a clean scan covered: a rule is evidence only for the languages it has a
    /// query for, so a rule with a Python query says nothing about a Go file it never looked at.
    pub fn coverage(&self) -> Vec<(&str, Vec<&str>, Vec<&str>)> {
        self.compiled
            .iter()
            .map(|c| {
                (
                    c.rule.id.as_str(),
                    c.queries.keys().map(String::as_str).collect(),
                    c.rule.requirement_ids.iter().map(String::as_str).collect(),
                )
            })
            .collect()
    }
}

/// The languages a grammar is compiled in for.
fn grammar(language: &str) -> Option<Language> {
    Some(match language {
        "python" => tree_sitter_python::LANGUAGE.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        // Not a language of its own to anything but the parser: `.tsx` is TypeScript with JSX in it,
        // and the plain TypeScript grammar gives up inside the first tag. Rules are written once, as
        // `typescript`, and compiled a second time against this grammar.
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "csharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        "dart" => tree_sitter_dart::LANGUAGE.into(),
        "shell" => tree_sitter_bash::LANGUAGE.into(),
        _ => return None,
    })
}

/// A piece of script taken out of a page, and where it sat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// The language to parse it as: `javascript`, or `typescript` when the page says so.
    pub language: &'static str,
    pub code: String,
    /// How many lines came before it, so a finding can name the line in the page rather than in
    /// the fragment. A reader given line 3 of something they cannot see is worse off than one
    /// given nothing.
    pub line_offset: usize,
}

/// What a page holds, and what could not be taken out of it.
#[derive(Debug, Default)]
pub struct HtmlScan {
    pub fragments: Vec<Fragment>,
    /// Something code-shaped that the extractor did not take. While this is true the page is still
    /// unread, and every rule stays silent about the whole app.
    ///
    /// One function decides both halves on purpose. When "does this page hold code" and "what code
    /// does this page hold" are answered by two pieces of code, they drift, and the direction they
    /// drift in is a page declared read whose code nobody extracted.
    pub left_behind: Option<String>,
}

/// Takes the script out of a page.
///
/// Handles the two places code really lives in markup: a `<script>` element, and an `on…=` handler
/// attribute. A `<script src=…>` with nothing between its tags holds no code — the file it names is
/// parsed like any other. Anything else code-shaped is left behind by name rather than ignored.
pub fn html_fragments(source: &str) -> HtmlScan {
    let mut out = HtmlScan::default();
    let lower = source.to_lowercase();

    // Script elements.
    let mut at = 0usize;
    while let Some(found) = lower[at..].find("<script") {
        let tag_start = at + found;
        let Some(tag_end) = lower[tag_start..].find('>').map(|i| tag_start + i) else {
            out.left_behind = Some("a `<script` tag that is never closed".to_owned());
            return out;
        };
        let attributes = &lower[tag_start..tag_end];
        let body_start = tag_end + 1;
        let Some(close) = lower[body_start..].find("</script").map(|i| body_start + i) else {
            out.left_behind = Some("a `<script>` with no `</script>` after it".to_owned());
            return out;
        };
        let body = &source[body_start..close];
        if !body.trim().is_empty() {
            // `lang="ts"` is how a Vue component says so; `type="text/typescript"` is the older way.
            let language = if attributes.contains("lang=\"ts\"")
                || attributes.contains("lang='ts'")
                || attributes.contains("typescript")
            {
                "typescript"
            } else {
                "javascript"
            };
            out.fragments.push(Fragment {
                language,
                code: body.to_owned(),
                line_offset: source[..body_start].matches('\n').count(),
            });
        }
        at = close;
    }

    // Handler attributes. The value is a statement, which parses as JavaScript on its own.
    let handler = regex::Regex::new("(?i)[\\s\"']on[a-z]+\\s*=\\s*(\"[^\"]*\"|'[^']*')")
        .expect("a fixed pattern compiles");
    for m in handler.captures_iter(source) {
        let quoted = m.get(1).expect("the group is not optional");
        let inner = &quoted.as_str()[1..quoted.as_str().len() - 1];
        out.fragments.push(Fragment {
            language: "javascript",
            code: unescape_html(inner),
            line_offset: source[..quoted.start()].matches('\n').count(),
        });
    }

    // A URL that is a program. Taken when it sits in a quoted attribute, where its end is not in
    // doubt, and named otherwise: an unquoted value ends at whitespace by one reading and at the
    // tag by another, and guessing between them is how a fragment ends up half a statement.
    let url = regex::Regex::new("(?i)=\\s*(\"[^\"]*\"|'[^']*')").expect("a fixed pattern compiles");
    let mut quoted_urls = 0usize;
    for m in url.captures_iter(source) {
        let quoted = m.get(1).expect("the group is not optional");
        let inner = &quoted.as_str()[1..quoted.as_str().len() - 1];
        let decoded = unescape_html(inner);
        let Some(program) = strip_javascript_scheme(&decoded) else {
            // A browser reads `java<tab>script:` as the scheme; this does not, and a value that
            // becomes one once its control characters are taken out is named rather than read.
            // Reading it would mean deciding what the rest of it means too.
            if looks_like_a_disguised_scheme(&decoded) {
                out.left_behind =
                    Some("a `javascript:` URL with characters written into the scheme".to_owned());
                return out;
            }
            continue;
        };
        quoted_urls += 1;
        out.fragments.push(Fragment {
            language: "javascript",
            code: percent_decode(program),
            line_offset: source[..quoted.start()].matches('\n').count(),
        });
    }
    // Every occurrence has to be accounted for. One that the pattern above did not take is one
    // written some way this does not read — unquoted, or with the scheme spelled around a newline,
    // both of which a browser accepts — and the page keeps its silence rather than pretend.
    if lower.matches("javascript:").count() > quoted_urls {
        out.left_behind = Some(
            "a `javascript:` URL that is not in a quoted attribute, so where it ends is a guess"
                .to_owned(),
        );
        return out;
    }

    // Finally: anything taken out has to be code the grammar can actually read. A fragment that
    // does not parse yields no findings, which is indistinguishable from a fragment that was clean
    // — so a page holding a `<script>` full of a template language, or a URL this decoded wrongly,
    // is left unread rather than counted as examined.
    //
    // This catches less than it looks like it does, and the reason is worth knowing: the JavaScript
    // grammar includes JSX, so a Vue or React template parses cleanly and reaches the rules as
    // markup rather than being refused. Handlebars, ERB and Jinja do not.
    if let Some(bad) = out
        .fragments
        .iter()
        .find(|f| !parses_cleanly(f.language, &f.code))
    {
        out.left_behind = Some(format!(
            "something taken out of this page is not {} the grammar can read",
            bad.language
        ));
    }
    out
}

/// The program in a `javascript:` URL, if that is what this attribute value is.
///
/// Leading whitespace is skipped because a browser does. The scheme is matched only when it is
/// written plainly: a browser also accepts `java\tscript:` and other spellings with control
/// characters inside the word, and a reader of this code should not have to wonder whether those
/// were handled — they are not, and the count above turns each one into a page that stays unread.
fn strip_javascript_scheme(value: &str) -> Option<&str> {
    let trimmed = value.trim_start();
    let head: String = trimmed.chars().take("javascript:".len()).collect();
    head.eq_ignore_ascii_case("javascript:")
        .then(|| &trimmed["javascript:".len()..])
}

/// Whether a value is a `javascript:` URL written so that only a browser would see it.
///
/// A browser drops ASCII control characters and whitespace from inside a scheme, so
/// `java&#9;script:` runs. This does not read those, and the point of noticing them is to keep the
/// page unread rather than to pretend the value was ordinary.
fn looks_like_a_disguised_scheme(value: &str) -> bool {
    let collapsed: String = value
        .chars()
        .take(64)
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    collapsed.len() >= "javascript:".len()
        && collapsed[.."javascript:".len()].eq_ignore_ascii_case("javascript:")
}

/// Turns `%20` back into a space, and leaves anything that is not a complete escape alone.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
            if let Some(byte) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    // A decode that does not produce text is a decode this had no business doing.
    String::from_utf8(out).unwrap_or_else(|_| text.to_owned())
}

/// Whether the grammar can read this fragment without falling over.
///
/// `has_error` is the whole point. Tree-sitter always returns a tree, so a fragment of something
/// that is not this language parses into a wreck that matches no rule and reports nothing — which
/// reads exactly like a fragment that was clean.
fn parses_cleanly(language: &str, code: &str) -> bool {
    let Some(grammar) = grammar(language) else {
        return false;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return false;
    }
    match parser.parse(code, None) {
        Some(tree) => !tree.root_node().has_error(),
        None => false,
    }
}

/// The five entities that can hide a quote or a bracket in an attribute value.
fn unescape_html(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        // Last, so it cannot go back over an entity it has just written.
        .replace("&amp;", "&")
}

/// Whether `sv` can read this language at all.
pub fn is_supported(language: &str) -> bool {
    grammar(language).is_some()
}

impl AstRules {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: RuleFile =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;

        let mut compiled = Vec::new();
        for rule in file.rules {
            let mut queries = BTreeMap::new();
            for (language, source) in &rule.queries {
                // A `#match?` here is silently ignored by the binding, so the rule would match every
                // call in every file and look right doing it. Refuse it rather than let it through.
                anyhow::ensure!(
                    !source.contains("#match?") && !source.contains("#eq?"),
                    "rule {} has a {language} query using a text predicate, which this binding parses \
                     and does not apply — use functionPattern or modulePattern instead",
                    rule.id
                );
                let grammar = grammar(language).with_context(|| {
                    format!(
                        "rule {} names language `{language}`, which has no grammar",
                        rule.id
                    )
                })?;
                let query = Query::new(&grammar, source).with_context(|| {
                    format!(
                        "rule {} has a {language} query tree-sitter cannot compile",
                        rule.id
                    )
                })?;
                queries.insert(language.clone(), query);
            }
            let compile_patterns = |patterns: &BTreeMap<String, String>, what: &str| {
                patterns
                    .iter()
                    .map(|(language, source)| {
                        regex::Regex::new(source)
                            .map(|re| (language.clone(), re))
                            .with_context(|| {
                                format!("rule {} has an unusable {what} for {language}", rule.id)
                            })
                    })
                    .collect::<Result<BTreeMap<_, _>>>()
            };
            let function = compile_patterns(&rule.function_patterns, "functionPattern")?;
            let module = compile_patterns(&rule.module_patterns, "modulePattern")?;
            let argument = compile_patterns(&rule.argument_patterns, "argumentPattern")?;
            let safe_argument =
                compile_patterns(&rule.safe_argument_patterns, "safeArgumentPattern")?;
            // A pattern for a language the rule has no query in is a pattern that never runs, and
            // the rule reads as if it had been taught that language.
            for (what, patterns) in [
                ("functionPattern", &rule.function_patterns),
                ("modulePattern", &rule.module_patterns),
                ("argumentPattern", &rule.argument_patterns),
                ("safeArgumentPattern", &rule.safe_argument_patterns),
            ] {
                if let Some(language) = patterns.keys().find(|l| !queries.contains_key(*l)) {
                    anyhow::bail!(
                        "rule {} has a {what} for {language} but no {language} query",
                        rule.id
                    );
                }
            }
            for language in rule.looks_for_in.keys() {
                anyhow::ensure!(
                    rule.queries.contains_key(language),
                    "rule {} says what it looks for in `{language}`, and has no {language} query",
                    rule.id
                );
            }
            for (language, why) in &rule.nothing_to_find {
                anyhow::ensure!(
                    grammar(language).is_some(),
                    "rule {} says there is nothing to find in `{language}`, which has no grammar",
                    rule.id
                );
                anyhow::ensure!(
                    !rule.queries.contains_key(language),
                    "rule {} has a {language} query and also says there is nothing to find in \
                     {language}",
                    rule.id
                );
                anyhow::ensure!(
                    !why.trim().is_empty(),
                    "rule {} says there is nothing to find in {language} without saying why",
                    rule.id
                );
            }
            let tsx = match rule.queries.get("typescript") {
                Some(source) => Some(
                    Query::new(&grammar("tsx").expect("tsx is compiled in"), source).with_context(
                        || {
                            format!(
                                "rule {} has a typescript query the TSX grammar cannot compile",
                                rule.id
                            )
                        },
                    )?,
                ),
                None => None,
            };
            compiled.push(Compiled {
                rule,
                queries,
                tsx,
                function,
                module,
                argument,
                safe_argument,
            });
        }
        Ok(AstRules { compiled })
    }

    pub fn len(&self) -> usize {
        self.compiled.len()
    }

    pub fn is_empty(&self) -> bool {
        self.compiled.is_empty()
    }

    /// The languages any rule has a query for.
    pub fn languages(&self) -> BTreeSet<&str> {
        self.compiled
            .iter()
            .flat_map(|c| c.queries.keys())
            .map(String::as_str)
            .collect()
    }
}

/// Node kinds that are a value written in the source, with nothing substituted into them.
///
/// A template string is only a literal when nothing is interpolated, which is exactly the distinction
/// that matters: `` `SELECT 1` `` is a constant and `` `SELECT ${id}` `` is the bug this looks for.
fn is_literal(node: tree_sitter::Node, source: &[u8]) -> bool {
    const LITERAL_KINDS: &[&str] = &[
        "string",
        "string_literal",
        "raw_string_literal",
        "interpreted_string_literal",
        "concatenated_string",
        "template_string",
        "integer",
        "float",
        "number",
        "true",
        "false",
        "none",
        "null",
        // Ruby's backtick form. `ls -la` is as fixed as any string; `ls #{dir}` is not, and the
        // interpolation check below is what tells them apart — the same test every other kind gets.
        "subshell",
        // C#'s plain strings and Kotlin's, whose grammar gives an interpolated one no node of its
        // own — see `has_interpolation` for how those two are told apart.
        "verbatim_string_literal",
        // PHP's double-quoted strings, which interpolate `$name` without any `{}` around it.
        "encapsed_string",
        "string_value",
        // Swift's strings, one line and several. Interpolation is `\(x)`, which the grammar gives a
        // node of its own; see `has_interpolation`.
        "line_string_literal",
        "multi_line_string_literal",
        // PHP's backtick form, which interpolates `$name` the way its double-quoted strings do.
        "shell_command_expression",
        // Shell: a bare word, a single-quoted string (which expands nothing), and a double-quoted one,
        // which is `string` like everyone else's and is told apart by `has_interpolation`.
        "word",
        "raw_string",
    ];

    // Swift's argument, labeled or not, is judged by the value it carries: the label is part of
    // the text a pattern can read, and never part of what was built.
    if node.kind() == "value_argument" {
        return node
            .child_by_field_name("value")
            .is_some_and(|value| is_literal(value, source));
    }
    // `["-c", "ls"]` is as fixed as the strings in it, and `["-c", cmd]` is not: a command handed to
    // a shell as the second element of a list is the Dart, Swift, and Rust way to write `sh -c`.
    if matches!(
        node.kind(),
        "list_literal" | "array_literal" | "array_expression"
    ) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .filter(|c| c.kind() != "type_arguments")
            .all(|c| is_literal(c, source));
    }

    // `"a" + "b"` is still a constant; `"a" + name` is not.
    if matches!(
        node.kind(),
        "binary_operator" | "binary_expression" | "additive_expression" | "concatenation"
    ) {
        let mut cursor = node.walk();
        return node
            .named_children(&mut cursor)
            .all(|c| is_literal(c, source));
    }
    if !LITERAL_KINDS.contains(&node.kind()) {
        return false;
    }
    // Anything with a value substituted into it was built, not written: a JavaScript template string
    // with `${…}` and a Python f-string with `{…}` are the same thing under different node names, and
    // an f-string is still a plain `string` node in its grammar. Missing this reports every SQL query
    // built with an f-string as a constant, which is the case the rule exists for.
    !has_interpolation(node, source)
}

/// Whether anything is substituted into this literal, however deeply.
fn has_interpolation(node: tree_sitter::Node, source: &[u8]) -> bool {
    // Kotlin's `"select $n"` has no interpolation node at all: the grammar splits it into plain
    // `string_content` children and the bare `$` becomes one of them. Measured rather than guessed,
    // because the obvious discriminators are both wrong — a plain string has one `string_content`
    // and so does nothing else, while `"cost \$5"` has two of them either side of an
    // `escape_sequence`. The `$` standing alone as its own node is what actually distinguishes
    // them, and an escaped one never does.
    if node.kind() == "string_literal" {
        let mut cursor = node.walk();
        if node
            .named_children(&mut cursor)
            .any(|c| c.kind() == "string_content" && c.utf8_text(source).map(str::trim) == Ok("$"))
        {
            return true;
        }
    }

    // PHP puts a plain `variable_name` inside a double-quoted string, with no wrapper node to
    // recognise: `"select ... $name"` is a built string that looks like a literal to the list below.
    if matches!(node.kind(), "encapsed_string" | "shell_command_expression") {
        let mut cursor = node.walk();
        if node
            .named_children(&mut cursor)
            .any(|c| c.kind() != "string_content" && c.kind() != "escape_sequence")
        {
            return true;
        }
    }

    let mut cursor = node.walk();
    node.children(&mut cursor).any(|child| {
        matches!(
            child.kind(),
            "interpolation"
                | "template_substitution"
                | "string_interpolation"
                | "format_specifier"
                | "interpolated_expression"
                | "simple_expansion"
                | "expansion"
                | "command_substitution"
                | "process_substitution"
                | "arithmetic_expansion"
        ) || has_interpolation(child, source)
    })
}

#[derive(Debug, Default)]
pub struct AstScan {
    pub findings: Vec<Finding>,
    /// Languages present in the app that no grammar reads, so nothing is claimed about them.
    pub unread_languages: BTreeSet<String>,
    pub files_parsed: usize,
    /// How many files were parsed in each language.
    pub parsed_by_language: BTreeMap<String, usize>,
    /// Rules that ran over everything they could read and found nothing.
    pub verified: Vec<crate::Verified>,
    /// Files in a language `sv` reads whose parse came back with an error in it.
    ///
    /// Whatever sat inside the error was not read, and the parser says nothing about how much that
    /// was. A `.tsx` file once went through a grammar with no JSX, lost everything inside its first
    /// tag, and still counted as read — so an `eval` in a click handler was missed and the report
    /// listed the requirement against `eval` as checked. Findings from such a file still stand; what
    /// it cannot do is support a claim that something is absent.
    pub unparsed_files: Vec<String>,
    /// Rules that met a language `sv` reads but the rule has not been taught, and so claim nothing.
    ///
    /// A shell-command rule with no Rust query that met a Rust file has not ruled out a shell
    /// command built in Rust. Before this was kept, such a rule claimed the requirement on the
    /// strength of the Python beside it.
    pub untaught: Vec<Untaught>,
}

/// One rule, and the languages in this app it was not able to look in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untaught {
    pub rule_id: String,
    pub title: String,
    pub languages: Vec<String>,
}

/// Runs every rule that has a query for this language over one file.
pub fn scan_file(rules: &AstRules, language: &str, relative: &str, source: &str) -> Vec<Finding> {
    read_file(rules, language, relative, source).findings
}

/// What reading one file produced.
pub struct FileRead {
    pub findings: Vec<Finding>,
    /// The parse came back with an error in it, so some of the file was not read.
    pub parse_error: bool,
}

/// Runs every rule over one file, and says whether the whole file was understood.
///
/// A `.tsx` file is parsed with the TSX grammar and matched with the rule's `typescript` query
/// compiled against it; everything else about it — the patterns, the coverage it counts towards — is
/// TypeScript's.
pub fn read_file(rules: &AstRules, language: &str, relative: &str, source: &str) -> FileRead {
    let unread = FileRead {
        findings: Vec::new(),
        parse_error: true,
    };
    let tsx = language == "typescript" && relative.to_lowercase().ends_with(".tsx");
    let Some(grammar) = grammar(if tsx { "tsx" } else { language }) else {
        return unread;
    };
    let mut parser = Parser::new();
    if parser.set_language(&grammar).is_err() {
        return unread;
    }
    let Some(tree) = parser.parse(source, None) else {
        return unread;
    };

    let mut out = Vec::new();
    for compiled in &rules.compiled {
        let query = if tsx {
            compiled.tsx.as_ref()
        } else {
            compiled.queries.get(language)
        };
        let Some(query) = query else {
            continue;
        };
        let arg_index = query.capture_index_for_name("arg");
        let hit_index = query.capture_index_for_name("hit");
        let fn_index = query.capture_index_for_name("fn");
        let mod_index = query.capture_index_for_name("mod");
        let text_of = |m: &tree_sitter::QueryMatch, index: Option<u32>| -> Option<String> {
            let index = index?;
            let capture = m.captures.iter().find(|c| c.index == index)?;
            capture
                .node
                .utf8_text(source.as_bytes())
                .ok()
                .map(str::to_owned)
        };
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(query, tree.root_node(), source.as_bytes());
        while let Some(m) = matches.next() {
            // The name filters the query cannot apply for itself.
            if let Some(pattern) = compiled.function.get(language) {
                match text_of(m, fn_index) {
                    Some(name) if pattern.is_match(&name) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.module.get(language) {
                match text_of(m, mod_index) {
                    Some(name) if pattern.is_match(&name) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.argument.get(language) {
                match text_of(m, arg_index) {
                    Some(text) if pattern.is_match(&text) => {}
                    _ => continue,
                }
            }
            if let Some(pattern) = compiled.safe_argument.get(language)
                && let Some(text) = text_of(m, arg_index)
                && pattern.is_match(&text)
            {
                continue;
            }
            // A literal argument means the call cannot be made to do anything the author did not write.
            if compiled.rule.literal_argument_is_safe
                && let Some(index) = arg_index
                && let Some(capture) = m.captures.iter().find(|c| c.index == index)
                && is_literal(capture.node, source.as_bytes())
            {
                continue;
            }
            let node = hit_index
                .and_then(|index| m.captures.iter().find(|c| c.index == index))
                .map(|c| c.node)
                .or_else(|| m.captures.first().map(|c| c.node));
            let Some(node) = node else { continue };
            out.push(Finding {
                rule_id: compiled.rule.id.clone(),
                title: compiled.rule.title.clone(),
                severity: compiled.rule.severity,
                confidence: compiled.rule.confidence,
                location: Location {
                    file: relative.to_owned(),
                    line: node.start_position().row + 1,
                },
                secret: None,
                requirement_ids: compiled.rule.requirement_ids.clone(),
                cwe: compiled.rule.cwe.clone(),
                description: compiled.rule.description.clone(),
                impact: compiled.rule.impact.clone(),
                fix: compiled.rule.fix.clone(),
            });
        }
    }
    out.sort_by(|a, b| {
        a.location
            .line
            .cmp(&b.location.line)
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    out.dedup_by(|a, b| a.rule_id == b.rule_id && a.location.line == b.location.line);
    FileRead {
        findings: out,
        parse_error: tree.root_node().has_error(),
    }
}

/// Runs the rules over every source file in the app whose language has a grammar.
///
/// Languages present but unread are recorded rather than skipped quietly. A Ruby app scanned by a tool
/// with no Ruby grammar produces no findings, and "no findings" is what a clean app produces too.
pub fn scan_dir(rules: &AstRules, app_dir: &std::path::Path) -> AstScan {
    let mut scan = AstScan::default();
    walk(app_dir, app_dir, rules, &mut scan);
    scan.findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.location.file.cmp(&b.location.file))
            .then_with(|| a.location.line.cmp(&b.location.line))
    });
    scan.untaught = untaught(rules, &scan);
    scan.verified = clean_rules(rules, &scan);
    scan
}

/// Every rule, with the languages read in this app that it has neither a query for nor a reason
/// to have none.
fn untaught(rules: &AstRules, scan: &AstScan) -> Vec<Untaught> {
    rules
        .compiled
        .iter()
        .filter_map(|c| {
            let languages: Vec<String> = scan
                .parsed_by_language
                .iter()
                .filter(|(language, n)| {
                    **n > 0
                        && !c.queries.contains_key(*language)
                        && !c.rule.nothing_to_find.contains_key(*language)
                })
                .map(|(language, _)| language.clone())
                .collect();
            (!languages.is_empty()).then(|| Untaught {
                rule_id: c.rule.id.clone(),
                title: c.rule.title.clone(),
                languages,
            })
        })
        .collect()
}

/// The rules that read everything they could have read, and found nothing.
///
/// Fail closed three times over. A rule says nothing unless it parsed at least one file in a
/// language it has a query for — a SQL rule that never saw a line of Python has not established
/// that the app builds no queries by hand. No rule says anything at all while a language present in
/// the app goes unread, because the injection it looks for could be sitting in the Ruby nobody
/// parsed. And a rule says nothing while a language that *was* read is one it was never taught:
/// the parser having read the Swift does not mean this rule looked in it.
fn clean_rules(rules: &AstRules, scan: &AstScan) -> Vec<crate::Verified> {
    if !scan.unread_languages.is_empty() || !scan.unparsed_files.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (rule_id, languages, requirement_ids) in rules.coverage() {
        if scan.findings.iter().any(|f| f.rule_id == rule_id)
            || scan.untaught.iter().any(|u| u.rule_id == rule_id)
        {
            continue;
        }
        let rule = rules.rules().find(|r| r.id == rule_id);
        // Files read, grouped by what the rule looks for in them: the rule's own words, or the
        // narrower ones it has for a language.
        let mut groups: Vec<(&str, Vec<String>)> = Vec::new();
        for language in &languages {
            let Some(n) = scan.parsed_by_language.get(*language).copied() else {
                continue;
            };
            if n == 0 {
                continue;
            }
            let files = format!("{n} {language} file{}", if n == 1 { "" } else { "s" });
            let phrase = rule
                .and_then(|r| r.looks_for_in.get(*language))
                .or(rule.map(|r| &r.looks_for))
                .map(String::as_str)
                .unwrap_or("");
            match groups.iter_mut().find(|(p, _)| *p == phrase) {
                Some((_, files_for)) => files_for.push(files),
                None => groups.push((phrase, vec![files])),
            }
        }
        if groups.is_empty() {
            continue;
        }
        // The rule's own words first, then each narrower one.
        groups.sort_by_key(|(p, _)| rule.is_none_or(|r| *p != r.looks_for));
        let scope = groups
            .iter()
            .map(|(phrase, files)| {
                let files = and_list(files);
                if phrase.is_empty() {
                    files
                } else {
                    format!("{phrase}, in {files}")
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        out.push(crate::Verified::new(rule_id, &requirement_ids, scope));
    }
    out
}

/// "a", "a and b", "a, b, and c".
fn and_list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{}, and {last}", rest.join(", ")),
    }
}

/// Reads the script out of a page and scans it as the language it is.
///
/// The page counts as read only when nothing code-shaped was left behind. A page whose script all
/// came out is one nothing is hiding in; a page with a `javascript:` URL still silences every rule,
/// because the extractor did not take that and saying otherwise would be the whole failure this
/// guards against.
fn read_page(rules: &AstRules, root: &std::path::Path, path: &std::path::Path, scan: &mut AstScan) {
    let Ok(source) = std::fs::read_to_string(path) else {
        // A page that cannot be opened is the one case where nothing at all is known about it.
        scan.unread_languages.insert("html".to_owned());
        return;
    };
    let page = html_fragments(&source);
    if page.left_behind.is_some() {
        scan.unread_languages.insert("html".to_owned());
        return;
    }
    if page.fragments.is_empty() {
        // A page of markup. Nothing to read, and nothing hidden.
        return;
    }

    let relative = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    scan.files_parsed += 1;
    for fragment in &page.fragments {
        // Counted under the language actually parsed. A page holding JavaScript is a file in which
        // JavaScript was read, and the rules that claim coverage of JavaScript really did read it.
        *scan
            .parsed_by_language
            .entry(fragment.language.to_owned())
            .or_default() += 1;
        for mut finding in scan_file(rules, fragment.language, &relative, &fragment.code) {
            // Back to the line in the page. Without this a reader is sent to line 3 of something
            // that does not exist as a file.
            finding.location.line += fragment.line_offset;
            scan.findings.push(finding);
        }
    }
}

fn walk(root: &std::path::Path, dir: &std::path::Path, rules: &AstRules, scan: &mut AstScan) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if path.is_dir() {
            if sv_scan::ecosystems::SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }
            walk(root, &path, rules, scan);
            continue;
        }
        let Some(extension) = path.extension().and_then(|e| e.to_str()) else {
            continue;
        };
        let Some(language) = sv_scan::ecosystems::language_of(&extension.to_lowercase()) else {
            continue;
        };
        if !is_supported(language) {
            // Present, and not read. The rules have nothing to say about this file and the report
            // should say that rather than let its silence be read as approval.
            //
            // Except for a page that holds no code. `html` covers `.html`, `.vue` and `.svelte`,
            // and almost every web application has at least one — so counting every page as unread
            // silenced every rule for nearly every real app, which is a great deal of silence
            // bought by a file that in most cases hides nothing at all.
            if language == "html" {
                read_page(rules, root, &path, scan);
                continue;
            }
            scan.unread_languages.insert(language.to_owned());
            continue;
        }
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        scan.files_parsed += 1;
        *scan
            .parsed_by_language
            .entry(language.to_owned())
            .or_default() += 1;
        let read = read_file(rules, language, &relative, &source);
        if read.parse_error {
            scan.unparsed_files.push(relative);
        }
        scan.findings.extend(read.findings);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn rules() -> AstRules {
        AstRules::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../data/ast-rules.json"))
            .expect("rules load")
    }

    fn scan(language: &str, source: &str) -> Vec<Finding> {
        scan_file(&rules(), language, &format!("src/app.{language}"), source)
    }

    fn ids(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.rule_id.as_str()).collect()
    }

    #[test]
    fn every_query_in_the_data_file_compiles() {
        // A query tree-sitter cannot compile is a rule that silently never fires, which looks exactly
        // like a rule finding nothing.
        let rules = rules();
        assert!(rules.len() >= 4, "only {} rules loaded", rules.len());
        assert!(rules.languages().contains("python"));
    }

    /// Writes a rule file to a scratch path so load-time refusals can be exercised.
    fn rules_from(json: &str) -> anyhow::Result<AstRules> {
        let dir = std::env::temp_dir().join(format!("sv-ast-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("rules-{}.json", json.len()));
        std::fs::write(&path, json).unwrap();
        let loaded = AstRules::load(&path);
        std::fs::remove_file(&path).ok();
        loaded
    }

    const ONE_RULE: &str = r#"{"rules":[{
        "id":"test.rule","title":"t","severity":"high","confidence":"high",
        "requirementIds":[],"cwe":[],"description":"d","impact":"i","fix":"f",
        "queries":{"python":"QUERY"}}]}"#;

    #[test]
    fn a_query_using_a_text_predicate_is_refused_at_load() {
        // The predicate that started this: tree-sitter's Rust binding parses `#match?` and then does
        // not apply it, so a rule written with one matches every call in the file while looking exactly
        // right. Every rule here did that, and the tests caught it only because they asserted what was
        // NOT a finding. Refusing the query is what stops it coming back.
        let refused = rules_from(&ONE_RULE.replace(
            "QUERY",
            "(call function: (identifier) @fn) @hit (#match? @fn \\\"^eval$\\\")",
        ));
        let error = match refused {
            Ok(_) => panic!("a text predicate must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("does not apply"), "{error}");
    }

    #[test]
    fn a_rule_naming_a_language_with_no_grammar_is_refused_at_load() {
        // Quietly dropping it would leave a rule that claims to cover a language and never runs.
        // C++ stands in for that here. This test has named Ruby and then C#, each until the
        // language got a grammar, which is the right way round for a test like this to break.
        let refused = rules_from(&ONE_RULE.replace("\"python\"", "\"cpp\""));
        let error = match refused {
            Ok(_) => panic!("an unknown language must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("no grammar"), "{error}");
    }

    #[test]
    fn a_query_tree_sitter_cannot_compile_is_refused_at_load() {
        let refused = rules_from(&ONE_RULE.replace("QUERY", "(this is not a query"));
        let error = match refused {
            Ok(_) => panic!("a broken query must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("cannot compile"), "{error}");
    }

    fn one_rule(extra: &str) -> String {
        format!(
            r#"{{"rules": [{{"id": "t", "title": "t", "severity": "high", "confidence": "high",
                "requirementIds": ["V1.3.2"], "cwe": [], "description": "", "impact": "", "fix": "",
                "queries": {{"python": "(call) @hit"}} {extra} }}]}}"#
        )
    }

    #[test]
    fn nothing_to_find_is_refused_beside_a_query_without_a_reason_or_without_a_grammar() {
        let both = one_rule(r#", "nothingToFind": {"python": "Python has no such thing."}"#);
        let err = rules_from(&both).err().expect("refused").to_string();
        assert!(err.contains("also says there is nothing to find"), "{err}");

        let no_reason = one_rule(r#", "nothingToFind": {"go": "  "}"#);
        let err = rules_from(&no_reason).err().expect("refused").to_string();
        assert!(err.contains("without saying why"), "{err}");

        let no_grammar = one_rule(r#", "nothingToFind": {"cpp": "C++ has none."}"#);
        let err = rules_from(&no_grammar).err().expect("refused").to_string();
        assert!(err.contains("no grammar"), "{err}");

        let fine = one_rule(r#", "nothingToFind": {"go": "Go has no eval."}"#);
        assert!(rules_from(&fine).is_ok());
    }

    #[test]
    fn a_pattern_for_a_language_the_rule_has_no_query_in_is_refused_at_load() {
        // It would never run, and the rule would read as if it had been taught that language.
        let refused = rules_from(
            &ONE_RULE
                .replace(
                    "\"queries\"",
                    "\"argumentPatterns\":{\"go\":\"md5\"},\"queries\"",
                )
                .replace("QUERY", "(call) @hit"),
        );
        let error = match refused {
            Ok(_) => panic!("a pattern with no query must be refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(error.contains("no go query"), "{error}");
    }

    #[test]
    fn python_eval_of_a_request_value_is_found() {
        let findings = scan(
            "python",
            "from flask import request\n\ndef run():\n    return eval(request.args['code'])\n",
        );
        assert!(
            ids(&findings).contains(&"ast.dynamic-code-execution"),
            "{findings:?}"
        );
        assert_eq!(findings[0].location.line, 4);
    }

    #[test]
    fn python_eval_of_a_literal_is_not_reported() {
        // `eval("1 + 1")` cannot be made to run anything the author did not write. Reporting it beside
        // a real one, at the same seriousness, is how a rule teaches people to skip its findings.
        let findings = scan("python", "x = eval('1 + 1')\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn javascript_eval_and_new_function_are_both_found() {
        let findings = scan(
            "javascript",
            "const f = new Function(req.body.src);\neval(req.query.x);\n",
        );
        assert_eq!(findings.len(), 2, "{findings:?}");
    }

    #[test]
    fn a_template_string_with_nothing_in_it_is_a_literal() {
        // The distinction the whole literal check turns on.
        let interpolated = scan(
            "javascript",
            "db.query(`SELECT * FROM t WHERE id = ${id}`);\n",
        );
        assert!(
            ids(&interpolated).contains(&"ast.sql-built-by-hand"),
            "{interpolated:?}"
        );
        let constant = scan("javascript", "db.query(`SELECT * FROM t`);\n");
        assert!(
            constant.is_empty(),
            "a constant query is not a finding: {constant:?}"
        );
    }

    #[test]
    fn python_sql_built_with_an_f_string_is_found() {
        let findings = scan(
            "python",
            "def get(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n",
        );
        assert!(
            ids(&findings).contains(&"ast.sql-built-by-hand"),
            "{findings:?}"
        );
    }

    #[test]
    fn python_sql_with_bound_parameters_is_not_a_finding() {
        // The correct way to do it must not be reported, or the rule is worse than nothing.
        let findings = scan(
            "python",
            "cur.execute('SELECT * FROM users WHERE name = ?', (name,))\n",
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_shell_command_built_from_a_value_is_found() {
        let python = scan("python", "import os\nos.system('rm -rf ' + path)\n");
        assert!(ids(&python).contains(&"ast.shell-command"), "{python:?}");

        let js = scan(
            "javascript",
            "const { exec } = require('child_process');\nexec(`ls ${dir}`);\n",
        );
        assert!(ids(&js).contains(&"ast.shell-command"), "{js:?}");
    }

    #[test]
    fn a_fixed_shell_command_is_not_reported() {
        let findings = scan("python", "import os\nos.system('ls -la')\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn python_pickle_and_unsafe_yaml_are_found() {
        let findings = scan(
            "python",
            "import pickle, yaml\n\ndef load(blob, text):\n    a = pickle.loads(blob)\n    b = yaml.load(text)\n    return a, b\n",
        );
        assert!(
            ids(&findings).contains(&"ast.unsafe-deserialization"),
            "{findings:?}"
        );
        assert_eq!(findings.len(), 2, "both calls are findings: {findings:?}");
    }

    #[test]
    fn yaml_safe_load_is_not_reported() {
        let findings = scan("python", "import yaml\nd = yaml.safe_load(text)\n");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn a_comment_mentioning_a_dangerous_call_is_not_a_finding() {
        // The reason this parses rather than greps. A regex over the text reports both of these.
        let findings = scan("python", "# never use eval(user_input) here\nx = 1\n");
        assert!(findings.is_empty(), "{findings:?}");
        let in_string = scan("python", "message = 'do not call eval(x)'\n");
        assert!(in_string.is_empty(), "{in_string:?}");
    }

    #[test]
    fn a_call_split_over_several_lines_is_still_found() {
        // The other reason: a regex anchored to one line misses this, and reformatting an app should
        // not change whether it has a vulnerability.
        let findings = scan(
            "python",
            "cur.execute(\n    f\"SELECT * FROM t WHERE id = {user_id}\"\n)\n",
        );
        assert!(
            ids(&findings).contains(&"ast.sql-built-by-hand"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_language_with_no_grammar_yields_nothing_rather_than_pretending() {
        // C++ is read by `sv-scan` — it counts towards what an app is written in — and has no
        // grammar here, which is the combination that has to stay silent rather than guess.
        assert!(scan_file(&rules(), "cpp", "app.cpp", "system(argv[1]);").is_empty());
        assert!(!is_supported("cpp"));
        assert!(is_supported("python") && is_supported("typescript"));
    }

    #[test]
    fn the_three_new_grammars_read_their_own_languages() {
        // The point of adding them. Each snippet is the shape somebody would really write.
        for (language, file, source, expected) in [
            (
                "ruby",
                "app.rb",
                "db.execute(\"select * from t where n = \" + name)",
                "ast.sql-built-by-hand",
            ),
            (
                "ruby",
                "app.rb",
                "Marshal.load(params[:blob])",
                "ast.unsafe-deserialization",
            ),
            (
                "php",
                "app.php",
                "<?php $db->query(\"select * from t where n = \" . $name);",
                "ast.sql-built-by-hand",
            ),
            (
                "php",
                "app.php",
                "<?php unserialize($_GET[\"blob\"]);",
                "ast.unsafe-deserialization",
            ),
            (
                "java",
                "App.java",
                "class A { void f(String n) { stmt.executeQuery(\"select * from t where n = \" + n); } }",
                "ast.sql-built-by-hand",
            ),
            (
                "java",
                "App.java",
                "class A { void f() { new ObjectInputStream(in).readObject(); } }",
                "ast.unsafe-deserialization",
            ),
        ] {
            let findings = scan_file(&rules(), language, file, source);
            assert!(
                ids(&findings).contains(&expected),
                "{language}: expected {expected}, got {:?}",
                ids(&findings)
            );
        }
    }

    #[test]
    fn ruby_backticks_are_a_shell_command_and_a_fixed_one_is_not_reported() {
        // The backtick form has no method name to match, so it is its own pattern. `ls` cannot be
        // made to run anything else; `ls #{dir}` can, and the literal check is what tells them
        // apart — the same rule the rest of this file runs on.
        let dangerous = scan_file(&rules(), "ruby", "app.rb", "`ls #{params[:dir]}`");
        assert!(
            ids(&dangerous).contains(&"ast.shell-command-backticks"),
            "{dangerous:?}"
        );
        let fixed = scan_file(&rules(), "ruby", "app.rb", "`ls -la`");
        assert!(
            !ids(&fixed).contains(&"ast.shell-command-backticks"),
            "a fixed command cannot be made to run anything else: {fixed:?}"
        );
    }

    #[test]
    fn what_comes_out_of_a_page_and_what_is_left_behind() {
        // One function answers both halves on purpose. When "does this page hold code" and "what
        // code does this page hold" are decided separately they drift, and the direction they
        // drift in is a page declared read whose code nobody extracted.
        let markup = html_fragments("<html><body><h1>Notes</h1></body></html>");
        assert!(markup.fragments.is_empty() && markup.left_behind.is_none());

        let external = html_fragments("<html><script src=\"app.js\"></script></html>");
        assert!(
            external.fragments.is_empty() && external.left_behind.is_none(),
            "the file it names is parsed like any other: {external:?}"
        );

        let whitespace = html_fragments("<html><script src=\"a.js\">\n  \n</script></html>");
        assert!(whitespace.fragments.is_empty() && whitespace.left_behind.is_none());

        let inline = html_fragments("<html><script>eval(x)</script></html>");
        assert_eq!(inline.fragments.len(), 1);
        assert_eq!(inline.fragments[0].language, "javascript");
        assert_eq!(inline.fragments[0].code, "eval(x)");
        assert!(inline.left_behind.is_none());

        let shouting = html_fragments("<html><SCRIPT>eval(x)</SCRIPT></html>");
        assert_eq!(
            shouting.fragments.len(),
            1,
            "tags match whatever their case"
        );
        assert_eq!(
            shouting.fragments[0].code, "eval(x)",
            "and the code comes out with its own case intact"
        );

        let typed = html_fragments("<script lang=\"ts\">const x: string = y</script>");
        assert_eq!(typed.fragments[0].language, "typescript");

        let handler = html_fragments("<button onclick=\"go(location.hash)\">go</button>");
        assert_eq!(handler.fragments.len(), 1);
        assert_eq!(handler.fragments[0].code, "go(location.hash)");

        let entities = html_fragments("<button onclick=\"go(&quot;a&quot; &amp; b)\">go</button>");
        assert_eq!(
            entities.fragments[0].code, "go(\"a\" & b)",
            "an entity can hide a quote, and must be put back before parsing"
        );

        let unclosed = html_fragments("<html><script>eval(x)");
        assert!(
            unclosed.left_behind.is_some(),
            "a script with no end cannot be bounded, so the page stays unread"
        );

        let url = html_fragments("<a href=\"javascript:go()\">go</a>");
        assert_eq!(url.fragments.len(), 1, "{url:?}");
        assert_eq!(url.fragments[0].code, "go()");
        assert!(url.left_behind.is_none());

        let shouting_url = html_fragments("<a href=\"JavaScript: go()\">go</a>");
        assert_eq!(
            shouting_url.fragments[0].code, " go()",
            "the scheme is matched whatever its case, and a browser skips the space"
        );

        let escaped_url = html_fragments("<a href=\"javascript:go(%22x%22)\">go</a>");
        assert_eq!(
            escaped_url.fragments[0].code, "go(\"x\")",
            "a percent escape has to come back before the grammar sees it"
        );

        let unquoted = html_fragments("<a href=javascript:go()>go</a>");
        assert!(
            unquoted.left_behind.is_some(),
            "where an unquoted value ends is a guess, so this one is named: {unquoted:?}"
        );

        let split_scheme = html_fragments("<a href=\"java\tscript:go()\">go</a>");
        assert!(
            split_scheme.left_behind.is_some(),
            "a browser reads this and this does not, so it is named: {split_scheme:?}"
        );

        let not_code = html_fragments(
            "<script type=\"text/x-template\">{{#each i}}<li>{{this}}</li>{{/each}}</script>",
        );
        assert!(
            not_code.left_behind.is_some(),
            "a fragment the grammar cannot read reports nothing, which must not read as clean: \
             {not_code:?}"
        );

        // And the limit of that, measured rather than assumed: the JavaScript grammar includes JSX,
        // so a Vue template parses cleanly and is not refused. It reaches the rules as markup.
        let jsx_shaped =
            html_fragments("<script type=\"text/x-template\"><div v-if=\"a\">x</div></script>");
        assert!(jsx_shaped.left_behind.is_none(), "{jsx_shaped:?}");

        let two = html_fragments("<script src=\"a.js\"></script><script>eval(x)</script>");
        assert_eq!(
            two.fragments.len(),
            1,
            "the second one is the one with code"
        );
    }

    #[test]
    fn a_finding_in_a_page_names_the_line_in_the_page() {
        // A reader sent to line 3 of a fragment they cannot see is worse off than one given
        // nothing at all.
        let page = "<html>\n<body>\n<h1>Notes</h1>\n<script>\neval(location.hash)\n</script>\n</body>\n</html>\n";
        let extracted = html_fragments(page);
        assert_eq!(extracted.fragments.len(), 1);
        let fragment = &extracted.fragments[0];
        let findings = scan_file(&rules(), fragment.language, "index.html", &fragment.code);
        assert_eq!(ids(&findings), vec!["ast.dynamic-code-execution"]);
        assert_eq!(
            findings[0].location.line + fragment.line_offset,
            5,
            "`eval` is on line 5 of the page"
        );
    }

    #[test]
    fn the_four_newest_grammars_read_their_own_languages() {
        for (language, file, source, expected) in [
            (
                "csharp",
                "App.cs",
                "class A { void F(string n) { cmd.ExecuteReader(\"select * from t where n = \" + n); } }",
                "ast.sql-built-by-hand",
            ),
            (
                "csharp",
                "App.cs",
                "class A { void F() { BinaryFormatter.Deserialize(stream); } }",
                "ast.unsafe-deserialization",
            ),
            (
                "kotlin",
                "App.kt",
                "fun f(n: String) { db.rawQuery(\"select * from t where n = \" + n, null) }",
                "ast.sql-built-by-hand",
            ),
            (
                "rust",
                "app.rs",
                "fn f(n: &str) { conn.execute(&format!(\"select * from t where n = {n}\"), []); }",
                "ast.sql-built-by-hand",
            ),
            (
                "c",
                "app.c",
                "void f(char *d) { char b[99]; sprintf(b, \"ls %s\", d); system(b); }",
                "ast.shell-command",
            ),
        ] {
            let findings = scan_file(&rules(), language, file, source);
            assert!(
                ids(&findings).contains(&expected),
                "{language}: expected {expected}, got {:?}",
                ids(&findings)
            );
        }
    }

    #[test]
    fn a_kotlin_string_template_is_not_a_literal_but_an_escaped_dollar_is() {
        // Kotlin's grammar gives an interpolated string no node of its own: `"select $n"` is three
        // plain `string_content` children with the `$` standing alone as one of them, and that last
        // part is the whole discriminator. Measured rather than guessed: counting the children
        // instead would report an escaped `\$`, which leaves two of them either side of an
        // `escape_sequence`.
        let built = scan_file(
            &rules(),
            "kotlin",
            "App.kt",
            "fun f(n: String) { db.execSQL(\"select * from t where n = $n\") }",
        );
        assert!(
            ids(&built).contains(&"ast.sql-built-by-hand"),
            "a Kotlin template is a built string: {built:?}"
        );

        let escaped = scan_file(
            &rules(),
            "kotlin",
            "App.kt",
            "fun f() { db.execSQL(\"select * from prices where label = 'cost \\$5'\") }",
        );
        assert!(
            !ids(&escaped).contains(&"ast.sql-built-by-hand"),
            "an escaped dollar is written out, not substituted: {escaped:?}"
        );

        let plain = scan_file(
            &rules(),
            "kotlin",
            "App.kt",
            "fun f() { db.execSQL(\"select 1\") }",
        );
        assert!(!ids(&plain).contains(&"ast.sql-built-by-hand"), "{plain:?}");
    }

    #[test]
    fn a_csharp_json_deserialise_is_not_reported() {
        // `Deserialize` is what every JSON library is called with. Only the receiver makes it the
        // dangerous one, and reporting the safe case would teach somebody to skip the rule.
        let safe = scan_file(
            &rules(),
            "csharp",
            "App.cs",
            "class A { void F() { JsonSerializer.Deserialize(body); } }",
        );
        assert!(
            !ids(&safe).contains(&"ast.unsafe-deserialization"),
            "{safe:?}"
        );
    }

    #[test]
    fn a_php_string_that_interpolates_a_variable_is_not_a_literal() {
        // PHP puts a bare `$name` inside a double-quoted string with no wrapper node, so the string
        // looks exactly like a written-out one to a check that only knows about `${…}` and `#{…}`.
        // Missing this reports every PHP query built the most natural way as a constant, which is
        // the case the rule exists for.
        let built = scan_file(
            &rules(),
            "php",
            "app.php",
            "<?php $db->query(\"select * from t where n = $name\");",
        );
        assert!(
            ids(&built).contains(&"ast.sql-built-by-hand"),
            "an interpolated PHP string is a built string: {built:?}"
        );
        let fixed = scan_file(
            &rules(),
            "php",
            "app.php",
            "<?php $db->query(\"select * from t where n = ?\");",
        );
        assert!(
            !ids(&fixed).contains(&"ast.sql-built-by-hand"),
            "a written-out query is not a finding: {fixed:?}"
        );
    }

    #[test]
    fn a_ruby_load_on_something_that_is_not_a_deserialiser_is_not_reported() {
        // `load` is far too common a method name to report on its own. The receiver is what makes
        // it a deserialisation, and over-reporting here would teach somebody to skip the rule.
        // A lower-case receiver is an `identifier`, which the query's own shape excludes.
        let findings = scan_file(&rules(), "ruby", "app.rb", "config.load(path)");
        assert!(
            !ids(&findings).contains(&"ast.unsafe-deserialization"),
            "{findings:?}"
        );
        // A capitalised one is a `constant`, which the query does match — so only the receiver
        // pattern stops it. Without this case the pattern could be deleted and every test here
        // would still pass, because the one above was being excluded by the node kind instead.
        let other_constant = scan_file(&rules(), "ruby", "app.rb", "Settings.load(path)");
        assert!(
            !ids(&other_constant).contains(&"ast.unsafe-deserialization"),
            "a constant that is not a deserialiser must not be reported: {other_constant:?}"
        );
        let real = scan_file(&rules(), "ruby", "app.rb", "YAML.load(untrusted)");
        assert!(
            ids(&real).contains(&"ast.unsafe-deserialization"),
            "{real:?}"
        );
    }

    /// One found case and one not-found case for every language each of these rules has a query in.
    ///
    /// Each `false` line is the correct way to do the same thing, or the idiom a careless rule would
    /// report — the negative half is what stops a query that matches every call from passing.
    #[rustfmt::skip]
    const WITNESSES: &[(&str, &str, &str, bool)] = &[
        // Paths.
        ("ast.file-path-from-value", "python", "open(os.path.join(UPLOADS, request.args['name']))", true),
        ("ast.file-path-from-value", "python", "open(os.path.join(UPLOADS, secure_filename(f.filename)))", false),
        ("ast.file-path-from-value", "python", "open(os.path.join(os.path.dirname(__file__), 'schema.sql'))", false),
        ("ast.file-path-from-value", "python", "return send_file(request.args['path'])", true),
        ("ast.file-path-from-value", "python", "open('config.toml')", false),
        ("ast.file-path-from-value", "javascript", "fs.readFileSync(req.query.file)", true),
        ("ast.file-path-from-value", "javascript", "res.sendFile(path.join(__dirname, 'public', 'index.html'))", false),
        ("ast.file-path-from-value", "javascript", "res.sendFile(path.join(__dirname, req.params.name))", true),
        ("ast.file-path-from-value", "typescript", "await fs.readFile(`uploads/${req.params.name}`)", true),
        ("ast.file-path-from-value", "typescript", "fs.readFileSync('package.json')", false),
        ("ast.file-path-from-value", "go", "f, err := os.Open(r.URL.Query().Get(\"f\"))", true),
        ("ast.file-path-from-value", "go", "f, err := os.Open(\"config.json\")", false),
        ("ast.file-path-from-value", "php", "<?php echo file_get_contents($_GET['page']);", true),
        ("ast.file-path-from-value", "php", "<?php echo file_get_contents('about.html');", false),
        ("ast.file-path-from-value", "ruby", "File.read(params[:name])", true),
        ("ast.file-path-from-value", "ruby", "File.read('config.yml')", false),
        ("ast.file-path-from-value", "java", "class A { void f(String n) { new FileInputStream(n); } }", true),
        ("ast.file-path-from-value", "java", "class A { void f() { new FileInputStream(\"app.properties\"); } }", false),
        ("ast.file-path-from-value", "csharp", "class A { void F(string n) { var t = File.ReadAllText(n); } }", true),
        ("ast.file-path-from-value", "csharp", "class A { void F() { var t = File.ReadAllText(\"a.json\"); } }", false),
        // A bare constant is the app's own configuration, not a request value.
        ("ast.file-path-from-value", "python", "with open(CONFIG_PATH) as f: pass", false),
        ("ast.file-path-from-value", "javascript", "fs.readFileSync(CERT_FILE)", false),
        ("ast.file-path-from-value", "ruby", "File.read(SETTINGS_FILE)", false),
        ("ast.file-path-from-value", "php", "<?php $s = file_get_contents(SETTINGS_FILE);", false),
        ("ast.file-path-from-value", "python", "with open(CONFIG_PATH + name) as f: pass", true),
        // The same method name on something that is not the file system.
        ("ast.file-path-from-value", "javascript", "const entry = zip.readFile(req.query.name)", false),
        ("ast.file-path-from-value", "go", "conn, err := pool.Open(r.FormValue(\"db\"))", false),
        ("ast.file-path-from-value", "ruby", "log = Logger.new(path)", false),
        ("ast.file-path-from-value", "csharp", "class A { void F(string n) { var t = Cache.Open(n); } }", false),
        // Hashes.
        ("ast.weak-hash-function", "python", "digest = hashlib.md5(password.encode()).hexdigest()", true),
        ("ast.weak-hash-function", "python", "etag = hashlib.md5(body, usedforsecurity=False).hexdigest()", false),
        ("ast.weak-hash-function", "python", "digest = hashlib.sha256(data).hexdigest()", false),
        ("ast.weak-hash-function", "javascript", "crypto.createHash('md5').update(pw).digest('hex')", true),
        ("ast.weak-hash-function", "javascript", "crypto.createHash('sha256').update(pw).digest('hex')", false),
        ("ast.weak-hash-function", "typescript", "crypto.createHash(\"SHA1\").update(x)", true),
        ("ast.weak-hash-function", "typescript", "crypto.createHash(\"sha512\").update(x)", false),
        ("ast.weak-hash-function", "go", "sum := md5.Sum([]byte(pw))", true),
        ("ast.weak-hash-function", "go", "sum := sha256.Sum256([]byte(pw))", false),
        ("ast.weak-hash-function", "php", "<?php $h = md5($password);", true),
        ("ast.weak-hash-function", "php", "<?php $h = password_hash($password, PASSWORD_DEFAULT);", false),
        ("ast.weak-hash-function", "ruby", "Digest::MD5.hexdigest(password)", true),
        ("ast.weak-hash-function", "ruby", "Digest::SHA256.hexdigest(password)", false),
        ("ast.weak-hash-function", "java", "class A { void f() throws Exception { MessageDigest.getInstance(\"MD5\"); } }", true),
        ("ast.weak-hash-function", "java", "class A { void f() throws Exception { MessageDigest.getInstance(\"SHA-256\"); } }", false),
        ("ast.weak-hash-function", "csharp", "class A { void F() { using var h = MD5.Create(); } }", true),
        ("ast.weak-hash-function", "csharp", "class A { void F() { using var h = SHA256.Create(); } }", false),
        ("ast.weak-hash-function", "kotlin", "fun f() { val d = MessageDigest.getInstance(\"SHA-1\") }", true),
        ("ast.weak-hash-function", "kotlin", "fun f() { val d = MessageDigest.getInstance(\"SHA-256\") }", false),
        ("ast.weak-hash-function", "go", "h := sha256.New()", false),
        // Ciphers.
        ("ast.weak-cipher", "python", "cipher = AES.new(key, AES.MODE_ECB)", true),
        ("ast.weak-cipher", "python", "cipher = AES.new(key, AES.MODE_GCM)", false),
        ("ast.weak-cipher", "python", "c = Cipher(algorithms.AES(key), modes.ECB())", true),
        ("ast.weak-cipher", "python", "c = Cipher(algorithms.AES(key), modes.GCM(iv))", false),
        ("ast.weak-cipher", "javascript", "crypto.createCipheriv('aes-128-ecb', key, null)", true),
        ("ast.weak-cipher", "javascript", "crypto.createCipheriv('aes-256-gcm', key, iv)", false),
        ("ast.weak-cipher", "typescript", "crypto.createCipheriv(\"des-ede3-cbc\", key, iv)", true),
        ("ast.weak-cipher", "typescript", "crypto.createCipheriv(\"chacha20-poly1305\", key, iv)", false),
        ("ast.weak-cipher", "go", "block, err := des.NewTripleDESCipher(key)", true),
        ("ast.weak-cipher", "go", "block, err := aes.NewCipher(key)", false),
        ("ast.weak-cipher", "php", "<?php openssl_encrypt($data, 'aes-128-ecb', $key);", true),
        ("ast.weak-cipher", "php", "<?php openssl_encrypt($data, 'aes-256-gcm', $key, 0, $iv, $tag);", false),
        ("ast.weak-cipher", "ruby", "c = OpenSSL::Cipher.new('des-ede3-cbc')", true),
        ("ast.weak-cipher", "ruby", "c = OpenSSL::Cipher.new('aes-256-gcm')", false),
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES\"); } }", true),
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { Cipher.getInstance(\"AES/GCM/NoPadding\"); } }", false),
        ("ast.weak-cipher", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.ECB; } }", true),
        ("ast.weak-cipher", "csharp", "class A { void F(Aes a) { a.Mode = CipherMode.CBC; } }", false),
        ("ast.weak-cipher", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\") }", true),
        ("ast.weak-cipher", "kotlin", "fun f() { val c = Cipher.getInstance(\"AES/GCM/NoPadding\") }", false),
        // Generating a key names the algorithm and no mode: "AES" here is not ECB.
        ("ast.weak-cipher", "java", "class A { void f() throws Exception { KeyGenerator.getInstance(\"AES\"); } }", false),
        ("ast.weak-cipher", "kotlin", "fun f() { val k = KeyGenerator.getInstance(\"AES\") }", false),
        // Redirects.
        ("ast.open-redirect", "python", "return redirect(request.args.get('next'))", true),
        ("ast.open-redirect", "python", "return redirect(url_for('index'))", false),
        ("ast.open-redirect", "python", "return redirect('/login')", false),
        ("ast.open-redirect", "javascript", "res.redirect(req.query.returnTo)", true),
        ("ast.open-redirect", "javascript", "res.redirect('/dashboard')", false),
        ("ast.open-redirect", "typescript", "res.redirect(req.body.next as string)", true),
        ("ast.open-redirect", "typescript", "res.redirect(`/items`)", false),
        ("ast.open-redirect", "go", "http.Redirect(w, r, r.URL.Query().Get(\"next\"), http.StatusFound)", true),
        ("ast.open-redirect", "go", "http.Redirect(w, r, \"/login\", http.StatusFound)", false),
        ("ast.open-redirect", "javascript", "router.redirect(from, to)", false),
        ("ast.open-redirect", "go", "cache.Redirect(w, r, next, 302)", false),
        ("ast.open-redirect", "php", "<?php header('Location: ' . $_GET['next']);", true),
        ("ast.open-redirect", "php", "<?php header('Content-Type: ' . $type);", false),
        ("ast.open-redirect", "ruby", "redirect_to params[:return_to]", true),
        ("ast.open-redirect", "ruby", "redirect_to root_path", false),
        ("ast.open-redirect", "java", "class A { void f(HttpServletResponse r, String u) throws Exception { r.sendRedirect(u); } }", true),
        ("ast.open-redirect", "java", "class A { void f(HttpServletResponse r) throws Exception { r.sendRedirect(\"/home\"); } }", false),
        ("ast.open-redirect", "csharp", "class C { IActionResult F(string returnUrl) { return Redirect(returnUrl); } }", true),
        ("ast.open-redirect", "csharp", "class C { IActionResult F() { return Redirect(Url.Action(\"Index\")); } }", false),
        // Dart and Swift, and the gaps the per-language rule showed in the others. Every rule has
        // both halves in both languages, or says there is nothing to find in it.
        ("ast.dynamic-code-execution", "dart", "void f(String u) { Isolate.spawnUri(Uri.parse(u), [], null); }", true),
        ("ast.dynamic-code-execution", "dart", "void f(String p) { Isolate.spawnUri(Uri.file(p), [], null); }", true),
        ("ast.dynamic-code-execution", "dart", "void f() { Isolate.spawnUri(Uri.parse('worker.dart'), [], null); }", false),
        ("ast.dynamic-code-execution", "dart", "void f() { Isolate.spawn(worker, null); }", false),
        ("ast.dynamic-code-execution", "swift", "func f(code: String) { ctx.evaluateScript(code) }", true),
        ("ast.dynamic-code-execution", "swift", "func f(s: String) { let e = NSExpression(format: s) }", true),
        ("ast.dynamic-code-execution", "swift", "func f() { ctx.evaluateScript(\"1 + 1\") }", false),
        ("ast.dynamic-code-execution", "swift", "func f(x: Int) { let e = NSExpression(format: \"%d + 1\", x) }", false),
        ("ast.dynamic-code-execution", "csharp", "class A { async void F(string c) { await CSharpScript.EvaluateAsync(c); } }", true),
        ("ast.dynamic-code-execution", "csharp", "class A { async void F() { await CSharpScript.EvaluateAsync(\"1 + 1\"); } }", false),
        ("ast.dynamic-code-execution", "kotlin", "fun f(code: String) { engine.eval(code) }", true),
        ("ast.dynamic-code-execution", "kotlin", "fun f() { engine.eval(\"1 + 1\") }", false),
        ("ast.shell-command", "dart", "void f(String cmd) { Process.run('sh', ['-c', cmd]); }", true),
        ("ast.shell-command", "dart", "void f(String dir) { Process.run(\"/bin/bash\", [\"-c\", \"ls $dir\"]); }", true),
        ("ast.shell-command", "dart", "void f(String exe) { Process.start(exe, []); }", true),
        ("ast.shell-command", "dart", "void f() { Process.run('sh', ['-c', 'ls -la']); }", false),
        ("ast.shell-command", "dart", "void f(String branch) { Process.run('git', ['log', branch]); }", false),
        ("ast.shell-command", "dart", "void f(String cmd) { Pool.run('sh', ['-c', cmd]); }", false),
        ("ast.shell-command", "dart", "void f() { Process.run('sh', <String>['-c', 'ls -la']); }", false),
        ("ast.shell-command", "dart", "void f() { Process.runSync('/bin/sh', <String>['-c', 'date']); }", false),
        ("ast.shell-command", "swift", "func f() { task.arguments = [\"-c\", \"ls \" + \"-la\"] }", false),
        ("ast.shell-command", "swift", "func f(cmd: String) { task.arguments = [\"-c\", cmd] }", true),
        ("ast.shell-command", "swift", "func f(cmd: String) { let p = Process.launchedProcess(launchPath: \"/bin/sh\", arguments: [\"-c\", cmd]) }", true),
        ("ast.shell-command", "swift", "func f(cmd: String) { system(cmd) }", true),
        ("ast.shell-command", "swift", "func f() { task.arguments = [\"-c\", \"ls -la\"] }", false),
        ("ast.shell-command", "swift", "func f(name: String) { task.arguments = [\"log\", name] }", false),
        ("ast.shell-command", "swift", "func f() { system(\"ls\") }", false),
        ("ast.shell-command", "go", "func f(c string) { exec.Command(\"sh\", \"-c\", c).Run() }", true),
        ("ast.shell-command", "go", "func f(ctx context.Context, c string) { exec.CommandContext(ctx, \"bash\", \"-c\", c).Run() }", true),
        ("ast.shell-command", "go", "func f(name string) { exec.Command(name).Run() }", true),
        ("ast.shell-command", "go", "func f() { exec.Command(\"sh\", \"-c\", \"ls -la\").Run() }", false),
        ("ast.shell-command", "go", "func f(b string) { exec.Command(\"git\", \"log\", b).Run() }", false),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery(\"select * from notes where name = '$n'\");", true),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery('select * from notes where name = ' + n);", true),
        ("ast.sql-built-by-hand", "dart", "Future f(String n) => db.rawQuery('select * from notes where name = ?', [n]);", false),
        ("ast.sql-built-by-hand", "dart", "Future f(String t) => db.query(t, where: 'id = ?', whereArgs: [1]);", false),
        ("ast.sql-built-by-hand", "dart", "Future f() => db.rawQuery('select * ' + 'from notes');", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) { sqlite3_exec(db, \"delete from notes where name = '\\(n)'\", nil, nil, nil) }", true),
        ("ast.sql-built-by-hand", "swift", "func f(q: String) throws { try db.execute(sql: q) }", true),
        ("ast.sql-built-by-hand", "swift", "func f() { sqlite3_exec(db, \"create table notes (name text)\", nil, nil, nil) }", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) throws { try db.execute(literal: \"insert into notes values (\\(n))\") }", false),
        ("ast.sql-built-by-hand", "swift", "func f(n: String) throws { try db.execute(sql: \"insert into notes values (?)\", arguments: [n]) }", false),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) { let o = NSKeyedUnarchiver.unarchiveObject(with: d) }", true),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) throws { let o = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(d) }", true),
        ("ast.unsafe-deserialization", "swift", "func f(d: Data) throws { let o = try NSKeyedUnarchiver.unarchivedObject(ofClass: Note.self, from: d) }", false),
        ("ast.unsafe-deserialization", "javascript", "const obj = serialize.unserialize(req.cookies.profile)", true),
        ("ast.unsafe-deserialization", "javascript", "const obj = JSON.parse(req.cookies.profile)", false),
        ("ast.unsafe-deserialization", "typescript", "const obj = unserialize(req.body.data as string)", true),
        ("ast.unsafe-deserialization", "typescript", "const obj = JSON.parse(req.body.data as string)", false),
        ("ast.shell-command-backticks", "php", "<?php $out = `ls {$_GET['dir']}`;", true),
        ("ast.shell-command-backticks", "php", "<?php $out = `cat $file`;", true),
        ("ast.shell-command-backticks", "php", "<?php $out = `ls -la`;", false),
        ("ast.shell-command-backticks", "php", "<?php echo `whoami`;", false),
        ("ast.file-path-from-value", "dart", "Future f(Request r) => File(r.url.queryParameters['f']!).readAsString();", true),
        ("ast.file-path-from-value", "dart", "Future f(String name) => File('uploads/$name').readAsString();", true),
        ("ast.file-path-from-value", "dart", "Future f() => File('config.json').readAsString();", false),
        ("ast.file-path-from-value", "swift", "func f(p: String) { let d = FileManager.default.contents(atPath: p) }", true),
        ("ast.file-path-from-value", "swift", "func f(p: String) throws { let s = try String(contentsOfFile: p) }", true),
        ("ast.file-path-from-value", "swift", "func f() throws { let s = try String(contentsOfFile: \"/etc/app.conf\") }", false),
        ("ast.file-path-from-value", "swift", "func f(n: Int) { let s = String(describing: n) }", false),
        ("ast.file-path-from-value", "swift", "func f() throws { let d = try Data(contentsOf: URL(fileURLWithPath: \"/etc/app.conf\")) }", false),
        ("ast.file-path-from-value", "kotlin", "fun f(name: String) { val t = File(name).readText() }", true),
        ("ast.file-path-from-value", "kotlin", "fun f() { val t = File(\"app.conf\").readText() }", false),
        ("ast.file-path-from-value", "rust", "fn f(p: &str) { let t = fs::read_to_string(p); }", true),
        ("ast.file-path-from-value", "rust", "fn f(p: String) { let t = File::open(&p); }", true),
        ("ast.file-path-from-value", "rust", "fn f() { let t = File::open(\"app.toml\"); }", false),
        ("ast.file-path-from-value", "rust", "fn f(p: &str) { let t = Path::new(p); }", false),
        ("ast.file-path-from-value", "c", "void f(const char *p) { FILE *fp = fopen(p, \"r\"); }", true),
        ("ast.file-path-from-value", "c", "void f(void) { FILE *fp = fopen(\"/etc/app.conf\", \"r\"); }", false),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => md5.convert(b).toString();", true),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => sha1.convert(b).toString();", true),
        ("ast.weak-hash-function", "dart", "String f(List<int> b) => sha256.convert(b).toString();", false),
        ("ast.weak-hash-function", "swift", "func f(d: Data) { let h = Insecure.MD5.hash(data: d) }", true),
        ("ast.weak-hash-function", "swift", "func f(p: UnsafeRawPointer, n: CC_LONG) { CC_SHA1(p, n, &out) }", true),
        ("ast.weak-hash-function", "swift", "func f(d: Data) { let h = SHA256.hash(data: d) }", false),
        ("ast.weak-hash-function", "swift", "func f(p: UnsafeRawPointer, n: CC_LONG) { CC_SHA256(p, n, &out) }", false),
        ("ast.weak-hash-function", "rust", "fn f(b: &[u8]) { let d = md5::compute(b); }", true),
        ("ast.weak-hash-function", "rust", "fn f() { let h = Sha1::new(); }", true),
        ("ast.weak-hash-function", "rust", "fn f() { let h = Sha256::new(); }", false),
        ("ast.weak-hash-function", "c", "void f(const unsigned char *d, size_t n, unsigned char *o) { MD5(d, n, o); }", true),
        ("ast.weak-hash-function", "c", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha1(), NULL); }", true),
        ("ast.weak-hash-function", "c", "void f(EVP_MD_CTX *c) { EVP_DigestInit_ex(c, EVP_sha256(), NULL); }", false),
        ("ast.weak-cipher", "dart", "final e = Encrypter(AES(key, mode: AESMode.ecb));", true),
        ("ast.weak-cipher", "dart", "final c = ECBBlockCipher(AESEngine());", true),
        ("ast.weak-cipher", "dart", "final e = Encrypter(AES(key, mode: AESMode.gcm));", false),
        ("ast.weak-cipher", "swift", "func f() { let s = CCCrypt(op, CCAlgorithm(kCCAlgorithmDES), 0, k, n, nil, i, m, o, l, &w) }", true),
        ("ast.weak-cipher", "swift", "func f() throws { let a = try AES(key: k, blockMode: ECB()) }", true),
        ("ast.weak-cipher", "swift", "func f() throws { let b = try AES.GCM.seal(d, using: key) }", false),
        ("ast.weak-cipher", "swift", "func f() { let s = CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), 0, k, n, iv, i, m, o, l, &w) }", false),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_128_ecb(), NULL, k, NULL); }", true),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_des_ede3_cbc(), NULL, k, iv); }", true),
        ("ast.weak-cipher", "c", "void f(EVP_CIPHER_CTX *c) { EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), NULL, k, iv); }", false),
        ("ast.open-redirect", "dart", "Response f(Request r) => Response.found(r.url.queryParameters['next']!);", true),
        ("ast.open-redirect", "dart", "void f(HttpRequest r, String next) { r.response.redirect(Uri.parse(next)); }", true),
        ("ast.open-redirect", "dart", "Response f() => Response.found('/login');", false),
        ("ast.open-redirect", "dart", "void f(HttpRequest r) { r.response.redirect(Uri.parse('/home')); }", false),
        ("ast.open-redirect", "swift", "func f(req: Request, next: String) -> Response { return req.redirect(to: next) }", true),
        ("ast.open-redirect", "swift", "func f(req: Request) -> Response { return req.redirect(to: \"/login\") }", false),
        ("ast.open-redirect", "swift", "func f(req: Request, next: String) -> Response { return req.redirect(to: \"/r/\\(next)\") }", true),
        ("ast.open-redirect", "kotlin", "fun f(next: String) { call.respondRedirect(next) }", true),
        ("ast.open-redirect", "kotlin", "fun f() { call.respondRedirect(\"/login\") }", false),
        ("ast.open-redirect", "rust", "async fn f(q: Query<Next>) -> Redirect { Redirect::to(&q.next) }", true),
        ("ast.open-redirect", "rust", "async fn f() -> Redirect { Redirect::to(\"/login\") }", false),
        // Shell scripts.
        ("ast.dynamic-code-execution", "shell", "eval \"$1\"", true),
        ("ast.dynamic-code-execution", "shell", "eval \"set -- $ARGS\"", true),
        ("ast.dynamic-code-execution", "shell", "eval 'export PATH=/opt/bin:$PATH'", false),
        ("ast.dynamic-code-execution", "shell", "eval \"$(ssh-agent -s)\"", false),
        ("ast.shell-command", "shell", "sh -c \"ls $dir\"", true),
        ("ast.shell-command", "shell", "/bin/bash -c \"$1\"", true),
        ("ast.shell-command", "shell", "bash -c 'ls -la'", false),
        ("ast.shell-command", "shell", "sh -c \"echo \\$HOME\"", false),
        ("ast.shell-command", "shell", "ls -c \"$dir\"", false),
        // A bare word, a `${…}`, a `$(…)`, and quoting mixed within one argument.
        ("ast.shell-command", "shell", "bash -c date", false),
        ("ast.sql-built-by-hand", "shell", "psql -c VACUUM", false),
        ("ast.shell-command", "shell", "sh -c \"ls \"'-la'", false),
        ("ast.sql-built-by-hand", "shell", "psql -c 'select '\"count(*)\"' from notes'", false),
        ("ast.dynamic-code-execution", "shell", "eval \"${CMD}\"", true),
        ("ast.shell-command", "shell", "sh -c \"rm -rf ${dir}\"", true),
        ("ast.shell-command", "shell", "sh -c \"ls $(cat dirs.txt)\"", true),
        ("ast.dynamic-code-execution", "shell", "eval \"$(cat script.txt)\"", true),
        ("ast.sql-built-by-hand", "shell", "psql -c \"select * from notes where name = '$1'\"", true),
        ("ast.sql-built-by-hand", "shell", "sqlite3 app.db \"delete from notes where id = $ID\"", true),
        ("ast.sql-built-by-hand", "shell", "psql -c 'select count(*) from notes'", false),
        ("ast.sql-built-by-hand", "shell", "psql -h \"$HOST\" -d notes", false),
        ("ast.file-path-from-value", "shell", "cat \"/srv/files/$QUERY_STRING\"", true),
        ("ast.file-path-from-value", "shell", "rm -f /tmp/upload${PATH_INFO}", true),
        ("ast.file-path-from-value", "shell", "cat \"$CONFIG_FILE\"", false),
        ("ast.file-path-from-value", "shell", "echo \"$QUERY_STRING\"", false),
        ("ast.weak-hash-function", "shell", "md5sum release.tar.gz", true),
        ("ast.weak-hash-function", "shell", "openssl dgst -sha1 release.tar.gz", true),
        ("ast.weak-hash-function", "shell", "sha256sum -c release.sha256", false),
        ("ast.weak-hash-function", "shell", "openssl dgst -sha256 release.tar.gz", false),
        ("ast.weak-cipher", "shell", "openssl enc -des3 -in secrets.txt -out secrets.enc", true),
        ("ast.weak-cipher", "shell", "openssl enc -aes-128-ecb -in a -out b", true),
        ("ast.weak-cipher", "shell", "openssl enc -aes-256-cbc -pbkdf2 -in a -out b", false),
        ("ast.open-redirect", "shell", "echo \"Location: $QUERY_STRING\"", true),
        ("ast.open-redirect", "shell", "printf 'Location: %s\\r\\n\\r\\n' \"$next\"", true),
        ("ast.open-redirect", "shell", "echo \"Location: /login\"", false),
        ("ast.open-redirect", "shell", "echo \"Content-Type: $type\"", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://get.example.com | sh", true),
        ("ast.download-piped-to-shell", "shell", "wget -qO- https://example.com/install | sudo bash -s -- -y", true),
        ("ast.download-piped-to-shell", "shell", "bash <(curl -s https://example.com/setup.sh)", true),
        ("ast.download-piped-to-shell", "shell", "curl -fsSL https://example.com/key.gpg | sudo tee /etc/apt/keyrings/example.gpg", false),
        ("ast.download-piped-to-shell", "shell", "curl -fsSLo install.sh https://example.com/install.sh && sha256sum -c install.sha256 && sh install.sh", false),
        ("ast.download-piped-to-shell", "shell", "cat notes.txt | sh", false),
        // The last three a rule had not been taught.
        ("ast.shell-command", "rust", "fn f(c: &str) { Command::new(\"sh\").arg(\"-c\").arg(c).output(); }", true),
        ("ast.shell-command", "rust", "fn f(c: &str) { Command::new(\"/bin/bash\").args([\"-c\", c]).status(); }", true),
        ("ast.shell-command", "rust", "fn f(c: &str) { std::process::Command::new(\"sh\").args(&[\"-c\", c]).spawn(); }", true),
        ("ast.shell-command", "rust", "fn f(exe: &str) { Command::new(exe).spawn(); }", true),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"sh\").arg(\"-c\").arg(\"ls -la\").output(); }", false),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"sh\").args([\"-c\", \"ls -la\"]).output(); }", false),
        ("ast.shell-command", "rust", "fn f() { Command::new(\"bash\").args(&[\"-c\", \"date\"]).output(); }", false),
        ("ast.shell-command", "rust", "fn f(b: &str) { Command::new(\"git\").arg(\"log\").arg(b).output(); }", false),
        ("ast.shell-command", "rust", "fn f(b: &str) { Command::new(\"git\").args([\"log\", b]).output(); }", false),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::des_ede3_cbc(); }", true),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::aes_128_ecb(); }", true),
        ("ast.weak-cipher", "rust", "fn f(k: &[u8]) { let c = TdesEde3::new_from_slice(k); }", true),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let e = ecb::Encryptor::<Aes128>::new(k); }", true),
        ("ast.weak-cipher", "rust", "fn f() { let c = Cipher::aes_256_gcm(); }", false),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let e = cbc::Encryptor::<Aes128>::new(k, iv); }", false),
        ("ast.weak-cipher", "rust", "fn f(k: &Key) { let c = Aes256Gcm::new(k); }", false),
        ("ast.open-redirect", "c", "void f(const char *u) { printf(\"Location: %s\\r\\n\\r\\n\", u); }", true),
        ("ast.open-redirect", "c", "void f(const char *u) { fprintf(stdout, \"Location: %s\\n\\n\", u); }", true),
        ("ast.open-redirect", "c", "void f(void) { printf(\"Location: /login\\n\\n\"); }", false),
        ("ast.open-redirect", "c", "void f(void) { printf(\"Location: %s\\n\\n\", \"/login\"); }", false),
        ("ast.open-redirect", "c", "void f(const char *t) { printf(\"Content-Type: %s\\n\\n\", t); }", false),
    ];

    #[test]
    fn the_newer_rules_find_the_unsafe_form_and_leave_the_safe_one() {
        let rules = rules();
        let mut wrong = Vec::new();
        for (rule, language, source, expected) in WITNESSES {
            let findings = scan_file(&rules, language, &format!("src/app.{language}"), source);
            let found = ids(&findings).contains(rule);
            if found != *expected {
                wrong.push(format!(
                    "{rule} in {language} {} `{source}`",
                    if *expected { "missed" } else { "reported" }
                ));
            }
            // A negative that another rule reports is still a negative for this one, but a
            // positive that fires a second, unrelated rule is a query matching too much.
            if *expected && let Some(other) = findings.iter().find(|f| f.rule_id != *rule) {
                wrong.push(format!(
                    "{rule} in {language}: `{source}` also fired {}",
                    other.rule_id
                ));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));

        // Every language each of these rules claims has a witness both ways. A query with no found
        // case is a query that may never fire; one with no not-found case may fire on everything.
        //
        // Which pairs that covers: every language of the four rules written with this table, every
        // rule's Dart, Swift, and shell, and any other language the table has a line for at all. The older
        // rules' first languages are witnessed by the tests above instead.
        const WRITTEN_WITH_THIS_TABLE: &[&str] = &[
            "ast.file-path-from-value",
            "ast.weak-hash-function",
            "ast.weak-cipher",
            "ast.open-redirect",
        ];
        let mut unwitnessed = Vec::new();
        for (rule_id, languages, _) in rules.coverage() {
            for language in languages {
                let owed = WRITTEN_WITH_THIS_TABLE.contains(&rule_id)
                    || matches!(language, "dart" | "swift" | "shell")
                    || WITNESSES
                        .iter()
                        .any(|(r, l, ..)| *r == rule_id && *l == language);
                if !owed {
                    continue;
                }
                for want in [true, false] {
                    if !WITNESSES
                        .iter()
                        .any(|(r, l, _, e)| *r == rule_id && *l == language && *e == want)
                    {
                        unwitnessed.push(format!("{rule_id} {language} has no {want} case"));
                    }
                }
            }
        }
        assert!(unwitnessed.is_empty(), "{}", unwitnessed.join("\n"));
    }

    /// Prints the parse tree of a snippet, for writing a query against what the grammar really
    /// produces rather than what it plausibly does. Not a test; run by hand:
    ///
    /// `SV_DUMP_LANG=dart SV_DUMP_SRC='…' cargo test -p sv-check --lib dump_trees -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dump_trees() {
        let lang = std::env::var("SV_DUMP_LANG").unwrap();
        let src = std::env::var("SV_DUMP_SRC").unwrap();
        let mut parser = Parser::new();
        parser.set_language(&grammar(&lang).unwrap()).unwrap();
        let tree = parser.parse(&src, None).unwrap();
        println!("{}", tree.root_node().to_sexp());
    }
}
